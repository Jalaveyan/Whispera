package client

import (
	"context"
	"errors"
	stdlog "log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nekoskin/whispera/core/crypto"
	"github.com/nekoskin/whispera/core/handshake"
	"github.com/nekoskin/whispera/core/protocol/quic"
	"github.com/nekoskin/whispera/core/tunnel"
)

const (
	connectAttemptTimeout = 8 * time.Second
	reviveBackoffStep     = 2 * time.Second
	reviveBackoffMax      = 10 * time.Second
)

var errNoLiveTunnel = errors.New("no live tunnel")

type tunnelPool struct {
	restart      func(*TransportEntry, *tunnel.Config) bool
	buildBaseCfg func(*TransportEntry) *tunnel.Config

	mu       sync.Mutex
	fails    int
	lastFail time.Time
}

func newTunnelPool(restart func(*TransportEntry, *tunnel.Config) bool, buildBaseCfg func(*TransportEntry) *tunnel.Config) *tunnelPool {
	return &tunnelPool{restart: restart, buildBaseCfg: buildBaseCfg}
}

func (p *tunnelPool) reviveAllowed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fails == 0 {
		return true
	}
	backoff := time.Duration(p.fails) * reviveBackoffStep
	if backoff > reviveBackoffMax {
		backoff = reviveBackoffMax
	}
	return time.Since(p.lastFail) >= backoff
}

func (p *tunnelPool) noteRevive(ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if ok {
		p.fails = 0
		return
	}
	p.fails++
	p.lastFail = time.Now()
}

func (p *tunnelPool) live() *tunnel.Manager {
	for _, e := range pool.List() {
		e.mu.Lock()
		enabled, mgr := e.Enabled, e.mgr
		e.mu.Unlock()
		if enabled && mgr != nil && mgr.IsConnected() {
			return mgr
		}
	}
	return nil
}

func (p *tunnelPool) revive() *tunnel.Manager {
	if !p.reviveAllowed() {
		return nil
	}
	attempted := false
	for _, e := range pool.List() {
		e.mu.Lock()
		enabled, mgr := e.Enabled, e.mgr
		e.mu.Unlock()
		if !enabled {
			continue
		}
		if mgr != nil && mgr.IsConnected() {
			return mgr
		}
		if !p.restart(e, p.buildBaseCfg(e)) {
			continue
		}
		attempted = true
		e.mu.Lock()
		mgr = e.mgr
		e.mu.Unlock()
		if mgr != nil && mgr.IsConnected() {
			p.noteRevive(true)
			return mgr
		}
	}
	if attempted {
		p.noteRevive(false)
	}
	return nil
}

func (p *tunnelPool) IsConnected() bool {
	if p.live() != nil {
		return true
	}
	for _, e := range pool.List() {
		e.mu.Lock()
		enabled := e.Enabled
		e.mu.Unlock()
		if enabled {
			return true
		}
	}
	return false
}

func (p *tunnelPool) OpenStream(ctx context.Context, proto byte, addr string, port uint16) (net.Conn, error) {
	mgr := p.live()
	if mgr == nil {
		if mgr = p.revive(); mgr == nil {
			return nil, errNoLiveTunnel
		}
		return mgr.OpenStream(ctx, proto, addr, port)
	}
	conn, err := mgr.OpenStream(ctx, proto, addr, port)
	if err == nil || ctx.Err() != nil {
		return conn, err
	}
	revived := p.revive()
	if revived == nil || revived == mgr {
		return nil, err
	}
	return revived.OpenStream(ctx, proto, addr, port)
}

func (p *tunnelPool) DialStream(ctx context.Context, network, addr string) (net.Conn, error) {
	mgr := p.live()
	if mgr == nil {
		if mgr = p.revive(); mgr == nil {
			return nil, errNoLiveTunnel
		}
		return mgr.DialStream(ctx, network, addr)
	}
	conn, err := mgr.DialStream(ctx, network, addr)
	if err == nil || ctx.Err() != nil {
		return conn, err
	}
	revived := p.revive()
	if revived == nil || revived == mgr {
		return nil, err
	}
	return revived.DialStream(ctx, network, addr)
}

func (p *tunnelPool) DatagramClient(addr string) (*quic.DatagramClient, bool) {
	mgr := p.live()
	if mgr == nil {
		return nil, false
	}
	return mgr.DatagramClient(addr)
}

func setEntryFailed(e *TransportEntry, err error) {
	e.mu.Lock()
	e.Status = connStatusFailed
	e.Error = err.Error()
	e.mu.Unlock()
}

func restartTransportEntry(ctx context.Context, e *TransportEntry, tunnelCfg *tunnel.Config, hsMod *handshake.Handler, cryptoMod *crypto.Provider) bool {
	if !atomic.CompareAndSwapInt32(&e.restarting, 0, 1) {
		return false
	}
	defer atomic.StoreInt32(&e.restarting, 0)

	e.mu.Lock()
	if e.cancel != nil {
		e.cancel()
	}
	oldMgr := e.mgr
	transport := e.Transport
	e.Status = connStatusConnecting
	e.Error = ""
	e.mu.Unlock()

	stdlog.Printf("restartEntry %s reconnecting %s...", e.ID, transport)

	if oldMgr != nil {
		oldMgr.Stop()
	}

	newMgr, err := tunnel.New(tunnelCfg)
	if err != nil {
		stdlog.Printf("restartEntry %s build failed: %v", e.ID, err)
		setEntryFailed(e, err)
		return true
	}
	newMgr.SetDependencies(nil, hsMod, cryptoMod)
	if tunnelCfg.BehavioralProfile != "" {
		if err := newMgr.SetBehavioralProfile(tunnelCfg.BehavioralProfile); err != nil {
			stdlog.Printf("restartEntry %s: set profile %q: %v", e.ID, tunnelCfg.BehavioralProfile, err)
		}
	}

	newCtx, newCancel := context.WithCancel(ctx)
	if err := newMgr.Init(newCtx, nil); err != nil {
		stdlog.Printf("restartEntry %s: init failed: %v", e.ID, err)
		newCancel()
		setEntryFailed(e, err)
		return true
	}
	e.mu.Lock()
	e.mgr = newMgr
	e.cancel = newCancel
	e.mu.Unlock()

	connectCtx, cancelConnect := context.WithTimeout(newCtx, connectAttemptTimeout)
	err = newMgr.Connect(connectCtx)
	cancelConnect()

	if err != nil {
		stdlog.Printf("restartEntry %s connect failed: %v", e.ID, err)
		newCancel()
		newMgr.Stop()
		setEntryFailed(e, err)
	} else {
		e.mu.Lock()
		e.Status = connStatusConnected
		e.ConnectedAt = time.Now()
		e.mu.Unlock()
		stdlog.Printf("restartEntry %s connected (encap=%v)", e.ID, tunnelCfg.CustomDialFn != nil)
	}
	return true
}
