package client

import (
	"context"
	stdlog "log"
	"sync/atomic"
	"time"

	"github.com/nekoskin/whispera/core/crypto"
	"github.com/nekoskin/whispera/core/handshake"
	"github.com/nekoskin/whispera/core/socks5"
	"github.com/nekoskin/whispera/core/tunnel"
)

const (
	primaryReconnectBackoff    = 2 * time.Second
	primaryReconnectMaxBackoff = 10 * time.Second
)

func runTransportWatchdog(ctx context.Context, primaryEntry *TransportEntry, transports []string, socksMod *socks5.Module, restartEntry func(*TransportEntry, *tunnel.Config), buildBaseCfg func(*TransportEntry) *tunnel.Config) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	var reconnecting int32
	var reconnectFails int32
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			primaryEntry.mu.Lock()
			currentMgr := primaryEntry.mgr
			wasConnected := primaryEntry.Status == connStatusConnected
			primaryEntry.mu.Unlock()

			if currentMgr != nil && currentMgr.IsConnected() {
				continue
			}

			if wasConnected {
				markPrimaryLost(primaryEntry, currentMgr, transports)
			}

			entries := pool.List()
			if !switchToConnectedStandby(entries, socksMod, currentMgr, primaryEntry) {
				activateStandby(entries, socksMod, restartEntry, buildBaseCfg)
			}

			reconnectPrimary(primaryEntry, transports, socksMod, restartEntry, buildBaseCfg, &reconnecting, &reconnectFails)
		}
	}
}

func markPrimaryLost(primaryEntry *TransportEntry, currentMgr *tunnel.Manager, transports []string) {
	reason := "tunnel reported not connected"
	if currentMgr != nil {
		if lastErr := currentMgr.LastError(); lastErr != nil {
			reason = lastErr.Error()
		}
	}
	primaryEntry.mu.Lock()
	primaryEntry.Status = connStatusRST
	primaryEntry.Error = reason
	primaryEntry.mu.Unlock()
	stdlog.Printf("Transport watchdog: primary %s is no longer connected (%s)", transports[0], reason)
}

func switchToConnectedStandby(entries []*TransportEntry, socksMod *socks5.Module, currentMgr *tunnel.Manager, primaryEntry *TransportEntry) bool {
	for _, e := range entries {
		e.mu.Lock()
		status := e.Status
		mgr := e.mgr
		e.mu.Unlock()

		if status == connStatusConnected && mgr != nil && mgr.IsConnected() && mgr != currentMgr {
			socksMod.SetTunnel(mgr)
			stdlog.Printf("Transport watchdog: switched SOCKS to %s", e.Transport)
			return true
		}
		if status == connStatusConnected && e != primaryEntry && (mgr == nil || !mgr.IsConnected()) {
			e.mu.Lock()
			e.Status = connStatusStandby
			e.mu.Unlock()
			stdlog.Printf("Transport watchdog: %s dropped, marking standby for retry", e.Transport)
		}
	}
	return false
}

func activateStandby(entries []*TransportEntry, socksMod *socks5.Module, restartEntry func(*TransportEntry, *tunnel.Config), buildBaseCfg func(*TransportEntry) *tunnel.Config) {
	for _, e := range entries {
		e.mu.Lock()
		status := e.Status
		mgr := e.mgr
		tr := e.Transport
		e.mu.Unlock()

		if status != connStatusStandby || mgr == nil {
			continue
		}
		stdlog.Printf("Transport watchdog: activating standby transport %s", tr)
		go func(entry *TransportEntry) {
			restartEntry(entry, buildBaseCfg(entry))

			entry.mu.Lock()
			connected := entry.Status == connStatusConnected && entry.mgr != nil
			mgr := entry.mgr
			tr := entry.Transport
			entry.mu.Unlock()
			if connected && mgr.IsConnected() {
				socksMod.SetTunnel(mgr)
				stdlog.Printf("Transport watchdog: standby %s now active", tr)
			}
		}(e)
		return
	}
}

func reconnectPrimary(primaryEntry *TransportEntry, transports []string, socksMod *socks5.Module, restartEntry func(*TransportEntry, *tunnel.Config), buildBaseCfg func(*TransportEntry) *tunnel.Config, reconnecting, reconnectFails *int32) {
	primaryEntry.mu.Lock()
	enabled := primaryEntry.Enabled
	primaryEntry.mu.Unlock()

	if !enabled || !atomic.CompareAndSwapInt32(reconnecting, 0, 1) {
		return
	}
	go func() {
		defer atomic.StoreInt32(reconnecting, 0)
		if fails := atomic.LoadInt32(reconnectFails); fails > 0 {
			backoff := time.Duration(fails) * primaryReconnectBackoff
			if backoff > primaryReconnectMaxBackoff {
				backoff = primaryReconnectMaxBackoff
			}
			time.Sleep(backoff)
		}

		stdlog.Printf("Transport watchdog: reconnecting primary %s...", transports[0])
		restartEntry(primaryEntry, buildBaseCfg(primaryEntry))

		primaryEntry.mu.Lock()
		connected := primaryEntry.Status == connStatusConnected && primaryEntry.mgr != nil
		primaryEntry.mu.Unlock()
		if connected {
			atomic.StoreInt32(reconnectFails, 0)
			socksMod.SetTunnel(primaryEntry.mgr)
			stdlog.Printf("Transport watchdog: primary reconnected, SOCKS restored")
		} else {
			atomic.AddInt32(reconnectFails, 1)
		}
	}()
}

func setEntryFailed(e *TransportEntry, err error) {
	e.mu.Lock()
	e.Status = connStatusFailed
	e.Error = err.Error()
	e.mu.Unlock()
}

func restartTransportEntry(ctx context.Context, e *TransportEntry, tunnelCfg *tunnel.Config, hsMod *handshake.Handler, cryptoMod *crypto.Provider) {
	if !atomic.CompareAndSwapInt32(&e.restarting, 0, 1) {
		return
	}
	defer atomic.StoreInt32(&e.restarting, 0)

	e.mu.Lock()
	if e.cancel != nil {
		e.cancel()
	}
	oldMgr := e.mgr
	e.Status = connStatusConnecting
	e.Error = ""
	e.mu.Unlock()

	if oldMgr != nil {
		oldMgr.Stop()
	}

	newMgr, err := tunnel.New(tunnelCfg)
	if err != nil {
		stdlog.Printf("restartEntry %s build failed: %v", e.ID, err)
		setEntryFailed(e, err)
		return
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
		return
	}
	e.mu.Lock()
	e.mgr = newMgr
	e.cancel = newCancel
	e.mu.Unlock()

	if err := newMgr.Connect(newCtx); err != nil {
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
}
