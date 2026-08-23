package main

import (
	"context"
	"fmt"
	"io"
	"net"
	rtdebug "runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/nekoskin/whispera/common/runtime/lifecycle"
	"github.com/nekoskin/whispera/common/stats"
	"github.com/nekoskin/whispera/core/config"
	"github.com/nekoskin/whispera/core/transport/tcp"
)

type prependConn struct {
	net.Conn
	prepend []byte
}

func (c *prependConn) Read(b []byte) (int, error) {
	if len(c.prepend) > 0 {
		n := copy(b, c.prepend)
		c.prepend = c.prepend[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

func peekConn(conn net.Conn) *prependConn {
	var peek [3]byte
	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	n, _ := io.ReadFull(conn, peek[:])
	conn.SetReadDeadline(time.Time{})
	return &prependConn{Conn: conn, prepend: peek[:n]}
}

func h2cChanFor(listenAddr string) (chan net.Conn, bool) {
	portH2CChansMu.Lock()
	defer portH2CChansMu.Unlock()
	ch, ok := portH2CChans[listenAddr]
	return ch, ok
}

func serveInboundConn(conn net.Conn, listenAddr string) {
	pConn := peekConn(conn)
	prefix := pConn.prepend

	if h2cCh, ok := h2cChanFor(listenAddr); ok && string(prefix) == "PRI" {
		select {
		case h2cCh <- pConn:
		default:
			pConn.Close()
		}
		return
	}

	release, ok := acquireConnSlot(conn.RemoteAddr())
	if !ok {
		pConn.Close()
		return
	}
	go func() {
		defer release()
		if globalRelay == nil {
			pConn.Close()
			return
		}
		globalRelay.ServeTunnel(stats.WrapConn(pConn, pConn.RemoteAddr().String()), false)
	}()
}

func acceptInbound(listener net.Listener, tag, listenAddr string) {
	defer func() {
		listenersMutex.Lock()
		delete(activeListeners, tag)
		listenersMutex.Unlock()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			continue
		}
		serveInboundConn(conn, listenAddr)
	}
}

func StartInbound(inbound config.InboundConfig, serverConfig *config.ServerConfig) error {
	listenersMutex.Lock()
	defer listenersMutex.Unlock()
	if _, exists := activeListeners[inbound.Tag]; exists {
		return fmt.Errorf("inbound %s already running", inbound.Tag)
	}

	if serverConfig.Whispera.Enabled {
		if _, chmPort, err := net.SplitHostPort(serverConfig.Whispera.ListenAddr); err == nil && chmPort != "" && strconv.Itoa(inbound.Port) == chmPort {
			return nil
		}
	}

	listenAddr := net.JoinHostPort(inbound.Listen, strconv.Itoa(inbound.Port))
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", listenAddr, err)
	}
	activeListeners[inbound.Tag] = listener

	go acceptInbound(listener, inbound.Tag, listenAddr)
	return nil
}
func StopInbound(tag string) error {
	listenersMutex.Lock()
	defer listenersMutex.Unlock()

	listener, exists := activeListeners[tag]
	if !exists {
		return fmt.Errorf("inbound %s not running", tag)
	}

	if err := listener.Close(); err != nil {
		return fmt.Errorf("failed to close listener %s: %w", tag, err)
	}

	delete(activeListeners, tag)
	return nil
}

func StartReverseInbound(inbound config.InboundConfig, stopCh <-chan struct{}) {
	remoteAddr := inbound.RemoteAddr

	if remoteAddr == "" {
		return
	}

	backoff := 2 * time.Second
	const maxBackoff = 60 * time.Second

	for {
		select {
		case <-stopCh:
			return
		default:
		}

		conn, err := (&net.Dialer{Timeout: 1 * time.Second}).DialContext(context.Background(), "tcp", remoteAddr)

		if err != nil {
			select {
			case <-stopCh:
				return
			case <-time.After(backoff):
			}
			if backoff < maxBackoff {
				backoff *= 2
			}
			continue
		}

		backoff = 2 * time.Second

		if globalRelay != nil {
			globalRelay.ServeTunnel(stats.WrapConn(conn, conn.RemoteAddr().String()), false)
		} else {
			conn.Close()
		}
	}
}

func acceptBackoff(d *time.Duration) {
	time.Sleep(*d)
	if *d < time.Second {
		*d *= 2
	}
}

func startConfiguredInbounds(sc *config.ServerConfig, ctx context.Context) {
	for _, inbound := range sc.Inbounds {
		if inbound.Mode == "reverse" {
			ib := inbound
			go StartReverseInbound(ib, ctx.Done())
			continue
		}
		if inbound.Port == 0 {
			continue
		}
		_ = StartInbound(inbound, sc)
	}
}

func startFallbackTCP(m *lifecycle.Manager, sc *config.ServerConfig) error {
	tcpTransport, err := tcp.New(&tcp.Config{
		ListenAddr:   sc.Transport.TCP.ListenAddr,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		KeepAlive:    30 * time.Second,
		MaxConns:     10000,
	})
	if err != nil {
		return err
	}
	if err := m.Register(tcpTransport); err != nil {
		return err
	}
	go acceptTCPLoop(tcpTransport)
	return nil
}

func acceptTCPLoop(t *tcp.Transport) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("PANIC in tcp accept loop: %v\n%s", r, rtdebug.Stack())
		}
	}()
	time.Sleep(1 * time.Second)
	backoff := 1 * time.Millisecond
	for {
		conn, err := t.Accept()
		if err != nil {
			acceptBackoff(&backoff)
			continue
		}
		backoff = 1 * time.Millisecond
		release, ok := acquireConnSlot(conn.RemoteAddr())
		if !ok {
			conn.Close()
			continue
		}
		go serveTCPConn(conn, release)
	}
}

func serveTCPConn(conn net.Conn, release func()) {
	defer release()
	if globalRelay == nil {
		conn.Close()
		return
	}
	globalRelay.ServeTunnel(stats.WrapConn(conn, conn.RemoteAddr().String()), false)
}
