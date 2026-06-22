package stats

import (
	"net"
	"sync"
)

type TrafficConn struct {
	net.Conn
	UserID    string
	closeOnce sync.Once
}

func (c *TrafficConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if n > 0 {
		AddRx(c.UserID, int64(n))
	}
	return
}

func (c *TrafficConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if n > 0 {
		AddTx(c.UserID, int64(n))
	}
	return
}

func (c *TrafficConn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(func() {
		DeregisterConn(c.UserID, c)
		Global().DecrementSessionCount(c.UserID)
	})
	return err
}

func WrapConn(conn net.Conn, userID string) net.Conn {
	tc := &TrafficConn{
		Conn:   conn,
		UserID: userID,
	}
	RegisterConn(userID, tc)
	g := Global()
	g.IncrementSessionCount(userID)
	if addr := conn.RemoteAddr(); addr != nil {
		host, _, err := net.SplitHostPort(addr.String())
		if err == nil {
			g.SetUserIP(userID, host)
		}
	}
	return tc
}

var connRegistry struct {
	mu    sync.Mutex
	conns map[string]map[net.Conn]struct{}
}

func init() {
	connRegistry.conns = make(map[string]map[net.Conn]struct{})
}

func RegisterConn(userID string, conn net.Conn) {
	connRegistry.mu.Lock()
	defer connRegistry.mu.Unlock()
	if connRegistry.conns[userID] == nil {
		connRegistry.conns[userID] = make(map[net.Conn]struct{})
	}
	connRegistry.conns[userID][conn] = struct{}{}
}

func DeregisterConn(userID string, conn net.Conn) {
	connRegistry.mu.Lock()
	defer connRegistry.mu.Unlock()
	if s, ok := connRegistry.conns[userID]; ok {
		delete(s, conn)
		if len(s) == 0 {
			delete(connRegistry.conns, userID)
		}
	}
}
