package stats

import (
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	logger "github.com/nekoskin/whispera/common/log"
)

var resetTraceLog = logger.Trace()

type TrafficConn struct {
	net.Conn
	UserID    string
	closeOnce sync.Once
	rxBytes   atomic.Int64
	txBytes   atomic.Int64
}

func isConnReset(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	return strings.Contains(err.Error(), "reset by peer")
}

func (c *TrafficConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if n > 0 {
		c.rxBytes.Add(int64(n))
	}
	if isConnReset(err) {
		resetTraceLog.Warnw("tcp_reset_detected",
			"direction", "read",
			"user", c.UserID,
			"remote", remoteAddrString(c.Conn),
			"up_bytes", c.txBytes.Load(),
			"down_bytes", c.rxBytes.Load(),
		)
	}
	return
}

func (c *TrafficConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if n > 0 {
		c.txBytes.Add(int64(n))
	}
	if isConnReset(err) {
		resetTraceLog.Warnw("tcp_reset_detected",
			"direction", "write",
			"user", c.UserID,
			"remote", remoteAddrString(c.Conn),
			"up_bytes", c.txBytes.Load(),
			"down_bytes", c.rxBytes.Load(),
		)
	}
	return
}

func remoteAddrString(conn net.Conn) string {
	if addr := conn.RemoteAddr(); addr != nil {
		return addr.String()
	}
	return ""
}

func (c *TrafficConn) Close() error {
	err := c.Conn.Close()
	return err
}

func (c *TrafficConn) NetConn() net.Conn {
	if nc, ok := c.Conn.(interface{ NetConn() net.Conn }); ok {
		return nc.NetConn()
	}
	return c.Conn
}

func (c *TrafficConn) CountTx(n int) {
	if n > 0 {
		c.txBytes.Add(int64(n))
	}
}

func WrapConn(conn net.Conn, userID string) net.Conn {
	return &TrafficConn{Conn: conn, UserID: userID}
}
