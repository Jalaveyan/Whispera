//go:build linux

package chameleon

import (
	"net"

	"golang.org/x/sys/unix"
)

func tcpFastKeepalive(c *net.TCPConn) {
	raw, err := c.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_KEEPIDLE, 15)
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_KEEPINTVL, 5)
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_KEEPCNT, 3)
	})
}
