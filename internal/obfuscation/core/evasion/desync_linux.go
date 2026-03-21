
package evasion

import (
	"net"
	"syscall"
)

func setTTL(conn *net.TCPConn, ttl int) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return
	}
	raw.Control(func(fd uintptr) {
		syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
	})
}
