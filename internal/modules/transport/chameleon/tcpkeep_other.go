//go:build !linux

package chameleon

import "net"

func tcpFastKeepalive(c *net.TCPConn) {}
