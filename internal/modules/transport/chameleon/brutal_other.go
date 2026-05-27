//go:build !linux

package chameleon

import "net"

// setBrutalRate is a no-op on non-Linux platforms (the tcp-brutal kernel
// module is Linux-only). Clients on Windows/macOS/Android keep standard CC.
func setBrutalRate(conn *net.TCPConn, mbps int) {}
