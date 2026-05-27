//go:build linux

package chameleon

import (
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// tcpBrutalParams is the setsockopt option number registered by the
// apernet/tcp-brutal kernel module (TCP_BRUTAL_PARAMS).
const tcpBrutalParams = 23301

// brutalParams mirrors the kernel module's struct brutal_params:
//
//	struct brutal_params { __u64 rate; __u32 cwnd_gain; }
//
// rate is bytes/sec; cwnd_gain is a multiplier in tenths (20 == 2.0x).
type brutalParams struct {
	rate     uint64
	cwndGain uint32
}

// setBrutalRate switches the connection's congestion control to "brutal" and
// paces it at mbps. Best-effort: if the kernel module is not loaded the
// TCP_CONGESTION setsockopt fails and the socket keeps its default CC (bbr).
func setBrutalRate(conn *net.TCPConn, mbps int) {
	if mbps <= 0 {
		return
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		if err := unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, "brutal"); err != nil {
			return
		}
		p := brutalParams{
			rate:     uint64(mbps) * 125000, // mbit/s -> bytes/s
			cwndGain: 20,
		}
		b := (*[unsafe.Sizeof(p)]byte)(unsafe.Pointer(&p))[:]
		_ = unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, tcpBrutalParams, string(b))
	})
}
