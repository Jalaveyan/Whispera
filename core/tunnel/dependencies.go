package tunnel

import (
	"context"
	"net"
	"time"
)

type killSwitchController interface {
	SetVPNServer(ip net.IP, port int)
	Enable() error
	Disable() error
}

type tcpBypassDialer interface {
	DialTCP(ctx context.Context, network, addr string) (net.Conn, error)
}

type tspuDetectorIface interface {
	RecordRST(sni string, timeToRST time.Duration)
	DetectTSPU() (dpiType int, confidence float64)
}
