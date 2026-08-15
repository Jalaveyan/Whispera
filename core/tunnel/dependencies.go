package tunnel

import (
	"context"
	"net"
)

type killSwitchController interface {
	SetVPNServer(ip net.IP, port int)
	Enable() error
	Disable() error
}

type tcpBypassDialer interface {
	DialTCP(ctx context.Context, network, addr string) (net.Conn, error)
}
