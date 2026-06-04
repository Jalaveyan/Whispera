package tunnel

import (
	"context"
	"fmt"
	"net"
)

// EncapsulatedConfig возвращает копию innerCfg, у которой CustomDialFn
// направляет соединение через уже поднятый outer Manager (tunnel-in-tunnel).
//
// Схема трафика:
//
//	Client → [innerTunnel: обфускация/крипто] → [outerTunnel: транспорт] → Bridge → Server
//
// Требования: outer должен быть в состоянии Connected до вызова DialStream.
func EncapsulatedConfig(innerCfg *Config, outer *Manager) *Config {
	cfg := *innerCfg // shallow copy полей
	serverAddr := innerCfg.ServerAddr

	cfg.CustomDialFn = func(ctx context.Context) (net.Conn, error) {
		if !outer.IsConnected() {
			return nil, fmt.Errorf("encap: outer tunnel not connected")
		}
		return outer.DialStream(ctx, "tcp", serverAddr)
	}

	return &cfg
}
