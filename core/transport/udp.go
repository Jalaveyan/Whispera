package transport

import (
	"context"
	"net"
	"sync"
	"time"

	"whispera/internal/modules/qos"
)

type UDPTransport struct {
	conn            net.Conn
	config          *Config
	listener        net.PacketConn
	isVoIPOptimized bool
	voipQoS         *qos.VoIPQoS
	discordDetector *qos.DiscordDetector
	mu              sync.RWMutex
}

func NewUDPTransport(config *Config) *UDPTransport {
	t := &UDPTransport{
		config:          config,
		isVoIPOptimized: true,
		voipQoS:         qos.NewVoIPQoS(),
		discordDetector: qos.NewDiscordDetector(),
	}

	if config.Metadata != nil && config.Metadata["voip"] == "false" {
		t.isVoIPOptimized = false
	}

	return t
}

func (t *UDPTransport) Dial(addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return err
	}

	if t.isVoIPOptimized {
		t.optimizeForVoIP(conn)

		if t.voipQoS != nil {
			t.voipQoS.Enable()
		}
	} else {
		t.optimizeForVoIP(conn)
	}

	t.conn = conn
	return nil
}

func (t *UDPTransport) Listen() error {
	udpAddr, err := net.ResolveUDPAddr("udp", t.config.Addr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}

	if t.isVoIPOptimized {
		t.optimizeListenerForVoIP(conn)

		if t.voipQoS != nil {
			t.voipQoS.Enable()
		}
	}

	t.listener = conn
	return nil
}

func (t *UDPTransport) WriteRaw(pkt []byte) error {
	if t.conn == nil {
		return ErrNotConnected
	}
	_, err := t.conn.Write(pkt)
	return err
}

func (t *UDPTransport) ReadRaw(buf []byte) (int, error) {
	if t.conn == nil {
		return 0, ErrNotConnected
	}
	return t.conn.Read(buf)
}

func (t *UDPTransport) WriteTo(pkt []byte, addr net.Addr) (int, error) {
	if t.listener == nil {
		return 0, ErrNotListening
	}

	if t.isVoIPOptimized && t.voipQoS != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		defer cancel()

		queuedPkt, err := t.voipQoS.ProcessPacket(ctx, pkt, pkt, addr)
		if err == nil && queuedPkt != nil {
			return t.listener.WriteTo(queuedPkt.Data, addr)
		}
	}

	return t.listener.WriteTo(pkt, addr)
}

func (t *UDPTransport) ReadFrom(buf []byte) (int, net.Addr, error) {
	if t.listener == nil {
		return 0, nil, ErrNotListening
	}

	n, addr, err := t.listener.ReadFrom(buf)
	if err == nil && n > 0 && t.isVoIPOptimized && t.discordDetector != nil {
		go t.discordDetector.AnalyzePacket(buf[:n], addr, t.LocalAddr())
	}

	return n, addr, err
}
func (t *UDPTransport) Close() error {
	var lastErr error

	if t.conn != nil {
		if err := t.conn.Close(); err != nil {
			lastErr = err
		}
	}

	if t.listener != nil {
		if err := t.listener.Close(); err != nil {
			lastErr = err
		}
	}

	return lastErr
}

func (t *UDPTransport) LocalAddr() net.Addr {
	if t.conn != nil {
		return t.conn.LocalAddr()
	}
	if t.listener != nil {
		return t.listener.LocalAddr()
	}
	return nil
}
func (t *UDPTransport) RemoteAddr() net.Addr {
	if t.conn != nil {
		return t.conn.RemoteAddr()
	}
	return nil
}

func (t *UDPTransport) optimizeForVoIP(conn *net.UDPConn) error {
	if err := conn.SetReadBuffer(67108864); err != nil {
		if err := conn.SetReadBuffer(16777216); err != nil {
			if err := conn.SetReadBuffer(8388608); err != nil {

			}
		}
	}
	if err := conn.SetWriteBuffer(67108864); err != nil {
		if err := conn.SetWriteBuffer(16777216); err != nil {
			if err := conn.SetWriteBuffer(8388608); err != nil {

			}
		}
	}

	if file, err := conn.File(); err == nil {
		defer file.Close()
		fd := int(file.Fd())

		if err := setIPTOS(fd, 0xB8); err == nil {

		}
	}

	return nil
}

func (t *UDPTransport) optimizeListenerForVoIP(conn *net.UDPConn) error {
	if err := conn.SetReadBuffer(67108864); err != nil {
		if err := conn.SetReadBuffer(16777216); err != nil {
			if err := conn.SetReadBuffer(8388608); err != nil {

			}
		}
	}
	if err := conn.SetWriteBuffer(67108864); err != nil {
		if err := conn.SetWriteBuffer(16777216); err != nil {
			if err := conn.SetWriteBuffer(8388608); err != nil {

			}
		}
	}

	if file, err := conn.File(); err == nil {
		defer file.Close()
		fd := int(file.Fd())
		if err := setIPTOS(fd, 0xB8); err == nil {

		}
	}

	return nil
}

func setIPTOS(fd int, tos int) error {
	return nil
}
