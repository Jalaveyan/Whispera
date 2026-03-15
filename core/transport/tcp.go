package transport

import (
	"context"
	"net"
	"time"
)


type TCPTransport struct {
	conn     net.Conn
	config   *Config
	listener net.Listener
}


func NewTCPTransport(config *Config) *TCPTransport {
	return &TCPTransport{
		config: config,
	}
}


func (t *TCPTransport) Dial(addr string) error {
	timeout := time.Duration(t.config.Timeout) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(context.Background(), "tcp", addr)
	if err != nil {
		return err
	}

	t.conn = conn
	return nil
}


func (t *TCPTransport) Listen() error {
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", t.config.Addr)
	if err != nil {
		return err
	}

	t.listener = listener
	return nil
}


func (t *TCPTransport) Accept() (net.Conn, error) {
	if t.listener == nil {
		return nil, ErrNotListening
	}
	return t.listener.Accept()
}


func (t *TCPTransport) WriteRaw(pkt []byte) error {
	if t.conn == nil {
		return ErrNotConnected
	}
	_, err := t.conn.Write(pkt)
	return err
}


func (t *TCPTransport) ReadRaw(buf []byte) (int, error) {
	if t.conn == nil {
		return 0, ErrNotConnected
	}
	return t.conn.Read(buf)
}


func (t *TCPTransport) Close() error {
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


func (t *TCPTransport) LocalAddr() net.Addr {
	if t.conn != nil {
		return t.conn.LocalAddr()
	}
	if t.listener != nil {
		return t.listener.Addr()
	}
	return nil
}


func (t *TCPTransport) RemoteAddr() net.Addr {
	if t.conn != nil {
		return t.conn.RemoteAddr()
	}
	return nil
}
