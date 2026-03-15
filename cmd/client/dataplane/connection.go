package dataplane

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type ConnectionState int32

const (
	StateUnsent ConnectionState = 0
	StateOpened ConnectionState = 1
	StateHeadersReceived ConnectionState = 2
	StateLoading ConnectionState = 3
	StateDone ConnectionState = 4
)

func (s ConnectionState) String() string {
	switch s {
	case StateUnsent:
		return "UNSENT"
	case StateOpened:
		return "OPENED"
	case StateHeadersReceived:
		return "HEADERS_RECEIVED"
	case StateLoading:
		return "LOADING"
	case StateDone:
		return "DONE"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", s)
	}
}

type ConnectionHeaders struct {
	Version     uint8             
	UUID        [16]byte          
	Addons      uint8             
	ObfProfile  string            
	Compression string            
	CustomData  map[string]string 
}

type StateChangeHandler func(oldState, newState ConnectionState)

type Connection struct {
	state         int32 
	stateHandlers []StateChangeHandler
	stateMu       sync.RWMutex
	serverAddr string
	transport  string 
	headers    ConnectionHeaders
	conn   net.Conn
	connMu sync.RWMutex
	ctx    context.Context
	cancel context.CancelFunc

	rxChan chan []byte
	txChan chan []byte

	bytesSent     uint64
	bytesReceived uint64
	startTime     time.Time
	lastError error
	errorMu   sync.RWMutex
}
func NewConnection(serverAddr string, transport string) *Connection {
	ctx, cancel := context.WithCancel(context.Background())
	return &Connection{
		state:      int32(StateUnsent),
		serverAddr: serverAddr,
		transport:  transport,
		ctx:        ctx,
		cancel:     cancel,
		rxChan:     make(chan []byte, 1024),
		txChan:     make(chan []byte, 1024),
		headers: ConnectionHeaders{
			Version:    1,
			CustomData: make(map[string]string),
		},
	}
}

func (c *Connection) State() ConnectionState {
	return ConnectionState(atomic.LoadInt32(&c.state))
}
func (c *Connection) OnStateChange(handler StateChangeHandler) {
	c.stateMu.Lock()
	c.stateHandlers = append(c.stateHandlers, handler)
	c.stateMu.Unlock()
}

func (c *Connection) setState(newState ConnectionState) error {
	oldState := ConnectionState(atomic.SwapInt32(&c.state, int32(newState)))

	if !c.isValidTransition(oldState, newState) {
		atomic.StoreInt32(&c.state, int32(oldState)) 
		return fmt.Errorf("invalid state transition: %s -> %s", oldState, newState)
	}

	c.stateMu.RLock()
	handlers := c.stateHandlers
	c.stateMu.RUnlock()

	for _, handler := range handlers {
		handler(oldState, newState)
	}

	return nil
}

func (c *Connection) isValidTransition(from, to ConnectionState) bool {
	switch from {
	case StateUnsent:
		return to == StateOpened
	case StateOpened:
		return to == StateHeadersReceived || to == StateDone
	case StateHeadersReceived:
		return to == StateLoading || to == StateDone
	case StateLoading:
		return to == StateDone
	case StateDone:
		return to == StateUnsent 
	default:
		return false
	}
}

func (c *Connection) Open() error {
	if c.State() != StateUnsent {
		return fmt.Errorf("cannot Open(): state is %s, expected UNSENT", c.State())
	}

	c.startTime = time.Now()
	return c.setState(StateOpened)
}

func (c *Connection) SetHeader(key, value string) error {
	if c.State() != StateOpened {
		return fmt.Errorf("cannot SetHeader(): state is %s, expected OPENED", c.State())
	}
	c.headers.CustomData[key] = value
	return nil
}

func (c *Connection) SetUUID(uuid [16]byte) error {
	if c.State() != StateOpened {
		return fmt.Errorf("cannot SetUUID(): state is %s, expected OPENED", c.State())
	}
	c.headers.UUID = uuid
	return nil
}

func (c *Connection) SetObfuscation(profile string, compression string) error {
	if c.State() != StateOpened {
		return fmt.Errorf("cannot SetObfuscation(): state is %s, expected OPENED", c.State())
	}
	c.headers.ObfProfile = profile
	c.headers.Compression = compression
	c.headers.Addons |= 0x01 
	if compression != "" {
		c.headers.Addons |= 0x02 
	}
	return nil
}

func (c *Connection) Send(ctx context.Context) error {
	if c.State() != StateOpened {
		return fmt.Errorf("cannot Send(): state is %s, expected OPENED", c.State())
	}

	var conn net.Conn
	var err error

	dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
	defer dialCancel()

	dialer := &net.Dialer{Timeout: 10 * time.Second}

	switch c.transport {
	case "udp":
		conn, err = dialer.DialContext(dialCtx, "udp", c.serverAddr)
	case "tcp", "websocket", "quic":
		conn, err = dialer.DialContext(dialCtx, "tcp", c.serverAddr)
	default:
		err = fmt.Errorf("unsupported transport: %s", c.transport)
	}

	if err != nil {
		c.setError(err)
		_ = c.setState(StateDone)
		return fmt.Errorf("dial failed: %w", err)
	}

	c.connMu.Lock()
	c.conn = conn
	c.connMu.Unlock()

	if err := c.sendHandshake(); err != nil {
		c.setError(err)
		_ = c.setState(StateDone)
		return fmt.Errorf("handshake failed: %w", err)
	}

	if err := c.receiveHeaders(); err != nil {
		c.setError(err)
		_ = c.setState(StateDone)
		return fmt.Errorf("receive headers failed: %w", err)
	}

	return c.setState(StateHeadersReceived)
}
func (c *Connection) sendHandshake() error {
	c.connMu.RLock()
	conn := c.conn
	c.connMu.RUnlock()

	if conn == nil {
		return fmt.Errorf("connection is nil")
	}

	handshake := make([]byte, 64)

	handshake[0] = 0x01

	handshake[1] = c.headers.Version

	copy(handshake[2:18], c.headers.UUID[:])

	for i := 18; i < 50; i++ {
		handshake[i] = byte(i * 7) 
	}

	timestamp := uint32(time.Now().Unix())
	handshake[50] = byte(timestamp >> 24)
	handshake[51] = byte(timestamp >> 16)
	handshake[52] = byte(timestamp >> 8)
	handshake[53] = byte(timestamp)

	for i := 54; i < 64; i++ {
		handshake[i] = byte(i + int(timestamp&0xFF))
	}

	_, err := conn.Write(handshake)
	if err != nil {
		return err
	}

	atomic.AddUint64(&c.bytesSent, uint64(len(handshake)))
	return nil
}

func (c *Connection) receiveHeaders() error {
	c.connMu.RLock()
	conn := c.conn
	c.connMu.RUnlock()

	if conn == nil {
		return fmt.Errorf("connection is nil")
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}

	if n < 6 {
		return fmt.Errorf("response too short: %d bytes", n)
	}

	respType := buf[0]
	status := buf[1]

	if respType != 0x02 {
		return fmt.Errorf("unexpected response type: 0x%02x", respType)
	}

	if status != 0x00 {
		return fmt.Errorf("server returned error status: 0x%02x", status)
	}
	if n >= 6 {
		sessionID := uint32(buf[2])<<24 | uint32(buf[3])<<16 | uint32(buf[4])<<8 | uint32(buf[5])
		c.headers.CustomData["session_id"] = fmt.Sprintf("%d", sessionID)
	}

	atomic.AddUint64(&c.bytesReceived, uint64(n))
	return nil
}

func (c *Connection) StartDataTransfer() error {
	if c.State() != StateHeadersReceived {
		return fmt.Errorf("cannot StartDataTransfer(): state is %s, expected HEADERS_RECEIVED", c.State())
	}

	if err := c.setState(StateLoading); err != nil {
		return err
	}

	go c.rxPump()
	go c.txPump()

	return nil
}

func (c *Connection) rxPump() {
	buf := make([]byte, 65535)
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		c.connMu.RLock()
		conn := c.conn
		c.connMu.RUnlock()

		if conn == nil {
			return
		}

		n, err := conn.Read(buf)
		if err != nil {
			c.setError(err)
			c.Close()
			return
		}

		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])

			atomic.AddUint64(&c.bytesReceived, uint64(n))

			select {
			case c.rxChan <- data:
			case <-c.ctx.Done():
				return
			default:
				select {
				case <-c.rxChan:
					c.rxChan <- data
				default:
				}
			}
		}
	}
}

func (c *Connection) txPump() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case data := <-c.txChan:
			c.connMu.RLock()
			conn := c.conn
			c.connMu.RUnlock()

			if conn == nil {
				return
			}

			n, err := conn.Write(data)
			if err != nil {
				c.setError(err)
				c.Close()
				return
			}

			atomic.AddUint64(&c.bytesSent, uint64(n))
		}
	}
}

func (c *Connection) Write(data []byte) (int, error) {
	if c.State() != StateLoading {
		return 0, fmt.Errorf("cannot Write(): state is %s, expected LOADING", c.State())
	}

	select {
	case c.txChan <- data:
		return len(data), nil
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	default:
		return 0, fmt.Errorf("write buffer full")
	}
}

func (c *Connection) Read(buf []byte) (int, error) {
	if c.State() != StateLoading {
		return 0, fmt.Errorf("cannot Read(): state is %s, expected LOADING", c.State())
	}

	select {
	case data := <-c.rxChan:
		n := copy(buf, data)
		return n, nil
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	}
}

func (c *Connection) Close() error {
	c.cancel()

	c.connMu.Lock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	c.connMu.Unlock()

	if c.State() != StateDone {
		return c.setState(StateDone)
	}
	return nil
}

func (c *Connection) Reset() error {
	if c.State() != StateDone {
		return fmt.Errorf("cannot Reset(): state is %s, expected DONE", c.State())
	}

	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.rxChan = make(chan []byte, 1024)
	c.txChan = make(chan []byte, 1024)
	c.bytesSent = 0
	c.bytesReceived = 0
	c.lastError = nil

	return c.setState(StateUnsent)
}

func (c *Connection) Error() error {
	c.errorMu.RLock()
	defer c.errorMu.RUnlock()
	return c.lastError
}

func (c *Connection) setError(err error) {
	c.errorMu.Lock()
	c.lastError = err
	c.errorMu.Unlock()
}

func (c *Connection) Stats() (sent, received uint64, duration time.Duration) {
	return atomic.LoadUint64(&c.bytesSent),
		atomic.LoadUint64(&c.bytesReceived),
		time.Since(c.startTime)
}
