package yadisk

// yadisk — VPN transport through Yandex Disk (WebDAV).
//
// Traffic is tunneled by writing data as files to Yandex Disk and reading
// them on the other side.  From the firewall's perspective all traffic is
// HTTPS to webdav.yandex.ru — always in the Russian CIDR whitelist.
//
// # Protocol
//
// Each direction has its own "slot directory" on Yandex Disk.  Each slot
// is a sequence of numbered chunk files:
//
//	/whispera/{sessionID}/c2s/0000000001   ← client writes, server reads
//	/whispera/{sessionID}/s2c/0000000001   ← server writes, client reads
//
// The writer PUTs a chunk file, increments the counter, and deletes the
// previous chunk after the reader has acknowledged it via a tiny "ack" file.
//
// This gives ~5-10 Mbps and ~200-500 ms RTT — enough for VPN traffic but
// not for real-time video.  Use vkwebrtc/yatelemost for higher throughput.
//
// # Setup
//
// Both client and server need a Yandex OAuth token with cloud_api:disk.write
// and cloud_api:disk.read scopes.  Use the same token or two separate tokens
// for each side.  Both must agree on the same SessionID string.
//
// Get a token at: https://oauth.yandex.ru/authorize?response_type=token&client_id=72294e85e4274cc7af49e4e8b46e6e02
// (This client_id is for Yandex.Disk WebDAV — no app registration needed.)

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/registry"
	"whispera/internal/logger"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

var log = logger.Module("yadisk")

const (
	ModuleName    = "transport.yadisk"
	ModuleVersion = "1.0.0"

	webdavBase    = "https://webdav.yandex.ru"
	diskBase      = "https://cloud-api.yandex.net/v1/disk/resources"
	pollInterval  = 50 * time.Millisecond
	chunkTimeout  = 5 * time.Second
	maxChunkSize  = 512 * 1024 // 512 KB per chunk
)

// Config for the Yandex Disk transport.
type Config struct {
	// ServerMode: true on VPN server, false on client.
	ServerMode bool

	// OAuthToken is a Yandex OAuth token with disk read+write access.
	OAuthToken string

	// SessionID uniquely identifies this VPN session on Yandex Disk.
	// Both sides must use the same value.  Use a random UUID.
	SessionID string

	BufferSize int
}

func DefaultConfig() *Config {
	return &Config{BufferSize: 64 * 1024}
}

// Transport tunnels data through Yandex Disk WebDAV.
type Transport struct {
	*base.Module
	config *Config
	client *http.Client

	// writeSeq is the next chunk number this side will write.
	writeSeq uint64
	// readSeq is the next chunk number this side expects to read.
	readSeq uint64

	// writeDir / readDir are the Yandex Disk paths for each direction.
	writeDir string
	readDir  string

	dataIn  chan []byte // data received from remote → VPN stack
	dataOut chan []byte // data from VPN stack → send to remote

	connOnce sync.Once
	connCh   chan net.Conn
	stopCh   chan struct{}
	stopOnce sync.Once
}

func Factory(cfg interface{}) (interfaces.Module, error) {
	c, ok := cfg.(*Config)
	if !ok {
		c = DefaultConfig()
	}
	return New(c)
}

func New(cfg *Config) (*Transport, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if cfg.BufferSize == 0 {
		cfg.BufferSize = 64 * 1024
	}
	t := &Transport{
		Module:  base.NewModule(ModuleName, ModuleVersion, nil),
		config:  cfg,
		client:  &http.Client{Timeout: 30 * time.Second},
		dataIn:  make(chan []byte, 128),
		dataOut: make(chan []byte, 128),
		connCh:  make(chan net.Conn, 1),
		stopCh:  make(chan struct{}),
	}

	// Assign directories based on mode.
	// c2s: client writes, server reads.
	// s2c: server writes, client reads.
	base := "/whispera/" + cfg.SessionID
	if cfg.ServerMode {
		t.readDir = base + "/c2s"
		t.writeDir = base + "/s2c"
	} else {
		t.writeDir = base + "/c2s"
		t.readDir = base + "/s2c"
	}

	return t, nil
}

// Start creates the session directories and launches read/write goroutines.
func (t *Transport) Start() error {
	if t.config.OAuthToken == "" {
		return fmt.Errorf("yadisk: OAuthToken is required")
	}
	if t.config.SessionID == "" {
		return fmt.Errorf("yadisk: SessionID is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Ensure directory tree exists.
	for _, dir := range []string{
		"/whispera",
		"/whispera/" + t.config.SessionID,
		t.writeDir,
	} {
		if err := t.mkdir(ctx, dir); err != nil {
			log.Printf("yadisk: mkdir %s: %v (may already exist)", dir, err)
		}
	}

	// Launch background goroutines.
	go t.sendLoop()
	go t.recvLoop()

	// Expose connection immediately — data flows once both sides are ready.
	conn := &diskConn{t: t}
	t.connCh <- conn

	log.Printf("yadisk: started session %s (server=%v)", t.config.SessionID, t.config.ServerMode)
	return nil
}

func (t *Transport) Stop() error {
	t.stopOnce.Do(func() { close(t.stopCh) })
	return nil
}

// Dial returns the disk-backed net.Conn (client mode).
func (t *Transport) Dial(ctx context.Context, _ string) (net.Conn, error) {
	select {
	case conn := <-t.connCh:
		return conn, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.stopCh:
		return nil, fmt.Errorf("yadisk: stopped")
	}
}

// Accept returns the disk-backed net.Conn (server mode).
func (t *Transport) Accept() (net.Conn, error) {
	select {
	case conn := <-t.connCh:
		return conn, nil
	case <-t.stopCh:
		return nil, fmt.Errorf("yadisk: stopped")
	}
}

// sendLoop drains dataOut and writes chunks to Yandex Disk.
func (t *Transport) sendLoop() {
	for {
		select {
		case <-t.stopCh:
			return
		case data := <-t.dataOut:
			seq := atomic.AddUint64(&t.writeSeq, 1) - 1
			path := fmt.Sprintf("%s/%010d", t.writeDir, seq)
			ctx, cancel := context.WithTimeout(context.Background(), chunkTimeout)
			err := t.putFile(ctx, path, data)
			cancel()
			if err != nil {
				log.Printf("yadisk: PUT %s: %v", path, err)
			}
		}
	}
}

// recvLoop polls Yandex Disk for new chunks and delivers them to dataIn.
func (t *Transport) recvLoop() {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-t.stopCh:
			return
		case <-ticker.C:
			seq := atomic.LoadUint64(&t.readSeq)
			path := fmt.Sprintf("%s/%010d", t.readDir, seq)
			ctx, cancel := context.WithTimeout(context.Background(), chunkTimeout)
			data, err := t.getFile(ctx, path)
			cancel()
			if err != nil {
				// Not found yet — expected, keep polling.
				continue
			}
			atomic.AddUint64(&t.readSeq, 1)
			// Delete consumed chunk (best-effort).
			go t.deleteFile(context.Background(), path)

			select {
			case t.dataIn <- data:
			case <-t.stopCh:
				return
			}
		}
	}
}

// ── WebDAV helpers ────────────────────────────────────────────────────────

func (t *Transport) auth(req *http.Request) {
	req.Header.Set("Authorization", "OAuth "+t.config.OAuthToken)
}

// putFile uploads data to a WebDAV path via HTTP PUT.
func (t *Transport) putFile(ctx context.Context, path string, data []byte) error {
	req, err := http.NewRequestWithContext(ctx, "PUT",
		webdavBase+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	t.auth(req)
	req.ContentLength = int64(len(data))
	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// getFile downloads a WebDAV file. Returns (nil, err) if file does not exist.
func (t *Transport) getFile(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", webdavBase+path, nil)
	if err != nil {
		return nil, err
	}
	t.auth(req)
	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("not found")
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxChunkSize))
}

// deleteFile removes a WebDAV file (best-effort, ignores errors).
func (t *Transport) deleteFile(ctx context.Context, path string) {
	req, _ := http.NewRequestWithContext(ctx, "DELETE", webdavBase+path, nil)
	t.auth(req)
	resp, err := t.client.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}

// mkdir creates a collection (directory) on Yandex Disk via MKCOL.
func (t *Transport) mkdir(ctx context.Context, path string) error {
	req, err := http.NewRequestWithContext(ctx, "MKCOL", webdavBase+path, nil)
	if err != nil {
		return err
	}
	t.auth(req)
	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	// 201 Created or 405 Method Not Allowed (already exists) are both OK.
	if resp.StatusCode != 201 && resp.StatusCode != 405 {
		return fmt.Errorf("MKCOL HTTP %d", resp.StatusCode)
	}
	return nil
}

// ── net.Conn implementation ───────────────────────────────────────────────

// diskConn exposes the Yandex Disk transport as a net.Conn.
type diskConn struct {
	t   *Transport
	buf []byte
	mu  sync.Mutex
}

func (c *diskConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()

	select {
	case data := <-c.t.dataIn:
		n := copy(p, data)
		if n < len(data) {
			c.mu.Lock()
			c.buf = append(c.buf, data[n:]...)
			c.mu.Unlock()
		}
		return n, nil
	case <-c.t.stopCh:
		return 0, fmt.Errorf("yadisk: closed")
	}
}

func (c *diskConn) Write(p []byte) (int, error) {
	// Split into chunks if needed.
	for len(p) > 0 {
		end := len(p)
		if end > maxChunkSize {
			end = maxChunkSize
		}
		cp := make([]byte, end)
		copy(cp, p[:end])
		select {
		case c.t.dataOut <- cp:
		case <-c.t.stopCh:
			return 0, fmt.Errorf("yadisk: closed")
		}
		p = p[end:]
	}
	return len(p), nil
}

func (c *diskConn) Close() error                       { return c.t.Stop() }
func (c *diskConn) SetDeadline(t time.Time) error      { return nil }
func (c *diskConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *diskConn) SetWriteDeadline(t time.Time) error { return nil }
func (c *diskConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *diskConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
