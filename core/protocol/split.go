package protocol

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/nekoskin/whispera/common/buf"
	http2 "golang.org/x/net/http2"
)

var loggedTransportModes sync.Map

func logTransportMode(mode string) {
	if _, seen := loggedTransportModes.LoadOrStore(mode, struct{}{}); !seen {
		stdlog.Printf("whispera: transport=%s", mode)
	}
}

const (
	splitUploadChunkMax = 128 * 1024
	hlsPlaylistMarker   = "#EXTM3U"
)

var errSplitUnsupported = errors.New("whispera: split not supported by server")

func splitEnabled() bool { return os.Getenv("WHISPERA_SPLIT") != "0" }

type splitParams struct {
	base      string
	uploadURL string
	sni       string
	origin    string
	token     string
	sessionID []byte
	anchor    time.Time
	prof      browserProfile
	local     net.Addr
	remote    net.Addr
}

type splitClientConn struct {
	ctx    context.Context
	cancel context.CancelFunc

	transport *http2.Transport
	client    *http.Client

	videoBase string
	uploadURL string
	sni       string
	origin    string
	token     string
	cookie    string
	prof      browserProfile

	dnReady   chan struct{}
	segReader *segmentReader
	dnErr     error

	upCh chan []byte

	closeOnce sync.Once
	closed    chan struct{}

	local  net.Addr
	remote net.Addr
}

func clientSplit(ctx context.Context, transport *http2.Transport, p splitParams) (net.Conn, error) {
	sctx, cancel := context.WithCancel(context.Background())
	c := &splitClientConn{
		ctx:       sctx,
		cancel:    cancel,
		transport: transport,
		client:    &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		videoBase: fmt.Sprintf("%s/video/%s", p.base, hex.EncodeToString(p.sessionID)),
		uploadURL: p.uploadURL,
		sni:       p.sni,
		origin:    p.origin,
		token:     p.token,
		cookie:    encodeSession(p.sessionID, p.anchor),
		prof:      p.prof,
		dnReady:   make(chan struct{}),
		upCh:      make(chan []byte, 256),
		closed:    make(chan struct{}),
		local:     p.local,
		remote:    p.remote,
	}

	go c.startDownload(ctx)

	select {
	case <-c.dnReady:
		if c.dnErr != nil {
			cancel()
			return nil, fmt.Errorf("whispera: split download: %w", c.dnErr)
		}
	case <-ctx.Done():
		cancel()
		return nil, ctx.Err()
	}

	go c.uploader()
	logTransportMode("split")
	return NewFrameConn(c), nil
}

func (c *splitClientConn) startDownload(budget context.Context) {
	err := c.openPlaylist(budget)
	if err == nil {
		c.segReader = newSegmentReader(c)
		close(c.dnReady)
		return
	}
	if !errors.Is(err, errSplitUnsupported) {
		stdlog.Printf("whispera: split download failed: %v", err)
	}
	c.dnErr = err
	close(c.dnReady)
}

func (c *splitClientConn) openPlaylist(ctx context.Context) error {
	url := c.videoBase + "/master.m3u8"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Host = c.sni
	req.Header.Set(headerToken, "Bearer "+c.token)
	c.prof.apply(req, c.origin)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: c.cookie})

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("playlist status %d", resp.StatusCode)
	}
	head := make([]byte, len(hlsPlaylistMarker))
	if _, err := io.ReadFull(resp.Body, head); err != nil {
		return err
	}
	if !bytes.Equal(head, []byte(hlsPlaylistMarker)) {
		return errSplitUnsupported
	}
	io.Copy(io.Discard, resp.Body)
	return nil
}

func (c *splitClientConn) fetchSegment(idx uint64) (io.ReadCloser, error) {
	url := fmt.Sprintf("%s/seg%04d.ts", c.videoBase, idx)
	req, err := http.NewRequestWithContext(c.ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Host = c.sni
	req.Header.Set(headerToken, "Bearer "+c.token)
	c.prof.apply(req, c.origin)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: c.cookie})

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("segment status %d", resp.StatusCode)
	}
	return resp.Body, nil
}

type segFetch struct {
	idx   uint64
	body  io.ReadCloser
	err   error
	ready chan struct{}
}

type segmentReader struct {
	fetch func(idx uint64) (io.ReadCloser, error)
	depth int

	mu      sync.Mutex
	queue   []*segFetch
	nextIdx uint64
	closed  bool
}

func newSegmentReader(c *splitClientConn) *segmentReader {
	return newSegmentReaderFunc(c.fetchSegment, segPrefetchDepth())
}

func newSegmentReaderFunc(fetch func(uint64) (io.ReadCloser, error), depth int) *segmentReader {
	if depth < 1 {
		depth = 1
	}
	s := &segmentReader{fetch: fetch, depth: depth}
	s.mu.Lock()
	s.refillLocked()
	s.mu.Unlock()
	return s
}

func segPrefetchDepth() int {
	d := buf.PerConnBudget()/segMinSize + 1
	if d < 2 {
		d = 2
	}
	return d
}

func (s *segmentReader) refillLocked() {
	for len(s.queue) < s.depth && !s.closed {
		f := &segFetch{idx: s.nextIdx, ready: make(chan struct{})}
		s.nextIdx++
		s.queue = append(s.queue, f)
		go func(f *segFetch) {
			f.body, f.err = s.fetch(f.idx)
			close(f.ready)
		}(f)
	}
}

func (s *segmentReader) Read(b []byte) (int, error) {
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return 0, io.EOF
		}
		if len(s.queue) == 0 {
			s.refillLocked()
		}
		head := s.queue[0]
		s.mu.Unlock()

		<-head.ready
		if head.err != nil {
			return 0, head.err
		}

		n, err := head.body.Read(b)
		if n > 0 {
			return n, nil
		}
		if err == io.EOF {
			head.body.Close()
			s.mu.Lock()
			if len(s.queue) > 0 && s.queue[0] == head {
				s.queue = s.queue[1:]
			}
			s.refillLocked()
			s.mu.Unlock()
			continue
		}
		if err != nil {
			return 0, err
		}
	}
}

func (s *segmentReader) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	q := s.queue
	s.queue = nil
	s.mu.Unlock()
	for _, f := range q {
		<-f.ready
		if f.body != nil {
			f.body.Close()
		}
	}
}

func (c *splitClientConn) uploader() {
	for {
		var batch []byte
		select {
		case p := <-c.upCh:
			batch = append(batch, p...)
		case <-c.closed:
			return
		case <-c.ctx.Done():
			return
		}
	drain:
		for len(batch) < splitUploadChunkMax {
			select {
			case p := <-c.upCh:
				if len(batch)+len(p) > splitUploadChunkMax {
					if err := c.postChunk(batch); err != nil {
						c.closeWithErr(err)
						return
					}
					batch = append(batch[:0], p...)
					continue
				}
				batch = append(batch, p...)
			default:
				break drain
			}
		}
		if err := c.postChunk(batch); err != nil {
			c.closeWithErr(err)
			return
		}
	}
}

func (c *splitClientConn) postChunk(chunk []byte) error {
	req, err := http.NewRequestWithContext(c.ctx, http.MethodPost, c.uploadURL, bytes.NewReader(chunk))
	if err != nil {
		return err
	}
	req.ContentLength = int64(len(chunk))
	req.Host = c.sni
	req.Header.Set("Content-Type", contentType)
	c.prof.apply(req, c.origin)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: c.cookie})

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("upload status %d", resp.StatusCode)
	}
	return nil
}

func (c *splitClientConn) Read(b []byte) (int, error) {
	<-c.dnReady
	if c.dnErr != nil {
		return 0, c.dnErr
	}
	if c.segReader == nil {
		return 0, io.EOF
	}
	return c.segReader.Read(b)
}

func (c *splitClientConn) Write(b []byte) (int, error) {
	p := make([]byte, len(b))
	copy(p, b)
	select {
	case c.upCh <- p:
		return len(b), nil
	case <-c.closed:
		return 0, io.ErrClosedPipe
	case <-c.ctx.Done():
		return 0, io.ErrClosedPipe
	}
}

func (c *splitClientConn) closeWithErr(err error) {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.cancel()
		if c.segReader != nil {
			c.segReader.Close()
		}
		c.transport.CloseIdleConnections()
	})
}

func (c *splitClientConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.cancel()
		if c.segReader != nil {
			c.segReader.Close()
		}
		c.transport.CloseIdleConnections()
	})
	return nil
}

func (c *splitClientConn) LocalAddr() net.Addr                { return c.local }
func (c *splitClientConn) RemoteAddr() net.Addr               { return c.remote }
func (c *splitClientConn) SetDeadline(t time.Time) error      { return nil }
func (c *splitClientConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *splitClientConn) SetWriteDeadline(t time.Time) error { return nil }
