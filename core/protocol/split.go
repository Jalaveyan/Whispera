package protocol

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	http2 "golang.org/x/net/http2"
)

var transportModeOnce sync.Once

func logTransportMode(mode string) {
	transportModeOnce.Do(func() { stdlog.Printf("whispera: transport=%s", mode) })
}

const (
	splitUploadChunkMax = 700 * 1024
	splitFtypPrefix     = 24
)

var errSplitUnsupported = errors.New("whispera: split not supported by server")

func splitEnabled() bool { return os.Getenv("WHISPERA_SPLIT") != "0" }

type splitParams struct {
	url       string
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

	url    string
	sni    string
	origin string
	token  string
	cookie string
	prof   browserProfile

	dnReady chan struct{}
	dnBody  io.ReadCloser
	dnErr   error

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
		url:       p.url,
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

	go c.startDownload()

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

func (c *splitClientConn) startDownload() {
	fail := func(err error) {
		c.dnErr = err
		close(c.dnReady)
	}
	req, err := http.NewRequestWithContext(c.ctx, http.MethodGet, c.url, nil)
	if err != nil {
		fail(err)
		return
	}
	req.Host = c.sni
	req.Header.Set(headerToken, "Bearer "+c.token)
	c.prof.apply(req, c.origin)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: c.cookie})

	resp, err := c.client.Do(req)
	if err != nil {
		fail(err)
		return
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		fail(fmt.Errorf("download status %d", resp.StatusCode))
		return
	}
	var ftyp [splitFtypPrefix]byte
	if _, err := io.ReadFull(resp.Body, ftyp[:]); err != nil {
		resp.Body.Close()
		fail(err)
		return
	}
	if !bytes.Equal(ftyp[:], mp4FtypAtom[:]) {
		resp.Body.Close()
		fail(errSplitUnsupported)
		return
	}
	c.dnBody = resp.Body
	close(c.dnReady)
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
	req, err := http.NewRequestWithContext(c.ctx, http.MethodPost, c.url, bytes.NewReader(chunk))
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
	if c.dnBody == nil {
		return 0, io.EOF
	}
	return c.dnBody.Read(b)
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
		if c.dnErr == nil {
			c.dnErr = err
		}
		close(c.closed)
		c.cancel()
		if c.dnBody != nil {
			c.dnBody.Close()
		}
		c.transport.CloseIdleConnections()
	})
}

func (c *splitClientConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.cancel()
		if c.dnBody != nil {
			c.dnBody.Close()
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
