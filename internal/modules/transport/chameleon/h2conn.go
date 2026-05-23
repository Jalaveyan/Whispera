package chameleon

import (
	"io"
	"net"
	"sync"
	"time"
)

type bufferedPipeWriter struct {
	pw   *io.PipeWriter
	ch   chan []byte
	done chan struct{}
	once sync.Once
}

func newBufferedPipeWriter(pw *io.PipeWriter) *bufferedPipeWriter {
	b := &bufferedPipeWriter{
		pw:   pw,
		ch:   make(chan []byte, 1024),
		done: make(chan struct{}),
	}
	go b.drain()
	return b
}

func (b *bufferedPipeWriter) Write(p []byte) (int, error) {
	cp := make([]byte, len(p))
	copy(cp, p)
	select {
	case b.ch <- cp:
		return len(p), nil
	case <-b.done:
		return 0, io.ErrClosedPipe
	}
}

func (b *bufferedPipeWriter) Close() {
	b.once.Do(func() { close(b.done) })
}

func (b *bufferedPipeWriter) drain() {
	defer b.pw.Close()
	var coalesce []byte
	for {
		select {
		case data := <-b.ch:
			coalesce = append(coalesce, data...)
		drain:
			for {
				select {
				case more := <-b.ch:
					coalesce = append(coalesce, more...)
				default:
					break drain
				}
			}
			if _, err := b.pw.Write(coalesce); err != nil {
				return
			}
			coalesce = coalesce[:0]
		case <-b.done:
			return
		}
	}
}

type pipelinedConn struct {
	bpw    *bufferedPipeWriter
	pr     *io.PipeReader
	cancel func()
	once   sync.Once
	sig    sync.Once

	readConn net.Conn
	readPeer net.Conn

	localAddr  net.Addr
	remoteAddr net.Addr
}

func newPipelinedConn(pr *io.PipeReader, bpw *bufferedPipeWriter, cancel func(), local, remote net.Addr) *pipelinedConn {
	readConn, readPeer := net.Pipe()
	return &pipelinedConn{
		pr:         pr,
		bpw:        bpw,
		cancel:     cancel,
		readConn:   readConn,
		readPeer:   readPeer,
		localAddr:  local,
		remoteAddr: remote,
	}
}

func (c *pipelinedConn) deliver(body io.ReadCloser) bool {
	ran := false
	c.sig.Do(func() {
		ran = true
		if body == nil {
			c.readPeer.Close()
			return
		}
		go func() {
			defer c.readPeer.Close()
			defer body.Close()
			io.CopyBuffer(c.readPeer, body, make([]byte, 256<<10))
		}()
	})
	return ran
}

func (c *pipelinedConn) Write(b []byte) (int, error) { return c.bpw.Write(b) }
func (c *pipelinedConn) Read(b []byte) (int, error)  { return c.readConn.Read(b) }

func (c *pipelinedConn) Close() error {
	c.once.Do(func() {
		c.bpw.Close()
		c.pr.Close()
		c.readConn.Close()
		c.readPeer.Close()
		c.cancel()
	})
	return nil
}

func (c *pipelinedConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *pipelinedConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *pipelinedConn) SetDeadline(t time.Time) error      { return c.readConn.SetReadDeadline(t) }
func (c *pipelinedConn) SetReadDeadline(t time.Time) error  { return c.readConn.SetReadDeadline(t) }
func (c *pipelinedConn) SetWriteDeadline(t time.Time) error { return nil }

type staticAddr struct{ network, addr string }

func (a staticAddr) Network() string { return a.network }
func (a staticAddr) String() string  { return a.addr }
