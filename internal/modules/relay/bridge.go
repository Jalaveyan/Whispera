package relay

import (
	"crypto/tls"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/logger"
	"whispera/internal/modules/phantom"
)

type Bridge struct {
	listener       net.Listener
	upstreamAddr   string
	phantomHandler *phantom.Handler
	log            *logger.Logger

	running    int32
	activeConn int32
	wg         sync.WaitGroup
}

type BridgeConfig struct {
	ListenAddr     string
	UpstreamServer string
	PhantomConfig  *phantom.Config
}

func NewBridge(cfg *BridgeConfig) (*Bridge, error) {
	ph, err := phantom.New(cfg.PhantomConfig)
	if err != nil {
		return nil, err
	}

	return &Bridge{
		upstreamAddr:   cfg.UpstreamServer,
		phantomHandler: ph,
		log:            logger.Module("bridge"),
	}, nil
}

func (b *Bridge) Start(listenAddr string) error {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	b.listener = listener
	atomic.StoreInt32(&b.running, 1)

	b.log.Info("Bridge started on %s -> %s", listenAddr, b.upstreamAddr)

	go b.acceptLoop()
	return nil
}

func (b *Bridge) Stop() {
	atomic.StoreInt32(&b.running, 0)
	if b.listener != nil {
		b.listener.Close()
	}
	b.wg.Wait()
	b.log.Info("Bridge stopped")
}

func (b *Bridge) acceptLoop() {
	for atomic.LoadInt32(&b.running) == 1 {
		conn, err := b.listener.Accept()
		if err != nil {
			if atomic.LoadInt32(&b.running) == 1 {
				b.log.Warn("Accept error: %v", err)
			}
			continue
		}

		b.wg.Add(1)
		go b.handleConnection(conn)
	}
}

func (b *Bridge) handleConnection(clientConn net.Conn) {
	defer b.wg.Done()
	defer clientConn.Close()
	atomic.AddInt32(&b.activeConn, 1)
	defer atomic.AddInt32(&b.activeConn, -1)

	clientConn.SetReadDeadline(time.Now().Add(10 * time.Second))

	buf := make([]byte, 16384)
	n, err := clientConn.Read(buf)
	if err != nil {
		b.log.Debug("Failed to read ClientHello: %v", err)
		return
	}
	clientHello := buf[:n]
	clientConn.SetReadDeadline(time.Time{})

	sni := b.extractSNI(clientHello)
	if sni == "" {
		b.log.Debug("No SNI in ClientHello, rejecting")
		return
	}

	b.log.Debug("Bridge: forwarding connection with SNI=%s", sni)

	upstreamConn, err := tls.Dial("tcp", b.upstreamAddr, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"whispera"},
	})
	if err != nil {
		b.log.Warn("Failed to connect to upstream %s: %v", b.upstreamAddr, err)
		return
	}
	defer upstreamConn.Close()

	_, err = upstreamConn.Write(clientHello)
	if err != nil {
		b.log.Warn("Failed to forward ClientHello: %v", err)
		return
	}

	done := make(chan struct{}, 2)

	go func() {
		io.Copy(upstreamConn, clientConn)
		upstreamConn.CloseWrite()
		done <- struct{}{}
	}()

	go func() {
		io.Copy(clientConn, upstreamConn)
		if tc, ok := clientConn.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()

	<-done
	<-done
}

func (b *Bridge) extractSNI(data []byte) string {
	if len(data) < 43 {
		return ""
	}

	if data[0] != 0x16 {
		return ""
	}

	pos := 5

	if pos >= len(data) || data[pos] != 0x01 {
		return ""
	}

	pos += 4

	pos += 2
	pos += 32

	if pos >= len(data) {
		return ""
	}

	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen

	if pos+2 > len(data) {
		return ""
	}

	cipherSuitesLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2 + cipherSuitesLen

	if pos+1 > len(data) {
		return ""
	}

	compressionLen := int(data[pos])
	pos += 1 + compressionLen

	if pos+2 > len(data) {
		return ""
	}

	extensionsLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2

	end := pos + extensionsLen
	if end > len(data) {
		end = len(data)
	}

	for pos+4 < end {
		extType := int(data[pos])<<8 | int(data[pos+1])
		extLen := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4

		if extType == 0 && pos+extLen <= end {
			sniData := data[pos : pos+extLen]
			return b.parseSNIExtension(sniData)
		}

		pos += extLen
	}

	return ""
}

func (b *Bridge) parseSNIExtension(data []byte) string {
	if len(data) < 5 {
		return ""
	}

	pos := 2

	if pos+3 > len(data) {
		return ""
	}

	nameType := data[pos]
	nameLen := int(data[pos+1])<<8 | int(data[pos+2])
	pos += 3

	if nameType != 0 {
		return ""
	}

	if pos+nameLen > len(data) {
		return ""
	}

	return string(data[pos : pos+nameLen])
}

func (b *Bridge) GetActiveConnections() int {
	return int(atomic.LoadInt32(&b.activeConn))
}
