package protocol

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mux2 "whispera/common/mux"
)

func genSelfSigned(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"example.com"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(crand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	cf, _ := os.Create(certPath)
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	cf.Close()
	kd, _ := x509.MarshalECPrivateKey(priv)
	kf, _ := os.Create(keyPath)
	pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
	kf.Close()
	return
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// cuttableProxy forwards client->backend and lets the test drop live conns.
type cuttableProxy struct {
	ln    net.Listener
	back  string
	mu    sync.Mutex
	conns []net.Conn
}

func newProxy(t *testing.T, listen, backend string) *cuttableProxy {
	t.Helper()
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		t.Fatal(err)
	}
	p := &cuttableProxy{ln: ln, back: backend}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handle(c)
		}
	}()
	return p
}

func (p *cuttableProxy) handle(c net.Conn) {
	b, err := net.Dial("tcp", p.back)
	if err != nil {
		c.Close()
		return
	}
	p.mu.Lock()
	p.conns = append(p.conns, c, b)
	p.mu.Unlock()
	go func() { io.Copy(b, c); b.Close() }()
	io.Copy(c, b)
	c.Close()
}

func (p *cuttableProxy) cut() {
	p.mu.Lock()
	conns := p.conns
	p.conns = nil
	p.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
}

func TestResilientOverRealH2POST(t *testing.T) {
	secret := bytes.Repeat([]byte{0x5a}, 32)
	rkey := mux2.DeriveResumeKey(secret)
	dir := t.TempDir()
	certPath, keyPath := genSelfSigned(t, dir)

	lnAddr := freePort(t)
	nonce, _ := mux2.NewResumeNonce()

	const win = 32
	type srvSess struct {
		resumeCh   chan net.Conn
		windowBase uint64
	}
	type tokEntry struct {
		sess *srvSess
		n    uint64
	}
	reg := map[[32]byte]tokEntry{}
	var regMu sync.Mutex
	regWindow := func(s *srvSess, base uint64) {
		for i := uint64(0); i < win; i++ {
			var k [32]byte
			copy(k[:], mux2.ResumeToken(rkey, nonce, base+i))
			reg[k] = tokEntry{sess: s, n: base + i}
		}
		s.windowBase = base
	}
	unregWindow := func(s *srvSess) {
		for i := uint64(0); i < win; i++ {
			var k [32]byte
			copy(k[:], mux2.ResumeToken(rkey, nonce, s.windowBase+i))
			delete(reg, k)
		}
	}
	gotBytes := make(chan []byte, 1)

	onConn := func(conn net.Conn, userID string, sec []byte) {
		typ, payload, err := mux2.ReadResumeHeader(conn)
		if err != nil {
			conn.Close()
			return
		}
		switch typ {
		case mux2.ResumeEstablish:
			s := &srvSess{resumeCh: make(chan net.Conn, 1)}
			s.resumeCh <- conn
			regMu.Lock()
			regWindow(s, 2)
			regMu.Unlock()
			nextUnder := func() (net.Conn, error) {
				select {
				case c, ok := <-s.resumeCh:
					if !ok {
						return nil, io.EOF
					}
					return c, nil
				case <-time.After(20 * time.Second):
					return nil, io.EOF
				}
			}
			rc := mux2.NewResilientConn(strAddrT("srv"), strAddrT("cli"), nextUnder)
			sess, err := mux2.Server(mux2.NewPaddedConn(rc, 128), &mux2.Config{MaxStreamBuffer: 1 << 20})
			if err != nil {
				return
			}
			stream, err := sess.AcceptStream()
			if err != nil {
				return
			}
			data, _ := io.ReadAll(stream)
			gotBytes <- data
		case mux2.ResumeResume:
			var k [32]byte
			copy(k[:], payload)
			regMu.Lock()
			ent, ok := reg[k]
			if ok {
				unregWindow(ent.sess)
				regWindow(ent.sess, ent.n+1)
			}
			regMu.Unlock()
			if !ok {
				conn.Close()
				return
			}
			select {
			case ent.sess.resumeCh <- conn:
			default:
				conn.Close()
			}
		default:
			conn.Close()
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = ListenAndServe(ctx, &ServerConfig{
			ListenAddr:   lnAddr,
			TLSCert:      certPath,
			TLSKey:       keyPath,
			SharedSecret: secret,
			OnConn:       onConn,
		})
	}()

	// wait for the listener
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.Dial("tcp", lnAddr)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("listener never came up")
		}
		time.Sleep(50 * time.Millisecond)
	}

	proxyAddr := freePort(t)
	proxy := newProxy(t, proxyAddr, lnAddr)

	var counter uint64
	var cmu sync.Mutex
	var curFc atomic.Value
	redial := func() (net.Conn, error) {
		backoff := 100 * time.Millisecond
		for {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			fc, err := Client(ctx, &ClientConfig{
				ServerAddr:   proxyAddr,
				ServerName:   "example.com",
				SharedSecret: secret,
			})
			if err == nil {
				cmu.Lock()
				counter++
				n := counter
				cmu.Unlock()
				var typ byte
				var pl []byte
				if n == 1 {
					typ, pl = mux2.ResumeEstablish, nonce
				} else {
					typ, pl = mux2.ResumeResume, mux2.ResumeToken(rkey, nonce, n)
				}
				if werr := mux2.WriteResumeHeader(fc, typ, pl); werr == nil {
					curFc.Store(fc)
					return fc, nil
				}
				fc.Close()
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
			if backoff < 2*time.Second {
				backoff *= 2
			}
		}
	}

	rc := mux2.NewResilientConn(strAddrT("cli"), strAddrT("srv"), redial)
	cli, err := mux2.Client(mux2.NewPaddedConn(rc, 128), &mux2.Config{MaxStreamBuffer: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	stream, err := cli.OpenStream()
	if err != nil {
		t.Fatal(err)
	}

	const total = 256 * 1024
	payload := make([]byte, total)
	for i := range payload {
		payload[i] = byte(i * 131)
	}

	werr := make(chan error, 1)
	go func() {
		if _, err := stream.Write(payload[:total/2]); err != nil {
			werr <- err
			return
		}
		proxy.cut()
		if fc, ok := curFc.Load().(net.Conn); ok {
			fc.Close()
		}
		time.Sleep(400 * time.Millisecond)
		if _, err := stream.Write(payload[total/2:]); err != nil {
			werr <- err
			return
		}
		stream.Close()
		werr <- nil
	}()

	var got []byte
	select {
	case got = <-gotBytes:
	case <-time.After(30 * time.Second):
		t.Fatal("server never received the full stream")
	}
	if err := <-werr; err != nil {
		t.Fatalf("client write: %v", err)
	}
	if len(got) != total {
		t.Fatalf("got %d bytes, want %d", len(got), total)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload corrupted across h2 POST drop")
	}
}

type strAddrT string

func (a strAddrT) Network() string { return "tcp" }
func (a strAddrT) String() string  { return string(a) }
