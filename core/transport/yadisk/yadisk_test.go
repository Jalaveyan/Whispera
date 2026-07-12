package yadisk

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/webdav"
)

type flakyPut struct {
	inner  http.Handler
	mu     sync.Mutex
	failed map[string]bool
}

func (f *flakyPut) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut {
		f.mu.Lock()
		if !f.failed[r.URL.Path] {
			f.failed[r.URL.Path] = true
			f.mu.Unlock()
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		f.mu.Unlock()
	}
	f.inner.ServeHTTP(w, r)
}

func readWithTimeout(t *testing.T, c interface{ Read([]byte) (int, error) }, d time.Duration) []byte {
	t.Helper()
	type res struct {
		n   int
		buf []byte
		err error
	}
	ch := make(chan res, 1)
	go func() {
		buf := make([]byte, 4096)
		n, err := c.Read(buf)
		ch <- res{n, buf[:n], err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("read error: %v", r.err)
		}
		return r.buf
	case <-time.After(d):
		t.Fatalf("read timed out after %s", d)
		return nil
	}
}

func TestYadiskEchoOverWebDAV(t *testing.T) {
	dav := &webdav.Handler{
		FileSystem: webdav.NewMemFS(),
		LockSystem: webdav.NewMemLS(),
	}
	srv := httptest.NewServer(dav)
	defer srv.Close()

	sess := "unit-session"

	st, err := New(&Config{ServerMode: true, OAuthToken: "tok", SessionID: sess, BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("server New: %v", err)
	}
	if err := st.Start(); err != nil {
		t.Fatalf("server Start: %v", err)
	}
	defer st.Stop()

	ct, err := New(&Config{ServerMode: false, OAuthToken: "tok", SessionID: sess, BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("client New: %v", err)
	}
	if err := ct.Start(); err != nil {
		t.Fatalf("client Start: %v", err)
	}
	defer ct.Stop()

	sconn, err := st.Accept()
	if err != nil {
		t.Fatalf("server Accept: %v", err)
	}
	cconn, err := ct.Dial(context.Background(), "")
	if err != nil {
		t.Fatalf("client Dial: %v", err)
	}

	// client -> server
	c2s := []byte("hello from client")
	n, err := cconn.Write(c2s)
	if err != nil {
		t.Fatalf("client Write: %v", err)
	}
	if n != len(c2s) {
		t.Fatalf("client Write returned n=%d, want %d", n, len(c2s))
	}
	got := readWithTimeout(t, sconn, 5*time.Second)
	if !bytes.Equal(got, c2s) {
		t.Fatalf("server read %q, want %q", got, c2s)
	}

	// server -> client
	s2c := []byte("hello back from server")
	if _, err := sconn.Write(s2c); err != nil {
		t.Fatalf("server Write: %v", err)
	}
	got = readWithTimeout(t, cconn, 5*time.Second)
	if !bytes.Equal(got, s2c) {
		t.Fatalf("client read %q, want %q", got, s2c)
	}

	// ordered multi-chunk client -> server
	for i := 0; i < 5; i++ {
		msg := []byte{'A' + byte(i)}
		if _, err := cconn.Write(msg); err != nil {
			t.Fatalf("client Write %d: %v", i, err)
		}
	}
	var acc []byte
	deadline := time.Now().Add(6 * time.Second)
	for len(acc) < 5 && time.Now().Before(deadline) {
		acc = append(acc, readWithTimeout(t, sconn, 5*time.Second)...)
	}
	if string(acc) != "ABCDE" {
		t.Fatalf("ordered read got %q, want ABCDE", acc)
	}
}

func TestYadiskSurvivesTransientPutFailure(t *testing.T) {
	dav := &webdav.Handler{
		FileSystem: webdav.NewMemFS(),
		LockSystem: webdav.NewMemLS(),
	}
	srv := httptest.NewServer(&flakyPut{inner: dav, failed: map[string]bool{}})
	defer srv.Close()

	sess := "flaky-session"
	st, _ := New(&Config{ServerMode: true, OAuthToken: "t", SessionID: sess, BaseURL: srv.URL})
	if err := st.Start(); err != nil {
		t.Fatalf("server Start: %v", err)
	}
	defer st.Stop()
	ct, _ := New(&Config{ServerMode: false, OAuthToken: "t", SessionID: sess, BaseURL: srv.URL})
	if err := ct.Start(); err != nil {
		t.Fatalf("client Start: %v", err)
	}
	defer ct.Stop()

	sconn, _ := st.Accept()
	cconn, _ := ct.Dial(context.Background(), "")

	// Every first PUT to a path fails; the send-retry must still deliver in order.
	for i := 0; i < 4; i++ {
		if _, err := cconn.Write([]byte{'1' + byte(i)}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	var acc []byte
	deadline := time.Now().Add(8 * time.Second)
	for len(acc) < 4 && time.Now().Before(deadline) {
		acc = append(acc, readWithTimeout(t, sconn, 6*time.Second)...)
	}
	if string(acc) != "1234" {
		t.Fatalf("got %q, want 1234 (retry lost/reordered data)", acc)
	}
}
