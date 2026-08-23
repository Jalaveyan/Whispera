package buf

import (
	"bytes"
	"io"
	"testing"
)

type tailReader struct {
	data []byte
	done bool
}

func (t *tailReader) Read(p []byte) (int, error) {
	if t.done {
		return 0, io.EOF
	}
	t.done = true
	n := copy(p, t.data)
	return n, io.EOF
}

func TestCopyKeepsBytesDeliveredWithEOF(t *testing.T) {
	payload := []byte("последний кусок перед EOF")
	var out bytes.Buffer
	n, err := Copy(NewReader(&tailReader{data: payload}), NewWriter(&out))
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if int(n) != len(payload) || !bytes.Equal(out.Bytes(), payload) {
		t.Fatalf("потеряно: скопировано %d из %d, получено %q", n, len(payload), out.String())
	}
}
