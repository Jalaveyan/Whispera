package buf

import (
	"io"
	"net"
)

func Relay(a, b net.Conn, aReader, bReader io.Reader) {
	if aReader == nil {
		aReader = a
	}
	if bReader == nil {
		bReader = b
	}
	done := make(chan struct{}, 2)
	pump := func(dst net.Conn, src io.Reader) {
		_, _ = io.Copy(dst, src)
		done <- struct{}{}
	}
	go pump(b, aReader)
	go pump(a, bReader)
	<-done
	a.Close()
	b.Close()
	<-done
}
