package buf

import (
	"io"
	"net"
)

func RawTCP(c net.Conn) *net.TCPConn {
	for c != nil {
		if tc, ok := c.(*net.TCPConn); ok {
			return tc
		}
		u, ok := c.(interface{ NetConn() net.Conn })
		if !ok {
			return nil
		}
		next := u.NetConn()
		if next == c {
			return nil
		}
		c = next
	}
	return nil
}

type spliceSource interface {
	SpliceTo(dst net.Conn) (int64, error)
}

func Relay(a, b net.Conn, aReader, bReader io.Reader) {
	if aReader == nil {
		aReader = a
	}

	if bReader == nil {
		bReader = b
	}
	done := make(chan struct{}, 2)

	pump := func(dst net.Conn, src io.Reader) {
		if s, ok := src.(spliceSource); ok {
			_, _ = s.SpliceTo(dst)
		} else {
			_, _ = Copy(NewReader(src), NewWriter(dst))
		}
		done <- struct{}{}
	}

	go pump(b, aReader)
	go pump(a, bReader)

	<-done

	a.Close()
	b.Close()

	<-done
}
