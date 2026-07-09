package tunnel

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
	"whispera/common/mux"
)

func (m *Manager) dialManagedConn(ctx context.Context, id string) (*managedConn, error) {
	dial := m.rtDial()
	if dial == nil {
		return nil, fmt.Errorf("dial: no whispera dialer available")
	}

	padMax := m.config.PaddingMaxSize
	if padMax <= 0 {
		padMax = 128
	}

	var muxConn net.Conn
	if m.resilientEnabled() {
		muxConn = mux.NewPaddedConn(m.newResilientConn(dial), padMax)
	} else {
		conn, err := dial(ctx)
		if err != nil {
			return nil, err
		}
		muxConn = mux.NewPaddedConn(conn, padMax)
	}

	sess, err := mux.Client(muxConn, m.getMuxConfig())
	if err != nil {
		muxConn.Close()
		return nil, fmt.Errorf("mux: %w", err)
	}

	stream, err := sess.OpenStream()
	if err != nil {
		sess.Close()
		return nil, fmt.Errorf("open stream: %w", err)
	}

	return &managedConn{
		Conn:      stream,
		session:   sess,
		id:        id,
		createdAt: time.Now(),
		closing:   make(chan struct{}),
	}, nil
}

func (m *Manager) resilientEnabled() bool {
	return m.config.EnableWhispera && len(m.config.WhisperaSecret) == 32 && os.Getenv("WHISPERA_RESILIENT") != "0"
}

type resilientAddr string

func (a resilientAddr) Network() string { return "tcp" }
func (a resilientAddr) String() string  { return string(a) }

func (m *Manager) newResilientConn(dial func(context.Context) (net.Conn, error)) *mux.ResilientConn {
	nonce, _ := mux.NewResumeNonce()
	sessionKey := mux.DeriveResumeKey(m.config.WhisperaSecret)
	var counter uint64
	var cmu sync.Mutex

	redial := func() (net.Conn, error) {
		parent := m.Context()
		if parent == nil {
			parent = context.Background()
		}
		backoff := 500 * time.Millisecond
		for {
			if err := parent.Err(); err != nil {
				return nil, err
			}
			dctx, cancel := context.WithTimeout(parent, m.config.ConnectionTimeout)
			conn, err := dial(dctx)
			cancel()
			if err == nil {
				cmu.Lock()
				counter++
				n := counter
				cmu.Unlock()
				var herr error
				if n == 1 {
					herr = mux.WriteResumeHeader(conn, mux.ResumeEstablish, nonce)
				} else {
					herr = mux.WriteResumeHeader(conn, mux.ResumeResume, mux.ResumeToken(sessionKey, nonce, n))
				}
				if herr == nil {
					return conn, nil
				}
				conn.Close()
			}
			select {
			case <-parent.Done():
				return nil, parent.Err()
			case <-time.After(backoff):
			}
			if backoff < 10*time.Second {
				backoff *= 2
			}
		}
	}

	a := m.config.WhisperaAddr
	if a == "" {
		a = m.config.ServerAddr
	}
	addr := resilientAddr(a)
	return mux.NewResilientConn(addr, addr, redial)
}
