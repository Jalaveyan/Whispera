package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	rtdebug "runtime/debug"
	"strconv"
	"time"

	"github.com/nekoskin/whispera/core/protocol"

	"github.com/nekoskin/whispera/common/runtime/lifecycle"
	"github.com/nekoskin/whispera/common/stats"
	"github.com/nekoskin/whispera/core/apiserver"
	"github.com/nekoskin/whispera/core/config"
	"github.com/nekoskin/whispera/core/protocol/fingerprint"
	"github.com/nekoskin/whispera/core/transport/grpc"
	"github.com/nekoskin/whispera/core/transport/yadisk"
)

func initWhispera(m *lifecycle.Manager, sc *config.ServerConfig, ctx context.Context) {
	cCfg := &protocol.ServerConfig{
		ListenAddr:     sc.Whispera.ListenAddr,
		BackendH2CAddr: sc.Whispera.BackendH2CAddr,
		TLSCert:        sc.Whispera.TLSCert,
		TLSKey:         sc.Whispera.TLSKey,
		Domain:         sc.Whispera.Domain,
		DecoyCertDir:   whisperaDecoyCertDir,
		ACMEDir:        sc.Whispera.ACMEDir,
		DecoyOrigin:    sc.Whispera.DecoyOrigin,
		GetUsers: func() []protocol.UserEntry {
			registered := apiserver.GetRegisteredUsers()
			entries := make([]protocol.UserEntry, 0, len(registered))
			for _, u := range registered {
				psk, err := base64.StdEncoding.DecodeString(u.PrivateKey)
				if err != nil || len(psk) != 32 {
					continue
				}
				entries = append(entries, protocol.UserEntry{UserID: u.UserID, PSK: psk})
			}
			return entries
		},
		OnConn: func(conn net.Conn, userID string, secret []byte) {
			log.Info("whispera: tunnel connected userID=%s remote=%s", userID, conn.RemoteAddr())
			tracked := stats.WrapConn(conn, userID)
			go func() {
				globalRelay.ServeTunnelResilient(tracked, false, secret)
				log.Info("whispera: tunnel closed userID=%s remote=%s", userID, conn.RemoteAddr())
			}()
		},
	}
	cCfg.QUICListenAddr = sc.Whispera.QUICListenAddr
	if len(sc.Whispera.ExtraPorts) > 0 {
		listenHost, _, _ := net.SplitHostPort(sc.Whispera.ListenAddr)
		for _, p := range sc.Whispera.ExtraPorts {
			if p <= 0 || p > 65535 {
				continue
			}
			cCfg.ExtraListenAddrs = append(cCfg.ExtraListenAddrs, net.JoinHostPort(listenHost, strconv.Itoa(p)))
		}
	}
	if len(sc.Whispera.QUICExtraPorts) > 0 && sc.Whispera.QUICListenAddr != "" {
		quicHost, _, _ := net.SplitHostPort(sc.Whispera.QUICListenAddr)
		for _, p := range sc.Whispera.QUICExtraPorts {
			if p <= 0 || p > 65535 {
				continue
			}
			cCfg.ExtraQUICListenAddrs = append(cCfg.ExtraQUICListenAddrs, net.JoinHostPort(quicHost, strconv.Itoa(p)))
		}
	}
	fingerprint.SetCollectDir(apiserver.FingerprintStoreDir)
	if id, err := protocol.LoadOrCreateCertIdentity(whisperaIdentityFile); err != nil {
		log.Warn("whispera: cert identity unavailable (verify-by-key disabled): %v", err)
	} else {
		protocol.SetCertIdentity(id)
	}
	go func() { _ = protocol.ListenAndServe(ctx, cCfg) }()
}

func verifyAltTransportAuth(conn net.Conn) bool {
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	var sidLenByte [1]byte
	if _, err := io.ReadFull(conn, sidLenByte[:]); err != nil {
		return false
	}
	sidLen := int(sidLenByte[0])
	if sidLen == 0 || sidLen > 64 {
		return false
	}
	sessionID := make([]byte, sidLen)
	if _, err := io.ReadFull(conn, sessionID); err != nil {
		return false
	}

	var tokLenBuf [2]byte
	if _, err := io.ReadFull(conn, tokLenBuf[:]); err != nil {
		return false
	}
	tokLen := int(binary.BigEndian.Uint16(tokLenBuf[:]))
	if tokLen == 0 || tokLen > 256 {
		return false
	}
	tokenBytes := make([]byte, tokLen)
	if _, err := io.ReadFull(conn, tokenBytes); err != nil {
		return false
	}
	token := string(tokenBytes)

	for _, u := range apiserver.GetRegisteredUsers() {
		psk, err := base64.StdEncoding.DecodeString(u.PrivateKey)
		if err != nil || len(psk) != 32 {
			continue
		}
		if protocol.VerifyAuthToken(psk, token, sessionID) {
			return true
		}
	}
	return false
}

func handleAltTransportConn(conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("PANIC in handleAltTransportConn: %v\n%s", r, rtdebug.Stack())
		}
	}()

	if !verifyAltTransportAuth(conn) {
		conn.Close()
		return
	}
	if globalRelay == nil {
		conn.Close()
		return
	}
	globalRelay.ServeTunnelRaw(stats.WrapConn(conn, conn.RemoteAddr().String()), false)
}

func initGRPC(m *lifecycle.Manager, sc *config.ServerConfig) error {
	if !sc.GRPC.Enabled || sc.GRPC.ListenAddr == "" {
		return nil
	}
	var grpcExtraAddrs []string
	if len(sc.GRPC.ExtraPorts) > 0 {
		grpcHost, _, _ := net.SplitHostPort(sc.GRPC.ListenAddr)
		for _, p := range sc.GRPC.ExtraPorts {
			if p <= 0 || p > 65535 {
				continue
			}
			grpcExtraAddrs = append(grpcExtraAddrs, net.JoinHostPort(grpcHost, strconv.Itoa(p)))
		}
	}
	t, err := grpc.New(&grpc.Config{
		ListenAddr:       sc.GRPC.ListenAddr,
		ExtraListenAddrs: grpcExtraAddrs,
		ServerName:       sc.GRPC.ServerName,
		UseTLS:           sc.GRPC.TLSCert != "",
		CertFile:         sc.GRPC.TLSCert,
		KeyFile:          sc.GRPC.TLSKey,
	})
	if err != nil {
		return err
	}
	if err := m.Register(t); err != nil {
		return err
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Error("PANIC in grpc accept loop: %v\n%s", r, rtdebug.Stack())
			}
		}()
		time.Sleep(1 * time.Second)
		backoffGRPC := 1 * time.Millisecond
		for {
			conn, err := t.Accept()
			if err != nil {
				acceptBackoff(&backoffGRPC)
				continue
			}
			backoffGRPC = 1 * time.Millisecond
			release, ok := acquireConnSlot(conn.RemoteAddr())
			if !ok {
				conn.Close()
				continue
			}
			go func() {
				defer release()
				handleAltTransportConn(conn)
			}()
		}
	}()
	return nil
}

func initYaDisk(m *lifecycle.Manager, sc *config.ServerConfig) error {
	if !sc.YaDisk.Enabled || sc.YaDisk.OAuthToken == "" {
		return nil
	}
	t, err := yadisk.New(&yadisk.Config{
		OAuthToken: sc.YaDisk.OAuthToken,
		SessionID:  sc.YaDisk.SessionID,
		ServerMode: true,
	})
	if err != nil {
		return err
	}
	if err := m.Register(t); err != nil {
		return err
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Error("PANIC in yadisk accept loop: %v\n%s", r, rtdebug.Stack())
			}
		}()
		time.Sleep(1 * time.Second)
		backoffYaDisk := 1 * time.Millisecond
		for {
			conn, err := t.Accept()
			if err != nil {
				acceptBackoff(&backoffYaDisk)
				continue
			}
			backoffYaDisk = 1 * time.Millisecond
			release, ok := acquireConnSlot(conn.RemoteAddr())
			if !ok {
				conn.Close()
				continue
			}
			go func() {
				defer release()
				handleAltTransportConn(conn)
			}()
		}
	}()
	return nil
}
