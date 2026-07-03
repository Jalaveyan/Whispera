package protocol

import (
	"context"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func TestCamoMarkerReachesWire(t *testing.T) {
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = byte(i + 1)
	}
	camoKey := deriveCamoKey(psk)
	if camoKey == nil {
		t.Fatal("nil camoKey")
	}
	keys := [][]byte{camoKey}

	ids := []utls.ClientHelloID{
		utls.HelloChrome_133,
		utls.HelloChrome_131,
		utls.HelloChrome_120_PQ,
		utls.HelloFirefox_148,
		utls.HelloFirefox_120,
		utls.HelloEdge_106,
		utls.HelloSafari_26_3,
		utls.HelloSafari_16_0,
		utls.HelloIOS_14,
	}

	for _, id := range ids {
		t.Run(id.Str(), func(t *testing.T) {
			cli, srv := net.Pipe()
			defer cli.Close()
			defer srv.Close()

			go func() {
				uCfg := &utls.Config{ServerName: "53.img.avito.st", InsecureSkipVerify: true}
				uConn := utls.UClient(cli, uCfg, id)
				if err := uConn.BuildHandshakeState(); err != nil {
					return
				}
				if hello := uConn.HandshakeState.Hello; hello != nil && len(hello.Random) == 32 {
					if ks := extractX25519KeyShare(hello.KeyShares); len(ks) > 0 {
						marker := buildCamoMarker(camoKey, ks)
						copy(hello.Random, marker[:])
					} else {
						t.Errorf("%s: no X25519 keyshare on client side", id.Str())
					}
				}
				_ = uConn.HandshakeContext(context.Background())
			}()

			srv.SetReadDeadline(time.Now().Add(2 * time.Second))
			ph, err := peekClientHello(srv)
			if err != nil {
				t.Fatalf("%s: peek err: %v", id.Str(), err)
			}
			if len(ph.keyShare) == 0 {
				t.Fatalf("%s: server parsed no X25519 keyshare on wire", id.Str())
			}
			if camoMarkerMatches(keys, ph.random, ph.keyShare) {
				t.Logf("%s: OK marker matched", id.Str())
			} else {
				t.Errorf("%s: MARKER MISMATCH -> would be relayed to decoy", id.Str())
			}
		})
	}
}

func TestCamoMarkerHarvestedApplyPreset(t *testing.T) {
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = byte(i + 1)
	}
	camoKey := deriveCamoKey(psk)
	keys := [][]byte{camoKey}

	seedIDs := []utls.ClientHelloID{
		utls.HelloChrome_133,
		utls.HelloChrome_120_PQ,
		utls.HelloFirefox_148,
		utls.HelloSafari_16_0,
	}

	for _, seed := range seedIDs {
		t.Run(seed.Str(), func(t *testing.T) {
			c0, s0 := net.Pipe()
			rawCh := make(chan []byte, 1)
			go func() {
				u := utls.UClient(c0, &utls.Config{ServerName: "x.example", InsecureSkipVerify: true}, seed)
				_ = u.BuildHandshakeState()
				_ = u.HandshakeContext(context.Background())
			}()
			s0.SetReadDeadline(time.Now().Add(2 * time.Second))
			ph0, err := peekClientHello(s0)
			c0.Close()
			s0.Close()
			if err != nil {
				t.Fatalf("seed peek: %v", err)
			}
			rawCh <- ph0.raw

			fp := &utls.Fingerprinter{AllowBluntMimicry: true}
			spec, err := fp.FingerprintClientHello(<-rawCh)
			if err != nil {
				t.Fatalf("fingerprint: %v", err)
			}

			cli, srv := net.Pipe()
			defer cli.Close()
			defer srv.Close()
			go func() {
				uConn := utls.UClient(cli, &utls.Config{ServerName: "53.img.avito.st", InsecureSkipVerify: true}, utls.HelloCustom)
				if err := uConn.ApplyPreset(spec); err != nil {
					return
				}
				if err := uConn.BuildHandshakeState(); err != nil {
					t.Errorf("%s: build: %v", seed.Str(), err)
					return
				}
				if hello := uConn.HandshakeState.Hello; hello != nil && len(hello.Random) == 32 {
					if ks := extractX25519KeyShare(hello.KeyShares); len(ks) > 0 {
						marker := buildCamoMarker(camoKey, ks)
						copy(hello.Random, marker[:])
					} else {
						t.Errorf("%s: no X25519 keyshare after ApplyPreset", seed.Str())
					}
				}
				_ = uConn.HandshakeContext(context.Background())
			}()

			srv.SetReadDeadline(time.Now().Add(2 * time.Second))
			ph, err := peekClientHello(srv)
			if err != nil {
				t.Fatalf("%s: peek: %v", seed.Str(), err)
			}
			if len(ph.keyShare) == 0 {
				t.Fatalf("%s: no X25519 keyshare on wire", seed.Str())
			}
			if camoMarkerMatches(keys, ph.random, ph.keyShare) {
				t.Logf("%s: OK marker matched (harvested path)", seed.Str())
			} else {
				t.Errorf("%s: HARVESTED PATH MISMATCH -> decoy", seed.Str())
			}
		})
	}
}
