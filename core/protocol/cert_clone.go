package protocol

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/nekoskin/whispera/common/fsown"
)

type ClonedCertInfo struct {
	Subject   string
	DNSNames  []string
	NotBefore time.Time
	NotAfter  time.Time
}

func fetchRealCert(domain string) (*x509.Certificate, error) {
	host := domain
	if h, _, err := net.SplitHostPort(domain); err == nil {
		host = h
	}
	addr := net.JoinHostPort(host, "443")

	dialCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	dialer := tls.Dialer{Config: &tls.Config{ServerName: host}}
	rawConn, err := dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tls dial %s: %w", addr, err)
	}
	conn, ok := rawConn.(*tls.Conn)
	if !ok {
		rawConn.Close()
		return nil, fmt.Errorf("tls dial %s returned %T, not a TLS connection", addr, rawConn)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificate presented by %s", addr)
	}
	return certs[0], nil
}

func cloneCertTemplate(real *x509.Certificate) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	notBefore := time.Now().Add(-24 * time.Hour)
	validity := real.NotAfter.Sub(real.NotBefore)
	if validity <= 0 {
		validity = 90 * 24 * time.Hour
	}
	notAfter := notBefore.Add(validity)

	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               real.Subject,
		DNSNames:              real.DNSNames,
		IPAddresses:           real.IPAddresses,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}, nil
}

func existingValidClone(domain, certPath, keyPath string) (*ClonedCertInfo, bool) {
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil || len(pair.Certificate) == 0 {
		return nil, false
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.PublicKeyAlgorithm != x509.ECDSA {
		return nil, false
	}
	if time.Now().After(leaf.NotAfter.Add(-24 * time.Hour)) {
		return nil, false
	}
	if id := activeCertIdentity(); id != nil {
		if !verifyCertBinding(id.PubB64(), domain, leaf) {
			return nil, false
		}
		if len(id.SelectorPub()) == 32 && selectorPubFromCert(leaf, id.PubB64()) == "" {
			return nil, false
		}
	}
	return &ClonedCertInfo{
		Subject:   leaf.Subject.String(),
		DNSNames:  leaf.DNSNames,
		NotBefore: leaf.NotBefore,
		NotAfter:  leaf.NotAfter,
	}, true
}

func reuseExistingClone(certPath, keyPath string) (*ecdsa.PrivateKey, *x509.Certificate) {
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil || len(pair.Certificate) == 0 {
		return nil, nil
	}
	priv, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, nil
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil
	}
	notBefore := time.Now().Add(-24 * time.Hour)
	validity := leaf.NotAfter.Sub(leaf.NotBefore)
	if validity <= 0 {
		validity = 90 * 24 * time.Hour
	}
	return priv, &x509.Certificate{
		SerialNumber:          serial,
		Subject:               leaf.Subject,
		DNSNames:              leaf.DNSNames,
		IPAddresses:           leaf.IPAddresses,
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
}

func writePEM(path string, mode os.FileMode, block *pem.Block) error {
	var buf bytes.Buffer
	if err := pem.Encode(&buf, block); err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	if err := fsown.WriteFile(path, buf.Bytes(), mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func CloneCertToFiles(domain, outCert, outKey string) (*ClonedCertInfo, error) {
	return cloneCertToFiles(domain, outCert, outKey, false)
}

func RecloneCertToFiles(domain, outCert, outKey string) (*ClonedCertInfo, error) {
	return cloneCertToFiles(domain, outCert, outKey, true)
}

func cloneCertToFiles(domain, outCert, outKey string, force bool) (*ClonedCertInfo, error) {
	if !force {
		if info, ok := existingValidClone(domain, outCert, outKey); ok {
			return info, nil
		}
	}

	priv, template := reuseExistingClone(outCert, outKey)
	if priv == nil || template == nil {
		real, err := fetchRealCert(domain)
		if err != nil {
			return nil, fmt.Errorf("fetch real certificate from %s: %w", domain, err)
		}
		template, err = cloneCertTemplate(real)
		if err != nil {
			return nil, fmt.Errorf("build certificate template: %w", err)
		}
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate keypair: %w", err)
		}
	}

	if id := activeCertIdentity(); id != nil {
		spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("marshal public key: %w", err)
		}
		ext, err := id.bindExtension(spki, domain)
		if err != nil {
			return nil, fmt.Errorf("build identity binding: %w", err)
		}
		template.ExtraExtensions = append(template.ExtraExtensions, ext)
		if selExt, err := id.selectorExtension(); err == nil {
			template.ExtraExtensions = append(template.ExtraExtensions, selExt)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	if err := writePEM(outCert, 0644, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, err
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	if err := writePEM(outKey, 0640, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return nil, err
	}

	if err := fsown.MatchParent(outCert); err != nil {
		return nil, fmt.Errorf("the service will not be able to read the clone: %w", err)
	}
	if err := fsown.MatchParent(outKey); err != nil {
		return nil, fmt.Errorf("the service will not be able to read the clone: %w", err)
	}

	return &ClonedCertInfo{
		Subject:   template.Subject.String(),
		DNSNames:  template.DNSNames,
		NotBefore: template.NotBefore,
		NotAfter:  template.NotAfter,
	}, nil
}

var sniFileSafe = regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)

func SNICertPaths(decoyCertDir, sni string) (certPath, keyPath string, ok bool) {
	if decoyCertDir == "" || sni == "" || !sniFileSafe.MatchString(sni) {
		return "", "", false
	}
	return filepath.Join(decoyCertDir, sni+".crt"), filepath.Join(decoyCertDir, sni+".key"), true
}

type cachedSNICert struct {
	cert    *tls.Certificate
	modTime time.Time
	size    int64
}

var (
	sniCertCacheMu    sync.RWMutex
	sniCertCache      = map[string]cachedSNICert{}
	sniCertLoadFailed sync.Map
)

func loadSNICert(decoyCertDir, sni string) (*tls.Certificate, bool) {
	certPath, keyPath, ok := SNICertPaths(decoyCertDir, sni)
	if !ok {
		return nil, false
	}

	sniCertCacheMu.RLock()
	c, found := sniCertCache[sni]
	sniCertCacheMu.RUnlock()

	fi, statErr := os.Stat(certPath)
	if found && statErr == nil && c.modTime.Equal(fi.ModTime()) && c.size == fi.Size() {
		return c.cert, true
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		if statErr == nil {
			if _, seen := sniCertLoadFailed.LoadOrStore(sni, true); !seen {
				traceLog.Errorw("decoy_sni_cert_load_failed", "sni", sni,
					"hint", "clone exists but unreadable (check ownership: must match the service user); serving static cert -> client cert-pin mismatch",
					"err", err.Error())
			}
		}
		return nil, false
	}

	if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil && leaf.PublicKeyAlgorithm != x509.ECDSA {
		if _, err := CloneCertToFiles(sni, certPath, keyPath); err == nil {
			if fixed, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
				cert = fixed
			}
		}
	}

	entry := cachedSNICert{cert: &cert}
	if fi, err := os.Stat(certPath); err == nil {
		entry.modTime, entry.size = fi.ModTime(), fi.Size()
	}
	sniCertCacheMu.Lock()
	sniCertCache[sni] = entry
	sniCertCacheMu.Unlock()
	sniCertLoadFailed.Delete(sni)
	return &cert, true
}

const sniCertSweepEvery = time.Hour

func MaintainSNICerts(ctx context.Context, decoyCertDir string) {
	EnsureSNICerts(decoyCertDir)
	ticker := time.NewTicker(sniCertSweepEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			EnsureSNICerts(decoyCertDir)
		}
	}
}

func clonePin(certPath string) string {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return ""
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return ""
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	return SPKIPin(leaf)
}

func EnsureSNICerts(decoyCertDir string) {
	entries, err := os.ReadDir(decoyCertDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".crt" {
			continue
		}
		sni := strings.TrimSuffix(e.Name(), ".crt")
		certPath, keyPath, ok := SNICertPaths(decoyCertDir, sni)
		if !ok {
			continue
		}
		if _, ok := existingValidClone(sni, certPath, keyPath); ok {
			continue
		}
		before := clonePin(certPath)
		info, err := CloneCertToFiles(sni, certPath, keyPath)
		if err != nil {
			traceLog.Errorw("decoy_sni_cert_unrepairable", "sni", sni,
				"hint", "this SNI will be served the static cert, and every key pinned to it will refuse the connection",
				"err", err.Error())
			continue
		}
		if after := clonePin(certPath); before != "" && after == before {
			traceLog.Infow("decoy_sni_cert_reissued", "sni", sni, "subject", info.Subject,
				"hint", "the clone was rebuilt to carry the current identity bindings; its key was kept, so pinned client keys keep working")
			continue
		}
		traceLog.Warnw("decoy_sni_cert_reissued", "sni", sni, "subject", info.Subject,
			"hint", "the clone on disk was unreadable or broken; a fresh key was issued, so keys carrying a cert pin (rather than an identity key) must be reissued")
	}
}
