package protocol

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"path/filepath"
	"testing"
	"time"
)

func buildBoundCert(t *testing.T, id *CertIdentity, sni string) (der []byte, spkiPin string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: sni},
		DNSNames:              []string{sni},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
	}
	if id != nil {
		ext, err := id.bindExtension(spki, sni)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)
	}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return der, SPKIPin(leaf)
}

func TestVerifyByKeyRoundTrip(t *testing.T) {
	id, err := LoadOrCreateCertIdentity(filepath.Join(t.TempDir(), "id.key"))
	if err != nil {
		t.Fatal(err)
	}
	const sni = "53.img.avito.st"
	der, pin := buildBoundCert(t, id, sni)

	if err := certVerifier("", id.PubB64(), sni)([][]byte{der}, nil); err != nil {
		t.Fatalf("verify-by-key should accept a bound cert: %v", err)
	}
	if err := certVerifier("", id.PubB64(), "other.example")([][]byte{der}, nil); err == nil {
		t.Fatal("verify-by-key must reject a binding for a different SNI")
	}

	other, err := LoadOrCreateCertIdentity(filepath.Join(t.TempDir(), "id2.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := certVerifier("", other.PubB64(), sni)([][]byte{der}, nil); err == nil {
		t.Fatal("verify-by-key must reject a binding from a different identity")
	}

	if err := certVerifier(pin, id.PubB64(), sni)([][]byte{der}, nil); err != nil {
		t.Fatalf("pin+idpub should accept: %v", err)
	}
}

func TestVerifyByKeyPinFallback(t *testing.T) {
	const sni = "53.img.avito.st"
	der, pin := buildBoundCert(t, nil, sni)

	if err := certVerifier(pin, "", sni)([][]byte{der}, nil); err != nil {
		t.Fatalf("pin-only must accept an unbound cert with matching pin: %v", err)
	}
	id, err := LoadOrCreateCertIdentity(filepath.Join(t.TempDir(), "id.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := certVerifier(pin, id.PubB64(), sni)([][]byte{der}, nil); err != nil {
		t.Fatalf("unbound cert should still pass via pin fallback: %v", err)
	}
	if err := certVerifier("", id.PubB64(), sni)([][]byte{der}, nil); err == nil {
		t.Fatal("unbound cert with idpub and no pin must be rejected")
	}
}
