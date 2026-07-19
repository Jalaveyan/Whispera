package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"os"
	"sync"

	"github.com/nekoskin/whispera/common/fsown"
)

var certBindOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 58888, 1, 1}

func certBindMessage(spki []byte, sni string) []byte {
	h := sha256.New()
	h.Write([]byte("whispera-cert-bind-v1"))
	h.Write([]byte{0})
	h.Write(spki)
	h.Write([]byte{0})
	h.Write([]byte(sni))
	return h.Sum(nil)
}

type CertIdentity struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

var (
	certIdentityMu sync.RWMutex
	certIdentity   *CertIdentity
)

func SetCertIdentity(id *CertIdentity) {
	certIdentityMu.Lock()
	certIdentity = id
	certIdentityMu.Unlock()
}

func activeCertIdentity() *CertIdentity {
	certIdentityMu.RLock()
	defer certIdentityMu.RUnlock()
	return certIdentity
}

func LoadOrCreateCertIdentity(path string) (*CertIdentity, error) {
	if data, err := os.ReadFile(path); err == nil && len(data) == ed25519.SeedSize {
		priv := ed25519.NewKeyFromSeed(data)
		return &CertIdentity{priv: priv, pub: priv.Public().(ed25519.PublicKey)}, nil
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, priv.Seed(), 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, err
	}
	fsown.MatchParent(path)
	return &CertIdentity{priv: priv, pub: pub}, nil
}

func (id *CertIdentity) PubB64() string {
	return base64.StdEncoding.EncodeToString(id.pub)
}

func (id *CertIdentity) bindExtension(spki []byte, sni string) (pkix.Extension, error) {
	sig := ed25519.Sign(id.priv, certBindMessage(spki, sni))
	val, err := asn1.Marshal(sig)
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{Id: certBindOID, Critical: false, Value: val}, nil
}

func extractCertBindSig(cert *x509.Certificate) []byte {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(certBindOID) {
			var sig []byte
			if _, err := asn1.Unmarshal(ext.Value, &sig); err == nil {
				return sig
			}
		}
	}
	return nil
}

func certHasBinding(cert *x509.Certificate) bool {
	return extractCertBindSig(cert) != nil
}

func verifyCertBinding(idPubB64, sni string, leaf *x509.Certificate) bool {
	pub, err := base64.StdEncoding.DecodeString(idPubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig := extractCertBindSig(leaf)
	if sig == nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), certBindMessage(leaf.RawSubjectPublicKeyInfo, sni), sig)
}

func certVerifier(pin, idPubB64, sni string) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("whispera: no server certificate to verify")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("whispera: parse server cert: %w", err)
		}
		if idPubB64 != "" && verifyCertBinding(idPubB64, sni, leaf) {
			return nil
		}
		if pin != "" && subtle.ConstantTimeCompare([]byte(SPKIPin(leaf)), []byte(pin)) == 1 {
			return nil
		}
		if idPubB64 != "" && pin == "" {
			return fmt.Errorf("whispera: server cert identity verification failed")
		}
		return fmt.Errorf("whispera: server cert pin mismatch")
	}
}
