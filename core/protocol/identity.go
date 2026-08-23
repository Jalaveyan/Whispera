package protocol

import (
	"crypto/ecdh"
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
	"github.com/nekoskin/whispera/core/protocol/camo"
)

var certBindOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 58888, 1, 1}

var selBindOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 58888, 1, 2}

type selectorBinding struct {
	Pub []byte
	Sig []byte
}

func selectorBindMessage(pub []byte) []byte {
	h := sha256.New()
	h.Write([]byte("whispera-selector-bind-v1"))
	h.Write([]byte{0})
	h.Write(pub)
	return h.Sum(nil)
}

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

	selOnce sync.Once
	selKey  *ecdh.PrivateKey
	selErr  error
}

func (c *CertIdentity) SelectorKey() (*ecdh.PrivateKey, error) {
	if c == nil {
		return nil, fmt.Errorf("whispera: no cert identity")
	}
	c.selOnce.Do(func() {
		c.selKey, c.selErr = camo.ServerKeyFromSeed(c.priv.Seed())
	})
	return c.selKey, c.selErr
}

func (c *CertIdentity) SelectorPub() []byte {
	k, err := c.SelectorKey()
	if err != nil {
		return nil
	}
	return k.PublicKey().Bytes()
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
	data, err := os.ReadFile(path)
	switch {
	case err == nil && len(data) == ed25519.SeedSize:
		priv := ed25519.NewKeyFromSeed(data)
		return &CertIdentity{priv: priv, pub: priv.Public().(ed25519.PublicKey)}, nil
	case err == nil:
		return nil, fmt.Errorf("whispera: identity %s is %d bytes, want %d — refusing to overwrite it", path, len(data), ed25519.SeedSize)
	case !os.IsNotExist(err):
		return nil, fmt.Errorf("whispera: read identity %s: %w — refusing to overwrite it", path, err)
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
	if err := fsown.MatchParent(path); err != nil {
		return nil, fmt.Errorf("whispera: the service will not be able to read identity %s: %w", path, err)
	}
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

func (id *CertIdentity) selectorExtension() (pkix.Extension, error) {
	pub := id.SelectorPub()
	if len(pub) != 32 {
		return pkix.Extension{}, fmt.Errorf("whispera: selector key unavailable")
	}
	val, err := asn1.Marshal(selectorBinding{Pub: pub, Sig: ed25519.Sign(id.priv, selectorBindMessage(pub))})
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{Id: selBindOID, Critical: false, Value: val}, nil
}

func selectorPubFromCert(cert *x509.Certificate, idPubB64 string) string {
	pub, err := base64.StdEncoding.DecodeString(idPubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return ""
	}
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(selBindOID) {
			continue
		}
		var b selectorBinding
		if _, err := asn1.Unmarshal(ext.Value, &b); err != nil || len(b.Pub) != 32 {
			return ""
		}
		if !ed25519.Verify(ed25519.PublicKey(pub), selectorBindMessage(b.Pub), b.Sig) {
			return ""
		}
		return base64.StdEncoding.EncodeToString(b.Pub)
	}
	return ""
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

// servedByDecoy reports whether the certificate we were given is a genuine,
// publicly trusted one for this SNI. The tunnel never serves such a cert, so
// seeing one means the camouflage gate did not recognize our marker and relayed
// the connection to the real site.
func servedByDecoy(leaf *x509.Certificate, rawCerts [][]byte, sni string) bool {
	if sni == "" {
		return false
	}
	pool := x509.NewCertPool()
	for _, raw := range rawCerts[1:] {
		if c, err := x509.ParseCertificate(raw); err == nil {
			pool.AddCert(c)
		}
	}
	_, err := leaf.Verify(x509.VerifyOptions{DNSName: sni, Intermediates: pool})
	return err == nil
}

func certVerifier(pin, idPubB64, sni string, onSelPub func(string)) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("whispera: no server certificate to verify")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("whispera: parse server cert: %w", err)
		}
		if idPubB64 != "" && verifyCertBinding(idPubB64, sni, leaf) {
			if onSelPub != nil {
				if sel := selectorPubFromCert(leaf, idPubB64); sel != "" {
					onSelPub(sel)
				}
			}
			return nil
		}
		if pin != "" && subtle.ConstantTimeCompare([]byte(SPKIPin(leaf)), []byte(pin)) == 1 {
			return nil
		}
		if servedByDecoy(leaf, rawCerts, sni) {
			return fmt.Errorf("whispera: the server served the decoy site instead of the tunnel — it did not recognize this key. "+
				"Either the key is not registered on this server, or /etc/whispera/users.json is not readable by the service user. "+
				"A key created seconds ago needs a moment to be picked up (sni %q)", sni)
		}
		if idPubB64 != "" && pin == "" {
			return fmt.Errorf("whispera: server cert identity verification failed")
		}
		return fmt.Errorf("whispera: server cert pin mismatch")
	}
}
