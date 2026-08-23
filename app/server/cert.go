package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/nekoskin/whispera/core/config"
)

func ensureWhisperaServerCert(sc *config.ServerConfig) {
	if sc.Whispera.TLSCert != "" {
		return
	}

	certPath := whisperaCertPath
	keyPath := whisperaKeyPath
	if _, err := os.Stat(certPath); err == nil {
		if !certHasStaleSigAlg(certPath) {
			sc.Whispera.TLSCert = certPath
			sc.Whispera.TLSKey = keyPath
			return
		}
		log.Warn("whispera: server cert at %s uses a signature algorithm most clients reject (e.g. Ed25519) — regenerating as ECDSA", certPath)
	}

	if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil {
		log.Warn("whispera: cannot create %s: %v — no server cert will be available", filepath.Dir(certPath), err)
		return
	}
	if err := generateSelfSignedCert(certPath, keyPath); err != nil {
		log.Warn("whispera: auto cert generation failed: %v", err)
		return
	}

	log.Info("whispera: generated self-signed server cert at %s", certPath)
	sc.Whispera.TLSCert = certPath
	sc.Whispera.TLSKey = keyPath
}

func certHasStaleSigAlg(certPath string) bool {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return false
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	return cert.PublicKeyAlgorithm != x509.ECDSA
}

func generateSelfSignedCert(certPath, keyPath string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	notBefore := time.Now().Add(-24 * time.Hour)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(825 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certOut, err := os.OpenFile(certPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return err
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	keyOut, err := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	return pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
}
