package apiserver

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"sort"
	"time"
	"whispera/core/config"
)

func ComputeWhisperaCertPin(certPath string) (string, error) {
	if certPath == "" {
		return "", fmt.Errorf("no certificate path configured")
	}
	raw, err := os.ReadFile(certPath)
	if err != nil {
		return "", fmt.Errorf("read cert: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return "", fmt.Errorf("no PEM block found in %s", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse cert: %w", err)
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}

func CLIDeleteUser(username string) (bool, error) {
	loadUsers()

	userStoreMu.Lock()
	foundID := -1
	for id, u := range userStore {
		if u.Username == username {
			foundID = id
			break
		}
	}
	if foundID == -1 {
		userStoreMu.Unlock()
		return false, nil
	}
	delete(userStore, foundID)
	userStoreMu.Unlock()

	saveUsers()
	return true, nil
}

func CLIUpsertUser(username string, trafficLimit int64, disableNeural bool) (privateKeyB64, publicKeyB64 string, err error) {
	loadUsers()

	userStoreMu.Lock()
	for _, u := range userStore {
		if u.Username == username {
			if trafficLimit > 0 {
				u.TrafficLimit = trafficLimit
			}
			u.DisableNeural = disableNeural
			privateKeyB64, publicKeyB64 = u.PrivateKey, u.PublicKey
			userStoreMu.Unlock()
			saveUsers()
			return privateKeyB64, publicKeyB64, nil
		}
	}

	keys, err := generateX25519Keys()
	if err != nil {
		userStoreMu.Unlock()
		return "", "", err
	}
	user := &User{
		ID:            nextUserID,
		Username:      username,
		PrivateKey:    keys.PrivateKey,
		PublicKey:     keys.PublicKey,
		TrafficLimit:  trafficLimit,
		DisableNeural: disableNeural,
		Status:        "active",
		CreatedAt:     time.Now(),
	}
	userStore[nextUserID] = user
	nextUserID++
	userStoreMu.Unlock()

	saveUsers()
	return keys.PrivateKey, keys.PublicKey, nil
}

type WhisperaKeyOptions struct {
	Addr        string
	SNI         string
	QUICAddr    string
	CertPin     string
	IDPub       string
	Fingerprint string
	FPRaw       string
}

type AltTransportKeyOptions struct {
	GRPCAddr         string
	GRPCServerName   string
	GRPCUseTLS       bool
	YaDiskOAuthToken string
	YaDiskSessionID  string
}

func fingerprintOrDefault(fp string) string {
	if fp == "" {
		return "chrome"
	}
	return fp
}

func CLIBuildConnectionKey(username, serverAddr, serverPubKeyB64, transport string, whispera WhisperaKeyOptions, alt AltTransportKeyOptions) (string, error) {
	loadUsers()

	userStoreMu.Lock()
	var user *User
	for _, u := range userStore {
		if u.Username == username {
			user = u
			break
		}
	}
	if user == nil {
		userStoreMu.Unlock()
		return "", fmt.Errorf("user %s not found", username)
	}

	ck := config.ConnectionKey{
		Version:          2,
		KeyID:            generateKeyID(),
		Server:           serverAddr,
		PSK:              user.PrivateKey,
		ServerPub:        serverPubKeyB64,
		Transport:        transport,
		ObfsPreset:       "default",
		ObfsProfile:      "vk",
		DisableNeural:    user.DisableNeural,
		EnableASNBypass:  true,
		TLSFingerprint:   fingerprintOrDefault(whispera.Fingerprint),
		WhisperaFPRaw:    whispera.FPRaw,
		WhisperaAddr:     whispera.Addr,
		WhisperaSNI:      whispera.SNI,
		WhisperaQUICAddr: whispera.QUICAddr,
		WhisperaCertPin:  whispera.CertPin,
		WhisperaIDPub:    whispera.IDPub,
		GRPCAddr:         alt.GRPCAddr,
		GRPCServerName:   alt.GRPCServerName,
		GRPCUseTLS:       alt.GRPCUseTLS,
		YaDiskOAuthToken: alt.YaDiskOAuthToken,
		YaDiskSessionID:  alt.YaDiskSessionID,
	}
	data, err := json.Marshal(ck)
	if err != nil {
		userStoreMu.Unlock()
		return "", err
	}
	uri := "whispera://" + base64.StdEncoding.EncodeToString(data)
	user.ConnectionURI = uri
	userStoreMu.Unlock()

	saveUsers()
	return uri, nil
}

func CLICreateSubscription(name string, usernames []string) (token string, err error) {
	loadUsers()
	loadSubscriptions()

	userStoreMu.RLock()
	var userIDs []int
	for _, uname := range usernames {
		for _, u := range userStore {
			if u.Username == uname {
				userIDs = append(userIDs, u.ID)
				break
			}
		}
	}
	userStoreMu.RUnlock()

	if len(userIDs) != len(usernames) {
		return "", fmt.Errorf("one or more users not found (resolved %d of %d)", len(userIDs), len(usernames))
	}

	raw, err := randomBase64(24)
	if err != nil {
		return "", err
	}
	token = base64.RawURLEncoding.EncodeToString([]byte(raw))[:32]

	subStoreMu.Lock()
	subNextID++
	sub := &Subscription{
		ID:        fmt.Sprintf("%d", subNextID),
		Name:      name,
		Token:     token,
		UserIDs:   userIDs,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	subStore[sub.ID] = sub
	subByToken[token] = sub
	subStoreMu.Unlock()
	saveSubscriptions()

	return token, nil
}

func DerivePublicKeyB64(privKeyB64 string) string {
	return derivePublicKeyB64(privKeyB64)
}

func CLIListUsers() []*User {
	loadUsers()

	userStoreMu.RLock()
	defer userStoreMu.RUnlock()

	out := make([]*User, 0, len(userStore))
	for _, u := range userStore {
		cp := *u
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
