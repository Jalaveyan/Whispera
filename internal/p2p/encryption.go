package p2p

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

type P2PEncryption struct {
	mu             sync.RWMutex
	keys           map[string]*EncryptionKey
	sessions       map[string]*EncryptionSession
	keyRotation    time.Duration
	lastRotation   time.Time
	sessionCounter int64
}

type EncryptionKey struct {
	ID        string    `json:"id"`
	Key       []byte    `json:"key"`
	Created   time.Time `json:"created"`
	Expires   time.Time `json:"expires"`
	Algorithm string    `json:"algorithm"`
	Strength  int       `json:"strength"`
}

type EncryptionSession struct {
	ID           string    `json:"id"`
	NodeID       string    `json:"node_id"`
	SendKey      []byte    `json:"send_key"`
	ReceiveKey   []byte    `json:"receive_key"`
	SendNonce    uint64    `json:"send_nonce"`
	ReceiveNonce uint64    `json:"receive_nonce"`
	Created      time.Time `json:"created"`
	LastUsed     time.Time `json:"last_used"`
	Algorithm    string    `json:"algorithm"`
}

type EncryptedMessage struct {
	SessionID string `json:"session_id"`
	Nonce     []byte `json:"nonce"`
	Data      []byte `json:"data"`
	MAC       []byte `json:"mac"`
	Timestamp int64  `json:"timestamp"`
	FromNode  string `json:"from"`
}

func NewP2PEncryption() *P2PEncryption {
	return &P2PEncryption{
		keys:         make(map[string]*EncryptionKey),
		sessions:     make(map[string]*EncryptionSession),
		keyRotation:  5 * time.Minute,
		lastRotation: time.Now(),
	}
}

func (pe *P2PEncryption) Start(ctx context.Context) {
	go pe.keyRotationLoop(ctx)

	go pe.sessionCleanupLoop(ctx)

	go pe.securityMonitoringLoop(ctx)
}

func (pe *P2PEncryption) keyRotationLoop(ctx context.Context) {
	ticker := time.NewTicker(pe.keyRotation)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pe.rotateKeys()
		}
	}
}

func (pe *P2PEncryption) sessionCleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pe.cleanupSessions()
		}
	}
}

func (pe *P2PEncryption) securityMonitoringLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pe.monitorSecurity()
		}
	}
}

func (pe *P2PEncryption) CreateSession(nodeID string) (*EncryptionSession, error) {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	sendKey := make([]byte, 32)
	receiveKey := make([]byte, 32)

	if _, err := rand.Read(sendKey); err != nil {
		return nil, fmt.Errorf("ошибка генерации send key: %v", err)
	}

	if _, err := rand.Read(receiveKey); err != nil {
		return nil, fmt.Errorf("ошибка генерации receive key: %v", err)
	}

	pe.sessionCounter++
	session := &EncryptionSession{
		ID:           fmt.Sprintf("session_%d_%d", time.Now().UnixNano(), pe.sessionCounter),
		NodeID:       nodeID,
		SendKey:      sendKey,
		ReceiveKey:   receiveKey,
		SendNonce:    0,
		ReceiveNonce: 0,
		Created:      time.Now(),
		LastUsed:     time.Now(),
		Algorithm:    "AES-256-GCM",
	}

	pe.sessions[session.ID] = session

	return session, nil
}

func (pe *P2PEncryption) CreateECDHSessionForPeers(
	myID, peerID string, sharedSecret []byte,
) (*EncryptionSession, error) {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	if len(sharedSecret) == 0 {
		return nil, fmt.Errorf("empty shared secret")
	}
	a, b := myID, peerID
	if a > b {
		a, b = b, a
	}
	sid := fmt.Sprintf("ecdh_%x", sha256.Sum256([]byte(a+":"+b)))
	if s, ok := pe.sessions[sid]; ok {
		s.LastUsed = time.Now()
		return s, nil
	}

	derive := func(info string) ([]byte, error) {
		r := hkdf.New(sha256.New, sharedSecret, nil, []byte(info))
		key := make([]byte, 32)
		if _, err := io.ReadFull(r, key); err != nil {
			return nil, err
		}
		return key, nil
	}
	var sendKey, recvKey []byte
	var err error
	if myID < peerID {
		sendKey, err = derive("send:" + a + "->" + b)
		if err != nil {
			return nil, err
		}
		recvKey, err = derive("recv:" + a + "<-" + b)
		if err != nil {
			return nil, err
		}
	} else {
		sendKey, err = derive("send:" + b + "->" + a)
		if err != nil {
			return nil, err
		}
		recvKey, err = derive("recv:" + b + "<-" + a)
		if err != nil {
			return nil, err
		}
	}

	pe.sessionCounter++
	s := &EncryptionSession{
		ID:           sid,
		NodeID:       peerID,
		SendKey:      sendKey,
		ReceiveKey:   recvKey,
		SendNonce:    0,
		ReceiveNonce: 0,
		Created:      time.Now(),
		LastUsed:     time.Now(),
		Algorithm:    "AES-256-GCM",
	}
	pe.sessions[s.ID] = s
	return s, nil
}

func (pe *P2PEncryption) EncryptMessage(sessionID string, data []byte) (*EncryptedMessage, error) {
	pe.mu.RLock()
	session, exists := pe.sessions[sessionID]
	pe.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("сессия %s не найдена", sessionID)
	}

	block, err := aes.NewCipher(session.SendKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания AES cipher: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания GCM: %v", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("ошибка генерации nonce: %v", err)
	}

	ciphertext := aesGCM.Seal(nil, nonce, data, nil)

	encryptedMsg := &EncryptedMessage{
		SessionID: sessionID,
		Nonce:     nonce,
		Data:      ciphertext,
		MAC:       ciphertext[len(ciphertext)-aesGCM.Overhead():],
		Timestamp: time.Now().Unix(),
	}

	pe.mu.Lock()
	session.SendNonce++
	session.LastUsed = time.Now()
	pe.mu.Unlock()

	return encryptedMsg, nil
}

func (pe *P2PEncryption) DecryptMessage(encryptedMsg *EncryptedMessage) ([]byte, error) {
	pe.mu.RLock()
	session, exists := pe.sessions[encryptedMsg.SessionID]
	pe.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("сессия %s не найдена", encryptedMsg.SessionID)
	}

	block, err := aes.NewCipher(session.ReceiveKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания AES cipher: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания GCM: %v", err)
	}

	plaintext, err := aesGCM.Open(nil, encryptedMsg.Nonce, encryptedMsg.Data, nil)
	if err != nil {
		return nil, fmt.Errorf("ошибка расшифровки: %v", err)
	}

	pe.mu.Lock()
	session.ReceiveNonce++
	session.LastUsed = time.Now()
	pe.mu.Unlock()

	return plaintext, nil
}

func (pe *P2PEncryption) rotateKeys() {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	newKey := &EncryptionKey{
		ID:        fmt.Sprintf("key_%d", time.Now().UnixNano()),
		Key:       make([]byte, 32),
		Created:   time.Now(),
		Expires:   time.Now().Add(pe.keyRotation),
		Algorithm: "AES-256",
		Strength:  256,
	}

	if _, err := rand.Read(newKey.Key); err != nil {
		return
	}

	pe.keys[newKey.ID] = newKey
	pe.lastRotation = time.Now()
}

func (pe *P2PEncryption) cleanupSessions() {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	now := time.Now()
	cleaned := 0

	for sessionID, session := range pe.sessions {
		if now.Sub(session.LastUsed) > 30*time.Minute {
			delete(pe.sessions, sessionID)
			cleaned++
		}
	}

	_ = cleaned
}

func (pe *P2PEncryption) monitorSecurity() {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	totalSessions := len(pe.sessions)
	totalKeys := len(pe.keys)

	activeSessions := 0
	for _, session := range pe.sessions {
		if time.Since(session.LastUsed) < 5*time.Minute {
			activeSessions++
		}
	}

	_ = totalSessions
	_ = activeSessions
	_ = totalKeys

	timeSinceRotation := time.Since(pe.lastRotation)
	_ = timeSinceRotation
}

func (pe *P2PEncryption) GetEncryptionStats() map[string]interface{} {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	return map[string]interface{}{
		"total_sessions":    len(pe.sessions),
		"total_keys":        len(pe.keys),
		"key_rotation_time": pe.keyRotation.String(),
		"last_rotation":     pe.lastRotation,
		"algorithms":        []string{"AES-256-GCM", "ChaCha20-Poly1305"},
	}
}

func (pe *P2PEncryption) CreateSharedSessionForPeers(myID, peerID string) (*EncryptionSession, error) {
	a, b := myID, peerID
	if a > b {
		a, b = b, a
	}
	sid := fmt.Sprintf("shared_%x", sha256.Sum256([]byte(a+":"+b)))
	key := sha256.Sum256([]byte("key:" + a + ":" + b))

	pe.mu.RLock()
	if s, ok := pe.sessions[sid]; ok {
		pe.mu.RUnlock()
		return s, nil
	}
	pe.mu.RUnlock()

	pe.mu.Lock()
	defer pe.mu.Unlock()
	if s, ok := pe.sessions[sid]; ok {
		return s, nil
	}
	s := &EncryptionSession{
		ID:           sid,
		NodeID:       peerID,
		SendKey:      key[:],
		ReceiveKey:   key[:],
		SendNonce:    0,
		ReceiveNonce: 0,
		Created:      time.Now(),
		LastUsed:     time.Now(),
		Algorithm:    "AES-256-GCM",
	}
	pe.sessions[sid] = s
	return s, nil
}

func (pe *P2PEncryption) GenerateSharedKey(node1ID, node2ID string) ([]byte, error) {
	combined := fmt.Sprintf("%s:%s:%d", node1ID, node2ID, time.Now().Unix())
	hash := sha256.Sum256([]byte(combined))

	return hash[:], nil
}

func (pe *P2PEncryption) ValidateSession(sessionID string) bool {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	session, exists := pe.sessions[sessionID]
	if !exists {
		return false
	}

	return time.Since(session.LastUsed) < 30*time.Minute
}

func (pe *P2PEncryption) GetSessionInfo(sessionID string) (*EncryptionSession, error) {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	session, exists := pe.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("сессия %s не найдена", sessionID)
	}

	return session, nil
}

func (pe *P2PEncryption) CloseSession(sessionID string) error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	if _, exists := pe.sessions[sessionID]; !exists {
		return fmt.Errorf("сессия %s не найдена", sessionID)
	}

	delete(pe.sessions, sessionID)

	return nil
}
