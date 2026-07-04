package apiserver

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
	"time"
	"whispera/common/fsown"

	"golang.org/x/crypto/curve25519"
)

type User struct {
	ID            int       `json:"id"`
	Username      string    `json:"username"`
	PrivateKey    string    `json:"privateKey,omitempty"`
	PublicKey     string    `json:"publicKey,omitempty"`
	ConnectionURI string    `json:"connectionURI,omitempty"`
	Upload        int64     `json:"upload"`
	Download      int64     `json:"download"`
	TrafficLimit  int64     `json:"trafficLimit"`
	ExpiryDate    string    `json:"expiryDate,omitempty"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"createdAt"`

	ObfsProfile       string `json:"obfsProfile,omitempty"`
	MarionetteProfile string `json:"marionetteProfile,omitempty"`
	RussianService    string `json:"russianService,omitempty"`

	InboundTags []string `json:"inboundTags,omitempty"`

	DisableNeural bool `json:"disableNeural,omitempty"`
}

var userDataFile = "/etc/whispera/users.json"

const userStoreReloadInterval = 5 * time.Second

var (
	userStore        = make(map[int]*User)
	userStoreMu      sync.RWMutex
	usersFileModTime time.Time
	nextUserID       = 1
)

type userPersist struct {
	Users      []*User `json:"users"`
	NextUserID int     `json:"next_user_id"`
}

type RegisteredUser struct {
	UserID     string
	PrivateKey string
}

type KeyPair struct {
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
}

func GetRegisteredUsers() []RegisteredUser {
	userStoreMu.RLock()
	defer userStoreMu.RUnlock()
	result := make([]RegisteredUser, 0, len(userStore))
	for _, u := range userStore {
		if u.PrivateKey != "" && u.Status != "disabled" {
			result = append(result, RegisteredUser{UserID: u.Username, PrivateKey: u.PrivateKey})
		}
	}
	return result
}

func IsNeuralDisabled(userID string) bool {
	userStoreMu.RLock()
	defer userStoreMu.RUnlock()
	for _, u := range userStore {
		if u.Username == userID {
			return u.DisableNeural
		}
	}
	return false
}

func saveUsers() {
	userStoreMu.RLock()
	list := make([]*User, 0, len(userStore))
	for _, u := range userStore {
		list = append(list, u)
	}
	nid := nextUserID
	userStoreMu.RUnlock()

	data, err := json.Marshal(userPersist{Users: list, NextUserID: nid})
	if err != nil {
		log.Error("failed to marshal users: %v", err)
		return
	}
	if err := os.WriteFile(userDataFile, data, 0600); err != nil {
		log.Error("failed to save users: %v", err)
		return
	}
	fsown.MatchParent(userDataFile)
}

func loadUsers() {
	applyUsersFromFile()
}

func applyUsersFromFile() {
	info, statErr := os.Stat(userDataFile)
	data, err := os.ReadFile(userDataFile)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Error("cannot read %s (users will be empty, all tunnels rejected): %v", userDataFile, err)
		}
		return
	}
	var p userPersist
	if err := json.Unmarshal(data, &p); err != nil {
		log.Error("failed to load users: %v", err)
		return
	}
	fresh := make(map[int]*User, len(p.Users))
	for _, u := range p.Users {
		fresh[u.ID] = u
	}
	userStoreMu.Lock()
	userStore = fresh
	if p.NextUserID > nextUserID {
		nextUserID = p.NextUserID
	}
	if statErr == nil {
		usersFileModTime = info.ModTime()
	}
	userStoreMu.Unlock()
}

// startUserStoreWatcher reloads users.json when it changes on disk so keys
// created or deleted by the CLI take effect without restarting the service.
func startUserStoreWatcher() {
	go func() {
		t := time.NewTicker(userStoreReloadInterval)
		defer t.Stop()
		for range t.C {
			info, err := os.Stat(userDataFile)
			if err != nil {
				continue
			}
			userStoreMu.RLock()
			unchanged := info.ModTime().Equal(usersFileModTime)
			userStoreMu.RUnlock()
			if !unchanged {
				applyUsersFromFile()
			}
		}
	}()
}

func generateX25519Keys() (*KeyPair, error) {
	privateBytes := make([]byte, 32)
	if _, err := rand.Read(privateBytes); err != nil {
		return nil, err
	}
	publicBytes, err := curve25519.X25519(privateBytes, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PrivateKey: base64.StdEncoding.EncodeToString(privateBytes),
		PublicKey:  base64.StdEncoding.EncodeToString(publicBytes),
	}, nil
}

func generateKeyID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
