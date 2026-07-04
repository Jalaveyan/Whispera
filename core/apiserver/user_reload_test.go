package apiserver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUserStoreReloadReplaces(t *testing.T) {
	dir := t.TempDir()
	old := userDataFile
	userDataFile = filepath.Join(dir, "users.json")
	t.Cleanup(func() {
		userDataFile = old
		userStoreMu.Lock()
		userStore = make(map[int]*User)
		usersFileModTime = time.Time{}
		userStoreMu.Unlock()
	})

	write := func(users []*User) {
		data, err := json.Marshal(userPersist{Users: users, NextUserID: 9})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(userDataFile, data, 0600); err != nil {
			t.Fatal(err)
		}
	}

	write([]*User{
		{ID: 1, Username: "alice", PrivateKey: "AAA", Status: "active"},
		{ID: 2, Username: "bob", PrivateKey: "BBB", Status: "active"},
	})
	applyUsersFromFile()
	if got := len(GetRegisteredUsers()); got != 2 {
		t.Fatalf("after load: want 2 users, got %d", got)
	}

	write([]*User{{ID: 1, Username: "alice", PrivateKey: "AAA", Status: "active"}})
	applyUsersFromFile()
	regs := GetRegisteredUsers()
	if len(regs) != 1 || regs[0].UserID != "alice" {
		t.Fatalf("reload must drop the deleted user, got %+v", regs)
	}
}
