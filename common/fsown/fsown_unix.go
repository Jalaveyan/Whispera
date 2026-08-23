//go:build unix

package fsown

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type owner struct {
	uid int
	gid int
}

func ownerOf(path string) (owner, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return owner{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return owner{}, fmt.Errorf("no ownership information for %s", path)
	}
	return owner{uid: int(st.Uid), gid: int(st.Gid)}, nil
}

func MatchParent(path string) error {
	want, err := ownerOf(filepath.Dir(path))
	if err != nil {
		return err
	}
	got, err := ownerOf(path)
	if err != nil {
		return err
	}
	if got == want {
		return nil
	}
	if err := os.Chown(path, want.uid, want.gid); err != nil {
		return fmt.Errorf("chown %s from %d:%d to %d:%d: %w", path, got.uid, got.gid, want.uid, want.gid, err)
	}
	return nil
}

func InheritGroup(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSetgid != 0 {
		return nil
	}
	if err := os.Chmod(dir, fi.Mode().Perm()|os.ModeSetgid); err != nil {
		return fmt.Errorf("set setgid on %s: %w", dir, err)
	}
	return nil
}

func MatchParentTree(dir string) error {
	if err := MatchParent(dir); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		if e.IsDir() {
			if err := MatchParentTree(path); err != nil {
				return err
			}
			continue
		}
		if err := MatchParent(path); err != nil {
			return err
		}
	}
	return nil
}
