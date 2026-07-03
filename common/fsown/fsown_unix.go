//go:build unix

package fsown

import (
	"os"
	"path/filepath"
	"syscall"
)

func MatchParent(path string) {
	fi, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	_ = os.Chown(path, int(st.Uid), int(st.Gid))
}
