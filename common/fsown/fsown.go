package fsown

import (
	"errors"
	"os"
)

// WriteFile replaces path with data atomically: it writes a sibling temp file,
// gives it the owner the directory implies, and renames it over the target.
// A crash or a full disk leaves the old file intact rather than a truncated one,
// and the rename also succeeds when the existing file belongs to another user —
// only the directory needs to be writable.
func WriteFile(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"

	err := os.WriteFile(tmp, data, mode)
	if errors.Is(err, os.ErrPermission) {
		if rmErr := os.Remove(tmp); rmErr == nil {
			err = os.WriteFile(tmp, data, mode)
		}
	}
	if err != nil {
		return err
	}

	if err := MatchParent(tmp); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
