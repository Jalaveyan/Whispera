//go:build !unix

package fsown

func MatchParent(path string) error { return nil }

func MatchParentTree(dir string) error { return nil }

func InheritGroup(dir string) error { return nil }
