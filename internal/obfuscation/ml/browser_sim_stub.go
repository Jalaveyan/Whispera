//go:build !linux

package ml

import "context"

// RunBrowserSim is a no-op on non-Linux platforms.
func RunBrowserSim(_ context.Context) {}
