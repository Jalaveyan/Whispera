//go:build !linux

package neural

import "context"

// RunBrowserSim is a no-op on non-Linux platforms.
func RunBrowserSim(_ context.Context) {}
