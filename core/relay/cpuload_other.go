//go:build !unix

package relay

import "time"

// Elsewhere the kernel path is nominal anyway — ReadFrom falls back to an
// ordinary copy — so there is nothing to decide.
func processCPU() time.Duration { return 0 }
