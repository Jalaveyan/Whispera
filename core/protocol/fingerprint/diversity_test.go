package fingerprint

import (
	"crypto/sha256"
	"testing"
)

// The point of generating hellos is that the set of them we can present is not
// finite, so a blocklist of known fingerprints cannot cover it. That only holds
// if they actually differ and each one still parses as a client hello — a
// generator that repeats itself, or that emits something no browser would send,
// buys nothing and costs the handshake.
func TestGeneratedHellosAreManyAndValid(t *testing.T) {
	const n = 500
	seen := make(map[[32]byte]struct{}, n)
	for i := 0; i < n; i++ {
		raw, err := Generate(int64(i))
		if err != nil {
			t.Fatalf("generate %d: %v", i, err)
		}
		if _, err := SpecFromRaw(raw); err != nil {
			t.Fatalf("generated hello %d does not parse as one: %v", i, err)
		}
		seen[sha256.Sum256(raw)] = struct{}{}
	}
	// Distinct enough that enumerating them is not a strategy. Exact equality
	// with n is not required — two seeds may land on the same recombination —
	// but anything near a handful means the pool is not being used.
	if len(seen) < n*9/10 {
		t.Fatalf("only %d distinct fingerprints out of %d attempts", len(seen), n)
	}
}
