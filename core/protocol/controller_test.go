package protocol

import "testing"

// The hold/switch tests want deterministic behavior; exploration is checked
// separately. Pin epsilon to zero for them.
func noExplore(t *testing.T) {
	prev := exploreEpsilon
	exploreEpsilon = 0
	t.Cleanup(func() { exploreEpsilon = prev })
}

func drive(h *HandshakeStrategy, ctx string, arms, goodArm, rounds int) int {
	last := 0
	for i := 0; i < rounds; i++ {
		a := h.Select(ctx, arms)
		res := HandshakeResetFast
		if a == goodArm {
			res = HandshakeOK
		}
		h.Observe(ctx, a, res)
		h.Record(ctx, res)
		last = a
	}
	return last
}

func TestControllerConvergesToGoodArm(t *testing.T) {
	noExplore(t)
	h := NewHandshakeStrategy()
	drive(h, "sni", 3, 2, 40)
	if got := h.Select("sni", 3); got != 2 {
		t.Fatalf("controller did not converge to the working arm 2, got %d", got)
	}
}

func TestControllerHoldsHealthyArm(t *testing.T) {
	noExplore(t)
	h := NewHandshakeStrategy()
	// Arm 0 works: the controller must not wander off it.
	for i := 0; i < 20; i++ {
		a := h.Select("sni", 3)
		if a != 0 {
			t.Fatalf("switched away from the healthy arm 0 to %d", a)
		}
		h.Observe("sni", a, HandshakeOK)
		h.Record("sni", HandshakeOK)
	}
}

func TestControllerSwitchesWhenArmDegrades(t *testing.T) {
	noExplore(t)
	h := NewHandshakeStrategy()
	// Arm 0 starts good, so the controller settles on it.
	for i := 0; i < 15; i++ {
		a := h.Select("sni", 3)
		h.Observe("sni", a, HandshakeOK)
		h.Record("sni", HandshakeOK)
	}
	if got := h.Select("sni", 3); got != 0 {
		t.Fatalf("expected to be on arm 0, got %d", got)
	}
	// Now arm 0 is blocked; a different arm (2) works. The controller must leave 0.
	last := drive(h, "sni", 3, 2, 60)
	if last == 0 {
		t.Fatalf("controller stayed on the now-blocked arm 0")
	}
	if got := h.Select("sni", 3); got == 0 {
		t.Fatalf("controller did not abandon the blocked arm 0")
	}
}

func TestControllerExplores(t *testing.T) {
	prev := exploreEpsilon
	defer func() { exploreEpsilon = prev }()

	exploreEpsilon = 0
	h := NewHandshakeStrategy()
	for i := 0; i < 10; i++ { // settle firmly on arm 0
		a := h.Select("sni", 3)
		h.Observe("sni", a, HandshakeOK)
		h.Record("sni", HandshakeOK)
	}
	exploreEpsilon = 1 // force exploration: must leave the settled arm for the least-tried
	if got := h.Select("sni", 3); got == 0 {
		t.Fatalf("exploration stayed on the settled arm 0")
	}
}
