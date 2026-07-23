package neural

import (
	"math/rand"
	"testing"
)

// trainReward runs the policy against a reward function and returns the mean
// reward over the last quarter of the run — the honest "did it learn to do
// better" signal, robust to policy-gradient distribution drift.
func trainReward(p *Policy, steps int, seed int64, reward func(ctx, action int, rng *rand.Rand) float64) float64 {
	rng := rand.New(rand.NewSource(seed))
	tail := steps / 4
	sum := 0.0
	for i := 0; i < steps; i++ {
		ctx := rng.Intn(2)
		x := []float64{0, 0}
		x[ctx] = 1
		a, _ := p.Sample(x)
		r := reward(ctx, a, rng)
		p.Update(x, a, r)
		if i >= steps-tail {
			sum += r
		}
	}
	return sum / float64(tail)
}

func TestPolicyLearnsContextualAction(t *testing.T) {
	p := NewPolicy(2, 8, 2, 0.1, 1)
	mean := trainReward(p, 4000, 42, func(ctx, a int, _ *rand.Rand) float64 {
		if a == ctx {
			return 1.0
		}
		return -1.0
	})
	if mean < 0.5 {
		t.Errorf("mean reward %.2f in last quarter, want >0.5 — policy did not learn", mean)
	}
	for ctx := 0; ctx < 2; ctx++ {
		x := []float64{0, 0}
		x[ctx] = 1
		if probs := p.Probs(x); probs[ctx] < 0.8 {
			t.Errorf("context %d: P(correct)=%.2f, want >0.8", ctx, probs[ctx])
		}
	}
}

func TestPolicyCannotBeatNoise(t *testing.T) {
	p := NewPolicy(2, 8, 2, 0.1, 1)
	mean := trainReward(p, 4000, 7, func(_, _ int, rng *rand.Rand) float64 {
		if rng.Float64() < 0.5 {
			return 1.0
		}
		return -1.0
	})
	if mean < -0.2 || mean > 0.2 {
		t.Errorf("mean reward %.2f on random signal, want ~0 — false learning", mean)
	}
}
