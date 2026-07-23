package neural

import (
	"math"
	"math/rand"
)

// Policy is a small feed-forward network (features -> ReLU hidden -> action
// logits) that picks an action and learns online by policy gradient: actions
// that lead to good outcomes get more probable. It is intentionally tiny so it
// can run and update on the device, only on rare handshake events.
type Policy struct {
	in, hid, out int
	w1           [][]float64
	b1           []float64
	w2           [][]float64
	b2           []float64
	lr           float64
	baseline     float64
	rng          *rand.Rand
}

func NewPolicy(in, hid, out int, lr float64, seed int64) *Policy {
	rng := rand.New(rand.NewSource(seed))
	p := &Policy{
		in:  in,
		hid: hid,
		out: out,
		w1:  make([][]float64, hid),
		b1:  make([]float64, hid),
		w2:  make([][]float64, out),
		b2:  make([]float64, out),
		lr:  lr,
		rng: rng,
	}
	scale1 := math.Sqrt(2.0 / float64(in))
	for j := range p.w1 {
		p.w1[j] = make([]float64, in)
		for i := range p.w1[j] {
			p.w1[j][i] = rng.NormFloat64() * scale1
		}
	}
	scale2 := math.Sqrt(2.0 / float64(hid))
	for k := range p.w2 {
		p.w2[k] = make([]float64, hid)
		for j := range p.w2[k] {
			p.w2[k][j] = rng.NormFloat64() * scale2
		}
	}
	return p
}

func (p *Policy) forward(x []float64) (hidden, probs []float64) {
	hidden = make([]float64, p.hid)
	for j := 0; j < p.hid; j++ {
		s := p.b1[j]
		for i := 0; i < p.in; i++ {
			s += p.w1[j][i] * x[i]
		}
		if s < 0 {
			s = 0
		}
		hidden[j] = s
	}
	logits := make([]float64, p.out)
	for k := 0; k < p.out; k++ {
		s := p.b2[k]
		for j := 0; j < p.hid; j++ {
			s += p.w2[k][j] * hidden[j]
		}
		logits[k] = s
	}
	return hidden, softmax(logits)
}

func softmax(logits []float64) []float64 {
	max := logits[0]
	for _, v := range logits {
		if v > max {
			max = v
		}
	}
	sum := 0.0
	out := make([]float64, len(logits))
	for i, v := range logits {
		out[i] = math.Exp(v - max)
		sum += out[i]
	}
	for i := range out {
		out[i] /= sum
	}
	return out
}

func (p *Policy) Probs(x []float64) []float64 {
	_, probs := p.forward(x)
	return probs
}

func (p *Policy) Sample(x []float64) (action int, probs []float64) {
	probs = p.Probs(x)
	r := p.rng.Float64()
	cum := 0.0
	for i, pr := range probs {
		cum += pr
		if r <= cum {
			return i, probs
		}
	}
	return len(probs) - 1, probs
}

func (p *Policy) Update(x []float64, action int, reward float64) {
	hidden, probs := p.forward(x)
	p.baseline += 0.05 * (reward - p.baseline)
	adv := reward - p.baseline

	dLogit := make([]float64, p.out)
	for k := 0; k < p.out; k++ {
		ind := 0.0
		if k == action {
			ind = 1.0
		}
		dLogit[k] = adv * (ind - probs[k])
	}

	dHidden := make([]float64, p.hid)
	for j := 0; j < p.hid; j++ {
		if hidden[j] <= 0 {
			continue
		}
		g := 0.0
		for k := 0; k < p.out; k++ {
			g += dLogit[k] * p.w2[k][j]
		}
		dHidden[j] = g
	}

	for k := 0; k < p.out; k++ {
		p.b2[k] += p.lr * dLogit[k]
		for j := 0; j < p.hid; j++ {
			p.w2[k][j] += p.lr * dLogit[k] * hidden[j]
		}
	}
	for j := 0; j < p.hid; j++ {
		if dHidden[j] == 0 {
			continue
		}
		p.b1[j] += p.lr * dHidden[j]
		for i := 0; i < p.in; i++ {
			p.w1[j][i] += p.lr * dHidden[j] * x[i]
		}
	}
}
