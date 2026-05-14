package ml

import (
	mrand "math/rand"

	"whispera/internal/obfuscation/ml/gnet"
)

// dqnForward runs a forward pass through a GorgoniaNet and returns activations
// at every layer (including input). Used by all small DQN agents.
func dqnForward(net *gnet.GorgoniaNet, input []float64) [][]float64 {
	acts := make([][]float64, len(net.Layers)+1)
	acts[0] = input
	cur := input
	for i, ld := range net.Layers {
		out := make([]float64, ld.OutSize)
		for j := 0; j < ld.OutSize; j++ {
			sum := ld.B[j]
			for k := 0; k < ld.InSize && k < len(cur); k++ {
				sum += cur[k] * ld.W[k*ld.OutSize+j]
			}
			if i < len(net.Layers)-1 && sum < 0 {
				sum = 0 // ReLU
			}
			out[j] = sum
		}
		acts[i+1] = out
		cur = out
	}
	return acts
}

// dqnBackprop runs one SGD step (MSE loss on dOut) backwards through net.
func dqnBackprop(net *gnet.GorgoniaNet, acts [][]float64, dOut []float64, lr float64) {
	delta := dOut
	for i := len(net.Layers) - 1; i >= 0; i-- {
		ld := &net.Layers[i]
		input := acts[i]
		output := acts[i+1]
		if i < len(net.Layers)-1 {
			for j := range delta {
				if output[j] <= 0 {
					delta[j] = 0
				}
			}
		}
		var prev []float64
		if i > 0 {
			prev = make([]float64, ld.InSize)
			for k := 0; k < ld.InSize; k++ {
				for j := 0; j < ld.OutSize; j++ {
					prev[k] += ld.W[k*ld.OutSize+j] * delta[j]
				}
			}
		}
		for k := 0; k < ld.InSize && k < len(input); k++ {
			for j := 0; j < ld.OutSize; j++ {
				ld.W[k*ld.OutSize+j] -= lr * delta[j] * input[k]
			}
		}
		for j := 0; j < ld.OutSize; j++ {
			ld.B[j] -= lr * delta[j]
		}
		delta = prev
	}
}

// dqnTrainBatch performs one minibatch DQN update on q-network using target network.
func dqnTrainBatch(q, target *gnet.GorgoniaNet, batch []Experience, numActions int, gamma, lr float64) {
	for _, exp := range batch {
		if exp.Action >= numActions {
			continue
		}
		acts := dqnForward(q, exp.State)
		qvals := acts[len(acts)-1]

		var targetQ float64
		if exp.Done {
			targetQ = exp.Reward
		} else {
			nextQ := target.Forward(exp.NextState)
			maxQ := nextQ[0]
			for _, v := range nextQ[1:] {
				if v > maxQ {
					maxQ = v
				}
			}
			targetQ = exp.Reward + gamma*maxQ
		}

		dOut := make([]float64, numActions)
		dOut[exp.Action] = -(targetQ - qvals[exp.Action])
		dqnBackprop(q, acts, dOut, lr)
	}
}

// dqnArgmax returns the action index with the highest Q-value.
func dqnArgmax(q *gnet.GorgoniaNet, state []float64, n int) int {
	qvals := q.Forward(state)
	best := 0
	for i := 1; i < n; i++ {
		if i < len(qvals) && qvals[i] > qvals[best] {
			best = i
		}
	}
	return best
}

// sampleBatch draws a random minibatch from the replay buffer.
// Returns (batch, ok); ok=false if buffer is too small.
func sampleBatch(buffer []Experience, bufIdx int, bufFull bool, batchSize int) ([]Experience, bool) {
	size := bufIdx
	if bufFull {
		size = len(buffer)
	}
	if size < batchSize*2 {
		return nil, false
	}
	batch := make([]Experience, batchSize)
	for i := range batch {
		batch[i] = buffer[mrand.Intn(size)]
	}
	return batch, true
}
