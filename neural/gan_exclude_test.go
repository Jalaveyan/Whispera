//go:build linux

package neural

import "testing"

func TestGANTrainSkipsExcludedFlow(t *testing.T) {
	g := NewTrafficGAN()

	before := g.trainCount
	g.Train(LabeledFlow{Label: FlowExcluded, Features: FlowFeatures{IATMean: 0.01, SizeMean: 1200}})
	if g.trainCount != before {
		t.Fatalf("excluded flow must not train the GAN: trainCount %d -> %d", before, g.trainCount)
	}

	g.Train(LabeledFlow{Label: FlowTunnel, Features: FlowFeatures{IATMean: 0.01, SizeMean: 1200}})
	if g.trainCount == before {
		t.Fatal("tunnel flow should train the GAN (trainCount unchanged)")
	}
}
