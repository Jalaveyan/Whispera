//go:build linux

package neural

import "testing"

func TestGANTrainSkipsExcludedFlow(t *testing.T) {
	g := NewTrafficGAN()

	_, _, before, _, _ := g.Diagnostics()
	g.Train(LabeledFlow{Label: FlowExcluded, Features: FlowFeatures{IATMean: 0.01, SizeMean: 1200}})
	_, _, afterExcluded, _, _ := g.Diagnostics()
	if afterExcluded != before {
		t.Fatalf("excluded flow must not train the GAN: trainCount %d -> %d", before, afterExcluded)
	}

	g.Train(LabeledFlow{Label: FlowTunnel, Features: FlowFeatures{IATMean: 0.01, SizeMean: 1200}})
	_, _, afterTunnel, _, _ := g.Diagnostics()
	if afterTunnel == before {
		t.Fatal("tunnel flow should train the GAN (trainCount unchanged)")
	}
}
