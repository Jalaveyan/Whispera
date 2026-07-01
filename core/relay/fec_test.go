package relay

import (
	"sync"
	"testing"
)

func TestFECEncodeDecodeRecoversLostShard(t *testing.T) {
	const k, m = 4, 2
	const headroom = 0

	enc := NewFECEncoder(k, m)
	if enc == nil {
		t.Fatal("NewFECEncoder returned nil")
	}

	dec := NewFECDecoder(k, m)

	dataShards := [][]byte{
		[]byte("shard-zero1"),
		[]byte("shard-one-x"),
		[]byte("shard-two-x"),
		[]byte("shard-three"),
	}

	for i, data := range dataShards {
		pkt := enc.EncodeFEC(data, uint32(i), headroom)
		if i == 1 {
			continue
		}
		if _, recovered := dec.DecodeFEC(pkt, uint32(i)); recovered {
			t.Fatalf("DecodeFEC unexpectedly reported recovery for packet %d", i)
		}
	}

	parity := enc.GetParityPackets(uint32(k), headroom)
	if len(parity) != m {
		t.Fatalf("expected %d parity packets, got %d", m, len(parity))
	}
	for i, pkt := range parity {
		dec.DecodeFEC(pkt, uint32(k+i))
	}

	recovered := dec.Reconstruct(0, k, m)
	if len(recovered) != 1 {
		t.Fatalf("expected to recover exactly 1 shard, got %d", len(recovered))
	}
	if string(recovered[0]) != string(dataShards[1]) {
		t.Fatalf("recovered shard mismatch: got %q, want %q", recovered[0], dataShards[1])
	}
}

func TestFECReconstructInsufficientShards(t *testing.T) {
	const k, m = 4, 2
	dec := NewFECDecoder(k, m)

	dec.packetBuffer[0] = []byte{0, 5, 'h', 'e', 'l', 'l', 'o'}

	if recovered := dec.Reconstruct(0, k, m); recovered != nil {
		t.Fatalf("expected nil when fewer than k shards are available, got %v", recovered)
	}
}

func TestDecodeFECRejectsShortPacket(t *testing.T) {
	dec := NewFECDecoder(4, 2)
	recovered, canRecover := dec.DecodeFEC([]byte{1, 2, 3}, 0)
	if recovered != nil || canRecover {
		t.Fatalf("expected (nil, false) for short packet, got (%v, %v)", recovered, canRecover)
	}
}

func TestFECDecoderConcurrentDecodeAndReconstruct(t *testing.T) {
	const k, m = 10, 4
	enc := NewFECEncoder(k, m)
	dec := NewFECDecoder(k, m)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for block := uint32(0); block < 200; block++ {
			base := block * uint32(k+m)
			for i := 0; i < k; i++ {
				pkt := enc.EncodeFEC([]byte("payload"), base+uint32(i), 0)
				dec.DecodeFEC(pkt, base+uint32(i))
			}
			for i, pkt := range enc.GetParityPackets(base+uint32(k), 0) {
				dec.DecodeFEC(pkt, base+uint32(k+i))
			}
		}
	}()

	go func() {
		defer wg.Done()
		for block := uint32(0); block < 200; block++ {
			dec.Reconstruct(block*uint32(k+m), k, m)
		}
	}()

	wg.Wait()
}
