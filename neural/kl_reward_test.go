package neural

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestFlowObserver_ConcurrentRecordPacket(t *testing.T) {
	f := &FlowObserver{}

	const (
		writers = 16
		perW    = 10000
	)
	var wg sync.WaitGroup
	wg.Add(writers)
	for i := 0; i < writers; i++ {
		i := i
		go func() {
			defer wg.Done()
			for j := 0; j < perW; j++ {
				f.RecordPacket(64 + (i*97+j)%2000)
			}
		}()
	}

	// Concurrent readers — they race against writers and the periodic reset.
	stop := make(chan struct{})
	var readerWG sync.WaitGroup
	for i := 0; i < 4; i++ {
		readerWG.Add(1)
		go func() {
			defer readerWG.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = f.KLReward()
				}
			}
		}()
	}

	wg.Wait()
	close(stop)
	readerWG.Wait()

	// Total should be exactly writers*perW; resets don't touch f.total.
	if got := atomic.LoadInt64(&f.total); got != int64(writers*perW) {
		t.Fatalf("total = %d, want %d", got, writers*perW)
	}
}

func TestFlowObserver_KLRewardAfterReset(t *testing.T) {
	f := &FlowObserver{}
	for i := 0; i < klDecayPerReset+klMinSamples+10; i++ {
		f.RecordPacket(1300)
	}
	r := f.KLReward()
	if r < 0 || r > klMaxReward {
		t.Fatalf("KLReward out of [0, %.2f]: %f", klMaxReward, r)
	}
}
