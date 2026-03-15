package proto

import (
	"sync"
	"time"
)

var (
	expiredIDsPool = sync.Pool{
		New: func() interface{} {
			return make([]uint32, 0, 16)
		},
	}
)

type ReassemblerMetrics struct {
	FragmentsInserted     int64
	PacketsReassembled    int64
	FragmentsExpired      int64
	FragmentsDropped      int64
	CapacityEvictions     int64
	CurrentBuffers        int
	TotalBytesReassembled int64
}

type Reassembler struct {
	mu       sync.Mutex
	byID     map[uint32]*fragBuf
	ttl      time.Duration
	capacity int
	metrics  ReassemblerMetrics
}

type fragBuf struct {
	created time.Time
	cnt     int
	chunks  [][]byte
	have    int
}

func NewReassembler(ttl time.Duration, capacity int) *Reassembler {
	return &Reassembler{
		byID:     make(map[uint32]*fragBuf),
		ttl:      ttl,
		capacity: capacity,
		metrics:  ReassemblerMetrics{},
	}
}

func (r *Reassembler) GetMetrics() ReassemblerMetrics {
	r.mu.Lock()
	defer r.mu.Unlock()

	m := r.metrics
	m.CurrentBuffers = len(r.byID)
	return m
}

func (r *Reassembler) Insert(id uint32, idx int, cnt int, chunk []byte, now time.Time) (bool, []byte, []uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()

	expired := r.evictLocked(now)
	r.metrics.FragmentsExpired += int64(len(expired))

	r.metrics.FragmentsInserted++

	fb := r.byID[id]
	if fb == nil {
		if cnt <= 0 || idx < 0 || idx >= cnt {
			r.metrics.FragmentsDropped++
			return false, nil, expired
		}
		if r.capacity > 0 && len(r.byID) >= r.capacity {
			toEvict := (r.capacity / 10)
			if toEvict < 1 {
				toEvict = 1
			}

			type entry struct {
				id   uint32
				time time.Time
			}
			entries := make([]entry, 0, len(r.byID))
			for k, v := range r.byID {
				entries = append(entries, entry{id: k, time: v.created})
			}

			for i := 0; i < toEvict && len(entries) > 0; i++ {
				oldestIdx := 0
				for j := 1; j < len(entries); j++ {
					if entries[j].time.Before(entries[oldestIdx].time) {
						oldestIdx = j
					}
				}
				oldestID := entries[oldestIdx].id
				delete(r.byID, oldestID)
				if expired == nil {
					expired = make([]uint32, 0, toEvict)
				}
				expired = append(expired, oldestID)
				r.metrics.CapacityEvictions++

				entries = append(entries[:oldestIdx], entries[oldestIdx+1:]...)
			}
		}
		fb = &fragBuf{created: now, cnt: cnt, chunks: make([][]byte, cnt)}
		r.byID[id] = fb
	} else if fb.cnt != cnt || idx < 0 || idx >= fb.cnt {
		r.metrics.FragmentsDropped++
		return false, nil, expired
	}

	if fb.chunks[idx] == nil {
		fb.chunks[idx] = chunk
		fb.have++
	}
	if fb.have < fb.cnt {
		return false, nil, expired
	}
	total := 0
	for i := 0; i < fb.cnt; i++ {
		total += len(fb.chunks[i])
	}

	result := make([]byte, total)
	pos := 0
	for i := 0; i < fb.cnt; i++ {
		pos += copy(result[pos:], fb.chunks[i])
	}

	delete(r.byID, id)

	r.metrics.PacketsReassembled++
	r.metrics.TotalBytesReassembled += int64(total)

	return true, result, expired
}

func (r *Reassembler) evictLocked(now time.Time) []uint32 {
	if r.ttl <= 0 {
		return nil
	}
	expired := expiredIDsPool.Get().([]uint32)
	expired = expired[:0]

	for id, fb := range r.byID {
		if now.Sub(fb.created) > r.ttl {
			delete(r.byID, id)
			if len(expired) < cap(expired) {
				expired = expired[:len(expired)+1]
				expired[len(expired)-1] = id
			} else {
				expired = append(expired, id)
			}
		}
	}

	if len(expired) == 0 {
		expiredIDsPool.Put(expired[:0])
		return nil
	}

	result := expired
	return result
}
