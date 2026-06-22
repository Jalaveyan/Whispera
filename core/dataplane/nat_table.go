package dataplane

import (
	"net"
	"sync/atomic"
	"time"
	"whispera/common/runtime/interfaces"
	"whispera/common/util"
)

type natEntry struct {
	SrcAddr      net.Addr
	DstAddr      net.Addr
	SessionID    uint32
	StreamID     uint16
	Destination  *interfaces.Destination
	CreatedAt    time.Time
	LastUsed     time.Time
	lastUsedNano int64
}

func (p *Processor) AddNATEntry(key string, srcAddr, dstAddr net.Addr, sessionID uint32, streamID uint16, dest *interfaces.Destination) {
	p.natTableMu.Lock()
	defer p.natTableMu.Unlock()

	now := time.Now()
	p.natTable[key] = &natEntry{
		SrcAddr:      srcAddr,
		DstAddr:      dstAddr,
		SessionID:    sessionID,
		StreamID:     streamID,
		Destination:  dest,
		CreatedAt:    now,
		LastUsed:     now,
		lastUsedNano: now.UnixNano(),
	}

	atomic.StoreUint64(&p.natEntries, uint64(len(p.natTable)))
}

func (p *Processor) LookupNATEntry(key string) (*natEntry, bool) {
	p.natTableMu.RLock()
	defer p.natTableMu.RUnlock()

	entry, ok := p.natTable[key]
	if ok {
		atomic.StoreInt64(&entry.lastUsedNano, util.GetGlobalTimeCache().NowNano())
	}
	return entry, ok
}

func (p *Processor) natCleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for p.IsRunning() {
		select {
		case <-p.Context().Done():
			return
		case <-ticker.C:
			p.cleanupNAT()
		}
	}
}

func (p *Processor) cleanupNAT() {
	p.natTableMu.Lock()
	defer p.natTableMu.Unlock()

	cutoff := time.Now().Add(-5 * time.Minute).UnixNano()
	for key, entry := range p.natTable {
		if atomic.LoadInt64(&entry.lastUsedNano) < cutoff {
			delete(p.natTable, key)
		}
	}

	atomic.StoreUint64(&p.natEntries, uint64(len(p.natTable)))
}
