package relay

import "sync"

type SACKTracker struct {
	receivedRanges []PacketRange
	mutex          sync.RWMutex
	maxSeqNum      uint32
	packetCount    int
	lossCount      int
}

type PacketRange struct {
	Start uint32
	End   uint32
}

func NewSACKTracker() *SACKTracker {
	return &SACKTracker{
		receivedRanges: make([]PacketRange, 0),
		packetCount:    0,
		lossCount:      0,
	}
}

func (st *SACKTracker) RecordPacket(seqNum uint32) {
	st.mutex.Lock()
	defer st.mutex.Unlock()

	st.packetCount++

	if seqNum > st.maxSeqNum {
		for missing := st.maxSeqNum + 1; missing < seqNum; missing++ {
			st.lossCount++
		}
		st.maxSeqNum = seqNum
	}

	st.addToRanges(seqNum)
}

func (st *SACKTracker) addToRanges(seqNum uint32) {
	found := false
	for i := range st.receivedRanges {
		if seqNum >= st.receivedRanges[i].Start-1 && seqNum <= st.receivedRanges[i].End+1 {
			if seqNum < st.receivedRanges[i].Start {
				st.receivedRanges[i].Start = seqNum
			}
			if seqNum > st.receivedRanges[i].End {
				st.receivedRanges[i].End = seqNum
			}
			found = true
			break
		}
	}

	if !found {
		st.receivedRanges = append(st.receivedRanges, PacketRange{Start: seqNum, End: seqNum})
	}
}

func (st *SACKTracker) GetMissingPackets(upTo uint32) []uint32 {
	st.mutex.RLock()
	defer st.mutex.RUnlock()

	missing := make([]uint32, 0)

	lastEnd := uint32(0)
	for _, r := range st.receivedRanges {
		for seq := lastEnd + 1; seq < r.Start; seq++ {
			if seq <= upTo {
				missing = append(missing, seq)
			}
		}
		lastEnd = r.End
	}

	for seq := lastEnd + 1; seq <= upTo; seq++ {
		missing = append(missing, seq)
	}

	return missing
}

func (st *SACKTracker) GetPacketLossRate() float32 {
	st.mutex.RLock()
	defer st.mutex.RUnlock()

	if st.packetCount == 0 {
		return 0
	}

	return float32(st.lossCount) / float32(st.packetCount+st.lossCount) * 100
}
