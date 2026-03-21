package vkwebrtc

import (
	"sync"
	"testing"
)

func BenchmarkFramePoolGetPut(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bp := framePool.Get().(*[]byte)
		*bp = (*bp)[:maxRTPPayload]
		framePool.Put(bp)
	}
}

func BenchmarkFramePoolGetPut_Parallel(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			bp := framePool.Get().(*[]byte)
			*bp = (*bp)[:maxRTPPayload]
			framePool.Put(bp)
		}
	})
}

func BenchmarkFramePoolVsAlloc(b *testing.B) {
	b.Run("pool", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bp := framePool.Get().(*[]byte)
			*bp = (*bp)[:maxRTPPayload]
			framePool.Put(bp)
		}
	})
	b.Run("alloc", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = make([]byte, maxRTPPayload)
		}
	})
}

func BenchmarkVP8FrameEncoding(b *testing.B) {
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i)
	}

	b.SetBytes(4096)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encodeVP8Chunks(data)
	}
}

func encodeVP8Chunks(data []byte) [][]byte {
	var chunks [][]byte
	offset := 0
	first := true

	for offset < len(data) {
		bp := framePool.Get().(*[]byte)
		var payload []byte

		if first {
			avail := maxRTPPayload - 3
			if avail > len(data)-offset {
				avail = len(data) - offset
			}
			payload = (*bp)[:3+avail]
			payload[0] = vp8Start
			payload[1] = byte(len(data) >> 8)
			payload[2] = byte(len(data))
			copy(payload[3:], data[offset:offset+avail])
			offset += avail
			first = false
		} else {
			avail := maxRTPPayload - 1
			if avail > len(data)-offset {
				avail = len(data) - offset
			}
			payload = (*bp)[:1+avail]
			payload[0] = vp8Cont
			copy(payload[1:], data[offset:offset+avail])
			offset += avail
		}

		out := make([]byte, len(payload))
		copy(out, payload)
		*bp = (*bp)[:cap(*bp)]
		framePool.Put(bp)
		chunks = append(chunks, out)
	}
	return chunks
}

func BenchmarkDataChannelWrite(b *testing.B) {
	ch := make(chan []byte, 1024)
	data := make([]byte, 1400)
	stop := make(chan struct{})

	go func() {
		for {
			select {
			case <-ch:
			case <-stop:
				return
			}
		}
	}()

	b.SetBytes(1400)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt := make([]byte, len(data))
		copy(pkt, data)
		ch <- pkt
	}
	b.StopTimer()
	close(stop)
}

func BenchmarkDataChannelWrite_Pool(b *testing.B) {
	pool := sync.Pool{
		New: func() interface{} {
			b := make([]byte, 0, 1500)
			return &b
		},
	}
	ch := make(chan *[]byte, 1024)
	data := make([]byte, 1400)
	stop := make(chan struct{})

	go func() {
		for {
			select {
			case bp := <-ch:
				*bp = (*bp)[:cap(*bp)]
				pool.Put(bp)
			case <-stop:
				return
			}
		}
	}()

	b.SetBytes(1400)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bp := pool.Get().(*[]byte)
		*bp = (*bp)[:1400]
		copy(*bp, data)
		ch <- bp
	}
	b.StopTimer()
	close(stop)
}
