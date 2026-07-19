package protocol

import (
	"bytes"
	"io"
	"testing"
	"time"
)

func benchSegReader(b *testing.B, depth int, rtt time.Duration) {
	const segSize = 256 * 1024
	segData := make([]byte, segSize)
	fetch := func(idx uint64) (io.ReadCloser, error) {
		time.Sleep(rtt)
		return io.NopCloser(bytes.NewReader(segData)), nil
	}
	sr := newSegmentReaderFunc(fetch, depth)
	defer sr.Close()

	rbuf := make([]byte, 64*1024)
	b.SetBytes(segSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		read := 0
		for read < segSize {
			n, err := sr.Read(rbuf)
			if err != nil {
				b.Fatal(err)
			}
			read += n
		}
	}
}

func BenchmarkSegReader_Sequential_RTT2ms(b *testing.B) { benchSegReader(b, 1, 2*time.Millisecond) }
func BenchmarkSegReader_Pipelined_RTT2ms(b *testing.B)  { benchSegReader(b, 8, 2*time.Millisecond) }
func BenchmarkSegReader_Production_RTT2ms(b *testing.B) {
	benchSegReader(b, segPrefetchDepth(), 2*time.Millisecond)
}

func BenchmarkSegReader_Sequential_RTT20ms(b *testing.B) { benchSegReader(b, 1, 20*time.Millisecond) }
func BenchmarkSegReader_Pipelined_RTT20ms(b *testing.B)  { benchSegReader(b, 8, 20*time.Millisecond) }
