package quic

import (
	"encoding/binary"
	"math/rand"
	"testing"
)

func wellFormedInitial() []byte {
	p := []byte{0xC0, 0, 0, 0, 1}
	p = append(p, 8)
	p = append(p, make([]byte, 8)...)
	p = append(p, 0)
	p = quicVarintAppend(p, 0)
	p = quicVarintAppend(p, 64)
	p = append(p, make([]byte, 64)...)
	return p
}

func TestParseInitialSurvivesMalformed(t *testing.T) {
	base := wellFormedInitial()
	rng := rand.New(rand.NewSource(1))

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("парсер паникует на битом пакете: %v", r)
		}
	}()

	for i := 0; i < 20000; i++ {
		p := append([]byte(nil), base...)
		switch rng.Intn(4) {
		case 0:
			p = p[:rng.Intn(len(p)+1)]
		case 1:
			if len(p) > 0 {
				p[rng.Intn(len(p))] = byte(rng.Intn(256))
			}
		case 2:
			for j := 0; j < 4 && len(p) > 0; j++ {
				p[rng.Intn(len(p))] = byte(rng.Intn(256))
			}
		case 3:
			p = make([]byte, rng.Intn(80))
			rng.Read(p)
			if len(p) > 0 {
				p[0] = 0xC0
			}
		}
		_, _ = parseQUICInitialClientHello(p)
		_, _ = parseQUICInitialHeader(p)
	}
}

func TestParseInitialRejectsHugeLengths(t *testing.T) {
	for _, huge := range []uint64{1 << 20, 1 << 31, 1 << 40, (1 << 62) - 1} {
		p := []byte{0xC0, 0, 0, 0, 1}
		p = append(p, 8)
		p = append(p, make([]byte, 8)...)
		p = append(p, 0)
		p = quicVarintAppend(p, huge)
		p = append(p, make([]byte, 16)...)

		if _, err := parseQUICInitialHeader(p); err == nil {
			t.Fatalf("длина токена %d принята, а пакет столько не несёт", huge)
		}
	}
}

func TestVarintParseBounds(t *testing.T) {
	if _, _, err := quicVarintParse(nil); err == nil {
		t.Fatal("пустой ввод должен отвергаться")
	}
	full := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	v, n, err := quicVarintParse(full)
	if err != nil || n != 8 {
		t.Fatalf("восьмибайтовый varint: n=%d err=%v", n, err)
	}
	if v != (1<<62)-1 {
		t.Fatalf("максимум varint разобран как %d", v)
	}
	if _, _, err := quicVarintParse(full[:4]); err == nil {
		t.Fatal("обрезанный varint должен отвергаться")
	}
}

func TestHeaderRejectsTruncatedIDs(t *testing.T) {
	p := []byte{0xC0, 0, 0, 0, 1, 200}
	p = append(p, make([]byte, 4)...)
	if _, err := parseQUICInitialHeader(p); err == nil {
		t.Fatal("dcid длиннее пакета должен отвергаться")
	}

	q := []byte{0xC0, 0, 0, 0, 1, 0, 200}
	q = append(q, make([]byte, 4)...)
	if _, err := parseQUICInitialHeader(q); err == nil {
		t.Fatal("scid длиннее пакета должен отвергаться")
	}
}

func TestExtractCryptoFrameBounds(t *testing.T) {
	cases := [][]byte{
		nil,
		{0x06},
		{0x06, 0x00},
		{0x06, 0x00, 0x41},
		append([]byte{0x06, 0x00, 0x44, 0x00}, make([]byte, 3)...),
	}
	for i, c := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("случай %d: паника %v", i, r)
				}
			}()
			_, _ = extractCryptoFrameData(c)
		}()
	}
}

func TestBuildProbeStaysParseable(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	pkt, err := BuildCamoProbe(key, "www.example.com")
	if err != nil {
		t.Fatalf("BuildCamoProbe: %v", err)
	}
	if binary.BigEndian.Uint32(pkt[1:5]) != 1 {
		t.Fatal("версия QUIC в собранном пакете не 1")
	}
	if _, err := parseQUICInitialHeader(pkt); err != nil {
		t.Fatalf("собственный пакет не разбирается: %v", err)
	}
}
