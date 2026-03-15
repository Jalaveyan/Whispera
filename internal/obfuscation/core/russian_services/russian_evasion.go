package russian_services

import (
	crand "crypto/rand"
	"encoding/binary"
	"math"
	"math/big"
	"sync"
	"time"
)

var (
	russianRandBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 8)
		},
	}

	russianSmallPaddingPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 256)
		},
	}

	russianMediumPaddingPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 1024)
		},
	}

	russianLargePaddingPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 4096)
		},
	}

	russianEntropyMapPool = sync.Pool{
		New: func() interface{} {
			return make(map[byte]int, 256)
		},
	}
)

func secureRandFloat64() float64 {
	b := russianRandBufferPool.Get().([]byte)
	defer russianRandBufferPool.Put(b)

	if _, err := crand.Read(b); err != nil {
		return 0.0
	}
	val := binary.BigEndian.Uint64(b)
	return float64(val) / float64(^uint64(0))
}

func secureRandInt(maxVal int) int {
	if maxVal <= 0 {
		return 0
	}
	n, err := crand.Int(crand.Reader, big.NewInt(int64(maxVal)))
	if err != nil {
		return 0
	}
	return int(n.Int64())
}

type RussianServiceEvasion struct {
	vkProfile     *VKontakteProfile
	yandexProfile *YandexProfile
	mailruProfile *MailruProfile
	rutubeProfile *RutubeProfile
	ozonProfile   *OzonProfile
}

type VKontakteProfile struct {
	PacketSizes     []int
	TimingPatterns  []time.Duration
	BehavioralScore float64
	DeviceID        string
	UserAgent       string
}

type YandexProfile struct {
	PacketSizes     []int
	TimingPatterns  []time.Duration
	BehavioralScore float64
	DeviceID        string
	UserAgent       string
}

type MailruProfile struct {
	PacketSizes     []int
	TimingPatterns  []time.Duration
	BehavioralScore float64
	DeviceID        string
	UserAgent       string
}

type RutubeProfile struct {
	PacketSizes     []int
	TimingPatterns  []time.Duration
	BehavioralScore float64
	DeviceID        string
	UserAgent       string
}

type OzonProfile struct {
	PacketSizes     []int
	TimingPatterns  []time.Duration
	BehavioralScore float64
	DeviceID        string
	UserAgent       string
}

func NewRussianServiceEvasion() *RussianServiceEvasion {
	return &RussianServiceEvasion{
		vkProfile:     &VKontakteProfile{},
		yandexProfile: &YandexProfile{},
		mailruProfile: &MailruProfile{},
		rutubeProfile: &RutubeProfile{},
		ozonProfile:   &OzonProfile{},
	}
}

func (r *RussianServiceEvasion) ApplyVKontakteEvasion(data []byte) ([]byte, time.Duration, error) {
	targetSize := r.calculateVKPacketSize(len(data))

	timing := r.calculateVKTiming()

	modifiedData := r.applyVKBehavioralPatterns(data)

	modifiedData = r.applyVKMLEvasion(modifiedData)

	modifiedData = r.resizeToVKTarget(modifiedData, targetSize)

	return modifiedData, timing, nil
}

func (r *RussianServiceEvasion) ApplyYandexEvasion(data []byte) ([]byte, time.Duration, error) {
	targetSize := r.calculateYandexPacketSize(len(data))

	timing := r.calculateYandexTiming()

	modifiedData := r.applyYandexBehavioralPatterns(data)

	modifiedData = r.applyYandexMLEvasion(modifiedData)

	modifiedData = r.resizeToYandexTarget(modifiedData, targetSize)

	return modifiedData, timing, nil
}

func (r *RussianServiceEvasion) ApplyMailruEvasion(data []byte) ([]byte, time.Duration, error) {
	targetSize := r.calculateMailruPacketSize(len(data))

	timing := r.calculateMailruTiming()

	modifiedData := r.applyMailruBehavioralPatterns(data)

	modifiedData = r.applyMailruMLEvasion(modifiedData)

	modifiedData = r.resizeToMailruTarget(modifiedData, targetSize)

	return modifiedData, timing, nil
}

func (r *RussianServiceEvasion) ApplyRutubeEvasion(data []byte) ([]byte, time.Duration, error) {
	targetSize := r.calculateRutubePacketSize(len(data))

	timing := r.calculateRutubeTiming()

	modifiedData := r.applyRutubeBehavioralPatterns(data)

	modifiedData = r.applyRutubeMLEvasion(modifiedData)

	modifiedData = r.resizeToRutubeTarget(modifiedData, targetSize)

	return modifiedData, timing, nil
}

func (r *RussianServiceEvasion) ApplyOzonEvasion(data []byte) ([]byte, time.Duration, error) {
	targetSize := r.calculateOzonPacketSize(len(data))

	timing := r.calculateOzonTiming()

	modifiedData := r.applyOzonBehavioralPatterns(data)

	modifiedData = r.applyOzonMLEvasion(modifiedData)

	modifiedData = r.resizeToOzonTarget(modifiedData, targetSize)

	return modifiedData, timing, nil
}

func (r *RussianServiceEvasion) ApplyGenericRussianEvasion(data []byte) ([]byte, time.Duration, error) {
	targetSize := r.calculateGenericRussianPacketSize(len(data))

	timing := r.calculateGenericRussianTiming()

	modifiedData := r.applyGenericRussianBehavioralPatterns(data)

	modifiedData = r.applyGenericRussianMLEvasion(modifiedData)

	modifiedData = r.resizeToGenericRussianTarget(modifiedData, targetSize)

	return modifiedData, timing, nil
}

func (r *RussianServiceEvasion) calculateVKPacketSize(_ int) int {
	sizes := []int{64, 128, 256, 512, 1024, 1500, 2048, 4096}
	weights := []float64{0.1, 0.2, 0.3, 0.2, 0.1, 0.05, 0.03, 0.02}

	randFloat := secureRandFloat64()

	cumulative := 0.0
	for i, weight := range weights {
		cumulative += weight
		if randFloat <= cumulative {
			return sizes[i]
		}
	}

	return sizes[len(sizes)-1]
}

func (r *RussianServiceEvasion) calculateVKTiming() time.Duration {
	baseDelay := 50 + secureRandInt(100)
	variance := 0.3

	return r.generateRealisticTiming(baseDelay, variance)
}

func (r *RussianServiceEvasion) applyVKBehavioralPatterns(data []byte) []byte {
	if len(data) <= 20 {
		return data
	}

	result := make([]byte, len(data))
	copy(result, data)

	if len(result) > 20 {
		vkHeaders := []byte("X-VK-Client: mobile\r\nX-VK-Version: 7.0\r\n")
		copy(result[5:5+len(vkHeaders)], vkHeaders)
	}

	return result
}

func (r *RussianServiceEvasion) applyVKMLEvasion(data []byte) []byte {
	if len(data) <= 10 {
		return data
	}

	result := make([]byte, len(data))
	copy(result, data)

	for i := 0; i < len(result) && i < 100; i += 10 {
		result[i] = byte(secureRandInt(256))
	}

	return result
}

func (r *RussianServiceEvasion) resizeToVKTarget(data []byte, targetSize int) []byte {
	if len(data) >= targetSize {
		return data[:targetSize]
	}

	paddingSize := targetSize - len(data)
	var padding []byte
	if paddingSize <= 256 {
		padding = russianSmallPaddingPool.Get().([]byte)
		if cap(padding) < paddingSize {
			padding = make([]byte, paddingSize)
		} else {
			padding = padding[:paddingSize]
		}
		defer russianSmallPaddingPool.Put(padding[:0])
	} else if paddingSize <= 1024 {
		padding = russianMediumPaddingPool.Get().([]byte)
		if cap(padding) < paddingSize {
			padding = make([]byte, paddingSize)
		} else {
			padding = padding[:paddingSize]
		}
		defer russianMediumPaddingPool.Put(padding[:0])
	} else if paddingSize <= 4096 {
		padding = russianLargePaddingPool.Get().([]byte)
		if cap(padding) < paddingSize {
			padding = make([]byte, paddingSize)
		} else {
			padding = padding[:paddingSize]
		}
		defer russianLargePaddingPool.Put(padding[:0])
	} else {
		padding = make([]byte, paddingSize)
	}

	if _, err := crand.Read(padding); err != nil {
		return data
	}

	result := make([]byte, targetSize)
	copy(result, data)
	copy(result[len(data):], padding)

	return result
}

func (r *RussianServiceEvasion) calculateYandexPacketSize(_ int) int {
	sizes := []int{128, 256, 512, 1024, 1500, 2048, 4096, 8192}
	weights := []float64{0.05, 0.15, 0.25, 0.25, 0.15, 0.1, 0.04, 0.01}

	randFloat := secureRandFloat64()

	cumulative := 0.0
	for i, weight := range weights {
		cumulative += weight
		if randFloat <= cumulative {
			return sizes[i]
		}
	}

	return sizes[len(sizes)-1]
}

func (r *RussianServiceEvasion) calculateYandexTiming() time.Duration {
	baseDelay := 30 + secureRandInt(80)
	variance := 0.25

	return r.generateRealisticTiming(baseDelay, variance)
}

func (r *RussianServiceEvasion) applyYandexBehavioralPatterns(data []byte) []byte {
	if len(data) <= 25 {
		return data
	}

	result := make([]byte, len(data))
	copy(result, data)

	if len(result) > 25 {
		yandexHeaders := []byte("X-Yandex-Client: mobile\r\nX-Yandex-Version: 23.1\r\n")
		copy(result[8:8+len(yandexHeaders)], yandexHeaders)
	}

	return result
}

func (r *RussianServiceEvasion) applyYandexMLEvasion(data []byte) []byte {
	if len(data) <= 8 {
		return data
	}

	result := make([]byte, len(data))
	copy(result, data)

	for i := 0; i < len(result) && i < 80; i += 8 {
		result[i] = byte(secureRandInt(256))
	}

	return result
}

func (r *RussianServiceEvasion) resizeToYandexTarget(data []byte, targetSize int) []byte {
	if len(data) >= targetSize {
		return data[:targetSize]
	}

	paddingSize := targetSize - len(data)
	var padding []byte
	if paddingSize <= 256 {
		padding = russianSmallPaddingPool.Get().([]byte)
		if cap(padding) < paddingSize {
			padding = make([]byte, paddingSize)
		} else {
			padding = padding[:paddingSize]
		}
		defer russianSmallPaddingPool.Put(padding[:0])
	} else if paddingSize <= 1024 {
		padding = russianMediumPaddingPool.Get().([]byte)
		if cap(padding) < paddingSize {
			padding = make([]byte, paddingSize)
		} else {
			padding = padding[:paddingSize]
		}
		defer russianMediumPaddingPool.Put(padding[:0])
	} else if paddingSize <= 4096 {
		padding = russianLargePaddingPool.Get().([]byte)
		if cap(padding) < paddingSize {
			padding = make([]byte, paddingSize)
		} else {
			padding = padding[:paddingSize]
		}
		defer russianLargePaddingPool.Put(padding[:0])
	} else {
		padding = make([]byte, paddingSize)
	}

	if _, err := crand.Read(padding); err != nil {
		return data
	}

	result := make([]byte, targetSize)
	copy(result, data)
	copy(result[len(data):], padding)

	return result
}

func (r *RussianServiceEvasion) calculateMailruPacketSize(_ int) int {
	sizes := []int{64, 128, 256, 512, 1024, 1500, 2048}
	weights := []float64{0.15, 0.25, 0.3, 0.15, 0.1, 0.04, 0.01}

	randFloat := secureRandFloat64()

	cumulative := 0.0
	for i, weight := range weights {
		cumulative += weight
		if randFloat <= cumulative {
			return sizes[i]
		}
	}

	return sizes[len(sizes)-1]
}

func (r *RussianServiceEvasion) calculateMailruTiming() time.Duration {
	baseDelay := 40 + secureRandInt(90)
	variance := 0.35

	return r.generateRealisticTiming(baseDelay, variance)
}

func (r *RussianServiceEvasion) applyMailruBehavioralPatterns(data []byte) []byte {
	if len(data) <= 30 {
		return data
	}

	result := make([]byte, len(data))
	copy(result, data)

	if len(result) > 30 {
		mailruHeaders := []byte("X-Mailru-Client: mobile\r\nX-Mailru-Version: 6.0\r\n")
		copy(result[10:10+len(mailruHeaders)], mailruHeaders)
	}

	return result
}

func (r *RussianServiceEvasion) applyMailruMLEvasion(data []byte) []byte {
	if len(data) <= 12 {
		return data
	}

	result := make([]byte, len(data))
	copy(result, data)

	for i := 0; i < len(result) && i < 60; i += 12 {
		result[i] = byte(secureRandInt(256))
	}

	return result
}

func (r *RussianServiceEvasion) resizeToMailruTarget(data []byte, targetSize int) []byte {
	if len(data) >= targetSize {
		return data[:targetSize]
	}

	paddingSize := targetSize - len(data)
	var padding []byte
	if paddingSize <= 256 {
		padding = russianSmallPaddingPool.Get().([]byte)
		if cap(padding) < paddingSize {
			padding = make([]byte, paddingSize)
		} else {
			padding = padding[:paddingSize]
		}
		defer russianSmallPaddingPool.Put(padding[:0])
	} else if paddingSize <= 1024 {
		padding = russianMediumPaddingPool.Get().([]byte)
		if cap(padding) < paddingSize {
			padding = make([]byte, paddingSize)
		} else {
			padding = padding[:paddingSize]
		}
		defer russianMediumPaddingPool.Put(padding[:0])
	} else if paddingSize <= 4096 {
		padding = russianLargePaddingPool.Get().([]byte)
		if cap(padding) < paddingSize {
			padding = make([]byte, paddingSize)
		} else {
			padding = padding[:paddingSize]
		}
		defer russianLargePaddingPool.Put(padding[:0])
	} else {
		padding = make([]byte, paddingSize)
	}

	if _, err := crand.Read(padding); err != nil {
		return data
	}

	result := make([]byte, targetSize)
	copy(result, data)
	copy(result[len(data):], padding)

	return result
}

func (r *RussianServiceEvasion) calculateRutubePacketSize(_ int) int {
	sizes := []int{1024, 1500, 2048, 4096, 8192, 16384}
	weights := []float64{0.1, 0.2, 0.3, 0.25, 0.1, 0.05}

	randFloat := secureRandFloat64()

	cumulative := 0.0
	for i, weight := range weights {
		cumulative += weight
		if randFloat <= cumulative {
			return sizes[i]
		}
	}

	return sizes[len(sizes)-1]
}

func (r *RussianServiceEvasion) calculateRutubeTiming() time.Duration {
	baseDelay := 20 + secureRandInt(60)
	variance := 0.2

	return r.generateRealisticTiming(baseDelay, variance)
}

func (r *RussianServiceEvasion) applyRutubeBehavioralPatterns(data []byte) []byte {
	if len(data) <= 35 {
		return data
	}

	result := make([]byte, len(data))
	copy(result, data)

	if len(result) > 35 {
		rutubeHeaders := []byte("X-Rutube-Client: mobile\r\nX-Rutube-Version: 4.0\r\n")
		copy(result[12:12+len(rutubeHeaders)], rutubeHeaders)
	}

	return result
}

func (r *RussianServiceEvasion) applyRutubeMLEvasion(data []byte) []byte {
	if len(data) <= 15 {
		return data
	}

	result := make([]byte, len(data))
	copy(result, data)

	for i := 0; i < len(result) && i < 120; i += 15 {
		result[i] = byte(secureRandInt(256))
	}

	return result
}

func (r *RussianServiceEvasion) resizeToRutubeTarget(data []byte, targetSize int) []byte {
	if len(data) >= targetSize {
		return data[:targetSize]
	}

	paddingSize := targetSize - len(data)
	var padding []byte
	if paddingSize <= 256 {
		padding = russianSmallPaddingPool.Get().([]byte)
		if cap(padding) < paddingSize {
			padding = make([]byte, paddingSize)
		} else {
			padding = padding[:paddingSize]
		}
		defer russianSmallPaddingPool.Put(padding[:0])
	} else if paddingSize <= 1024 {
		padding = russianMediumPaddingPool.Get().([]byte)
		if cap(padding) < paddingSize {
			padding = make([]byte, paddingSize)
		} else {
			padding = padding[:paddingSize]
		}
		defer russianMediumPaddingPool.Put(padding[:0])
	} else if paddingSize <= 4096 {
		padding = russianLargePaddingPool.Get().([]byte)
		if cap(padding) < paddingSize {
			padding = make([]byte, paddingSize)
		} else {
			padding = padding[:paddingSize]
		}
		defer russianLargePaddingPool.Put(padding[:0])
	} else {
		padding = make([]byte, paddingSize)
	}

	if _, err := crand.Read(padding); err != nil {
		return data
	}

	result := make([]byte, targetSize)
	copy(result, data)
	copy(result[len(data):], padding)

	return result
}

func (r *RussianServiceEvasion) calculateOzonPacketSize(_ int) int {
	sizes := []int{128, 256, 512, 1024, 1500, 2048, 4096}
	weights := []float64{0.1, 0.2, 0.25, 0.25, 0.15, 0.04, 0.01}

	randFloat := secureRandFloat64()

	cumulative := 0.0
	for i, weight := range weights {
		cumulative += weight
		if randFloat <= cumulative {
			return sizes[i]
		}
	}

	return sizes[len(sizes)-1]
}

func (r *RussianServiceEvasion) calculateOzonTiming() time.Duration {
	baseDelay := 35 + secureRandInt(85)
	variance := 0.3

	return r.generateRealisticTiming(baseDelay, variance)
}

func (r *RussianServiceEvasion) applyOzonBehavioralPatterns(data []byte) []byte {
	if len(data) <= 40 {
		return data
	}

	result := make([]byte, len(data))
	copy(result, data)

	if len(result) > 40 {
		ozonHeaders := []byte("X-Ozon-Client: mobile\r\nX-Ozon-Version: 3.0\r\n")
		copy(result[15:15+len(ozonHeaders)], ozonHeaders)
	}

	return result
}

func (r *RussianServiceEvasion) applyOzonMLEvasion(data []byte) []byte {
	if len(data) <= 20 {
		return data
	}

	result := make([]byte, len(data))
	copy(result, data)

	for i := 0; i < len(result) && i < 100; i += 20 {
		result[i] = byte(secureRandInt(256))
	}

	return result
}

func (r *RussianServiceEvasion) resizeToOzonTarget(data []byte, targetSize int) []byte {
	if len(data) >= targetSize {
		return data[:targetSize]
	}

	paddingSize := targetSize - len(data)
	var padding []byte
	if paddingSize <= 256 {
		padding = russianSmallPaddingPool.Get().([]byte)
		if cap(padding) < paddingSize {
			padding = make([]byte, paddingSize)
		} else {
			padding = padding[:paddingSize]
		}
		defer russianSmallPaddingPool.Put(padding[:0])
	} else if paddingSize <= 1024 {
		padding = russianMediumPaddingPool.Get().([]byte)
		if cap(padding) < paddingSize {
			padding = make([]byte, paddingSize)
		} else {
			padding = padding[:paddingSize]
		}
		defer russianMediumPaddingPool.Put(padding[:0])
	} else if paddingSize <= 4096 {
		padding = russianLargePaddingPool.Get().([]byte)
		if cap(padding) < paddingSize {
			padding = make([]byte, paddingSize)
		} else {
			padding = padding[:paddingSize]
		}
		defer russianLargePaddingPool.Put(padding[:0])
	} else {
		padding = make([]byte, paddingSize)
	}

	if _, err := crand.Read(padding); err != nil {
		return data
	}

	result := make([]byte, targetSize)
	copy(result, data)
	copy(result[len(data):], padding)

	return result
}

func (r *RussianServiceEvasion) calculateGenericRussianPacketSize(_ int) int {
	sizes := []int{64, 128, 256, 512, 1024, 1500, 2048, 4096}
	weights := []float64{0.12, 0.18, 0.25, 0.2, 0.15, 0.07, 0.02, 0.01}

	randFloat := secureRandFloat64()

	cumulative := 0.0
	for i, weight := range weights {
		cumulative += weight
		if randFloat <= cumulative {
			return sizes[i]
		}
	}

	return sizes[len(sizes)-1]
}

func (r *RussianServiceEvasion) calculateGenericRussianTiming() time.Duration {
	baseDelay := 45 + secureRandInt(95)
	variance := 0.4

	return r.generateRealisticTiming(baseDelay, variance)
}

func (r *RussianServiceEvasion) applyGenericRussianBehavioralPatterns(data []byte) []byte {
	if len(data) <= 45 {
		return data
	}

	result := make([]byte, len(data))
	copy(result, data)

	if len(result) > 45 {
		genericHeaders := []byte("X-Russian-Service: mobile\r\nX-Client-Version: 1.0\r\n")
		copy(result[20:20+len(genericHeaders)], genericHeaders)
	}

	return result
}

func (r *RussianServiceEvasion) applyGenericRussianMLEvasion(data []byte) []byte {
	if len(data) <= 25 {
		return data
	}

	result := make([]byte, len(data))
	copy(result, data)

	for i := 0; i < len(result) && i < 150; i += 25 {
		result[i] = byte(secureRandInt(256))
	}

	return result
}

func (r *RussianServiceEvasion) resizeToGenericRussianTarget(data []byte, targetSize int) []byte {
	if len(data) >= targetSize {
		return data[:targetSize]
	}

	paddingSize := targetSize - len(data)
	var padding []byte
	if paddingSize <= 256 {
		padding = russianSmallPaddingPool.Get().([]byte)
		if cap(padding) < paddingSize {
			padding = make([]byte, paddingSize)
		} else {
			padding = padding[:paddingSize]
		}
		defer russianSmallPaddingPool.Put(padding[:0])
	} else if paddingSize <= 1024 {
		padding = russianMediumPaddingPool.Get().([]byte)
		if cap(padding) < paddingSize {
			padding = make([]byte, paddingSize)
		} else {
			padding = padding[:paddingSize]
		}
		defer russianMediumPaddingPool.Put(padding[:0])
	} else if paddingSize <= 4096 {
		padding = russianLargePaddingPool.Get().([]byte)
		if cap(padding) < paddingSize {
			padding = make([]byte, paddingSize)
		} else {
			padding = padding[:paddingSize]
		}
		defer russianLargePaddingPool.Put(padding[:0])
	} else {
		padding = make([]byte, paddingSize)
	}

	if _, err := crand.Read(padding); err != nil {
		return data
	}

	result := make([]byte, targetSize)
	copy(result, data)
	copy(result[len(data):], padding)

	return result
}

func (r *RussianServiceEvasion) generateRealisticTiming(baseDelay int, variance float64) time.Duration {
	thinkTime := r.generateHumanThinkTime()

	jitter := r.generateNetworkJitter()

	delay := float64(baseDelay) * (1.0 + thinkTime + jitter) * (1.0 + variance*(secureRandFloat64()-0.5))

	return time.Duration(delay) * time.Millisecond
}

func (r *RussianServiceEvasion) generateHumanThinkTime() float64 {
	return 0.1 + secureRandFloat64()*0.4
}

func (r *RussianServiceEvasion) generateNetworkJitter() float64 {
	return (secureRandFloat64() - 0.5) * 0.2
}

func (r *RussianServiceEvasion) GenerateScientificDeviceID() string {
	deviceID := "sci_device_"
	deviceID += string(rune(65 + secureRandInt(26)))
	deviceID += string(rune(48 + secureRandInt(10)))
	deviceID += string(rune(48 + secureRandInt(10)))
	deviceID += "_"
	deviceID += string(rune(48 + secureRandInt(10)))
	deviceID += string(rune(48 + secureRandInt(10)))
	deviceID += string(rune(48 + secureRandInt(10)))

	return deviceID
}

func (r *RussianServiceEvasion) CalculateScientificBehavioralScore(data []byte) float64 {
	entropy := r.calculateEntropy(data)
	size := len(data)

	score := entropy*0.4 + float64(size%100)/100.0*0.6

	return score
}

func (r *RussianServiceEvasion) calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	freq := russianEntropyMapPool.Get().(map[byte]int)
	for k := range freq {
		delete(freq, k)
	}
	defer russianEntropyMapPool.Put(freq)

	for _, b := range data {
		freq[b]++
	}

	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / float64(len(data))
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}
