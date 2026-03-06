package marionette

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"math"
	mrand "math/rand"
	"time"

	"golang.org/x/crypto/curve25519"

	"whispera/internal/obfuscation/core/types"
)

var _ = []interface{}{
	(*Marionette).generateVKJSONPadding,
	(*Marionette).generateYandexSearchPadding,
	(*Marionette).generateMailruEmailPadding,
	(*Marionette).generateRutubeVideoPadding,
	(*Marionette).generateOzonProductPadding,
	(*Marionette).generateDefaultHTTPPadding,
	(*Marionette).shapeTiming,
	(*Marionette).learnPatterns,
}


func (m *Marionette) ApplyTrafficObfuscation(data []byte, profile *TrafficObfuscationProfile) []byte {
	if !profile.Enabled {
		return data
	}

	if profile.RealityPublicKey != "" {
		return data
	}

	m.Mutex.RLock()
	if m.RealityKey != "" {
		m.Mutex.RUnlock()
		return data
	}
	m.Mutex.RUnlock()

	switch profile.ObfuscationType {
	case "protocol":
		data = m.applyProtocolObfuscation(data, profile)
	case "application":
		data = m.applyApplicationObfuscation(data, profile)
	case "behavioral":
		data = m.applyBehavioralObfuscation(data, profile)
	}
	if profile.StatisticalMasking {
		data = m.applyStatisticalMaskingTraffic(data, profile)
	}
	if profile.EntropyAdjustment {
		data = m.applyEntropyAdjustment(data, profile)
	}
	if profile.TimingRandomization {
		data = m.applyTimingRandomization(data, profile)
	}
	if profile.SizeRandomization {
		data = m.applySizeRandomization(data, profile)
	}
	return data
}

func (m *Marionette) applyProtocolObfuscation(data []byte, profile *TrafficObfuscationProfile) []byte {
	if len(data) == 0 {
		return data
	}
	if profile.ObfuscationLevel > 5 {
		data = m.addProtocolDataPatterns(data, profile)
	}
	if profile.ObfuscationLevel > 7 {
		data = m.addProtocolTimingPatterns(data, profile)
	}
	if profile.ObfuscationLevel > 3 && profile.RealityPublicKey == "" {
		data = m.addProtocolHeaders(data, profile)
	}

	m.Mutex.RLock()
	m.Mutex.RUnlock()


	return data
}

func (m *Marionette) addProtocolHeaders(data []byte, _ *TrafficObfuscationProfile) []byte {


	length := len(data)
	header := []byte{
		0x17,
		0x03, 0x03,
		byte(length >> 8), byte(length & 0xFF),
	}

	res := make([]byte, len(header)+length)
	copy(res, header)
	copy(res[len(header):], data)
	return res
}

func (m *Marionette) addProtocolDataPatterns(data []byte, profile *TrafficObfuscationProfile) []byte {
	var pref, suff []byte
	if profile.ObfuscationLevel > 5 {
		pref, suff = []byte(`{"method":"`), []byte(`","params":{}}`)
	} else {
		pref, suff = []byte(`{"api":"`), []byte(`","data":{}}`)
	}
	res := make([]byte, len(pref)+len(data)+len(suff))
	copy(res, pref)
	copy(res[len(pref):], data)
	copy(res[len(pref)+len(data):], suff)
	return res
}

func (m *Marionette) addProtocolTimingPatterns(data []byte, profile *TrafficObfuscationProfile) []byte {
	h := []byte{0x00, 0x00}
	if profile.ObfuscationLevel > 7 {
		h = []byte{0x00, 0x00, 0x00, 0x00}
	}
	res := make([]byte, len(h)+len(data))
	copy(res, h)
	copy(res[len(h):], data)
	return res
}

func (m *Marionette) applyApplicationObfuscation(data []byte, profile *TrafficObfuscationProfile) []byte {
	if len(data) == 0 {
		return data
	}
	if profile.ObfuscationLevel > 5 {
		data = m.addApplicationSpecificDataPatterns(data, profile)
	}
	if profile.ObfuscationLevel > 7 {
		data = m.addApplicationSpecificTimingPatterns(data, profile)
	}
	if profile.ObfuscationLevel > 3 {
		data = m.addApplicationSpecificHeadersTraffic(data, profile)
	}
	return data
}

func (m *Marionette) addApplicationSpecificHeadersTraffic(data []byte, _ *TrafficObfuscationProfile) []byte {
	length := len(data)
	header := []byte{
		0x17,
		0x03, 0x03,
		byte(length >> 8), byte(length & 0xFF),
	}

	res := make([]byte, len(header)+length)
	copy(res, header)
	copy(res[len(header):], data)
	return res
}

func (m *Marionette) addApplicationSpecificDataPatterns(data []byte, profile *TrafficObfuscationProfile) []byte {
	var pref, suff []byte
	if profile.ObfuscationLevel > 7 {
		pref, suff = []byte(`{"method":"`), []byte(`","params":{}}`)
	} else {
		pref, suff = []byte(`{"api":"`), []byte(`","data":{}}`)
	}
	res := make([]byte, len(pref)+len(data)+len(suff))
	copy(res, pref)
	copy(res[len(pref):], data)
	copy(res[len(pref)+len(data):], suff)
	return res
}

func (m *Marionette) addApplicationSpecificTimingPatterns(data []byte, profile *TrafficObfuscationProfile) []byte {
	h := []byte{0x00, 0x00}
	if profile.ObfuscationLevel > 7 {
		h = []byte{0x00, 0x00, 0x00, 0x00}
	}
	res := make([]byte, len(h)+len(data))
	copy(res, h)
	copy(res[len(h):], data)
	return res
}

func (m *Marionette) applyBehavioralObfuscation(data []byte, profile *TrafficObfuscationProfile) []byte {
	if len(data) == 0 {
		return data
	}
	if profile.ObfuscationLevel > 3 {
		data = m.applyHumanLikeBehaviorTraffic(data, profile)
	}
	if profile.ObfuscationLevel > 5 {
		data = m.applySessionBasedBehaviorTraffic(data, profile)
	}
	if profile.ObfuscationLevel > 7 {
		data = m.applyDeviceSpecificBehaviorTraffic(data, profile)
	}
	return data
}

func (m *Marionette) applyHumanLikeBehaviorTraffic(data []byte, _ *TrafficObfuscationProfile) []byte {
	return data
}

func (m *Marionette) applySessionBasedBehaviorTraffic(data []byte, _ *TrafficObfuscationProfile) []byte {
	return data
}

func (m *Marionette) applyDeviceSpecificBehaviorTraffic(data []byte, _ *TrafficObfuscationProfile) []byte {
	return data
}

func (m *Marionette) applyEntropyAdjustment(data []byte, profile *TrafficObfuscationProfile) []byte {
	if len(data) == 0 {
		return data
	}
	cur := m.calculateEntropyTraffic(data)
	target := 0.7 * float64(profile.ObfuscationLevel) / 10.0
	if cur < target {
		return m.increaseEntropyTraffic(data, target)
	}
	if cur > target {
		return m.decreaseEntropyTraffic(data, target)
	}
	return data
}

func (m *Marionette) calculateEntropyTraffic(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}
	f := make(map[byte]int)
	for _, b := range data {
		f[b]++
	}
	e, dl := 0.0, float64(len(data))
	for _, c := range f {
		p := float64(c) / dl
		e -= p * math.Log2(p)
	}
	return e
}

func (m *Marionette) applyStatisticalMaskingTraffic(data []byte, profile *TrafficObfuscationProfile) []byte {
	if profile.ObfuscationLevel > 3 {
		data = m.applyStatisticalNoiseTraffic(data, profile)
	}
	if profile.ObfuscationLevel > 5 {
		data = m.applyPatternRandomizationTraffic(data, profile)
	}
	if profile.ObfuscationLevel > 7 {
		data = m.applySequenceObfuscationTraffic(data, profile)
	}
	return data
}


func (m *Marionette) decreaseEntropyTraffic(data []byte, targetEntropy float64) []byte {
	cur := m.calculateEntropyTraffic(data)
	if cur <= targetEntropy {
		return data
	}
	size := int((cur - targetEntropy) * float64(len(data)))
	if size <= 0 {
		size = 1
	}
	padding := make([]byte, size)
	p := []byte{0x00, 0x01, 0x02, 0x03}
	for i := range padding {
		padding[i] = p[i%len(p)]
	}
	res := make([]byte, len(data)+len(padding))
	copy(res, data)
	copy(res[len(data):], padding)
	return res
}

func (m *Marionette) increaseEntropyTraffic(data []byte, targetEntropy float64) []byte {
	cur := m.calculateEntropyTraffic(data)
	if cur >= targetEntropy {
		return data
	}
	size := int((targetEntropy - cur) * float64(len(data)))
	if size <= 0 {
		size = 1
	}
	padding := make([]byte, size)
	for i := range padding {
		padding[i] = byte(m.generateRandomFloat() * 256)
	}
	res := make([]byte, len(data)+len(padding))
	copy(res, data)
	copy(res[len(data):], padding)
	return res
}

func (m *Marionette) applyTimingRandomization(data []byte, profile *TrafficObfuscationProfile) []byte {
	if len(data) == 0 {
		return data
	}
	markers := m.generateTimingMarkersTraffic(len(data), profile)
	return m.insertTimingMarkersTraffic(data, markers, profile)
}

func (m *Marionette) generateTimingMarkersTraffic(dataLen int, profile *TrafficObfuscationProfile) []byte {
	cnt := dataLen / (10 - int(profile.ObfuscationLevel))
	if cnt <= 0 {
		cnt = 1
	}
	markers := make([]byte, cnt)
	for i := range markers {
		markers[i] = byte(int(m.generateRandomFloat()*1000*float64(profile.ObfuscationLevel)/10.0) % 256)
	}
	return markers
}

func (m *Marionette) insertTimingMarkersTraffic(data, markers []byte, profile *TrafficObfuscationProfile) []byte {
	if len(markers) == 0 {
		return data
	}
	step := len(data) / len(markers) * int(profile.ObfuscationLevel) / 10
	res := make([]byte, 0, len(data)+len(markers))
	mIdx := 0
	for i, b := range data {
		if mIdx < len(markers) && i == mIdx*step {
			res = append(res, markers[mIdx])
			mIdx++
		}
		res = append(res, b)
	}
	return res
}

func (m *Marionette) applySizeRandomization(data []byte, profile *TrafficObfuscationProfile) []byte {
	if len(data) == 0 {
		return data
	}
	target := m.calculateRandomizedSizeTraffic(len(data), profile)
	if len(data) < target {
		return m.padToTargetSizeTraffic(data, target, profile)
	}
	if len(data) > target {
		return data[:target]
	}
	return data
}

func (m *Marionette) calculateRandomizedSizeTraffic(originalSize int, profile *TrafficObfuscationProfile) int {
	variation := int(m.generateRandomFloat() * 0.2 * float64(profile.ObfuscationLevel) / 10.0 * float64(originalSize))
	target := originalSize + variation
	if target < 1 {
		target = 1
	}
	if target > originalSize*2 {
		target = originalSize * 2
	}
	return target
}

func (m *Marionette) padToTargetSizeTraffic(data []byte, targetSize int, profile *TrafficObfuscationProfile) []byte {
	if len(data) >= targetSize {
		return data
	}
	padding := make([]byte, targetSize-len(data))
	for i := range padding {
		padding[i] = byte(m.generateRandomFloat() * 256 * float64(profile.ObfuscationLevel) / 10.0)
	}
	res := make([]byte, len(data)+len(padding))
	copy(res, data)
	copy(res[len(data):], padding)
	return res
}

func (m *Marionette) applyStatisticalNoiseTraffic(data []byte, profile *TrafficObfuscationProfile) []byte {
	transform := func(buf []byte) {
		noiseSize := int(m.generateRandomFloat() * 0.1 * float64(profile.ObfuscationLevel) / 10.0 * float64(len(buf)))
		if noiseSize <= 0 {
			return
		}

		for i := 0; i < noiseSize && i < len(buf); i++ {
			idx := int(m.generateRandomFloat() * float64(len(buf)-1))
			buf[idx] ^= byte(m.generateRandomFloat() * 256)
		}
	}

	return m.processWithBufferReuse(data, transform)
}

func (m *Marionette) applyPatternRandomizationTraffic(data []byte, _ *TrafficObfuscationProfile) []byte {
	if len(data) < 2 {
		return data
	}
	res := make([]byte, len(data))
	copy(res, data)
	idx := int(m.generateRandomFloat() * float64(len(data)-1))
	res[idx], res[idx+1] = res[idx+1], res[idx]
	return res
}

func (m *Marionette) applySequenceObfuscationTraffic(data []byte, _ *TrafficObfuscationProfile) []byte {
	if len(data) == 0 {
		return data
	}
	res := make([]byte, len(data))
	for i, b := range data {
		res[i] = b ^ byte(i%256)
	}
	return res
}


func (m *Marionette) generateFakeClientHello(sni string, realityPubKeyHex string) []byte {

	defaultPubKey := ""

	targetKey := realityPubKeyHex
	if targetKey == "" {
		targetKey = defaultPubKey
	}

	clientRandom := make([]byte, 32)
	if _, err := rand.Read(clientRandom); err != nil {
		m.Rand.Read(clientRandom)
	}

	var sessionID []byte

	pubKeyBytes, err := base64.StdEncoding.DecodeString(targetKey)
	if err == nil && len(pubKeyBytes) == 32 {
		priv := make([]byte, 32)
		if _, err := rand.Read(priv); err == nil {
			myPub, err := curve25519.X25519(priv, curve25519.Basepoint)
			if err == nil {
				copy(clientRandom, myPub)

				sharedSecret, err := curve25519.X25519(priv, pubKeyBytes)
				if err == nil {
					timestamp := uint64(time.Now().UnixMilli())
					mac := hmac.New(sha256.New, sharedSecret)
					mac.Write([]byte("whispera-session-id"))
					timestampBytes := make([]byte, 8)
					binary.BigEndian.PutUint64(timestampBytes, timestamp)
					mac.Write(timestampBytes)
					hmacResult := mac.Sum(nil)

					sessionID = make([]byte, 32)
					binary.BigEndian.PutUint64(sessionID[0:8], timestamp)
					copy(sessionID[8:32], hmacResult[:24])
				}
			}
		}
	}

	if sessionID == nil {
		sessionID = make([]byte, 32)
		m.Rand.Read(sessionID)
	}


	sniContent := []byte(sni)
	sniExtLen := 5 + len(sniContent)
	sniExt := make([]byte, 4+sniExtLen)
	sniExt[0], sniExt[1] = 0x00, 0x00
	sniExt[2], sniExt[3] = byte(sniExtLen>>8), byte(sniExtLen)
	sniExt[4], sniExt[5] = byte((sniExtLen-2)>>8), byte(sniExtLen-2)
	sniExt[6] = 0x00
	sniExt[7], sniExt[8] = byte(len(sniContent)>>8), byte(len(sniContent))
	copy(sniExt[9:], sniContent)

	groups := []byte{0x00, 0x1d, 0x00, 0x17, 0x00, 0x18}
	sgExt := make([]byte, 4+2+len(groups))
	sgExt[0], sgExt[1] = 0x00, 0x0a
	sgExt[2], sgExt[3] = 0x00, byte(2+len(groups))
	sgExt[4], sgExt[5] = 0x00, byte(len(groups))
	copy(sgExt[6:], groups)

	keyShareData := make([]byte, 32)
	m.Rand.Read(keyShareData)
	ksContentLen := 2 + 2 + 2 + 32
	ksExt := make([]byte, 4+ksContentLen)
	ksExt[0], ksExt[1] = 0x00, 0x33
	ksExt[2], ksExt[3] = byte(ksContentLen>>8), byte(ksContentLen)
	idx := 4
	ksExt[idx], ksExt[idx+1] = byte((ksContentLen-2)>>8), byte(ksContentLen-2)
	idx += 2
	ksExt[idx], ksExt[idx+1] = 0x00, 0x1d
	idx += 2
	ksExt[idx], ksExt[idx+1] = 0x00, 0x20
	idx += 2
	copy(ksExt[idx:], keyShareData)

	svExt := []byte{
		0x00, 0x2b,
		0x00, 0x03,
		0x02,
		0x03, 0x04,
	}

	saExt := []byte{
		0x00, 0x0d,
		0x00, 0x08,
		0x00, 0x06,
		0x04, 0x03,
		0x08, 0x04,
		0x04, 0x01,
	}

	extensions := []byte{}
	extensions = append(extensions, sniExt...)
	extensions = append(extensions, saExt...)
	extensions = append(extensions, sgExt...)
	extensions = append(extensions, svExt...)
	extensions = append(extensions, ksExt...)


	ciphers := []byte{
		0x13, 0x01,
		0x13, 0x02,
		0x13, 0x03,
		0xc0, 0x2b,
		0xc0, 0x2f,
	}

	compression := []byte{0x01, 0x00}

	bodyLen := 2 + 32 + 1 + 32 + 2 + len(ciphers) + len(compression) + 2 + len(extensions)

	handshake := make([]byte, 4+bodyLen)
	handshake[0] = 0x01
	handshake[1] = 0x00
	handshake[2] = byte(bodyLen >> 8)
	handshake[3] = byte(bodyLen)

	idx = 4
	handshake[idx], handshake[idx+1] = 0x03, 0x03
	idx += 2
	copy(handshake[idx:], clientRandom)
	idx += 32
	handshake[idx] = 32
	idx++
	copy(handshake[idx:], sessionID)
	idx += 32
	handshake[idx], handshake[idx+1] = byte(len(ciphers)>>8), byte(len(ciphers))
	idx += 2
	copy(handshake[idx:], ciphers)
	idx += len(ciphers)
	copy(handshake[idx:], compression)
	idx += len(compression)
	handshake[idx], handshake[idx+1] = byte(len(extensions)>>8), byte(len(extensions))
	idx += 2
	copy(handshake[idx:], extensions)

	recordLen := len(handshake)
	record := make([]byte, 5+recordLen)
	record[0] = 0x16
	record[1], record[2] = 0x03, 0x01
	record[3], record[4] = byte(recordLen>>8), byte(recordLen)
	copy(record[5:], handshake)

	return record
}


func (m *Marionette) generateVKJSONPadding(padding []byte, r *mrand.Rand) {
	for i := range padding {
		switch i % 3 {
		case 0:
			padding[i] = byte(32 + r.Intn(95))
		case 1:
			padding[i] = byte(97 + r.Intn(26))
		default:
			padding[i] = byte(48 + r.Intn(10))
		}
	}
}

func (m *Marionette) generateYandexSearchPadding(padding []byte, r *mrand.Rand) {
	for i := range padding {
		switch i % 4 {
		case 0:
			padding[i] = byte(32 + r.Intn(95))
		case 1:
			padding[i] = byte(97 + r.Intn(26))
		case 2:
			padding[i] = byte(65 + r.Intn(26))
		default:
			padding[i] = byte(48 + r.Intn(10))
		}
	}
}

func (m *Marionette) generateMailruEmailPadding(padding []byte, r *mrand.Rand) {
	for i := range padding {
		switch i % 5 {
		case 0:
			padding[i] = byte(32 + r.Intn(95))
		case 1:
			padding[i] = byte(97 + r.Intn(26))
		case 2:
			padding[i] = byte(65 + r.Intn(26))
		case 3:
			padding[i] = byte(48 + r.Intn(10))
		default:
			padding[i] = byte(33 + r.Intn(15))
		}
	}
}

func (m *Marionette) generateRutubeVideoPadding(padding []byte, r *mrand.Rand) {
	for i := range padding {
		padding[i] = byte(r.Intn(256))
	}
}

func (m *Marionette) generateOzonProductPadding(padding []byte, r *mrand.Rand) {
	for i := range padding {
		switch i % 6 {
		case 0:
			padding[i] = byte(32 + r.Intn(95))
		case 1:
			padding[i] = byte(97 + r.Intn(26))
		case 2:
			padding[i] = byte(65 + r.Intn(26))
		case 3:
			padding[i] = byte(48 + r.Intn(10))
		case 4:
			padding[i] = byte(33 + r.Intn(15))
		default:
			padding[i] = byte(128 + r.Intn(128))
		}
	}
}

func (m *Marionette) generateDefaultHTTPPadding(padding []byte, r *mrand.Rand) {
	for i := range padding {
		padding[i] = byte(r.Intn(256))
	}
}


func (m *Marionette) applyAction(action types.Action, data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	switch action.Type {
	case "shape_size":
		if len(data) > 4096 {
			return m.shapeSize(data, params)
		}
	case "shape_timing":
		return data, m.shapeTiming(action.Parameters)
	case "enable_burst":
		if len(data) > 2048 {
			return m.enableBurst(data, params)
		}
	case "increase_obfuscation":
		return m.increaseObfuscationHelper(data, params)
	case "learn_patterns":
		return data, 0
	case "apply_russian_mimicry":
		return applyRussianMimicry(m, data, params)
	case "apply_ml_evasion":
		return applyMLEvasion(m, data, params)
	case "obfuscate_traffic":
		level, _ := params["level"].(int)
		if level == 0 {
			level = 5
		}

		prof := &TrafficObfuscationProfile{
			Enabled:          true,
			ObfuscationType:  "protocol",
			ObfuscationLevel: level,
			TargetService:    m.Active,
		}

		// Prefer SNI from the active behavioral profile's CDN (matches the real messenger).
		m.Mutex.RLock()
		behavioralProfile := m.ActiveBehavioralProfile
		m.Mutex.RUnlock()
		if behavioralProfile != nil && len(behavioralProfile.Context.CDN.Domains) > 0 {
			prof.SNI = behavioralProfile.Context.CDN.Domains[0]
		} else if sni, ok := params["sni"].(string); ok {
			prof.SNI = sni
		}
		if pubKey, ok := params["reality_public_key"].(string); ok {
			prof.RealityPublicKey = pubKey
		}

		m.Mutex.RLock()
		if m.RealityKey != "" {
			prof.RealityPublicKey = m.RealityKey
		}
		m.Mutex.RUnlock()

		if prof.TargetService == "" {
			prof.TargetService = "example"
		}

		return m.ApplyTrafficObfuscation(data, prof), 0
	}
	return data, 0
}

func (m *Marionette) evaluateConditionFast(condition types.Condition) bool {
	switch condition.Field {
	case "size":
		return evaluateIntCondition(len(m.CoverTraffic), condition.Operator, condition.Value)
	case "packet_count":
		return evaluateIntCondition(m.State.PacketCount, condition.Operator, condition.Value)
	}
	return true
}

func evaluateIntCondition(actual int, op string, val interface{}) bool {
	target, ok := val.(int)
	if !ok {
		if f, ok := val.(float64); ok {
			target = int(f)
		} else {
			return false
		}
	}
	switch op {
	case ">":
		return actual > target
	case ">=":
		return actual >= target
	case "<":
		return actual < target
	case "<=":
		return actual <= target
	case "==":
		return actual == target
	case "!=":
		return actual != target
	}
	return false
}


func (m *Marionette) shapeSize(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	method, _ := params["method"].(string)
	if method == "weighted_random" && len(data) > 4096 {
		targetSize := len(data) * 95 / 100
		if targetSize < len(data) {
			return data[:targetSize], 0
		}
	}
	return data, 0
}

func (m *Marionette) shapeTiming(params map[string]interface{}) time.Duration {
	method, _ := params["method"].(string)
	if method == "exponential" {
		minInterval, _ := params["min_interval"].(int)
		maxInterval, _ := params["max_interval"].(int)
		meanInterval, _ := params["mean_interval"].(int)

		lambda := 1.0 / float64(meanInterval)
		delay := -math.Log(float64(m.State.PacketCount%100)/100.0) / lambda

		if delay < float64(minInterval) {
			delay = float64(minInterval)
		}
		if delay > float64(maxInterval) {
			delay = float64(maxInterval)
		}

		return time.Duration(delay) * time.Millisecond
	}
	return 50 * time.Millisecond
}

func (m *Marionette) enableBurst(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	probability, _ := params["probability"].(float64)
	minBurst, _ := params["min_burst"].(int)
	maxBurst, _ := params["max_burst"].(int)

	if float64(len(data)%100)/100.0 < probability {
		burst := minBurst
		if maxBurst > minBurst {
			burst = minBurst + int(m.generateRandomFloat()*float64(maxBurst-minBurst))
		}
		targetSize := len(data) / (burst + 1)
		if targetSize < 8 {
			targetSize = 8
		}
		return m.resizeToTarget(data, targetSize), 0
	}
	return data, 0
}

func (m *Marionette) increaseObfuscationHelper(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	paddingFactor, _ := params["padding_factor"].(float64)
	targetSize := int(float64(len(data)) * paddingFactor)
	return m.resizeToTarget(data, targetSize), 0
}

func (m *Marionette) learnPatterns(data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	learningRate, _ := params["learning_rate"].(float64)
	if len(m.State.PacketSizes) > 10 {
		recentSizes := m.State.PacketSizes[len(m.State.PacketSizes)-10:]
		avgSize := 0
		for _, size := range recentSizes {
			avgSize += size
		}
		avgSize /= len(recentSizes)
		adaptedSize := int(float64(avgSize) * (1.0 + learningRate))
		return m.resizeToTarget(data, adaptedSize), 0
	}
	return data, 0
}


func (m *Marionette) applyProductionVKontakteEvasion(data []byte) ([]byte, time.Duration, error) {
	if len(data) == 0 {
		return data, 0, nil
	}
	r := m.Rand
	switch {
	case len(data) < 256:
		// Simulate VK LongPoll keepalive: {"ts":"NNNNNNN","updates":[]}
		// Typical size: 256–512 bytes.
		target := 256 + r.Intn(256)
		padding := make([]byte, target-len(data))
		m.generateVKJSONPadding(padding, r)
		data = append(data, padding...)
	case len(data) < 2048:
		// Simulate VK API response frame. Round up to the nearest 512-byte
		// boundary matching VK's HTTP/2 DATA frame granularity.
		target := ((len(data) + 511) / 512) * 512
		if target == len(data) {
			target += 512
		}
		if target > 4096 {
			target = 4096
		}
		padding := make([]byte, target-len(data))
		m.generateVKJSONPadding(padding, r)
		data = append(data, padding...)
	default:
		// Large frame: add small random jitter to avoid exact-power-of-two sizes
		// that are characteristic of VPN framing.
		jitter := 32 + r.Intn(96)
		padding := make([]byte, jitter)
		m.generateVKJSONPadding(padding, r)
		data = append(data, padding...)
	}
	return data, 0, nil
}

func (m *Marionette) applyProductionYandexEvasion(data []byte) ([]byte, time.Duration, error) {
	return m.applyProductionGenericRussianEvasion(data)
}

func (m *Marionette) applyProductionMailruEvasion(data []byte) ([]byte, time.Duration, error) {
	// Used for MAX messenger (Mail.ru product) as well as Mail.ru.
	if len(data) == 0 {
		return data, 0, nil
	}
	r := m.Rand
	switch {
	case len(data) < 256:
		// MAX API keepalive / small status packet.
		target := 128 + r.Intn(384)
		if target <= len(data) {
			target = len(data) + 64
		}
		padding := make([]byte, target-len(data))
		m.generateMailruEmailPadding(padding, r)
		data = append(data, padding...)
	case len(data) < 2048:
		// MAX API response frame, 256-byte granularity.
		target := ((len(data) + 255) / 256) * 256
		if target == len(data) {
			target += 256
		}
		if target > 4096 {
			target = 4096
		}
		padding := make([]byte, target-len(data))
		m.generateMailruEmailPadding(padding, r)
		data = append(data, padding...)
	default:
		jitter := 16 + r.Intn(80)
		padding := make([]byte, jitter)
		m.generateMailruEmailPadding(padding, r)
		data = append(data, padding...)
	}
	return data, 0, nil
}

func (m *Marionette) applyProductionRutubeEvasion(data []byte) ([]byte, time.Duration, error) {
	return m.applyProductionGenericRussianEvasion(data)
}

func (m *Marionette) applyProductionOzonEvasion(data []byte) ([]byte, time.Duration, error) {
	return m.applyProductionGenericRussianEvasion(data)
}

func (m *Marionette) applyProductionGenericRussianEvasion(data []byte) ([]byte, time.Duration, error) {
	if len(data) == 0 {
		return data, 0, nil
	}
	if len(data) < 1400 {
		padding := make([]byte, 64+m.generateRealisticRandom(256))
		for i := range padding {
			padding[i] = byte(m.generateRealisticRandom(256))
		}
		data = append(data, padding...)
	}
	return data, 0, nil
}

func applyRussianMimicry(m *Marionette, data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	intensity := 1.0
	if val, ok := params["intensity"].(float64); ok {
		intensity = val
	}

	result := m.applyEnhancedBehavioralMimicry(data)

	if intensity > 0.5 {
		paddingSize := int(float64(len(result)) * 0.1 * intensity)
		padding := make([]byte, paddingSize)
		for i := range padding {
			padding[i] = byte(m.generateRealisticRandom(256))
		}
		result = append(result, padding...)
	}

	return result, 0
}

func applyMLEvasion(m *Marionette, data []byte, params map[string]interface{}) ([]byte, time.Duration) {
	aggressiveMode := false
	if val, ok := params["aggressive"].(bool); ok {
		aggressiveMode = val
	}

	result := m.applyMLClassificationEvasion(data)

	if aggressiveMode {
		for i := 0; i < len(result) && i < 16; i++ {
			result[i] ^= byte(m.generateRealisticRandom(256))
		}
	}

	return result, 0
}
