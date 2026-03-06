package marionette

import (
	"time"
	"whispera/internal/obfuscation/core/types"
)

var _ = []interface{}{
	(*Marionette).generateTLSExtensions,
	(*Marionette).generateJA4Extensions,
}


func (m *Marionette) generateTLSExtensions() []byte {
	extensions := make([]byte, 0, 64)
	hostname := m.getHostnameForActiveProfile()

	sniHost := []byte(hostname)
	sniNameLen := len(sniHost)
	sniListLen := 3 + sniNameLen
	extLen := 2 + sniListLen

	extensions = append(extensions, 0x00, 0x00, byte(extLen>>8), byte(extLen), byte(sniListLen>>8), byte(sniListLen), 0x00, byte(sniNameLen>>8), byte(sniNameLen))
	extensions = append(extensions, sniHost...)

	alpnH2 := []byte{0x02, 'h', '2'}
	alpnH11 := []byte{0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'}
	alpnListLen := len(alpnH2) + len(alpnH11)
	alpnExtLen := 2 + alpnListLen

	extensions = append(extensions, 0x00, 0x10, byte(alpnExtLen>>8), byte(alpnExtLen), byte(alpnListLen>>8), byte(alpnListLen))
	extensions = append(extensions, alpnH2...)
	extensions = append(extensions, alpnH11...)

	return extensions
}

func (m *Marionette) generateJA4Extensions() []byte {
	extensions := make([]byte, 0, 128)
	hostname := m.getHostnameForActiveProfile()

	sniHost := []byte(hostname)
	sniNameLen := len(sniHost)
	sniListLen := 3 + sniNameLen
	extLen := 2 + sniListLen
	extensions = append(extensions, 0x00, 0x00, byte(extLen>>8), byte(extLen), byte(sniListLen>>8), byte(sniListLen), 0x00, byte(sniNameLen>>8), byte(sniNameLen))
	extensions = append(extensions, sniHost...)

	alpnH2 := []byte{0x02, 'h', '2'}
	alpnH11 := []byte{0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'}
	alpnListLen := len(alpnH2) + len(alpnH11)
	alpnExtLen := 2 + alpnListLen
	extensions = append(extensions, 0x00, 0x10, byte(alpnExtLen>>8), byte(alpnExtLen), byte(alpnListLen>>8), byte(alpnListLen))
	extensions = append(extensions, alpnH2...)
	extensions = append(extensions, alpnH11...)

	extensions = append(extensions, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04)
	extensions = append(extensions, 0x00, 0x0d, 0x00, 0x08, 0x00, 0x06, 0x04, 0x03, 0x08, 0x04, 0x08, 0x05)

	return extensions
}

func (m *Marionette) getHostnameForActiveProfile() string {
	switch m.Active {
	case "vk":
		return "vk.com"
	case "yandex":
		return "yandex.ru"
	case "mailru":
		return "mail.ru"
	case "rutube":
		return "rutube.ru"
	case "ozon":
		return "ozon.ru"
	default:
		return "example.com"
	}
}


func (m *Marionette) initMobileDeviceProfiles() {
	m.Profiles["mobile_vk_android"] = &types.TrafficProfile{
		Name: "VK Mobile Android",
		SizeDistribution: &types.SizeDistribution{
			Min: 32, Max: 4096, Mean: 256, StdDev: 128,
			Weights: []float64{0.4, 0.3, 0.2, 0.1}, Bins: []int{32, 128, 512, 2048},
		},
		IntervalDistribution: &types.IntervalDistribution{
			Min: 50 * time.Millisecond, Max: 300 * time.Millisecond,
			Mean: 100 * time.Millisecond, StdDev: 50 * time.Millisecond, Pattern: "exponential",
		},
	}

	m.Profiles["mobile_vk_ios"] = &types.TrafficProfile{
		Name: "VK Mobile iOS",
		SizeDistribution: &types.SizeDistribution{
			Min: 32, Max: 4096, Mean: 256, StdDev: 128,
			Weights: []float64{0.4, 0.3, 0.2, 0.1}, Bins: []int{32, 128, 512, 2048},
		},
		IntervalDistribution: &types.IntervalDistribution{
			Min: 50 * time.Millisecond, Max: 300 * time.Millisecond,
			Mean: 100 * time.Millisecond, StdDev: 50 * time.Millisecond, Pattern: "exponential",
		},
	}
}


func (m *Marionette) initDefaultProfiles() {
	m.Profiles["http2"] = &types.TrafficProfile{
		Name: "HTTP/2",
		PacketSizes: types.SizeDistribution{
			Min: 64, Max: 16384, Mean: 1400, StdDev: 800,
			Weights: []float64{0.05, 0.1, 0.3, 0.35, 0.2},
			Bins:    []int{64, 256, 1300, 2800, 16000},
		},
		Intervals: types.IntervalDistribution{
			Min: 1 * time.Millisecond, Max: 80 * time.Millisecond,
			Mean: 15 * time.Millisecond, StdDev: 10 * time.Millisecond,
			Pattern: "burst_heavy",
		},
		BurstPatterns: types.BurstProfile{Probability: 0.35, MinBurst: 5, MaxBurst: 40, BurstGap: 80 * time.Millisecond},
		Coverage:      types.CoverageProfile{Enabled: true, Probability: 0.15, MinSize: 40, MaxSize: 120, Interval: 5 * time.Second},
		Adaptation:    types.AdaptationProfile{Enabled: true, Sensitivity: 0.8, LearningRate: 0.15, AdaptationThreshold: 0.7},
	}
	m.Profiles["vk"] = m.createDynamicProfile("VKontakte", "vk")
	m.Profiles["yandex"] = m.createDynamicProfile("Yandex", "yandex")
	m.Profiles["mailru"] = m.createDynamicProfile("Mail.ru", "mailru")
	m.Profiles["websocket"] = &types.TrafficProfile{
		Name: "WebSocket",
		PacketSizes: types.SizeDistribution{
			Min: 12, Max: 1400, Mean: 120, StdDev: 100,
			Weights: []float64{0.6, 0.3, 0.08, 0.02}, Bins: []int{12, 150, 500, 1200},
		},
		Intervals: types.IntervalDistribution{
			Min: 50 * time.Millisecond, Max: 5 * time.Second,
			Mean: 800 * time.Millisecond, StdDev: 500 * time.Millisecond, Pattern: "human_typing",
		},
		BurstPatterns: types.BurstProfile{Probability: 0.1, MinBurst: 1, MaxBurst: 5, BurstGap: 200 * time.Millisecond},
		Coverage:      types.CoverageProfile{Enabled: true, Probability: 0.5, MinSize: 10, MaxSize: 40, Interval: 25 * time.Second},
		Adaptation:    types.AdaptationProfile{Enabled: true, Sensitivity: 0.8, LearningRate: 0.15, AdaptationThreshold: 0.75},
	}
	m.Profiles["quic"] = &types.TrafficProfile{
		Name: "QUIC",
		PacketSizes: types.SizeDistribution{
			Min: 1200, Max: 1350, Mean: 1280, StdDev: 50, Weights: []float64{0.05, 0.1, 0.85}, Bins: []int{64, 1000, 1300},
		},
		Intervals: types.IntervalDistribution{
			Min: 1 * time.Millisecond, Max: 40 * time.Millisecond, Mean: 8 * time.Millisecond, StdDev: 5 * time.Millisecond, Pattern: "udp_stream",
		},
		BurstPatterns: types.BurstProfile{Probability: 0.5, MinBurst: 20, MaxBurst: 100, BurstGap: 40 * time.Millisecond},
		Coverage:      types.CoverageProfile{Enabled: true, Probability: 0.1, MinSize: 1200, MaxSize: 1280, Interval: 500 * time.Millisecond},
		Adaptation:    types.AdaptationProfile{Enabled: true, Sensitivity: 0.6, LearningRate: 0.2, AdaptationThreshold: 0.85},
	}
}

func (m *Marionette) initRussianServiceProfiles() {
	m.addRussianServiceRules("vk")
	m.addRussianServiceRules("yandex")
	m.addRussianServiceRules("mailru")
}

func (m *Marionette) addRussianServiceRules(service string) {
	m.Rules = append(m.Rules, types.ObfuscationRule{
		Name:     "rule_" + service + "_protocol",
		Priority: 10,
		Enabled:  true,
		Condition: types.Condition{
			Field:    "packet_count",
			Operator: ">=",
			Value:    0,
		},
		Action: types.Action{
			Type: "obfuscate_traffic",
			Parameters: map[string]interface{}{
				"level": 5,
			},
		},
	})
}


func (m *Marionette) initDefaultRules() {
	m.Rules = append(m.Rules, types.ObfuscationRule{
		Name:     "rule_default_timing",
		Priority: 8,
		Enabled:  true,
		Condition: types.Condition{
			Field:    "packet_count",
			Operator: ">",
			Value:    0,
		},
		Action: types.Action{
			Type: "shape_timing",
			Parameters: map[string]interface{}{
				"method":        "exponential",
				"min_interval":  10,
				"max_interval":  100,
				"mean_interval": 50,
			},
		},
	})

	m.Rules = append(m.Rules, types.ObfuscationRule{
		Name:     "rule_default_protocol",
		Priority: 10,
		Enabled:  true,
		Condition: types.Condition{
			Field:    "packet_count",
			Operator: ">=",
			Value:    0,
		},
		Action: types.Action{
			Type: "obfuscate_traffic",
			Parameters: map[string]interface{}{
				"level": 5,
				"sni":   "www.microsoft.com",
			},
		},
	})
}
