package bridgepool

import (
	"fmt"
	"testing"
	"time"
)

func BenchmarkGetAliveBridges(b *testing.B) {
	r := NewRegistry("")
	for i := 0; i < 100; i++ {
		r.RegisterBridge(&BridgeInfo{
			Address:    fmt.Sprintf("10.0.0.%d:8443", i%256),
			Type:       BridgeOperator,
			IsAlive:    i%3 != 0,
			Latency:    50 + i%200,
			TrustLevel: 50 + i%50,
			CreatedAt:  time.Now(),
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.GetAliveBridges()
	}
}

func BenchmarkGetBridgesForUser(b *testing.B) {
	r := NewRegistry("")
	for i := 0; i < 100; i++ {
		r.RegisterBridge(&BridgeInfo{
			Address:    fmt.Sprintf("10.0.0.%d:8443", i%256),
			Type:       BridgeOperator,
			IsAlive:    true,
			Latency:    50 + i%200,
			TrustLevel: 50 + i%50,
			CreatedAt:  time.Now(),
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.GetBridgesForUser("user-12345", 3)
	}
}

func BenchmarkUpdateBridgeStatus(b *testing.B) {
	r := NewRegistry("")
	ids := make([]string, 50)
	for i := 0; i < 50; i++ {
		info := &BridgeInfo{
			Address: fmt.Sprintf("10.0.0.%d:8443", i),
			Type:    BridgeOperator,
			IsAlive: true,
		}
		r.RegisterBridge(info)
		ids[i] = info.ID
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.UpdateBridgeStatus(ids[i%50], true, 42)
	}
}

func BenchmarkTrustCalculation(b *testing.B) {
	r := NewRegistry("")
	tm := NewTrustManager(r)
	bridge := &BridgeInfo{
		Type:      BridgeCommunity,
		IsAlive:   true,
		Latency:   120,
		PublicKey: "dGVzdA==",
		CreatedAt: time.Now().Add(-10 * 24 * time.Hour),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tm.CalculateTrustLevel(bridge)
	}
}

func BenchmarkMLRankBridges_Fallback(b *testing.B) {
	bridges := make([]*BridgeInfo, 20)
	for i := range bridges {
		bridges[i] = &BridgeInfo{
			ID:      fmt.Sprintf("bridge-%d", i),
			IsAlive: true,
			Latency: 50 + i*10,
			Load:    float64(i) * 0.05,
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mlRankBridges(bridges)
	}
}

func BenchmarkGetAliveBridges_Parallel(b *testing.B) {
	r := NewRegistry("")
	for i := 0; i < 100; i++ {
		r.RegisterBridge(&BridgeInfo{
			Address:    fmt.Sprintf("10.0.0.%d:8443", i%256),
			Type:       BridgeOperator,
			IsAlive:    true,
			Latency:    50,
			TrustLevel: 80,
			CreatedAt:  time.Now(),
		})
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			r.GetAliveBridges()
		}
	})
}
