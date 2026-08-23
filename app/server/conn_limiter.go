package main

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nekoskin/whispera/common/ipdetect"
)

const (
	maxTCPConnsPerIP = 200

	refusalLogInterval = 60
)

var (
	connLimiterMu    sync.Mutex
	connLimiterPerIP = make(map[string]int)

	lastRefusalLog atomic.Int64
)

func logRefusal(ip string) {
	now := time.Now().Unix()
	prev := lastRefusalLog.Load()
	if now-prev < refusalLogInterval || !lastRefusalLog.CompareAndSwap(prev, now) {
		return
	}
	log.Warn("conn limiter: refusing %s, per-IP cap %d reached — this looks like a block to that client", ip, maxTCPConnsPerIP)
}

func acquireConnSlot(addr net.Addr) (release func(), ok bool) {
	ip := ipdetect.HostFromAddr(addr)

	connLimiterMu.Lock()
	if connLimiterPerIP[ip] >= maxTCPConnsPerIP {
		connLimiterMu.Unlock()
		logRefusal(ip)
		return nil, false
	}
	connLimiterPerIP[ip]++
	connLimiterMu.Unlock()

	var once sync.Once
	release = func() {
		once.Do(func() {
			connLimiterMu.Lock()
			connLimiterPerIP[ip]--
			if connLimiterPerIP[ip] <= 0 {
				delete(connLimiterPerIP, ip)
			}
			connLimiterMu.Unlock()
		})
	}
	return release, true
}
