package client

import (
	stdlog "log"
	"runtime"
	"sync"
	"time"

	"github.com/nekoskin/whispera/common/runtime/lifecycle"
)

func fatalf(format string, a ...any) {
	if mobileMode {
		stdlog.Printf(format, a...)
		runtime.Goexit()
	}
	stdlog.Fatalf(format, a...)
}

var (
	mobileMode    bool
	mobileRunning bool
	mobileMu      sync.Mutex
	pkgLC         *lifecycle.Manager
)

func Start(key, socks, logFile, fingerprint, dns, rules string, hwid bool) {
	mobileMu.Lock()
	if mobileRunning {
		old := pkgLC
		mobileMu.Unlock()
		if old != nil {
			_ = old.Stop()
		}
		deadline := time.Now().Add(3 * time.Second)
		for {
			mobileMu.Lock()
			if !mobileRunning || time.Now().After(deadline) {
				break
			}
			mobileMu.Unlock()
			time.Sleep(20 * time.Millisecond)
		}
	}
	mobileMode = true
	mobileRunning = true
	pkgLC = lifecycle.NewManager(lifecycle.Config{
		ShutdownTimeout: 1 * time.Second,
	})
	*connKey = key
	*socksAddr = socks
	*logFilePath = logFile
	*forceFingerprint = fingerprint
	*dnsUpstream = dns
	*splitRulesJSON = rules
	*hwidFlag = hwid
	*noInternalTun = true
	mobileMu.Unlock()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				stdlog.Printf("go-client panic: %v", r)
			}
			mobileMu.Lock()
			mobileRunning = false
			mobileMu.Unlock()
		}()
		RunMain()
	}()
}

func Stop() {
	mobileMu.Lock()
	lc := pkgLC
	pkgLC = nil
	mobileMu.Unlock()
	if lc != nil {
		_ = lc.Stop()
	}
}
