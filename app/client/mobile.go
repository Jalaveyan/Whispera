package client

import (
	stdlog "log"
	"runtime"
	"sync"
	"time"

	"github.com/nekoskin/whispera/common/runtime/lifecycle"
)

// fatalf ends startup on an unrecoverable error. As a forked CLI that means
// exiting the process; in-process (mobileMode) it must NOT kill the host app —
// it logs and unwinds just the client goroutine.
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

func Start(key, socks, logFile, fingerprint string, hwid bool) {
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
	// Create the lifecycle up front so Stop() can always find it (no race with
	// RunMain setting it mid-startup) — the deterministic in-process stop.
	pkgLC = lifecycle.NewManager(lifecycle.Config{
		ShutdownTimeout: 1 * time.Second,
		GracefulStop:    true,
	})
	*connKey = key
	*socksAddr = socks
	*logFilePath = logFile
	*forceFingerprint = fingerprint
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
	mobileRunning = false
	mobileMu.Unlock()
	if lc != nil {
		_ = lc.Stop()
	}
}
