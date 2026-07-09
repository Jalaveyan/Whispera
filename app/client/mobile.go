package client

import (
	"sync"

	"whispera/common/runtime/lifecycle"
)

var (
	mobileMode    bool
	mobileRunning bool
	mobileMu      sync.Mutex
	pkgLC         *lifecycle.Manager
)

func Start(key, socks, logFile, fingerprint string, hwid bool) {
	mobileMu.Lock()
	if mobileRunning {
		mobileMu.Unlock()
		return
	}
	mobileMode = true
	mobileRunning = true
	*connKey = key
	*socksAddr = socks
	*logFilePath = logFile
	*forceFingerprint = fingerprint
	*hwidFlag = hwid
	*noInternalTun = true
	mobileMu.Unlock()

	go RunMain()
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
