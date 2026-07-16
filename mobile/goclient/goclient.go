package goclient

import "github.com/nekoskin/whispera/app/client"

// Start runs the Whispera go-client in-process (Android/iOS via gomobile) so it
// is not a forked child that Android's phantom-process killer reaps. Non-blocking.
func Start(key, socks, logFile, fingerprint string, hwid bool) {
	client.Start(key, socks, logFile, fingerprint, hwid)
}

// Stop tears the in-process client down (cancels the lifecycle, closing the
// SOCKS listener and all modules).
func Stop() {
	client.Stop()
}
