package protocol

import "embed"

//go:embed seed_fingerprints/*.bin
var seedFingerprintFS embed.FS

func loadSeedFingerprints() int {
	entries, err := seedFingerprintFS.ReadDir("seed_fingerprints")
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		data, err := seedFingerprintFS.ReadFile("seed_fingerprints/" + e.Name())
		if err != nil {
			continue
		}
		if HarvestRawClientHello(data) == nil {
			n++
		}
	}
	return n
}
