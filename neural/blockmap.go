package neural

type TransportRate struct {
	OK   int64   `json:"ok"`
	Fail int64   `json:"fail"`
	Rate float64 `json:"rate"`
}

type OONIContext struct {
	AnomalyRate     float64 `json:"anomaly_rate"`
	TLSInterference float64 `json:"tls_interference"`
	TorBlocked      bool    `json:"tor_blocked"`
	UDPThrottled    bool    `json:"udp_throttled"`
	UpdatedAt       int64   `json:"updated_at"`
}

type BlockmapEntry struct {
	CC         string                   `json:"cc"`
	ASN        string                   `json:"asn"`
	OONI       OONIContext              `json:"ooni"`
	Transports map[string]TransportRate `json:"transports"`
	Pool       []string                 `json:"pool"`
	Avoid      []string                 `json:"avoid"`
}

type BlockReport struct {
	CC      string                   `json:"cc"`
	ASN     string                   `json:"asn"`
	Reports map[string]TransportRate `json:"reports"`
}
