module github.com/nekoskin/whispera

go 1.26

toolchain go1.26.5

require (
	github.com/google/uuid v1.6.0
	github.com/hashicorp/golang-lru/v2 v2.0.7
	github.com/jackc/pgx/v5 v5.9.0
	github.com/nats-io/nats.go v1.49.0
	github.com/quic-go/quic-go v0.59.0
	github.com/refraction-networking/utls v1.8.3-0.20260301010127-aa6edf4b11af
	github.com/sagernet/sing v0.8.11
	github.com/sagernet/sing-mux v0.3.5
	github.com/sourcegraph/conc v0.3.0
	go.uber.org/automaxprocs v1.6.0
	go.uber.org/goleak v1.3.0
	go.uber.org/zap v1.27.1
	golang.org/x/crypto v0.53.0
	golang.org/x/net v0.56.0
	google.golang.org/grpc v1.81.1
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/hashicorp/yamux v0.1.2 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/nats-io/nkeys v0.4.12 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/sagernet/smux v1.5.50-sing-box-mod.1 // indirect
	go.opentelemetry.io/otel v1.44.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
)

replace (
	golang.org/x/crypto => golang.org/x/crypto v0.53.0
	golang.org/x/net => golang.org/x/net v0.56.0
	golang.org/x/sys => golang.org/x/sys v0.35.0
	golang.org/x/text => golang.org/x/text v0.28.0
// gvisor.dev/gvisor => ./internal/gvisor/gvisor@v0.0.0-20251115042331-9fc4303aefe1
)

require (
	github.com/andybalholm/brotli v1.1.1 // indirect
	github.com/klauspost/compress v1.18.2 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/klauspost/reedsolomon v1.13.0
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/text v0.38.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/protobuf v1.36.11
)
