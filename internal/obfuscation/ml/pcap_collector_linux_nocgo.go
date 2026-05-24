//go:build linux && !cgo

package ml

import "net"

type FlowLabel int

const (
	FlowUnknown FlowLabel = iota
	FlowTunnel
	FlowDecoy
)

type FlowFeatures struct {
	IATMean, IATStd, IATP90    float64
	SizeMean, SizeStd, SizeP90 float64
	UpRatio, BurstSize         float64
	Duration, PacketCount      float64
}

func (f FlowFeatures) Vec() []float64 {
	return []float64{
		f.IATMean, f.IATStd, f.IATP90,
		f.SizeMean, f.SizeStd, f.SizeP90,
		f.UpRatio, f.BurstSize,
		f.Duration, f.PacketCount,
	}
}

const FlowFeatureSize = 10

type LabeledFlow struct {
	Features FlowFeatures
	Label    FlowLabel
}

var FlowRegistry = &flowRegistry{}

type flowRegistry struct{}

func (r *flowRegistry) Register(remoteAddr string, label FlowLabel)           {}
func (r *flowRegistry) RegisterConn(local, remote net.Addr, label FlowLabel) {}
func (r *flowRegistry) Get(key string) FlowLabel                              { return FlowUnknown }
func (r *flowRegistry) Delete(remoteAddr string)                              {}
func (r *flowRegistry) DeleteConn(local, remote net.Addr)                    {}

type PCAPCollector struct{ out chan LabeledFlow }

func NewPCAPCollector(iface string, port int) *PCAPCollector {
	return &PCAPCollector{out: make(chan LabeledFlow)}
}
func (c *PCAPCollector) Start() error           { return nil }
func (c *PCAPCollector) Stop()                  {}
func (c *PCAPCollector) Out() <-chan LabeledFlow { return c.out }
