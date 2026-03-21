package gnet

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"

	"gorgonia.org/gorgonia"
	"gorgonia.org/tensor"
)

type LayerDef struct {
	InSize  int       `json:"in"`
	OutSize int       `json:"out"`
	W       []float64 `json:"w"`
	B       []float64 `json:"b"`
}

type GorgoniaNet struct {
	Layers []LayerDef
}

func New(sizes []int) *GorgoniaNet {
	net := &GorgoniaNet{}
	for i := 0; i < len(sizes)-1; i++ {
		in, out := sizes[i], sizes[i+1]
		scale := math.Sqrt(2.0 / float64(in))
		w := make([]float64, out*in)
		for j := range w {
			w[j] = RandNorm() * scale
		}
		b := make([]float64, out)
		net.Layers = append(net.Layers, LayerDef{InSize: in, OutSize: out, W: w, B: b})
	}
	return net
}

func (net *GorgoniaNet) Forward(input []float64) []float64 {
	g := gorgonia.NewGraph()
	inSize := net.Layers[0].InSize

	inp := make([]float64, inSize)
	copy(inp, input)
	xVal := tensor.New(tensor.WithShape(1, inSize), tensor.WithBacking(inp))
	x := gorgonia.NewMatrix(g, gorgonia.Float64, gorgonia.WithShape(1, inSize), gorgonia.WithValue(xVal), gorgonia.WithName("x"))

	result := x
	for i, ld := range net.Layers {
		wVal := tensor.New(tensor.WithShape(ld.InSize, ld.OutSize), tensor.WithBacking(CopyF64(ld.W)))
		bVal := tensor.New(tensor.WithShape(1, ld.OutSize), tensor.WithBacking(CopyF64(ld.B)))
		wNode := gorgonia.NewMatrix(g, gorgonia.Float64, gorgonia.WithShape(ld.InSize, ld.OutSize), gorgonia.WithValue(wVal), gorgonia.WithName(fmt.Sprintf("w%d", i)))
		bNode := gorgonia.NewMatrix(g, gorgonia.Float64, gorgonia.WithShape(1, ld.OutSize), gorgonia.WithValue(bVal), gorgonia.WithName(fmt.Sprintf("b%d", i)))

		linear := gorgonia.Must(gorgonia.Mul(result, wNode))
		linear = gorgonia.Must(gorgonia.Add(linear, bNode))

		if i < len(net.Layers)-1 {
			result = gorgonia.Must(gorgonia.Rectify(linear))
		} else {
			result = linear
		}
	}

	vm := gorgonia.NewTapeMachine(g)
	defer vm.Close()
	if err := vm.RunAll(); err != nil {
		return make([]float64, net.Layers[len(net.Layers)-1].OutSize)
	}

	outTensor := result.Value().(tensor.Tensor)
	out := make([]float64, net.Layers[len(net.Layers)-1].OutSize)
	copy(out, outTensor.Data().([]float64))
	return out
}

func (net *GorgoniaNet) LoadWeights(layers []LayerDef) {
	for i, l := range layers {
		if i >= len(net.Layers) {
			break
		}
		if len(l.W) == len(net.Layers[i].W) {
			copy(net.Layers[i].W, l.W)
		}
		if len(l.B) == len(net.Layers[i].B) {
			copy(net.Layers[i].B, l.B)
		}
	}
}

func Clone(src *GorgoniaNet) *GorgoniaNet {
	dst := &GorgoniaNet{}
	for _, l := range src.Layers {
		dst.Layers = append(dst.Layers, LayerDef{
			InSize: l.InSize, OutSize: l.OutSize,
			W: CopyF64(l.W), B: CopyF64(l.B),
		})
	}
	return dst
}

func RandNorm() float64 {
	var buf [8]byte
	rand.Read(buf[:])
	u1 := float64(binary.LittleEndian.Uint64(buf[:])) / float64(math.MaxUint64)
	if u1 < 1e-15 {
		u1 = 1e-15
	}
	rand.Read(buf[:])
	u2 := float64(binary.LittleEndian.Uint64(buf[:])) / float64(math.MaxUint64)
	return math.Sqrt(-2*math.Log(u1)) * math.Cos(2*math.Pi*u2)
}

func CopyF64(src []float64) []float64 {
	dst := make([]float64, len(src))
	copy(dst, src)
	return dst
}
