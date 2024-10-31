package ring

import (
	"fmt"

	"github.com/Pro7ech/lattigo/utils/sampling"
)

// Sampler is an interface for random polynomial samplers.
// It has a single Read method which takes as argument the polynomial to be
// populated according to the Sampler's distribution.
type Sampler interface {
	GetSource() *sampling.Source
	Read(pol RNSPoly)
	ReadNew(N int) (pol RNSPoly)
	ReadAndAdd(pol RNSPoly)
	AtLevel(level int) Sampler
	WithSource(source *sampling.Source) Sampler
}

// NewSampler instantiates a new [Sampler] interface from the provided [rand.Source],
// modulic chain and [DistributionParameters].
func NewSampler(source *sampling.Source, moduli []uint64, X DistributionParameters) (Sampler, error) {
	switch X := X.(type) {
	case *DiscreteGaussian:
		return NewGaussianSampler(source, moduli, *X), nil
	case *Ternary:
		return NewTernarySampler(source, moduli, *X)
	case *Uniform:
		return NewUniformSampler(source, moduli), nil
	default:
		return nil, fmt.Errorf("invalid distribution: want ring.DiscreteGaussianDistribution, ring.TernaryDistribution or ring.UniformDistribution but have %T", X)
	}
}
