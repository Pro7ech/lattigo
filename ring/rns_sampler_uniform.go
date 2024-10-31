package ring

import (
	"math/bits"

	"github.com/Pro7ech/lattigo/utils/sampling"
)

// UniformSampler wraps a util.PRNG and represents
// the state of a sampler of uniform polynomials.
type UniformSampler struct {
	Moduli []uint64
	*sampling.Source
}

// NewUniformSampler creates a new instance of UniformSampler from a
// [sampling.Source] and a list of moduli.
func NewUniformSampler(source *sampling.Source, moduli []uint64) (u *UniformSampler) {
	u = new(UniformSampler)
	u.Moduli = moduli
	u.Source = source
	return
}

// GetSource returns the underlying [sampling.Source] used by the sampler.
func (u UniformSampler) GetSource() *sampling.Source {
	return u.Source
}

// WithSource returns an instance of the underlying sampler with
// a new [sampling.Source].
// It can be used concurrently with the original sampler.
func (u UniformSampler) WithSource(source *sampling.Source) Sampler {
	return &UniformSampler{
		Moduli: u.Moduli,
		Source: source,
	}
}

// AtLevel returns an instance of the target UniformSampler to sample at the given level.
// The returned sampler cannot be used concurrently to the original sampler.
func (u UniformSampler) AtLevel(level int) Sampler {
	return &UniformSampler{
		Moduli: u.Moduli[:level+1],
		Source: u.Source,
	}
}

func (u *UniformSampler) Read(pol RNSPoly) {
	u.read(pol, func(a, b, c uint64) uint64 {
		return b
	})
}

func (u *UniformSampler) ReadAndAdd(pol RNSPoly) {
	u.read(pol, func(a, b, c uint64) uint64 {
		return CRed(a+b, c)
	})
}

func (u *UniformSampler) read(pol RNSPoly, f func(a, b, c uint64) uint64) {

	var c, mask uint64

	r := u.Source

	for j, qi := range u.Moduli {

		mask = (1 << uint64(bits.Len64(qi-1))) - 1

		coeffs := pol.At(j)

		for i := range coeffs {

			c = r.Uint64() & mask

			for c >= qi {
				c = r.Uint64() & mask
			}

			coeffs[i] = f(coeffs[i], c, qi)
		}
	}
}

// ReadNew generates a new polynomial with coefficients following a uniform distribution over [0, Qi-1].
// Polynomial is created at the max level.
func (u *UniformSampler) ReadNew(N int) (pol RNSPoly) {
	pol = NewRNSPoly(N, len(u.Moduli)-1)
	u.Read(pol)
	return
}
