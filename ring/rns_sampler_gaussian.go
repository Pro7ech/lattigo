package ring

import (
	"math"
	"math/big"
	"math/rand/v2"
	"unsafe"

	"github.com/Pro7ech/lattigo/utils/bignum"
	"github.com/Pro7ech/lattigo/utils/sampling"
)

// GaussianSampler keeps the state of a truncated Gaussian polynomial sampler.
type GaussianSampler struct {
	*sampling.Source
	Xe     DiscreteGaussian
	Moduli []uint64
}

// NewGaussianSampler creates a new instance of [GaussianSampler] from a [sampling.Source],
// a moduli chain and a [DiscreteGaussian] distribution parameter.
func NewGaussianSampler(source *sampling.Source, moduli []uint64, Xe DiscreteGaussian) (g *GaussianSampler) {
	g = new(GaussianSampler)
	g.Source = source
	g.Moduli = moduli
	g.Xe = Xe
	return
}

// GetSource returns the underlying [sampling.Source] used by the sampler.
func (g GaussianSampler) GetSource() *sampling.Source {
	return g.Source
}

// WithSource returns an instance of the underlying sampler with
// a new [sampling.Source].
// It can be used concurrently with the original sampler.
func (g GaussianSampler) WithSource(source *sampling.Source) Sampler {
	return &GaussianSampler{
		Source: source,
		Moduli: g.Moduli,
		Xe:     g.Xe,
	}
}

// AtLevel returns an instance of the target GaussianSampler that operates at the target level.
// This instance is not thread safe and cannot be used concurrently to the base instance.
func (g GaussianSampler) AtLevel(level int) Sampler {
	return &GaussianSampler{
		Moduli: g.Moduli[:level+1],
		Source: g.Source,
		Xe:     g.Xe,
	}
}

// Read samples a truncated Gaussian polynomial on "pol" at the maximum level in the default ring, standard deviation and bound.
func (g *GaussianSampler) Read(pol RNSPoly) {
	g.read(pol, func(a, b, c uint64) uint64 {
		return b
	})
}

// ReadNew samples a new truncated Gaussian polynomial at the maximum level in the default ring, standard deviation and bound.
func (g *GaussianSampler) ReadNew(N int) (pol RNSPoly) {
	pol = NewRNSPoly(N, len(g.Moduli)-1)
	g.Read(pol)
	return pol
}

// ReadAndAdd samples a truncated Gaussian polynomial at the given level for the receiver's default standard deviation and bound and adds it on "pol".
func (g *GaussianSampler) ReadAndAdd(pol RNSPoly) {
	g.read(pol, func(a, b, c uint64) uint64 {
		return CRed(a+b, c)
	})
}

func (g *GaussianSampler) read(pol RNSPoly, f func(a, b, c uint64) uint64) {
	var norm float64

	var sign uint64

	bound := g.Xe.Bound
	sigma := float64(g.Xe.Sigma)

	coeffs := pol

	moduli := g.Moduli

	// If the standard deviation is greater than float64 precision
	// and the bound is greater than uint64, we switch to an approximation
	// using arbitrary precision.
	//
	// The approximation of the large norm sampling is done by sampling
	// a uniform value [0, sigma] * ceil(norm) * sign.
	if sigma > 0x20000000000000 && bound > 0xffffffffffffffff {

		var coeffInt, coeffU64, boundInt, coeffInt53, signInt, zero big.Int
		var coeffF64 big.Float

		Qi := make([]big.Int, len(moduli))

		for i, qi := range moduli {
			Qi[i] = *bignum.NewInt(qi)
		}

		new(big.Float).SetFloat64(bound).Int(&boundInt)

		/* #nosec G404: Source is cryptographically secure */
		r := rand.New(g.Source)

		for i := 0; i < len(coeffs[0]); i++ {

			for {
				norm = r.NormFloat64()

				/* #nosec G103: sign extraction of IEEE754 */
				sign = *(*uint64)(unsafe.Pointer(&norm)) >> 63

				signInt.SetInt64(2*int64(sign) - 1)

				// Sets coeffF64 to the scaled standard deviation.
				// Adds 0.5 to ensure proper rounding when converting to int.
				coeffF64.SetFloat64(math.Abs(norm*sigma) + 0.5).Int(&coeffInt)

				// If log2(coeffInt) > 53, then populates the
				// lower log2(coeffInt)-53 bits of coeffInt with
				// uniform bytes
				if coeffInt53.Rsh(&coeffInt, 53).Cmp(&zero) > 0 {
					coeffInt.Add(&coeffInt, bignum.RandInt(g.Source, &coeffInt53))
				}

				coeffInt.Mul(&coeffInt, &signInt)

				if coeffInt.Cmp(&boundInt) < 1 {
					break
				}
			}

			for j, qi := range moduli {
				coeffs[j][i] = f(coeffs[j][i], coeffU64.Mod(&coeffInt, &Qi[j]).Uint64(), qi)
			}
		}

	} else {

		var coeffInt uint64

		/* #nosec G404: Source is cryptographically secure */
		r := rand.New(g.Source)

		for i := 0; i < len(coeffs[0]); i++ {

			for {

				norm = r.NormFloat64()

				/* #nosec G103: sign extraction of IEEE754 */
				sign = *(*uint64)(unsafe.Pointer(&norm)) >> 63

				if v := math.Abs(norm * sigma); v <= bound {
					coeffInt = uint64(v + 0.5) // rounding
					break
				}
			}

			for j, qi := range moduli {
				coeffs[j][i] = f(coeffs[j][i], (coeffInt*sign)|(qi-coeffInt)*(sign^1), qi)
			}
		}
	}
}
