// Package hebin implements blind rotations evaluation for RLWE schemes.
package hebin

import (
	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
)

// InitTestPolynomial takes a function g, and creates a test polynomial polynomial for the function in the interval [a, b].
// Inputs to the blind rotation evaluation are assumed to have been normalized with the change of basis (2*x - a - b)/(b-a).
// Interval [a, b] should take into account the "drift" of the value x, caused by the change of modulus from Q to 2N.
func InitTestPolynomial(g func(x float64) (y float64), scale rlwe.Scale, rQ ring.RNSRing, a, b float64) (F ring.RNSPoly) {
	F = rQ.NewRNSPoly()
	Q := rQ.ModuliChain()[:rQ.Level()+1]

	sf64 := scale.Float64()

	N := rQ.N()

	// Discretization interval
	interval := 2.0 / float64(N)

	for j, qi := range Q {

		// Interval [-1, 0] of g(x)
		for i := 0; i < (N>>1)+1; i++ {
			F.At(j)[i] = scaleUp(g(normalizeInv(-interval*float64(i), a, b)), sf64, qi)
		}

		// Interval ]0, 1[ of g(x)
		for i := (N >> 1) + 1; i < N; i++ {
			F.At(j)[i] = scaleUp(-g(normalizeInv(interval*float64(N-i), a, b)), sf64, qi)
		}
	}

	rQ.NTT(F, F)

	return
}
