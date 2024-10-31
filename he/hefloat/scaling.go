package hefloat

import (
	"math/big"

	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/utils/bignum"
)

func bigComplexToRNSScalar(r ring.RNSRing, scale *big.Float, cmplx *bignum.Complex) (RNSReal, RNSImag ring.RNSScalar) {

	if scale == nil {
		scale = new(big.Float).SetFloat64(1)
	}

	real := new(big.Int)
	bReal := new(big.Float).Mul(&cmplx[0], scale)

	if cmp := cmplx[0].Cmp(new(big.Float)); cmp > 0 {
		bReal.Add(bReal, new(big.Float).SetFloat64(0.5))
	} else if cmp < 0 {
		bReal.Sub(bReal, new(big.Float).SetFloat64(0.5))
	}

	bReal.Int(real)

	imag := new(big.Int)
	bImag := new(big.Float).Mul(&cmplx[1], scale)

	if cmp := cmplx[1].Cmp(new(big.Float)); cmp > 0 {
		bImag.Add(bImag, new(big.Float).SetFloat64(0.5))
	} else if cmp < 0 {
		bImag.Sub(bImag, new(big.Float).SetFloat64(0.5))
	}

	bImag.Int(imag)

	return r.NewRNSScalarFromBigint(real), r.NewRNSScalarFromBigint(imag)
}

// Divides x by n, returns a float.
func scaleDown(coeff *big.Int, n float64) (x float64) {

	x, _ = new(big.Float).SetInt(coeff).Float64()
	x /= n

	return
}
