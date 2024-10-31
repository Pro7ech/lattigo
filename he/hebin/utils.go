package hebin

import (
	"math/big"

	"github.com/Pro7ech/lattigo/utils"
	"github.com/Pro7ech/lattigo/utils/bignum"
)

// MulBySmallMonomialMod2N multiplies pol by x^n, with 0 <= n < N
func mulBySmallMonomialMod2N(mask uint64, coeffs []uint64, n int) {
	if n != 0 {
		utils.RotateSliceAllocFree(coeffs, len(coeffs)-n, coeffs)
		for j := 0; j < n; j++ {
			coeffs[j] = -coeffs[j] & mask
		}
	}
}

func normalizeInv(x, a, b float64) (y float64) {
	return (x*(b-a) + b + a) / 2.0
}

func scaleUp(value float64, scale float64, Q uint64) (res uint64) {

	var isNegative bool
	var xFlo *big.Float
	var xInt *big.Int

	isNegative = false
	if value < 0 {
		isNegative = true
		xFlo = big.NewFloat(-scale * value)
	} else {
		xFlo = big.NewFloat(scale * value)
	}

	xFlo.Add(xFlo, big.NewFloat(0.5))

	xInt = new(big.Int)
	xFlo.Int(xInt)
	xInt.Mod(xInt, bignum.NewInt(Q))

	res = xInt.Uint64()

	if isNegative {
		res = Q - res
	}

	return
}
