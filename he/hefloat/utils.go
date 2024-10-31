package hefloat

import (
	"math"
	"math/big"

	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/bignum"
)

// GetRootsBigComplex returns the roots e^{2*pi*i/m *j} for 0 <= j <= NthRoot
// with prec bits of precision.
func GetRootsBigComplex(NthRoot int, prec uint) (roots []bignum.Complex) {

	roots = make([]bignum.Complex, NthRoot+1)

	quarm := NthRoot >> 2

	Pi := bignum.Pi(prec)

	e2ipi := bignum.NewFloat(2, prec)
	e2ipi.Mul(e2ipi, Pi)
	e2ipi.Quo(e2ipi, bignum.NewFloat(float64(NthRoot), prec))

	angle := new(big.Float).SetPrec(prec)

	roots[0][0].SetPrec(prec).SetInt64(1)
	roots[0][1].SetPrec(prec)

	for i := 1; i < quarm; i++ {
		roots[i][0].Set(bignum.Cos(angle.Mul(e2ipi, bignum.NewFloat(float64(i), prec))))
	}

	for i := 1; i < quarm; i++ {
		roots[quarm-i][1].Set(&roots[i][0])
	}

	roots[quarm][0].SetPrec(prec)
	roots[quarm][1].SetPrec(prec).SetInt64(1)

	for i := 1; i < quarm+1; i++ {
		roots[i+1*quarm][0].Neg(roots[quarm-i].Real())
		roots[i+1*quarm][1].Set(roots[quarm-i].Imag())
		roots[i+2*quarm][0].Neg(roots[i].Real())
		roots[i+2*quarm][1].Neg(roots[i].Imag())
		roots[i+3*quarm][0].Set(roots[quarm-i].Real())
		roots[i+3*quarm][1].Neg(roots[quarm-i].Imag())
	}

	roots[NthRoot].Set(&roots[0])

	return
}

// GetRootsComplex128 returns the roots e^{2*pi*i/m *j} for 0 <= j <= NthRoot.
func GetRootsComplex128(NthRoot int) (roots []complex128) {
	roots = make([]complex128, NthRoot+1)

	quarm := NthRoot >> 2

	angle := 2 * 3.141592653589793 / float64(NthRoot)

	for i := 0; i < quarm; i++ {
		roots[i] = complex(math.Cos(angle*float64(i)), 0)
	}

	for i := 0; i < quarm; i++ {
		roots[quarm-i] += complex(0, real(roots[i]))
	}

	for i := 1; i < quarm+1; i++ {
		roots[i+1*quarm] = complex(-real(roots[quarm-i]), imag(roots[quarm-i]))
		roots[i+2*quarm] = -roots[i]
		roots[i+3*quarm] = complex(real(roots[quarm-i]), -imag(roots[quarm-i]))
	}

	roots[NthRoot] = roots[0]

	return
}

// StandardDeviation computes the scaled standard deviation of the input vector.
func StandardDeviation(vec interface{}, scale rlwe.Scale) (std float64) {

	switch vec := vec.(type) {
	case []float64:
		// We assume that the error is centered around zero
		var err, tmp, mean, n float64

		n = float64(len(vec))

		for _, c := range vec {
			mean += c
		}

		mean /= n

		for _, c := range vec {
			tmp = c - mean
			err += tmp * tmp
		}

		std = math.Sqrt(err/(n-1)) * scale.Float64()
	case []big.Float:
		mean := new(big.Float)

		for i := range vec {
			mean.Add(mean, &vec[i])
		}

		mean.Quo(mean, new(big.Float).SetInt64(int64(len(vec))))

		err := new(big.Float)
		tmp := new(big.Float)
		for i := range vec {
			tmp.Sub(&vec[i], mean)
			tmp.Mul(tmp, tmp)
			err.Add(err, tmp)
		}

		err.Quo(err, new(big.Float).SetInt64(int64(len(vec)-1)))
		err.Sqrt(err)
		err.Mul(err, &scale.Value)

		std, _ = err.Float64()
	}

	return
}

// Complex128ToFixedPointCRT encodes a vector of complex128 on a CRT polynomial.
// The real part is put in a left N/2 coefficient and the imaginary in the right N/2 coefficients.
func Complex128ToFixedPointCRT(r ring.RNSRing, values []complex128, scale float64, coeffs ring.RNSPoly) {

	for i, v := range values {
		SingleFloat64ToFixedPointCRT(r, i, real(v), scale, coeffs)
	}

	var start int
	if r.Type() == ring.Standard {
		slots := len(values)
		for i, v := range values {
			SingleFloat64ToFixedPointCRT(r, i+slots, imag(v), scale, coeffs)
		}

		start = 2 * len(values)

	} else {
		start = len(values)
	}

	end := len(coeffs[0])
	for i := start; i < end; i++ {
		SingleFloat64ToFixedPointCRT(r, i, 0, 0, coeffs)
	}
}

// Float64ToFixedPointCRT encodes a vector of floats on a CRT polynomial.
func Float64ToFixedPointCRT(r ring.RNSRing, values []float64, scale float64, coeffs ring.RNSPoly) {

	start := len(values)
	end := len(coeffs[0])

	for i := 0; i < start; i++ {
		SingleFloat64ToFixedPointCRT(r, i, values[i], scale, coeffs)
	}

	for i := start; i < end; i++ {
		SingleFloat64ToFixedPointCRT(r, i, 0, 0, coeffs)
	}
}

// SingleFloat64ToFixedPointCRT encodes a single float64 on a CRT polynomialon in the i-th coefficient.
func SingleFloat64ToFixedPointCRT(r ring.RNSRing, i int, value float64, scale float64, coeffs ring.RNSPoly) {

	if value == 0 {
		for j := range coeffs {
			coeffs[j][i] = 0
		}

		return
	}

	var isNegative bool
	var xFlo *big.Float
	var xInt *big.Int
	tmp := new(big.Int)
	var c uint64

	isNegative = false

	if value < 0 {
		isNegative = true
		scale *= -1
	}

	value *= scale

	moduli := r.ModuliChain()[:r.Level()+1]

	if value >= 1.8446744073709552e+19 {
		xFlo = big.NewFloat(value)
		xFlo.Add(xFlo, big.NewFloat(0.5))
		xInt = new(big.Int)
		xFlo.Int(xInt)
		for j := range moduli {
			tmp.Mod(xInt, bignum.NewInt(moduli[j]))
			if isNegative {
				coeffs[j][i] = moduli[j] - tmp.Uint64()
			} else {
				coeffs[j][i] = tmp.Uint64()
			}
		}

	} else {
		brc := r.BRedConstants()

		c = uint64(value + 0.5)
		if isNegative {
			for j, qi := range moduli {
				if c > qi {
					coeffs[j][i] = qi - ring.BRedAdd(c, qi, brc[j])
				} else {
					coeffs[j][i] = qi - c
				}
			}
		} else {
			for j, qi := range moduli {
				if c > 0x1fffffffffffffff {
					coeffs[j][i] = ring.BRedAdd(c, qi, brc[j])
				} else {
					coeffs[j][i] = c
				}
			}
		}
	}
}

func ComplexArbitraryToFixedPointCRT(r ring.RNSRing, values []bignum.Complex, scale *big.Float, coeffs ring.RNSPoly) {

	xFlo := new(big.Float)
	xInt := new(big.Int)
	tmp := new(big.Int)

	zero := new(big.Float)

	half := new(big.Float).SetFloat64(0.5)

	moduli := r.ModuliChain()[:r.Level()+1]

	var negative bool

	for i := range values {

		xFlo.Mul(scale, &values[i][0])

		if values[i][0].Cmp(zero) < 0 {
			xFlo.Sub(xFlo, half)
			negative = true
		} else {
			xFlo.Add(xFlo, half)
			negative = false
		}

		xFlo.Int(xInt)

		for j := range moduli {

			Q := bignum.NewInt(moduli[j])

			tmp.Mod(xInt, Q)

			if negative {
				tmp.Add(tmp, Q)
			}

			coeffs[j][i] = tmp.Uint64()
		}
	}

	if r.Type() == ring.Standard {

		slots := len(values)

		for i := range values {

			xFlo.Mul(scale, &values[i][1])

			if values[i][1].Cmp(zero) < 0 {
				xFlo.Sub(xFlo, half)
				negative = true
			} else {
				xFlo.Add(xFlo, half)
				negative = false
			}

			xFlo.Int(xInt)

			for j := range moduli {

				Q := bignum.NewInt(moduli[j])

				tmp.Mod(xInt, Q)

				if negative {
					tmp.Add(tmp, Q)
				}
				coeffs[j][i+slots] = tmp.Uint64()
			}
		}
	}
}

func BigFloatToFixedPointCRT(r ring.RNSRing, values []big.Float, scale *big.Float, coeffs ring.RNSPoly) {

	prec := values[0].Prec()

	xFlo := bignum.NewFloat(0, prec)
	xInt := new(big.Int)
	tmp := new(big.Int)

	zero := new(big.Float)

	half := bignum.NewFloat(0.5, prec)

	moduli := r.ModuliChain()[:r.Level()+1]

	for i := range values {

		if values[i].Cmp(zero) == 0 {
			for j := range moduli {
				coeffs[j][i] = 0
			}
		} else {

			xFlo.Mul(scale, &values[i])

			if values[i].Cmp(zero) < 0 {
				xFlo.Sub(xFlo, half)
			} else {
				xFlo.Add(xFlo, half)
			}

			xFlo.Int(xInt)

			for j := range moduli {

				Q := bignum.NewInt(moduli[j])

				tmp.Mod(xInt, Q)

				if values[i].Cmp(zero) < 0 {
					tmp.Add(tmp, Q)
				}

				coeffs[j][i] = tmp.Uint64()
			}
		}
	}
}
