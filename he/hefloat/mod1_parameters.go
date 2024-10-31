package hefloat

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"math/bits"

	"github.com/Pro7ech/lattigo/he/hefloat/cosine"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/bignum"
)

// Mod1Type is the type of function/approximation used to evaluate x mod 1.
type Mod1Type uint64

// Sin and Cos are the two proposed functions for Mod1Type.
// These trigonometric functions offer a good approximation of the function x mod 1 when the values are close to the origin.
const (
	CosDiscrete   = Mod1Type(0) // Special approximation (Han and Ki) of pow((1/2pi), 1/2^r) * cos(2pi(x-0.25)/2^r); this method requires a minimum degree of 2*(K-1).
	SinContinuous = Mod1Type(1) // Standard Chebyshev approximation of (1/2pi) * sin(2pix) on the full Mod1Interval
	CosContinuous = Mod1Type(2) // Standard Chebyshev approximation of pow((1/2pi), 1/2^r) * cos(2pi(x-0.25)/2^r) on the full Mod1Interval
)

// Mod1ParametersLiteral a struct for the parameters of the mod 1 procedure.
// The x mod 1 procedure goal is to homomorphically evaluate a modular reduction by Q[0] (the first prime of the moduli chain) on the encrypted plaintext.
// This struct is consumed by `NewMod1ParametersLiteralFromLiteral` to generate the `Mod1ParametersLiteral` struct, which notably stores
// the coefficient of the polynomial approximating the function x mod Q[0].
type Mod1ParametersLiteral struct {
	LevelQ          int      // Starting level of x mod 1
	LogScale        int      // Log2 of the scaling factor used during x mod 1
	Mod1Type        Mod1Type // Chose between [Sin(2*pi*x)] or [cos(2*pi*x/r) with double angle formula]
	Scaling         float64  // Value by which the output is scaled by
	LogMessageRatio int      // Log2 of the ratio between Q0 and m, i.e. Q[0]/|m|
	Mod1Degree      int      // Degree of f: x mod 1
	Mod1Interval    int      // Interval of f: x mod 1
	DoubleAngle     int      // Number of rescale and double angle formula (only applies for cos and is ignored if sin is used)
	Mod1InvDegree   int      // Degree of f^-1: (x mod 1)^-1
}

// MarshalBinary returns a JSON representation of the the target Mod1ParametersLiteral struct on a slice of bytes.
// See `Marshal` from the `encoding/json` package.
func (evm Mod1ParametersLiteral) MarshalBinary() (data []byte, err error) {
	return json.Marshal(evm)
}

// UnmarshalBinary reads a JSON representation on the target Mod1ParametersLiteral struct.
// See `Unmarshal` from the `encoding/json` package.
func (evm *Mod1ParametersLiteral) UnmarshalBinary(data []byte) (err error) {
	return json.Unmarshal(data, evm)
}

// Depth returns the depth required to evaluate x mod 1.
func (evm Mod1ParametersLiteral) Depth() (depth int) {

	if evm.Mod1Type == CosDiscrete { // this method requires a minimum degree of 2*K-1.
		depth += int(bits.Len64(uint64(max(evm.Mod1Degree, 2*evm.Mod1Interval-1))))
	} else {
		depth += int(bits.Len64(uint64(evm.Mod1Degree)))
	}

	if evm.Mod1Type != SinContinuous {
		depth += evm.DoubleAngle
	}

	depth += int(bits.Len64(uint64(evm.Mod1InvDegree)))
	return depth
}

// Mod1Parameters is a struct storing the parameters and polynomials approximating the function x mod Q[0] (the first prime of the moduli chain).
type Mod1Parameters struct {
	LevelQ          int                // starting level of the operation
	LogDefaultScale int                // log2 of the default scaling factor
	Mod1Type        Mod1Type           // type of approximation for the f: x mod 1 function
	LogMessageRatio int                // Log2 of the ratio between Q0 and m, i.e. Q[0]/|m|
	DoubleAngle     int                // Number of rescale and double angle formula (only applies for cos and is ignored if sin is used)
	QDiff           float64            // Q / 2^round(Log2(Q))
	Sqrt2Pi         float64            // (1/2pi)^(1.0/scFac)
	Mod1Poly        *bignum.Polynomial // Polynomial for f: x mod 1
	Mod1InvPoly     *bignum.Polynomial // Polynomial for f^-1: (x mod 1)^-1
}

// Mod1Interval returns the unscaled interval of the polynomial
// approximation of f: x mod 1.
func (evp Mod1Parameters) Mod1Interval() float64 {
	f64, _ := evp.Mod1Poly.B.Float64()
	return f64 / evp.Mod1IntervalScalingFactor()
}

// Mod1IntervalScaled returns the scaled interval (by 1/2^{DoubleAngle})
// of the polynomial approximation of f: x mod 1.
func (evp Mod1Parameters) Mod1IntervalScaled() float64 {
	f64, _ := evp.Mod1Poly.A.Float64()
	return f64
}

// Mod1IntervalScalingFactor returns the value by which the interval
// of the polynomial approximation of f: x mod 1 is scaled by.
// This value is equal to 1/2^{DoubleAngle}.
func (evp Mod1Parameters) Mod1IntervalScalingFactor() float64 {
	return 1 / math.Exp2(float64(evp.DoubleAngle))
}

// ScalingFactor returns scaling factor used during the x mod 1.
func (evp Mod1Parameters) ScalingFactor() rlwe.Scale {
	return rlwe.NewScale(math.Exp2(float64(evp.LogDefaultScale)))
}

// MessageRatio returns the pre-set ratio Q[0]/|m|.
func (evp Mod1Parameters) MessageRatio() float64 {
	return float64(uint(1 << evp.LogMessageRatio))
}

// NewMod1ParametersFromLiteral generates an Mod1Parameters struct from the Mod1ParametersLiteral struct.
// The Mod1Parameters struct is to instantiates a Mod1Evaluator, which homomorphically evaluates x mod 1.
func NewMod1ParametersFromLiteral(params Parameters, evm Mod1ParametersLiteral) (Mod1Parameters, error) {

	if evm.Mod1Type == SinContinuous && evm.DoubleAngle != 0 {
		return Mod1Parameters{}, fmt.Errorf("cannot use double angle formula for Mod1Type = Sin -> must use Mod1Type = Cos")
	}

	if evm.Mod1Type == CosDiscrete && evm.Mod1Degree < 2*(evm.Mod1Interval-1) {
		return Mod1Parameters{}, fmt.Errorf("CosDiscrete uses a minimum degree of 2*(K-1) but Mod1Degree is smaller")
	}

	var mod1InvPoly *bignum.Polynomial
	var mod1Poly *bignum.Polynomial
	var sqrt2pi float64

	doubleAngle := evm.DoubleAngle
	if evm.Mod1Type == SinContinuous {
		doubleAngle = 0
	}

	scFac := math.Exp2(float64(doubleAngle))

	K := float64(evm.Mod1Interval) / scFac

	Q := params.Q()[0]
	qDiff := float64(Q) / math.Exp2(math.Round(math.Log2(float64(Q))))
	scaling := evm.Scaling

	if scaling == 0 {
		scaling = 1
	}

	if evm.Mod1InvDegree > 0 {

		sqrt2pi = 1.0

		coeffs := make([]complex128, evm.Mod1InvDegree+1)

		coeffs[1] = 0.15915494309189535 * complex(qDiff*scaling, 0)

		for i := 3; i < evm.Mod1InvDegree+1; i += 2 {
			coeffs[i] = coeffs[i-2] * complex(float64(i*i-4*i+4)/float64(i*i-i), 0)
		}

		p := bignum.NewPolynomial(bignum.Monomial, coeffs, nil)

		mod1InvPoly = p
		mod1InvPoly.IsEven = false

	} else {
		sqrt2pi = math.Pow(0.15915494309189535*qDiff*scaling, 1.0/scFac)
	}

	switch evm.Mod1Type {
	case SinContinuous:

		mod1Poly = bignum.ChebyshevApproximation(sin2pi, bignum.Interval{
			Nodes: evm.Mod1Degree,
			A:     *new(big.Float).SetPrec(cosine.EncodingPrecision).SetFloat64(-K),
			B:     *new(big.Float).SetPrec(cosine.EncodingPrecision).SetFloat64(K),
		})
		mod1Poly.IsEven = false

	case CosDiscrete:
		mod1Poly = bignum.NewPolynomial(bignum.Chebyshev, cosine.ApproximateCos(evm.Mod1Interval, evm.Mod1Degree, float64(uint(1<<evm.LogMessageRatio)), int(evm.DoubleAngle)), [2]float64{-K, K})
		mod1Poly.IsOdd = false

	case CosContinuous:
		mod1Poly = bignum.ChebyshevApproximation(cos2pi, bignum.Interval{
			Nodes: evm.Mod1Degree,
			A:     *new(big.Float).SetPrec(cosine.EncodingPrecision).SetFloat64(-K),
			B:     *new(big.Float).SetPrec(cosine.EncodingPrecision).SetFloat64(K),
		})
		mod1Poly.IsOdd = false

	default:
		return Mod1Parameters{}, fmt.Errorf("invalid Mod1Type")
	}

	sqrt2piBig := new(big.Float).SetFloat64(sqrt2pi)
	for i := range mod1Poly.Coeffs {
		mod1Poly.Coeffs[i][0].Mul(&mod1Poly.Coeffs[i][0], sqrt2piBig)
		mod1Poly.Coeffs[i][1].Mul(&mod1Poly.Coeffs[i][1], sqrt2piBig)
	}

	return Mod1Parameters{
		LevelQ:          evm.LevelQ,
		LogDefaultScale: evm.LogScale,
		Mod1Type:        evm.Mod1Type,
		LogMessageRatio: evm.LogMessageRatio,
		DoubleAngle:     doubleAngle,
		QDiff:           qDiff,
		Sqrt2Pi:         sqrt2pi,
		Mod1Poly:        mod1Poly,
		Mod1InvPoly:     mod1InvPoly,
	}, nil
}

func sin2pi(x *big.Float) (y *big.Float) {
	y = new(big.Float).Set(x)
	y.Mul(y, new(big.Float).SetFloat64(2))
	y.Mul(y, bignum.Pi(x.Prec()))
	return bignum.Sin(y)
}

func cos2pi(x *big.Float) (y *big.Float) {
	y = new(big.Float).Set(x)
	y.Mul(y, new(big.Float).SetFloat64(2))
	y.Mul(y, bignum.Pi(x.Prec()))
	y = bignum.Cos(y)
	return y
}
