package hefloat

import (
	"math/big"
	"math/bits"

	"github.com/Pro7ech/lattigo/he"
	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/bignum"
)

// simEvaluator is a struct used to pre-computed the scaling
// factors of the polynomial coefficients used by the inlined
// polynomial evaluation by running the polynomial evaluation
// with dummy operands.
// This struct implements the interface he.SimEvaluator.
type simEvaluator struct {
	params Parameters
}

// LogDimensions returns the base-two logarithm of the plaintext shape.
func (d simEvaluator) LogDimensions() ring.Dimensions {
	return d.params.LogMaxDimensions()
}

// LevelsConsumedPerRescaling returns the number of level consumed by a rescaling.
func (d simEvaluator) LevelsConsumedPerRescaling() int {
	return d.params.LevelsConsumedPerRescaling()
}

// PolynomialDepth returns the depth of the polynomial.
func (d simEvaluator) PolynomialDepth(degree int) int {
	return d.LevelsConsumedPerRescaling() * (bits.Len64(uint64(degree)) - 1)
}

// Rescale rescales the target he.SimOperand n times and returns it.
func (d simEvaluator) Rescale(op0 *he.SimOperand) {
	for i := 0; i < d.LevelsConsumedPerRescaling(); i++ {
		op0.Scale = op0.Scale.Div(rlwe.NewScale(d.params.Q()[op0.Level]))
		op0.Level--
	}
}

// MulNew multiplies two he.SimOperand, stores the result the target he.SimOperand and returns the result.
func (d simEvaluator) MulNew(op0, op1 *he.SimOperand) (opOut *he.SimOperand) {
	opOut = new(he.SimOperand)
	opOut.Level = min(op0.Level, op1.Level)
	opOut.Scale = op0.Scale.Mul(op1.Scale)
	return
}

// UpdateLevelAndScaleBabyStep returns the updated level and scale for a baby-step.
func (d simEvaluator) UpdateLevelAndScaleBabyStep(lead bool, tLevelOld int, tScaleOld rlwe.Scale, pol *he.Polynomial, pb he.SimPowerBasis) (tLevelNew int, tScaleNew rlwe.Scale, maximumCiphertextDegree int) {

	minimumDegreeNonZeroCoefficient := len(pol.Coeffs) - 1
	if pol.IsEven && !pol.IsOdd {
		minimumDegreeNonZeroCoefficient = max(0, minimumDegreeNonZeroCoefficient-1)
	}

	maximumCiphertextDegree = 0
	for i := pol.Degree(); i > 0; i-- {
		if x, ok := pb[i]; ok {
			maximumCiphertextDegree = max(maximumCiphertextDegree, x.Degree)
		}
	}

	if minimumDegreeNonZeroCoefficient < 1 {
		maximumCiphertextDegree = 0
	}

	tLevelNew = tLevelOld
	tScaleNew = tScaleOld

	if lead {
		for i := 0; i < d.LevelsConsumedPerRescaling(); i++ {
			tScaleNew = tScaleNew.Mul(rlwe.NewScale(d.params.Q()[tLevelNew-i]))
		}
	}

	return
}

// UpdateLevelAndScaleGiantStep returns the updated level and scale for a giant-step.
func (d simEvaluator) UpdateLevelAndScaleGiantStep(lead bool, tLevelOld int, tScaleOld, xPowScale rlwe.Scale, pol *he.Polynomial) (tLevelNew int, tScaleNew rlwe.Scale) {

	Q := d.params.Q()

	var qi *big.Int
	if lead {
		qi = bignum.NewInt(Q[tLevelOld])
		for i := 1; i < d.LevelsConsumedPerRescaling(); i++ {
			qi.Mul(qi, bignum.NewInt(Q[tLevelOld-i]))
		}
	} else {
		qi = bignum.NewInt(Q[tLevelOld+d.LevelsConsumedPerRescaling()])
		for i := 1; i < d.LevelsConsumedPerRescaling(); i++ {
			qi.Mul(qi, bignum.NewInt(Q[tLevelOld+d.LevelsConsumedPerRescaling()-i]))
		}
	}

	tLevelNew = tLevelOld + d.LevelsConsumedPerRescaling()
	tScaleNew = tScaleOld.Mul(rlwe.NewScale(qi))
	tScaleNew = tScaleNew.Div(xPowScale)

	return
}
