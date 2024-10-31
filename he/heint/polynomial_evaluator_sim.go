package heint

import (
	"math/big"
	"math/bits"

	"github.com/Pro7ech/lattigo/he"
	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
)

// simEvaluator is a struct used to pre-computed the scaling
// factors of the polynomial coefficients used by the inlined
// polynomial evaluation by running the polynomial evaluation
// with dummy operands.
// This struct implements the interface he.SimEvaluator.
type simEvaluator struct {
	params             Parameters
	InvariantTensoring bool
}

// PolynomialDepth returns the depth of the polynomial.
func (d simEvaluator) PolynomialDepth(degree int) int {
	if d.InvariantTensoring {
		return 0
	}
	return bits.Len64(uint64(degree)) - 1
}

// LogDimensions returns the base-two logarithm of the plaintext shape.
func (d simEvaluator) LogDimensions() ring.Dimensions {
	return d.params.LogMaxDimensions()
}

// Rescale rescales the target he.SimOperand n times and returns it.
func (d simEvaluator) Rescale(op0 *he.SimOperand) {
	if !d.InvariantTensoring {
		op0.Scale = op0.Scale.Div(rlwe.NewScale(d.params.Q()[op0.Level]))
		op0.Level--
	}
}

// MulNew multiplies two he.SimOperand, stores the result the target he.SimOperand and returns the result.
func (d simEvaluator) MulNew(op0, op1 *he.SimOperand) (opOut *he.SimOperand) {
	opOut = new(he.SimOperand)
	opOut.Level = min(op0.Level, op1.Level)
	opOut.Degree = 1

	// If op0 or op1 Degree == 0, then its ct x pt mul with regular
	// tensoring
	if !d.InvariantTensoring || op0.Degree == 0 || op1.Degree == 0 {
		opOut.Scale = op0.Scale.Mul(op1.Scale)
	} else {
		opOut.Scale = UpdateScaleInvariant(d.params, op0.Scale, op1.Scale, opOut.Level)
	}

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
	if !d.InvariantTensoring && lead {
		tScaleNew = tScaleOld.Mul(d.params.NewScale(d.params.Q()[tLevelOld]))
	}

	return
}

// UpdateLevelAndScaleGiantStep returns the updated level and scale for a giant-step.
func (d simEvaluator) UpdateLevelAndScaleGiantStep(lead bool, tLevelOld int, tScaleOld, xPowScale rlwe.Scale, pol *he.Polynomial) (tLevelNew int, tScaleNew rlwe.Scale) {

	Q := d.params.Q()

	tLevelNew = tLevelOld
	tScaleNew = tScaleOld.Div(xPowScale)

	// tScaleNew = targetScale*currentQi/XPow.Scale
	if !d.InvariantTensoring {

		var currentQi uint64
		if lead {
			currentQi = Q[tLevelNew]
		} else {
			currentQi = Q[tLevelNew+1]
		}

		tScaleNew = tScaleNew.Mul(d.params.NewScale(currentQi))

	} else {

		minimumDegreeNonZeroCoefficient := len(pol.Coeffs) - 1
		if pol.IsEven && !pol.IsOdd {
			minimumDegreeNonZeroCoefficient = max(0, minimumDegreeNonZeroCoefficient-1)
		}

		// If minimumDegreeNonZeroCoefficient == 0, then the target scale stays the same
		// since we have pt x ct multiplication (no invariant tensoring and not rescaling)
		if minimumDegreeNonZeroCoefficient != 0 {
			T := d.params.PlaintextModulus()

			// -Q mod T
			qModTNeg := new(big.Int).Mod(d.params.RingQ().AtLevel(tLevelNew).Modulus(), new(big.Int).SetUint64(T)).Uint64()
			qModTNeg = T - qModTNeg
			tScaleNew = tScaleNew.Mul(d.params.NewScale(qModTNeg))
		}

	}

	if !d.InvariantTensoring {
		tLevelNew++
	}

	return
}
