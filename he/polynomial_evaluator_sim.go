package he

import (
	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
)

// SimOperand is a dummy operand that
// only stores its level and scale.
type SimOperand struct {
	Level  int
	Degree int
	Scale  rlwe.Scale
}

// SimEvaluator defines a set of method on SimOperands.
type SimEvaluator interface {
	LogDimensions() ring.Dimensions
	MulNew(op0, op1 *SimOperand) *SimOperand
	Rescale(op0 *SimOperand)
	PolynomialDepth(degree int) int
	UpdateLevelAndScaleGiantStep(lead bool, tLevelOld int, tScaleOld, xPowScale rlwe.Scale, p *Polynomial) (tLevelNew int, tScaleNew rlwe.Scale)
	UpdateLevelAndScaleBabyStep(lead bool, tLevelOld int, tScaleOld rlwe.Scale, p *Polynomial, pb SimPowerBasis) (tLevelNew int, tScaleNew rlwe.Scale, degree int)
}

// SimPowerBasis is a map storing powers of SimOperands indexed by their power.
type SimPowerBasis map[int]*SimOperand

// GenPower populates the target SimPowerBasis with the nth power.
func (d SimPowerBasis) GenPower(Lazy bool, n int, eval SimEvaluator) {

	if n < 2 {
		return
	}

	a, b := SplitDegree(n)

	d.GenPower(Lazy, a, eval)
	d.GenPower(Lazy, b, eval)

	d[a].Degree = 1
	d[b].Degree = 1

	d[n] = eval.MulNew(d[a], d[b])

	if Lazy {
		d[n].Degree = 2
	} else {
		d[n].Degree = 1
	}

	eval.Rescale(d[n])
}
