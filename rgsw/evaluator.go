package rgsw

import (
	"fmt"

	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
)

// Evaluator is a type for evaluating homomorphic operations involving RGSW ciphertexts.
// It currently supports the external product between a RLWE and a RGSW ciphertext (see
// Evaluator.ExternalProduct).
type Evaluator struct {
	rlwe.Evaluator
}

// NewEvaluator creates a new Evaluator type supporting RGSW operations in addition
// to rlwe.Evaluator operations.
func NewEvaluator(params rlwe.ParameterProvider, evk rlwe.EvaluationKeySet) *Evaluator {
	return &Evaluator{*rlwe.NewEvaluator(params, evk)}
}

// ShallowCopy creates a shallow copy of this Evaluator in which all the read-only data-structures are
// shared with the receiver and the temporary buffers are reallocated. The receiver and the returned
// Evaluators can be used concurrently.
func (eval Evaluator) ShallowCopy() *Evaluator {
	return &Evaluator{*eval.Evaluator.ShallowCopy()}
}

// WithKey creates a shallow copy of the receiver Evaluator for which the new EvaluationKey is evaluationKey
// and where the temporary buffers are shared. The receiver and the returned Evaluators cannot be used concurrently.
func (eval Evaluator) WithKey(evk rlwe.EvaluationKeySet) *Evaluator {
	return &Evaluator{*eval.Evaluator.WithKey(evk)}
}

// Product computes the left to right RGSW (op0) x RGSW (op1) -> RGSW (op2) product.
//
// Product is evaluated as two series of external products:
// - RLWE[0][i][j] x RGSW -> RLWE[0][i][j]
// - RLWE[1][i][j] x RGSW -> RLWE[1][i][j]
//
// The method will return an error if
// - op0.LevelQ() != op2.LevelQ()
// - op0.LevelP() or op2.LevelP() != -1
func (eval Evaluator) Product(op0, op1, op2 *Ciphertext) (err error) {

	if op0.LevelQ() != op2.LevelQ() {
		return fmt.Errorf("invalid inputs: op0 and op2 LevelQ does not match")
	}

	if op0.LevelP() != -1 || op2.LevelP() != -1 {
		return fmt.Errorf("invalid inputs: op1 and op2 LevelP must be -1")
	}

	rQ := eval.GetRLWEParameters().RingQAtLevel(min(op0.LevelQ(), op2.LevelQ()))

	dims := op0.At(0).Dims()
	for k := range 2 {
		for i := range dims {
			for j := range dims[i] {

				c0 := op0.At(k).At(i, j)
				c1 := op0.At(k).At(i, j)

				rQ.IMForm(c0.Q[0], c0.Q[0])
				rQ.IMForm(c0.Q[1], c0.Q[1])

				eval.ExternalProduct(c0, op1, c1)

				rQ.MForm(c1.Q[0], c1.Q[0])
				rQ.MForm(c1.Q[1], c1.Q[1])
			}
		}
	}

	return
}

// ExternalProduct computes RLWE x RGSW -> RLWE
//
//	RLWE : (-as + m + e, a)
//	x
//	RGSW : [(-as + P*w*m1 + e, a), (-bs + e, b + P*w*m1)]
//	=
//	RLWE : (<RLWE, RGSW[0]>, <RLWE, RGSW[1]>)
func (eval Evaluator) ExternalProduct(op0 *rlwe.Ciphertext, op1 *Ciphertext, opOut *rlwe.Ciphertext) {

	LevelQ, LevelP := op1.LevelQ(), op1.LevelP()

	c0Q := eval.BuffQ[1]
	c1Q := eval.BuffQ[2]

	var c0P, c1P ring.RNSPoly
	if LevelP > -1 {
		c0P = eval.BuffP[1]
		c1P = eval.BuffP[2]
	}

	params := eval.GetRLWEParameters()

	// If log(Q) * (Q-1)**2 < 2^{64}-1
	if rQ := params.RingQ(); LevelQ == 0 && LevelP == -1 && (rQ[0].Modulus>>29) == 0 {
		eval.externalProduct32Bit(op0, op1, c0Q, c1Q)
		rQ.AtLevel(0).IMForm(c0Q, opOut.Q[0])
		rQ.AtLevel(0).IMForm(c1Q, opOut.Q[1])
	} else {

		tmp, err := rlwe.NewCiphertextAtLevelFromPoly(LevelQ, LevelP, []ring.RNSPoly{c0Q, c1Q}, []ring.RNSPoly{c0P, c1P})
		if err != nil {
			panic(err)
		}
		tmp.IsNTT = true

		if err := eval.GadgetProductLazy(LevelQ, true, op0.Q[0], true, op1.At(0), tmp); err != nil {
			panic(err)
		}

		if err := eval.GadgetProductLazy(LevelQ, false, op0.Q[1], true, op1.At(1), tmp); err != nil {
			panic(err)
		}

		if LevelP != -1 {
			rQ = rQ.AtLevel(LevelQ)
			rP := params.RingP().AtLevel(LevelP)
			rQ.ModDownNTT(rP, c0Q, c0P, eval.BuffModDownQ, eval.BuffModDownP, opOut.Q[0])
			rQ.ModDownNTT(rP, c1Q, c1P, eval.BuffModDownQ, eval.BuffModDownP, opOut.Q[1])
		} else {
			opOut.Q[0].CopyLvl(LevelQ, &c0Q)
			opOut.Q[1].CopyLvl(LevelQ, &c1Q)
		}
	}
}

func (eval Evaluator) externalProduct32Bit(ct0 *rlwe.Ciphertext, rgsw *Ciphertext, c0, c1 ring.RNSPoly) {

	// rgsw = [(-as + P*w*m1 + e, a), (-bs + e, b + P*w*m1)]
	// ct = [-cs + m0 + e, c]
	// opOut = [<ct, rgsw[0]>, <ct, rgsw[1]>] = [ct[0] * rgsw[0][0] + ct[1] * rgsw[0][1], ct[0] * rgsw[1][0] + ct[1] * rgsw[1][1]]
	params := eval.GetRLWEParameters()
	subRing := params.RingQ()[0]

	cw := eval.BuffQ[0].At(0)

	ddt := rgsw.DigitDecomposition.Type
	log2basis := rgsw.DigitDecomposition.Log2Basis

	var decompose func(s *ring.Ring, i int, log2basis uint64, signed, cw []uint64)
	var centermod func(s *ring.Ring, in, out []uint64)

	signed := eval.BuffInvNTT.At(0)
	carry := eval.BuffDigitDecomp[0]

	switch ddt {
	case rlwe.Unsigned:
		decompose = func(s *ring.Ring, i int, log2basis uint64, in, out []uint64) {
			s.DecomposeUnsigned(i, log2basis, in, out)
		}
		centermod = func(s *ring.Ring, in, out []uint64) {
			copy(out, in)
		}
	case rlwe.Signed:
		decompose = func(s *ring.Ring, i int, log2basis uint64, in, out []uint64) {
			s.DecomposeSigned(i, log2basis, in, carry, out)
		}
		centermod = func(s *ring.Ring, in, out []uint64) {
			s.CenterModU64(in, out)
		}
	case rlwe.SignedBalanced:
		decompose = func(s *ring.Ring, i int, log2basis uint64, in, out []uint64) {
			s.DecomposeSignedBalanced(i, log2basis, in, carry, out)
		}
		centermod = func(s *ring.Ring, in, out []uint64) {
			s.CenterModU64(in, out)
		}
	}

	acc0 := c0.At(0)
	acc1 := c1.At(0)

	// (a, b) + (c0 * rgsw[0][0], c0 * rgsw[0][1])
	// (a, b) + (c1 * rgsw[1][0], c1 * rgsw[1][1])
	for i, el := range rgsw.Matrix {
		subRing.INTT(ct0.Q[i].At(0), signed)
		centermod(subRing, signed, signed)
		for j := range el[0].Q[0] {
			decompose(subRing, j, uint64(log2basis), signed, cw)
			subRing.NTTLazy(cw, cw)
			if j == 0 && i == 0 {
				subRing.MulCoeffsLazy(el[0].Q[0][j].At(0), cw, acc0)
				subRing.MulCoeffsLazy(el[1].Q[0][j].At(0), cw, acc1)
			} else {
				subRing.MulCoeffsLazyThenAddLazy(el[0].Q[0][j].At(0), cw, acc0)
				subRing.MulCoeffsLazyThenAddLazy(el[1].Q[0][j].At(0), cw, acc1)
			}
		}
	}
}

// AddLazy adds op to opOut, without modular reduction.
func AddLazy(rQ, rP ring.RNSRing, op interface{}, opOut *Ciphertext) {
	switch el := op.(type) {
	case *Plaintext:

		nQ := rQ.Level() + 1

		var nP int
		if rP != nil {
			nP = rP.Level() + 1
		}

		if nP == 0 {
			nP = 1
		}

		s := rQ[0] // Doesn't matter which one since we add without modular reduction

		for i := range opOut.Matrix[0][0].Q {
			for j := range opOut.Matrix[0][0].Q[i] {
				start, end := i*nP, (i+1)*nP
				if end > nQ {
					end = nQ
				}
				for k := start; k < end; k++ {
					s.AddLazy(opOut.Matrix[0][0].Q[i][j].At(k), el.Value[j].At(k), opOut.Matrix[0][0].Q[i][j].At(k))
					s.AddLazy(opOut.Matrix[1][1].Q[i][j].At(k), el.Value[j].At(k), opOut.Matrix[1][1].Q[i][j].At(k))
				}
			}
		}
	case *Ciphertext:
		for i := range opOut.Matrix[0][0].Q {
			for j := range opOut.Matrix[0][0].Q[i] {
				rQ.AddLazy(opOut.Matrix[0][0].Q[i][j], el.Matrix[0][0].Q[i][j], opOut.Matrix[0][0].Q[i][j])
				rQ.AddLazy(opOut.Matrix[0][1].Q[i][j], el.Matrix[0][1].Q[i][j], opOut.Matrix[0][1].Q[i][j])
				rQ.AddLazy(opOut.Matrix[1][0].Q[i][j], el.Matrix[1][0].Q[i][j], opOut.Matrix[1][0].Q[i][j])
				rQ.AddLazy(opOut.Matrix[1][1].Q[i][j], el.Matrix[1][1].Q[i][j], opOut.Matrix[1][1].Q[i][j])

				if rP != nil {
					rP.AddLazy(opOut.Matrix[0][0].P[i][j], el.Matrix[0][0].P[i][j], opOut.Matrix[0][0].P[i][j])
					rP.AddLazy(opOut.Matrix[0][1].P[i][j], el.Matrix[0][1].P[i][j], opOut.Matrix[0][1].P[i][j])
					rP.AddLazy(opOut.Matrix[1][0].P[i][j], el.Matrix[1][0].P[i][j], opOut.Matrix[1][0].P[i][j])
					rP.AddLazy(opOut.Matrix[1][1].P[i][j], el.Matrix[1][1].P[i][j], opOut.Matrix[1][1].P[i][j])
				}
			}
		}
	default:
		panic("cannot AddLazy: unsuported op.(type), must be either *rgsw.Plaintext or *rgsw.Ciphertext")
	}
}

// Reduce applies the modular reduction on ctIn and returns the result on opOut.
func Reduce(rQ, rP *ring.RNSRing, ctIn *Ciphertext, opOut *Ciphertext) {
	for i := range ctIn.Matrix[0][0].Q {
		for j := range ctIn.Matrix[0][0].Q[i] {

			rQ.Reduce(ctIn.Matrix[0][0].Q[i][j], opOut.Matrix[0][0].Q[i][j])
			rQ.Reduce(ctIn.Matrix[0][1].Q[i][j], opOut.Matrix[0][1].Q[i][j])
			rQ.Reduce(ctIn.Matrix[1][0].Q[i][j], opOut.Matrix[1][0].Q[i][j])
			rQ.Reduce(ctIn.Matrix[1][1].Q[i][j], opOut.Matrix[1][1].Q[i][j])

			if rP != nil {
				rP.Reduce(ctIn.Matrix[0][0].P[i][j], opOut.Matrix[0][0].P[i][j])
				rP.Reduce(ctIn.Matrix[0][1].P[i][j], opOut.Matrix[0][1].P[i][j])
				rP.Reduce(ctIn.Matrix[1][0].P[i][j], opOut.Matrix[1][0].P[i][j])
				rP.Reduce(ctIn.Matrix[1][1].P[i][j], opOut.Matrix[1][1].P[i][j])
			}
		}
	}
}

// MulByXPowAlphaMinusOneLazy multiplies opOut by (X^alpha - 1) and returns the result on opOut.
func MulByXPowAlphaMinusOneLazy(rQ, rP *ring.RNSRing, ctIn *Ciphertext, powXMinusOne [2]ring.RNSPoly, opOut *Ciphertext) {
	for i := range ctIn.Matrix[0][0].Q {
		for j := range ctIn.Matrix[0][0].Q[i] {

			rQ.MulCoeffsMontgomeryLazy(ctIn.Matrix[0][0].Q[i][j], powXMinusOne[0], opOut.Matrix[0][0].Q[i][j])
			rQ.MulCoeffsMontgomeryLazy(ctIn.Matrix[0][1].Q[i][j], powXMinusOne[0], opOut.Matrix[0][1].Q[i][j])
			rQ.MulCoeffsMontgomeryLazy(ctIn.Matrix[1][0].Q[i][j], powXMinusOne[0], opOut.Matrix[1][0].Q[i][j])
			rQ.MulCoeffsMontgomeryLazy(ctIn.Matrix[1][1].Q[i][j], powXMinusOne[0], opOut.Matrix[1][1].Q[i][j])

			if rP != nil {
				rP.MulCoeffsMontgomeryLazy(ctIn.Matrix[0][0].P[i][j], powXMinusOne[1], opOut.Matrix[0][0].P[i][j])
				rP.MulCoeffsMontgomeryLazy(ctIn.Matrix[0][1].P[i][j], powXMinusOne[1], opOut.Matrix[0][1].P[i][j])
				rP.MulCoeffsMontgomeryLazy(ctIn.Matrix[1][0].P[i][j], powXMinusOne[1], opOut.Matrix[1][0].P[i][j])
				rP.MulCoeffsMontgomeryLazy(ctIn.Matrix[1][1].P[i][j], powXMinusOne[1], opOut.Matrix[1][1].P[i][j])
			}
		}
	}
}

// MulByXPowAlphaMinusOneThenAddLazy multiplies opOut by (X^alpha - 1) and adds the result on opOut.
func MulByXPowAlphaMinusOneThenAddLazy(rQ, rP *ring.RNSRing, ctIn *Ciphertext, powXMinusOne [2]ring.RNSPoly, opOut *Ciphertext) {
	for i := range ctIn.Matrix[0][0].Q {
		for j := range ctIn.Matrix[0][0].Q[i] {

			rQ.MulCoeffsMontgomeryLazyThenAddLazy(ctIn.Matrix[0][0].Q[i][j], powXMinusOne[0], opOut.Matrix[0][0].Q[i][j])
			rQ.MulCoeffsMontgomeryLazyThenAddLazy(ctIn.Matrix[0][1].Q[i][j], powXMinusOne[0], opOut.Matrix[0][1].Q[i][j])
			rQ.MulCoeffsMontgomeryLazyThenAddLazy(ctIn.Matrix[1][0].Q[i][j], powXMinusOne[0], opOut.Matrix[1][0].Q[i][j])
			rQ.MulCoeffsMontgomeryLazyThenAddLazy(ctIn.Matrix[1][1].Q[i][j], powXMinusOne[0], opOut.Matrix[1][1].Q[i][j])

			if rP != nil {
				rP.MulCoeffsMontgomeryLazyThenAddLazy(ctIn.Matrix[0][0].P[i][j], powXMinusOne[1], opOut.Matrix[0][0].P[i][j])
				rP.MulCoeffsMontgomeryLazyThenAddLazy(ctIn.Matrix[0][1].P[i][j], powXMinusOne[1], opOut.Matrix[0][1].P[i][j])
				rP.MulCoeffsMontgomeryLazyThenAddLazy(ctIn.Matrix[1][0].P[i][j], powXMinusOne[1], opOut.Matrix[1][0].P[i][j])
				rP.MulCoeffsMontgomeryLazyThenAddLazy(ctIn.Matrix[1][1].P[i][j], powXMinusOne[1], opOut.Matrix[1][1].P[i][j])
			}
		}
	}
}
