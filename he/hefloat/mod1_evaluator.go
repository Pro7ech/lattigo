package hefloat

import (
	"fmt"
	"math/big"
	"math/cmplx"

	"github.com/Pro7ech/lattigo/he"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/bignum"
)

// EvaluatorForMod1 defines a set of common and scheme agnostic
// methods that are necessary to instantiate a Mod1Evaluator.
// The default hefloat.Evaluator is compliant to this interface.
type EvaluatorForMod1 interface {
	he.Evaluator
	Parameters() Parameters
}

// Mod1Evaluator is an evaluator providing an API for homomorphic evaluations of scaled x mod 1.
// All fields of this struct are public, enabling custom instantiations.
type Mod1Evaluator struct {
	EvaluatorForMod1
	PolynomialEvaluator *PolynomialEvaluator
	Mod1Parameters      Mod1Parameters
}

// NewMod1Evaluator instantiates a new Mod1Evaluator evaluator.
// The default hefloat.Evaluator is compliant to the EvaluatorForMod1 interface.
// This method is allocation free.
func NewMod1Evaluator(eval EvaluatorForMod1, evalPoly *PolynomialEvaluator, Mod1Parameters Mod1Parameters) *Mod1Evaluator {
	return &Mod1Evaluator{EvaluatorForMod1: eval, PolynomialEvaluator: evalPoly, Mod1Parameters: Mod1Parameters}
}

// EvaluateNew applies a homomorphic mod Q on a vector scaled by Delta, scaled down to mod 1 :
//
//  1. Delta * (Q/Delta * I(X) + m(X)) (Delta = scaling factor, I(X) integer poly, m(X) message)
//  2. Delta * (I(X) + Delta/Q * m(X)) (divide by Q/Delta)
//  3. Delta * (Delta/Q * m(X)) (x mod 1)
//  4. Delta * (m(X)) (multiply back by Q/Delta)
//
// Since Q is not a power of two, but Delta is, then does an approximate division by the closest
// power of two to Q instead. Hence, it assumes that the input plaintext is already scaled by
// the correcting factor Q/2^{round(log(Q))}.
//
// !! Assumes that the input is normalized by 1/K for K the range of the approximation.
//
// Scaling back error correction by 2^{round(log(Q))}/Q afterward is included in the polynomial.
func (eval Mod1Evaluator) EvaluateNew(ct *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	return eval.EvaluateWithAffineTransformationNew(ct, 1, 0)
}

// EvaluateWithAffineTransformationNew calls EvaluateNew and then applies the affine transformation y = ax + b on the output,
// without consumming an additional level.
func (eval Mod1Evaluator) EvaluateWithAffineTransformationNew(ct *rlwe.Ciphertext, a, b complex128) (*rlwe.Ciphertext, error) {

	var err error

	evm := eval.Mod1Parameters

	out := ct.Clone()

	if out.Level() < evm.LevelQ {
		return nil, fmt.Errorf("cannot Evaluate: ct.Level() < Mod1Parameters.LevelStart")
	}

	if out.Level() > evm.LevelQ {
		eval.DropLevel(out, out.Level()-evm.LevelQ)
	}

	// Normalize the modular reduction to mod by 1 (division by Q)
	out.Scale = evm.ScalingFactor()

	// Compute the scales that the ciphertext should have before the double angle
	// formula such that after it it has the scale it had before the polynomial
	// evaluation

	Qi := eval.Parameters().Q()

	targetScale := out.Scale
	for i := 0; i < evm.DoubleAngle; i++ {
		targetScale = targetScale.Mul(rlwe.NewScale(Qi[ct.LevelQ()-evm.Mod1Poly.Depth()-evm.DoubleAngle+i+1]))
		targetScale.Value.Sqrt(&targetScale.Value)
	}

	// Division by 1/2^r and change of variable for the Chebyshev evaluation
	if evm.Mod1Type == CosDiscrete || evm.Mod1Type == CosContinuous {
		offset := new(big.Float).Sub(&evm.Mod1Poly.B, &evm.Mod1Poly.A)
		offset.Quo(offset, new(big.Float).SetFloat64(evm.Mod1IntervalScalingFactor()))
		offset.Quo(new(big.Float).SetFloat64(-0.5), offset)
		if err = eval.Add(out, offset, out); err != nil {
			return nil, fmt.Errorf("eval.Add: %w", err)
		}
	}

	sqrt2pi := complex(evm.Sqrt2Pi, 0)

	var mod1Poly, mod1InvPoly *bignum.Polynomial

	if evm.Mod1InvPoly == nil {
		a = cmplx.Pow(a, complex(evm.Mod1IntervalScalingFactor(), 0))
		sqrt2pi *= a
		mod1Poly = evm.Mod1Poly.Affine(a, 0)
	} else {
		mod1Poly = evm.Mod1Poly
		mod1InvPoly = evm.Mod1InvPoly.Affine(a, 0)
	}

	// Chebyshev evaluation
	if out, err = eval.PolynomialEvaluator.Evaluate(out, mod1Poly, rlwe.NewScale(targetScale)); err != nil {
		return nil, fmt.Errorf("eval.PolynomialEvaluator.Evaluate: %w", err)
	}

	if err = eval.Rescale(out, out); err != nil {
		return nil, fmt.Errorf("eval.Rescale: %w", err)
	}

	// Double angle
	for i := 0; i < evm.DoubleAngle; i++ {
		sqrt2pi *= sqrt2pi

		if err = eval.MulRelin(out, out, out); err != nil {
			return nil, fmt.Errorf("eval.MulRelin: %w", err)
		}

		if err = eval.Add(out, out, out); err != nil {
			return nil, fmt.Errorf("eval.Add: %w", err)
		}

		if err = eval.Add(out, -sqrt2pi, out); err != nil {
			return nil, fmt.Errorf("eval.Add: %w", err)
		}

		if err = eval.Rescale(out, out); err != nil {
			return nil, fmt.Errorf("eval.Rescale: %w", err)
		}
	}

	// ArcSine
	if evm.Mod1InvPoly != nil {
		if out, err = eval.PolynomialEvaluator.Evaluate(out, mod1InvPoly, out.Scale); err != nil {
			return nil, fmt.Errorf("eval.PolynomialEvaluator.Evaluate: %w", err)
		}

		if err = eval.Rescale(out, out); err != nil {
			return nil, fmt.Errorf("eval.Rescale: %w", err)
		}
	}

	// Multiplies back by q/Delta
	out.Scale = ct.Scale

	if b != 0 {
		if err = eval.Add(out, b, out); err != nil {
			return nil, fmt.Errorf("eval.Add: %w", err)
		}
	}

	return out, nil
}
