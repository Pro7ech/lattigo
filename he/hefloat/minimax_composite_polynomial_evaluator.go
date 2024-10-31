package hefloat

import (
	"fmt"

	"github.com/Pro7ech/lattigo/he"
	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
)

// EvaluatorForMinimaxCompositePolynomial defines a set of common and scheme agnostic method that are necessary to instantiate a MinimaxCompositePolynomialEvaluator.
type EvaluatorForMinimaxCompositePolynomial interface {
	he.Evaluator
	ConjugateNew(ct *rlwe.Ciphertext) (ctConj *rlwe.Ciphertext, err error)
}

// MinimaxCompositePolynomialEvaluator is an evaluator used to evaluate composite polynomials on ciphertexts.
// All fields of this struct are publics, enabling custom instantiations.
type MinimaxCompositePolynomialEvaluator struct {
	EvaluatorForMinimaxCompositePolynomial
	PolynomialEvaluator
	he.Bootstrapper[rlwe.Ciphertext]
	Parameters Parameters
}

// NewMinimaxCompositePolynomialEvaluator instantiates a new MinimaxCompositePolynomialEvaluator.
// The default hefloat.Evaluator is compliant to the EvaluatorForMinimaxCompositePolynomial interface.
// This method is allocation free.
func NewMinimaxCompositePolynomialEvaluator(params Parameters, eval EvaluatorForMinimaxCompositePolynomial, bootstrapper he.Bootstrapper[rlwe.Ciphertext]) *MinimaxCompositePolynomialEvaluator {
	return &MinimaxCompositePolynomialEvaluator{eval, *NewPolynomialEvaluator(params, eval), bootstrapper, params}
}

// Evaluate evaluates the provided MinimaxCompositePolynomial on the input ciphertext.
func (eval MinimaxCompositePolynomialEvaluator) Evaluate(in *rlwe.Ciphertext, mcp MinimaxCompositePolynomial, targetScale rlwe.Scale) (out *rlwe.Ciphertext, err error) {

	params := eval.Parameters

	btp := eval.Bootstrapper

	levelsConsumedPerRescaling := params.LevelsConsumedPerRescaling()

	if btp != nil {
		// Checks that the number of levels available after the bootstrapping is enough to evaluate all polynomials
		if maxDepth := mcp.MaxDepth() * levelsConsumedPerRescaling; params.MaxLevel() < maxDepth+btp.MinimumInputLevel() {
			return nil, fmt.Errorf("parameters do not enable the evaluation of the minimax composite polynomial, required levels is %d but parameters only provide %d levels", maxDepth+btp.MinimumInputLevel(), params.MaxLevel())
		}
	} else {
		// Checks that the number of levels available after the bootstrapping is enough to evaluate all polynomials
		if maxDepth := mcp.MaxDepth() * levelsConsumedPerRescaling; params.MaxLevel() < maxDepth {
			return nil, fmt.Errorf("parameters do not enable the evaluation of the minimax composite polynomial, required levels is %d but parameters only provide %d levels", maxDepth, params.MaxLevel())
		}
	}

	out = in.Clone()

	for k, poly := range mcp {

		// Checks that out has enough level to evaluate the next polynomial, else bootstrap
		if out.Level() < poly.Depth()*params.LevelsConsumedPerRescaling()+btp.MinimumInputLevel() {
			if out, err = btp.Bootstrap(out); err != nil {
				return
			}
		}

		// Define the scale that out must have after the polynomial evaluation.
		// If we use the regular CKKS (with complex values), we chose a scale to be
		// half of the desired scale, so that (x + conj(x)/2) has the correct scale.
		var targetScale rlwe.Scale
		if params.RingType() == ring.Standard {
			targetScale = params.DefaultScale().Div(rlwe.NewScale(2))
		} else {
			targetScale = params.DefaultScale()
		}

		// Evaluate the polynomial
		if out, err = eval.PolynomialEvaluator.Evaluate(out, &poly, targetScale); err != nil {
			return nil, fmt.Errorf("evaluate polynomial: %w", err)
		}

		// Clean the imaginary part (else it tends to explode)
		if params.RingType() == ring.Standard {

			// Reassigns the scale back to the original one
			out.Scale = out.Scale.Mul(rlwe.NewScale(2))

			var outConj *rlwe.Ciphertext
			if outConj, err = eval.ConjugateNew(out); err != nil {
				return
			}

			if err = eval.Add(out, outConj, out); err != nil {
				return
			}
		}

		if k != len(mcp)-1 {
			if err = eval.Rescale(out, out); err != nil {
				return nil, fmt.Errorf("eval.Rescale: %w", err)
			}
		}
	}

	return
}
