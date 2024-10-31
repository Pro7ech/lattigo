package hefloat

import (
	"fmt"
	"math"
	"math/big"

	"github.com/Pro7ech/lattigo/he"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/bignum"
)

// EvaluatorForInverse defines a set of common and scheme agnostic
// methods that are necessary to instantiate an InverseEvaluator.
// The default hefloat.Evaluator is compliant to this interface.
type EvaluatorForInverse interface {
	EvaluatorForMinimaxCompositePolynomial
	MatchScalesForMul(op0, op1 *rlwe.Ciphertext, targetScale rlwe.Scale) (err error)
	SetScale(op0 *rlwe.Ciphertext, scale rlwe.Scale) (err error)
}

// InverseEvaluator is an evaluator used to evaluate the inverses of ciphertexts.
// All fields of this struct are public, enabling custom instantiations.
type InverseEvaluator struct {
	EvaluatorForInverse
	*MinimaxCompositePolynomialEvaluator
	he.Bootstrapper[rlwe.Ciphertext]
	Parameters Parameters
}

// NewInverseEvaluator instantiates a new InverseEvaluator.
// The default hefloat.Evaluator is compliant to the EvaluatorForInverse interface.
// The field he.Bootstrapper[rlwe.Ciphertext] can be nil if the parameters have enough levels to support the computation.
// This method is allocation free.
func NewInverseEvaluator(params Parameters, eval EvaluatorForInverse, btp he.Bootstrapper[rlwe.Ciphertext]) InverseEvaluator {
	return InverseEvaluator{
		EvaluatorForInverse:                 eval,
		MinimaxCompositePolynomialEvaluator: NewMinimaxCompositePolynomialEvaluator(params, eval, btp),
		Bootstrapper:                        btp,
		Parameters:                          params,
	}
}

// InverseFullDomainNew computes 1/x for x in [-Max, -Min] U [Min, Max].
//  1. Reduce the interval from [-Max, -Min] U [Min, Max] to [-1, -Min] U [Min, 1] by computing an approximate
//     inverse c such that |c * x| <= 1. For |x| > 1, c tends to 1/x while for |x| < c tends to 1.
//     This is done by using the work Efficient Homomorphic Evaluation on Large Intervals (https://eprint.iacr.org/2022/280.pdf).
//  2. Compute |c * x| = sign(x * c) * (x * c), this is required for the next step, which can only accept positive values.
//  3. Compute y' = 1/(|c * x|) with the iterative Goldschmidt division algorithm.
//  4. Compute y = y' * c * sign(x * c)
//
// The user can provide a Minimax composite polynomial (signMinimaxPoly) for the sign function in the interval
// [-1-e, -Min] U [Min, 1+e] (where e is an upperbound on the scheme error).
// If no such polynomial is provided, then the DefaultMinimaxCompositePolynomialForSign is used by default.
// Note that the precision of the output of sign(x * c) does not impact the circuit precision since this value ends up being both at
// the numerator and denoMinator, thus cancelling itself.
func (eval *InverseEvaluator) InverseFullDomainNew(in *rlwe.Ciphertext, Min, Max float64, signMinimaxPoly ...MinimaxCompositePolynomial) (err error) {

	var poly MinimaxCompositePolynomial
	if len(signMinimaxPoly) == 1 {
		poly = signMinimaxPoly[0]
	} else {
		poly = NewMinimaxCompositePolynomial(DefaultMinimaxCompositePolynomialForSign)
	}

	return eval.evaluate(in, Min, Max, true, poly)
}

// InversePositiveDomainNew computes 1/x for x in [Min, Max].
//  1. Reduce the interval from [Min, Max] to [Min, 1] by computing an approximate
//     inverse c such that |c * x| <= 1. For |x| > 1, c tends to 1/x while for |x| < c tends to 1.
//     This is done by using the work Efficient Homomorphic Evaluation on Large Intervals (https://eprint.iacr.org/2022/280.pdf).
//  2. Compute y' = 1/(c * x) with the iterative Goldschmidt division algorithm.
//  3. Compute y = y' * c
func (eval *InverseEvaluator) InversePositiveDomainNew(in *rlwe.Ciphertext, Min, Max float64) (err error) {
	return eval.evaluate(in, Min, Max, false, nil)
}

// InverseNegativeDomainNew computes 1/x for x in [-Max, -Min].
//  1. Reduce the interval from [-Max, -Min] to [-1, -Min] by computing an approximate
//     inverse c such that |c * x| <= 1. For |x| > 1, c tends to 1/x while for |x| < c tends to 1.
//     This is done by using the work Efficient Homomorphic Evaluation on Large Intervals (https://eprint.iacr.org/2022/280.pdf).
//  2. Compute y' = 1/(c * x) with the iterative Goldschmidt division algorithm.
//  3. Compute y = y' * c
func (eval *InverseEvaluator) InverseNegativeDomainNew(in *rlwe.Ciphertext, Min, Max float64) (err error) {

	if err = eval.Mul(in, -1, in); err != nil {
		return fmt.Errorf("eval.MulNew: %w", err)
	}

	if err = eval.InversePositiveDomainNew(in, Min, Max); err != nil {
		return fmt.Errorf("eval.EvaluatePositiveDomainNew: %w", err)
	}

	if err = eval.Mul(in, -1, in); err != nil {
		return fmt.Errorf("eval.MulNew: %w", err)
	}

	return
}

// InvSqrt evaluates y = 1/sqrt(x) with r iterations of y = y * 1.5 - (x/2*y)*(y*y),
// which provides a quadratic convergence.
//
//   - cts: values already "rougthly" close to 1/sqrt(x). This can be done by first
//     evaluating a low-precision polynomial approximation of 1/sqrt(x).
//   - half: x/2
//
// The total depth is 2*r.
func (eval *InverseEvaluator) InvSqrt(in, inHalf *rlwe.Ciphertext, r int) (err error) {

	btp := eval.Bootstrapper

	params := eval.Parameters

	levelsPerRescaling := params.LevelsConsumedPerRescaling()

	for range r {

		if btp != nil && in.Level() < 2*levelsPerRescaling {
			if in, err = btp.Bootstrap(in); err != nil {
				return fmt.Errorf("[he.Bootstrapper][Bootstrap][in]: %w", err)
			}
		}

		// y = y * 1.5 - (x/2*y)*(y*y)
		var ysqrt *rlwe.Ciphertext
		if ysqrt, err = eval.MulRelinNew(in, in); err != nil {
			return fmt.Errorf("[hefloat.Evaluator][MulRelinNew][in, in]: %w", err)
		}

		if err = eval.Rescale(ysqrt, ysqrt); err != nil {
			return fmt.Errorf("[hefloat.Evaluator][Rescale][ysqrt, ysqrt]: %w", err)
		}

		if btp != nil && inHalf.Level() < in.Level() {
			if inHalf, err = btp.Bootstrap(inHalf); err != nil {
				return fmt.Errorf("[he.Bootstrapper][Bootstrap][inHalf]: %w", err)
			}
		}

		var xy *rlwe.Ciphertext
		if xy, err = eval.MulRelinNew(inHalf, in); err != nil {
			return fmt.Errorf("[hefloat.Evaluator][MulRelin][inHalf, in]: %w", err)
		}

		if err = eval.Rescale(xy, xy); err != nil {
			return fmt.Errorf("[hefloat.Evaluator][Rescale][xy, xy]: %w", err)
		}

		if err = eval.MulRelin(ysqrt, xy, ysqrt); err != nil {
			return fmt.Errorf("[hefloat.Evaluator][MulRelin][ysqrt, xy, ysqrt]: %w", err)
		}

		if err = eval.Mul(ysqrt, -1, ysqrt); err != nil {
			return fmt.Errorf("[hefloat.Evaluator][Mul][ysqrt, -1, ysqrt]: %w", err)
		}

		if err = eval.MulThenAdd(in, 1.5, ysqrt); err != nil {
			return fmt.Errorf("[hefloat.Evaluator][MulThenAdd][in, 1.5, ysqrt]: %w", err)
		}

		if err = eval.Rescale(ysqrt, in); err != nil {
			return fmt.Errorf("[hefloat.Evaluator][Rescale][ysqrt, in]: %w", err)
		}
	}

	return
}

func (eval *InverseEvaluator) evaluate(in *rlwe.Ciphertext, Min, Max float64, fulldomain bool, signMinimaxPoly MinimaxCompositePolynomial) (err error) {

	if Min < 0 || Max < 0 {
		return fmt.Errorf("invalid parameters: Min or Max cannot be negative")
	}

	params := eval.Parameters

	levelsPerRescaling := params.LevelsConsumedPerRescaling()

	btp := eval.Bootstrapper

	var norm *rlwe.Ciphertext

	// If Max > 1, then normalizes the ciphertext interval from  [-Max, -Min] U [Min, Max]
	// to [-1, -Min] U [Min, 1], and returns the encrypted normalization factor.
	if Max > 2 {
		if norm, err = eval.IntervalNormalization(in, 1, Max, 1); err != nil {
			return fmt.Errorf("preprocessing: norm: %w", err)
		}
	}

	var sign *rlwe.Ciphertext

	if fulldomain {

		if eval.MinimaxCompositePolynomialEvaluator == nil {
			return fmt.Errorf("preprocessing: cannot EvaluateNew: MinimaxCompositePolynomialEvaluator is nil but fulldomain is set to true")
		}

		// Computes the sign with precision [-1, -a] U [a, 1]
		if sign, err = eval.MinimaxCompositePolynomialEvaluator.Evaluate(in, signMinimaxPoly, in.Scale); err != nil {
			return fmt.Errorf("preprocessing: fulldomain: true -> sign: %w", err)
		}

		if err = eval.Rescale(sign, sign); err != nil {
			return fmt.Errorf("preprocessing: rescale %w", err)
		}

		if sign.Level() < btp.MinimumInputLevel()+levelsPerRescaling {
			if sign, err = btp.Bootstrap(sign); err != nil {
				return fmt.Errorf("preprocessing: fulldomain: true -> sign -> Bootstrap(sign): %w", err)
			}
		}

		// Checks that in have at least one level remaining above the Minimum
		// level required for the bootstrapping.
		if in.Level() < btp.MinimumInputLevel()+levelsPerRescaling {
			if in, err = btp.Bootstrap(in); err != nil {
				return fmt.Errorf("preprocessing: fulldomain: true -> sign -> Bootstrap(in): %w", err)
			}
		}

		if err = eval.MatchScalesForMul(in, sign, params.DefaultScale()); err != nil {
			return
		}

		// Gets |x| = x * sign(x)
		if err = eval.MulRelin(in, sign, in); err != nil {
			return fmt.Errorf("preprocessing: fulldomain: true -> sign -> Bootstrap -> mul(in, sign): %w", err)
		}

		if err = eval.Rescale(in, in); err != nil {
			return fmt.Errorf("preprocessing: fulldomain: true -> sign -> Bootstrap -> mul(in, sign) -> rescale: %w", err)
		}
	}

	// 2^{-(prec - LogN + 1)}
	prec := float64(params.N()/2) / in.Scale.Float64()

	// Estimates the number of iterations required to achieve the desired precision, given the interval [Min, 2-Min]
	start := 1 - Min
	var iters = 1
	for start >= prec {
		start *= start // Doubles the bit-precision at each iteration
		iters++
	}

	// Minimum of 3 iterations
	// This Minimum is set in the case where Min is close to 0.
	iters = max(iters, 3)

	// Computes the inverse of x in [Min, 1]
	if err = eval.GoldschmidtDivision(iters, in); err != nil {
		return fmt.Errorf("division: GoldschmidtDivisionNew: %w", err)
	}

	var postprocessdepth int

	if norm != nil || fulldomain {
		postprocessdepth += levelsPerRescaling
	}

	if fulldomain {
		postprocessdepth += levelsPerRescaling
	}

	// If x > 1 then multiplies back with the encrypted normalization vector
	if norm != nil {

		if in.Level() < btp.MinimumInputLevel()+postprocessdepth {
			if in, err = btp.Bootstrap(in); err != nil {
				return fmt.Errorf("norm: Bootstrap(in): %w", err)
			}
		}

		if norm.Level() < btp.MinimumInputLevel()+postprocessdepth {
			if norm, err = btp.Bootstrap(norm); err != nil {
				return fmt.Errorf("norm: bootstrap(norm): %w", err)
			}
		}

		if err = eval.MatchScalesForMul(in, norm, params.DefaultScale()); err != nil {
			return
		}

		if err = eval.MulRelin(in, norm, in); err != nil {
			return fmt.Errorf("norm: mul(in): %w", err)
		}

		if err = eval.Rescale(in, in); err != nil {
			return fmt.Errorf("norm: rescale(in): %w", err)
		}
	}

	if fulldomain {

		if err = eval.MatchScalesForMul(in, sign, params.DefaultScale()); err != nil {
			return
		}

		// Multiplies back with the encrypted sign
		if err = eval.MulRelin(in, sign, in); err != nil {
			return fmt.Errorf("fulldomain: mul(in):  %w", err)
		}

		if err = eval.Rescale(in, in); err != nil {
			return fmt.Errorf("fulldomain: rescale(in): %w", err)
		}
	}

	return nil
}

// GoldschmidtDivision homomorphically computes 1/x in the domain [0, 2].
// input: ct: Enc(x) with values in the interval [0+2^{-log2min}, 2-2^{-log2min}].
// output: Enc(1/x - e), where |e| <= (1-x)^2^(#iterations+1) -> the bit-precision doubles after each iteration.
// This method automatically estimates how many iterations are needed to
// achieve the optimal precision, which is derived from the plaintext scale.
// This method will return an error if the input ciphertext does not have enough
// remaining level and if the InverseEvaluator was instantiated with no bootstrapper.
// This method will return an error if something goes wrong with the bootstrapping or the rescaling operations.
func (eval *InverseEvaluator) GoldschmidtDivision(iters int, ct *rlwe.Ciphertext) (err error) {

	btp := eval.Bootstrapper

	params := eval.Parameters

	levelsPerRescaling := params.LevelsConsumedPerRescaling()

	if depth := iters * levelsPerRescaling; btp == nil && depth > ct.Level() {
		return fmt.Errorf("cannot GoldschmidtDivisionNew: ct.Level()=%d < depth=%d and rlwe.Bootstrapper is nil", ct.Level(), depth)
	}

	var b *rlwe.Ciphertext
	a := ct

	if err = eval.Mul(a, -1, a); err != nil {
		return
	}

	if b, err = eval.AddNew(a, 1); err != nil {
		return
	}

	if err = eval.Add(a, 2, a); err != nil {
		return
	}

	for range iters {

		if btp != nil && (b.Level() == btp.MinimumInputLevel() || b.Level() == levelsPerRescaling-1) {
			if b, err = btp.Bootstrap(b); err != nil {
				return
			}
		}

		if btp != nil && (a.Level() == btp.MinimumInputLevel() || a.Level() == levelsPerRescaling-1) {
			if a, err = btp.Bootstrap(a); err != nil {
				return
			}
		}

		if err = eval.MulRelin(b, b, b); err != nil {
			return
		}

		if err = eval.Rescale(b, b); err != nil {
			return
		}

		if btp != nil && (b.Level() == btp.MinimumInputLevel() || b.Level() == levelsPerRescaling-1) {
			if b, err = btp.Bootstrap(b); err != nil {
				return
			}
		}

		var tmp *rlwe.Ciphertext
		if tmp, err = eval.MulRelinNew(a, b); err != nil {
			return
		}

		if err = eval.Rescale(tmp, tmp); err != nil {
			return
		}

		// a is at a higher level than tmp but at the same scale magnitude
		// We consume a level to bring a to the same level as tmp
		if err = eval.SetScale(a, tmp.Scale); err != nil {
			return
		}

		if err = eval.Add(a, tmp, a); err != nil {
			return
		}
	}

	return
}

// IntervalNormalization applies a modified version of Algorithm 2 of Efficient Homomorphic Evaluation on Large Intervals (https://eprint.iacr.org/2022/280)
// to normalize the interval from [-Max/Fac, Max/Fac] to [-1*scaling, 1*scaling]. Also returns the encrypted normalization factor.
//
// The original algorithm of https://eprint.iacr.org/2022/280 works by successive evaluation of a function that compresses values greater than some threshold
// to this threshold and let values smaller than the threshold untouched (mostly). The process is iterated, each time reducing the threshold by a pre-defined
// factor L. We can modify the algorithm to keep track of the compression factor so that we can get back the original values (before the compression) afterward.
//
// Given ct with values [-max, max], the method will compute y such that ct * y has values in [-1, 1].
// The normalization factor is independant to each slot:
//   - values smaller than 1 will have a normalization factor that tends to 1
//   - values greater than 1 will have a normalization factor that tends to 1/x
func (eval *InverseEvaluator) IntervalNormalization(in *rlwe.Ciphertext, scaling, Max float64, Fac int) (norm *rlwe.Ciphertext, err error) {

	params := eval.Parameters
	btp := eval.Bootstrapper

	levelsPerRescaling := params.LevelsConsumedPerRescaling()

	L := new(big.Float).SetPrec(128).SetFloat64(2.45) // Compression factor (experimental)
	twentySeven := new(big.Float).SetPrec(128).SetInt64(27)
	n := int(math.Ceil(math.Log2(Max) / math.Log2(2.45))) // log_{L}(Max)

	var z0, z1, z2, z0z1, z0z2 *rlwe.Ciphertext

	for i := range n {

		if btp != nil && in.Level() < btp.MinimumInputLevel()+2*levelsPerRescaling || (i != 0 && norm != nil && (norm.Level() == btp.MinimumInputLevel() || norm.Level() == levelsPerRescaling-1)) {

			cts := []rlwe.Ciphertext{*in, *norm}
			if cts, err = btp.BootstrapMany(cts); err != nil {
				return
			}
			in = &cts[0]
			norm = &cts[1]
		}

		num := new(big.Float).SetPrec(128).SetFloat64(4)
		num.Mul(num, new(big.Float).SetPrec(128).SetInt64(int64(Fac*Fac)))

		den := bignum.Pow(L, new(big.Float).SetPrec(128).SetInt64(2*int64(n-1-i)))
		den.Mul(den, twentySeven)

		// c = (4 * Fac * Fac) / (27 * L^{2*(n-1-i)})
		c := num.Quo(num, den)

		if i == n-1 {
			c.Mul(c, new(big.Float).SetPrec(128).SetFloat64(scaling))
		}

		Q := params.Q()
		for j := range 2 {
			for i := range levelsPerRescaling {
				c.Mul(c, new(big.Float).SetPrec(128).SetUint64(Q[in.Level()-i-j*levelsPerRescaling]))
			}
		}
		c.Quo(c, &in.Scale.Value)
		c.Quo(c, &in.Scale.Value)

		// x = x - x * c * x * x
		// y = y - x * c * x * y

		// z0z1 = (x * c) * (x * x)
		// z0z2 = (x * c) * (norm * x) -> (norm * c) * (x * x)

		if z0, err = eval.MulRelinNew(in, c); err != nil {
			return
		}

		if err = eval.Rescale(z0, z0); err != nil {
			return nil, fmt.Errorf("[hefloat.Evaluator][Rescale][z0,z0]: %w", err)
		}

		// z1 = x * x
		if z1, err = eval.MulRelinNew(in, in); err != nil {
			return nil, fmt.Errorf("[hefloat.Evaluator][MulRelinNew][in,in,z1]: %w", err)
		}

		if err = eval.Rescale(z1, z1); err != nil {
			return nil, fmt.Errorf("[hefloat.Evaluator][Rescale][z1,z1]: %w", err)
		}

		if i > 0 {

			// z2 = norm * x
			if z2, err = eval.MulRelinNew(norm, in); err != nil {
				return nil, fmt.Errorf("[hefloat.Evaluator][MulRelinNew][norm,in,z2]: %w", err)
			}

			if err = eval.Rescale(z2, z2); err != nil {
				return nil, fmt.Errorf("[hefloat.Evaluator][Rescale][z2,z2]: %w", err)
			}

		} else {
			z2 = in.Clone()
			if err = eval.SetScale(z2, z1.Scale); err != nil {
				return
			}
		}

		if z0z1, err = eval.MulRelinNew(z0, z1); err != nil {
			return nil, fmt.Errorf("[hefloat.Evaluator][MulRelinNew][z0,z1,z0z1]: %w", err)
		}

		if err = eval.Rescale(z0z1, z0z1); err != nil {
			return nil, fmt.Errorf("[hefloat.Evaluator][Rescale][z0z1,z0z1]: %w", err)
		}

		z0z1.Scale = in.Scale

		if z0z2, err = eval.MulRelinNew(z0, z2); err != nil {
			return nil, fmt.Errorf("[hefloat.Evaluator][MulRelinNew][z0,z2,z0z2]: %w", err)
		}

		if err = eval.Rescale(z0z2, z0z2); err != nil {
			return nil, fmt.Errorf("[hefloat.Evaluator][Rescale][z0z2,z0z2]: %w", err)
		}

		z0z2.Scale = in.Scale

		if i == 0 {
			if err = eval.Mul(z0z2, -1, z0z2); err != nil {
				return nil, fmt.Errorf("[hefloat.Evaluator][Mul][z0z2,-1,z0z2]: %w", err)
			}
			if err = eval.Add(z0z2, 1, z0z2); err != nil {
				return nil, fmt.Errorf("[hefloat.Evaluator][Add][z0z2,1,z0z2]: %w", err)
			}
			norm = z0z2.Clone()
		} else {

			if i == n-1 {
				if err = eval.Mul(norm, scaling, norm); err != nil {
					return
				}

				if float64(int(scaling)) != scaling {
					if err = eval.Rescale(norm, norm); err != nil {
						return
					}
				}
			}

			if err = eval.Sub(norm, z0z2, norm); err != nil {
				return nil, fmt.Errorf("[hefloat.Evaluator][Sub][norm,z0z2,norm]: %w", err)
			}
		}

		if i == n-1 {

			if err = eval.Mul(in, scaling, in); err != nil {
				return
			}

			if float64(int(scaling)) != scaling {
				if err = eval.Rescale(in, in); err != nil {
					return
				}
			}
		}

		if err = eval.Sub(in, z0z1, in); err != nil {
			return nil, fmt.Errorf("[hefloat.Evaluator][Sub][in,z0z1,in]: %w", err)
		}
	}

	if err = eval.Mul(in, Fac, in); err != nil {
		return nil, fmt.Errorf("[hefloat.Evaluator][Sub][in,Fac,in]: %w", err)
	}

	return
}
