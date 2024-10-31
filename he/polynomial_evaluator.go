package he

import (
	"fmt"
	"math/bits"

	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/bignum"
)

// EvaluatorForPolynomial defines a set of common and scheme agnostic method that are necessary to instantiate a PolynomialVectorEvaluator.
type EvaluatorForPolynomial interface {
	Evaluator
	LevelsConsumedPerRescaling() int
	EvaluatePatersonStockmeyerPolynomialVector(poly *PatersonStockmeyerPolynomialVector, pb *PowerBasis) (res *rlwe.Ciphertext, err error)
	//EvaluatePatersonStockmeyerPolynomialEncoded(poly PatersonStockmeyerPolynomialEncoded, pb PowerBasis) (res *rlwe.Ciphertext, err error)
}

// CoefficientGetter defines an interface to get the coefficients of a Polynomial.
type CoefficientGetter[T any] interface {

	// GetVectorCoefficient should return a slice []T containing the k-th coefficient
	// of each polynomial of PolynomialVector indexed by its Mapping.
	// See PolynomialVector for additional information about the Mapping.
	GetVectorCoefficient(pol *PolynomialVector, k int) (values []T)

	// GetSingleCoefficient should return the k-th coefficient of Polynomial as the type T.
	GetSingleCoefficient(pol *Polynomial, k int) (value T)

	// ShallowCopy should return a thread-safe copy of the original CoefficientGetter.
	ShallowCopy() CoefficientGetter[T]
}

// EvaluatePolynomial is a generic and scheme agnostic method to evaluate polynomials on rlwe.Ciphertexts.
func EvaluatePolynomial(eval EvaluatorForPolynomial, input interface{}, p interface{}, targetScale rlwe.Scale, SimEval SimEvaluator) (opOut *rlwe.Ciphertext, err error) {

	var polyVec *PolynomialVector
	switch p := p.(type) {
	case *bignum.Polynomial:
		polyVec = &PolynomialVector{Value: map[int]*Polynomial{0: {Polynomial: p, MaxDeg: p.Degree(), Lead: true, Lazy: false}}}
	case *Polynomial:
		polyVec = &PolynomialVector{Value: map[int]*Polynomial{0: p}}
	case *PolynomialVector:
		polyVec = p
	default:
		return nil, fmt.Errorf("cannot Polynomial: invalid polynomial type, must be either *bignum.Polynomial, *he.Polynomial or *he.PolynomialVector, but is %T", p)
	}

	var powerbasis *PowerBasis
	switch input := input.(type) {
	case *rlwe.Ciphertext:
		powerbasis = NewPowerBasis(input, polyVec.Basis())
	case *PowerBasis:
		if input.Value[1] == nil {
			return nil, fmt.Errorf("cannot evaluatePolyVector: given PowerBasis.Value[1] is empty")
		}
		powerbasis = input
	default:
		return nil, fmt.Errorf("cannot evaluatePolyVector: invalid input, must be either *rlwe.Ciphertext or *PowerBasis but is %T", input)
	}

	if level, depth := powerbasis.Value[1].Level(), eval.LevelsConsumedPerRescaling()*polyVec.Depth(); level < depth {
		return nil, fmt.Errorf("%d levels < %d log(d) -> cannot evaluate poly", level, depth)
	}

	if err = polyVec.PopulatePowerBasis(eval, powerbasis); err != nil {
		return nil, fmt.Errorf("polyVec.PopulatePowerBasis: %w", err)
	}

	/*
		for i := 0; i < 128; i++{
			if p, ok := powerbasis.Value[i]; ok{
				fmt.Println(i, p.Degree())
			}
		}
	*/

	PS := polyVec.GetPatersonStockmeyerPolynomial(*eval.GetRLWEParameters(), powerbasis.Value[1].Level(), powerbasis.Value[1].Scale, targetScale, SimEval)

	if opOut, err = eval.EvaluatePatersonStockmeyerPolynomialVector(PS, powerbasis); err != nil {
		return nil, err
	}

	return opOut, err
}

// BabyStep is a struct storing the result of a baby-step
// of the Paterson-Stockmeyer polynomial evaluation algorithm.
type BabyStep struct {
	Degree int
	Value  *rlwe.Ciphertext
}

// EvaluatePatersonStockmeyerPolynomialVector evaluates a pre-decomposed PatersonStockmeyerPolynomialVector on a pre-computed power basis [1, X^{1}, X^{2}, ..., X^{2^{n}}, X^{2^{n+1}}, ..., X^{2^{m}}]
func EvaluatePatersonStockmeyerPolynomialVector[T any](eval Evaluator, poly *PatersonStockmeyerPolynomialVector, cg CoefficientGetter[T], pb *PowerBasis) (res *rlwe.Ciphertext, err error) {

	split := poly.Split()

	babySteps := make([]*BabyStep, split)

	// Small steps
	for i := range babySteps {
		// eval & cg are not thread-safe
		if babySteps[split-i-1], err = EvaluateBabyStep(i, eval, poly, cg, pb); err != nil {
			return nil, fmt.Errorf("cannot EvaluateBabyStep: %w", err)
		}
	}

	return ProcessBabySteps(eval, babySteps, pb)
}

// EvaluateBabyStep evaluates a baby-step of the PatersonStockmeyer polynomial evaluation algorithm, i.e. the inner-product between the precomputed
// powers [1, T, T^2, ..., T^{n-1}] and the coefficients [ci0, ci1, ci2, ..., ci{n-1}].
func EvaluateBabyStep[T any](i int, eval Evaluator, poly *PatersonStockmeyerPolynomialVector, cg CoefficientGetter[T], pb *PowerBasis) (ct *BabyStep, err error) {

	polyVec := &PolynomialVector{
		Value:   map[int]*Polynomial{},
		Mapping: poly.Mapping,
	}

	// Transposes the polynomial matrix
	for j := range poly.Value {
		polyVec.Value[j] = &poly.Value[j].Value[i]
	}

	level := poly.Level(i)
	scale := poly.Scale(i)

	ct = new(BabyStep)
	ct.Degree = poly.Degree(i)
	if ct.Value, err = EvaluatePolynomialVectorFromPowerBasis(eval, level, polyVec, cg, pb, scale); err != nil {
		return ct, fmt.Errorf("cannot EvaluatePolynomialVectorFromPowerBasis: polynomial[%d]: %w", i, err)
	}

	return ct, nil
}

func ProcessBabySteps(eval Evaluator, babySteps []*BabyStep, pb *PowerBasis) (res *rlwe.Ciphertext, err error) {

	// Loops as long as there is more than one sub-polynomial
	for len(babySteps) != 1 {

		// Precomputes the ops to apply in the giant steps loop
		giantsteps := make([]int, len(babySteps))
		for i := 0; i < len(babySteps); i++ {
			if i == len(babySteps)-1 {
				giantsteps[i] = 2
			} else if babySteps[i].Degree == babySteps[i+1].Degree {
				giantsteps[i] = 1
				i++
			}
		}

		for i := 0; i < len(babySteps); i++ {

			// eval is not thread-safe
			if err = EvaluateGianStep(i, giantsteps, babySteps, eval, pb); err != nil {
				return nil, err
			}
		}

		// Discards processed sub-polynomials
		var idx int
		for i := range babySteps {
			if babySteps[i] != nil {
				babySteps[idx] = babySteps[i]
				idx++
			}
		}

		babySteps = babySteps[:idx]
	}

	if babySteps[0].Value.Degree() == 2 {
		if err = eval.Relinearize(babySteps[0].Value, babySteps[0].Value); err != nil {
			return nil, fmt.Errorf("cannot EvaluatePatersonStockmeyerPolynomial: %w", err)
		}
	}

	return babySteps[0].Value, nil
}

// EvaluateGianStep evaluates a giant-step of the PatersonStockmeyer polynomial evaluation algorithm, which consists
// in combining the baby-steps <[1, T, T^2, ..., T^{n-1}], [ci0, ci1, ci2, ..., ci{n-1}]> together with powers T^{2^k}.
func EvaluateGianStep(i int, giantSteps []int, babySteps []*BabyStep, eval Evaluator, pb *PowerBasis) (err error) {

	// If we reach the end of the list it means we weren't able to combine
	// the last two sub-polynomials which necessarily implies that that the
	// last one has degree smaller than the previous one and that there is
	// no next polynomial to combine it with.
	// Therefore we update it's degree to the one of the previous one.
	if giantSteps[i] == 2 {
		babySteps[i].Degree = babySteps[i-1].Degree

		// If two consecutive sub-polynomials, from ascending degree order, have the
		// same degree, we combine them.
	} else if giantSteps[i] == 1 {

		even, odd := babySteps[i], babySteps[i+1]

		deg := 1 << bits.Len64(uint64(babySteps[i].Degree))

		if err = EvaluateMonomial(even.Value, odd.Value, pb.Value[deg], eval); err != nil {
			return fmt.Errorf("EvaluateMonomial: %w", err)
		}

		odd.Degree = 2*deg - 1
		babySteps[i] = nil

		i++
	}

	return
}

// EvaluateMonomial evaluates a monomial of the form a + b * X^{pow} and writes the results in b.
func EvaluateMonomial(a, b, xpow *rlwe.Ciphertext, eval Evaluator) (err error) {

	if b.Degree() == 2 {
		if err = eval.Relinearize(b, b); err != nil {
			return fmt.Errorf("eval.Relinearize: %w", err)
		}
	}

	if err = eval.Rescale(b, b); err != nil {
		return fmt.Errorf("eval.Rescale: %w", err)
	}

	if xpow.Degree() == 2 && b.Degree() != 0 {
		if err = eval.Relinearize(xpow, xpow); err != nil {
			return fmt.Errorf("eval.Relinearize: %w", err)
		}
	}

	if err = eval.Mul(b, xpow, b); err != nil {
		return fmt.Errorf("eval.Mul: %w", err)
	}

	if !a.Scale.InDelta(b.Scale, float64(rlwe.ScalePrecision-12)) {
		return fmt.Errorf("scale discrepency: (rescale(b) * X^{n}).Scale = %v != a.Scale = %v", &a.Scale.Value, &b.Scale.Value)
	}

	if err = eval.Add(b, a, b); err != nil {
		return fmt.Errorf("eval.Add: %w", err)
	}

	return
}

// EvaluatePolynomialVectorFromPowerBasis a method that complies to the interface he.PolynomialVectorEvaluator. This method evaluates P(ct) = sum c_i * ct^{i}.
func EvaluatePolynomialVectorFromPowerBasis[T any](eval Evaluator, targetLevel int, pol *PolynomialVector, cg CoefficientGetter[T], pb *PowerBasis, targetScale rlwe.Scale) (res *rlwe.Ciphertext, err error) {

	// Map[int] of the powers [X^{0}, X^{1}, X^{2}, ...]
	X := pb.Value

	params := eval.GetRLWEParameters()
	mapping := pol.Mapping
	even := pol.IsEven()
	odd := pol.IsOdd()

	// Retrieve the degree of the highest degree non-zero coefficient
	// TODO: optimize for nil/zero coefficients
	minimumDegreeNonZeroCoefficient := pol.Degree()
	if even && !odd && (minimumDegreeNonZeroCoefficient+1)&1 == 0 {
		minimumDegreeNonZeroCoefficient = max(0, minimumDegreeNonZeroCoefficient-1)
	}

	// Gets the maximum degree of the ciphertexts among the power basis
	// TODO: optimize for nil/zero coefficients, odd/even polynomial
	maximumCiphertextDegree := 0
	for i := minimumDegreeNonZeroCoefficient; i > 0; i-- {
		if x, ok := X[i]; ok {
			maximumCiphertextDegree = max(maximumCiphertextDegree, x.Degree())
		}
	}

	if minimumDegreeNonZeroCoefficient < 1 {
		maximumCiphertextDegree = 0
	}

	// Allocates the output ciphertext
	res = rlwe.NewCiphertext(params, maximumCiphertextDegree, targetLevel, -1)
	*res.MetaData = *X[1].MetaData
	res.Scale = targetScale

	// If an index slot is given (either multiply polynomials or masking)
	if mapping != nil {

		if even {
			if err = eval.Add(res, cg.GetVectorCoefficient(pol, 0), res); err != nil {
				return nil, err
			}
		}

		// Loops starting from the highest degree coefficient
		for key := minimumDegreeNonZeroCoefficient; key > 0; key-- {
			if !(even || odd) || (key&1 == 0 && even) || (key&1 == 1 && odd) {
				if err = eval.MulThenAdd(X[key], cg.GetVectorCoefficient(pol, key), res); err != nil {
					return
				}
			}
		}

	} else {

		if even {
			if err = eval.Add(res, cg.GetSingleCoefficient(pol.Value[0], 0), res); err != nil {
				return
			}
		}

		for key := minimumDegreeNonZeroCoefficient; key > 0; key-- {
			if key != 0 && (!(even || odd) || (key&1 == 0 && even) || (key&1 == 1 && odd)) {
				// MulScalarAndAdd automatically scales c to match the scale of res.
				if err = eval.MulThenAdd(X[key], cg.GetSingleCoefficient(pol.Value[0], key), res); err != nil {
					return
				}
			}
		}
	}

	return
}
