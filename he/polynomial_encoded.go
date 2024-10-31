package he

import (
	"fmt"
	"math/bits"

	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/bignum"
)

// EncodedPolynomialVector is a struct storing an encoded [PolynomialVector].
// Using an EncodedPolynomialVector provides significantly faster polynomial
// evaluation as the plaintext vectors are pre-encoded, the tradeoff being
// a loss in flexibility as an EncodedPolynomialVector must be evaluated
// on a ciphertext at a specific level and scale.
type EncodedPolynomialVector struct {
	Value     [][]*rlwe.Plaintext
	Basis     bignum.Basis
	Depth     int
	LogDegree int
	LogSplit  int
	IsOdd     bool
	IsEven    bool
	Lazy      bool
}

// GetEncodedPolynomialVector generates an [EncodedPolynomialVector] from a [PolynomialVector].
func GetEncodedPolynomialVector[T any](params rlwe.ParameterProvider, ecd Encoder, polys *PolynomialVector, cg CoefficientGetter[T], inputLevel int, inputScale, targetScale rlwe.Scale, eval SimEvaluator) (pspe *EncodedPolynomialVector, err error) {

	psp := polys.GetPatersonStockmeyerPolynomial(params, inputLevel, inputScale, targetScale, eval)

	split := psp.Split()

	pspe = new(EncodedPolynomialVector)
	pspe.Value = make([][]*rlwe.Plaintext, split)

	// ceil(log2(degree))
	logDegree := bits.Len64(uint64(polys.Degree()))

	// optimal ratio between degree(pi(X)) et degree(P(X))
	logSplit := bignum.OptimalSplit(logDegree)

	pspe.LogDegree = logDegree
	pspe.LogSplit = logSplit
	pspe.IsOdd = polys.IsOdd()
	pspe.IsEven = polys.IsEven()
	pspe.Lazy = polys.Lazy()
	pspe.Depth = polys.Depth()
	pspe.Basis = polys.Basis()

	// Initializes the simulated polynomial evaluation
	pb := SimPowerBasis{}
	pb[1] = &SimOperand{
		Level: inputLevel,
		Scale: inputScale,
	}

	// Generates the simulated powers (to get the scaling factors)
	pb.GenPower(polys.Lazy(), 1<<logDegree, eval)
	for i := (1 << logSplit) - 1; i > 2; i-- {
		pb.GenPower(polys.Lazy(), i, eval)
	}

	// Small steps
	for i := range split {

		polyVec := &PolynomialVector{
			Value:   map[int]*Polynomial{},
			Mapping: psp.Mapping,
		}

		// Transposes the polynomial matrix
		for j := range psp.Value {
			polyVec.Value[j] = &psp.Value[j].Value[i]
		}

		targetLevel := psp.Level(i)
		targetScale := psp.Scale(i)

		// eval & cg are not thread-safe
		if pspe.Value[split-i-1], err = GetBabyStepPlaintextVector(params, ecd, targetLevel, polyVec, cg, pb, eval.LogDimensions(), targetScale); err != nil {
			return nil, fmt.Errorf("GetBabyStepPlaintextVector: %w", err)
		}
	}

	return
}

// GetBabyStepPlaintextVector a method that complies to the interface he.PolynomialVectorEvaluator. This method evaluates P(ct) = sum pt_i * ct^{i}.
func GetBabyStepPlaintextVector[T any](p rlwe.ParameterProvider, encoder Encoder, targetLevel int, pol *PolynomialVector, cg CoefficientGetter[T], pb SimPowerBasis, logDimensions ring.Dimensions, targetScale rlwe.Scale) (pts []*rlwe.Plaintext, err error) {

	// Map[int] of the powers [X^{0}, X^{1}, X^{2}, ...]
	X := pb

	params := p.GetRLWEParameters()
	mapping := pol.Mapping
	even := pol.IsEven()
	odd := pol.IsOdd()

	// Retrieve the degree of the highest degree non-zero coefficient
	// TODO: optimize for nil/zero coefficients
	minimumDegreeNonZeroCoefficient := pol.Degree()
	if even && !odd && (minimumDegreeNonZeroCoefficient+1)&1 == 0 {
		minimumDegreeNonZeroCoefficient = max(0, minimumDegreeNonZeroCoefficient-1)
	}

	pts = make([]*rlwe.Plaintext, minimumDegreeNonZeroCoefficient+1)

	// If an index slot is given (either multiply polynomials or masking)
	if mapping != nil {
		if even {
			pts[0] = rlwe.NewPlaintext(params, targetLevel, -1)
			pts[0].LogDimensions = logDimensions
			pts[0].IsBatched = true
			pts[0].Scale = targetScale
			if err = encoder.Embed(cg.GetVectorCoefficient(pol, 0), pts[0].MetaData, *pts[0].Point); err != nil {
				return nil, fmt.Errorf("encoder.Embed: %w", err)
			}
		}

		// Loops starting from the highest degree coefficient
		for key := minimumDegreeNonZeroCoefficient; key > 0; key-- {
			if !(even || odd) || (key&1 == 0 && even) || (key&1 == 1 && odd) {
				pts[key] = rlwe.NewPlaintext(params, targetLevel, -1)
				pts[key].LogDimensions = logDimensions
				pts[key].IsBatched = true
				pts[key].Scale = targetScale
				pts[key].Scale = pts[key].Scale.Div(X[key].Scale)
				if err = encoder.Embed(cg.GetVectorCoefficient(pol, key), pts[key].MetaData, *pts[key].Point); err != nil {
					return nil, fmt.Errorf("encoder.Embed: %w", err)
				}
			}
		}
	} else {
		return nil, fmt.Errorf("polynomial mapping is nil")
	}

	return
}

// PopulatePowerBasis populates a [PowerBasis] with the missing ciphertext powers to evaluate the [EncodedPolynomialVector].
func (p *EncodedPolynomialVector) PopulatePowerBasis(eval EvaluatorForPolynomial, pb *PowerBasis) (err error) {

	// Computes all the powers of two with relinearization
	// This will recursively compute and store all powers of two up to 2^logDegree
	if err = pb.GenPower(1<<(p.LogDegree-1), p.Lazy, eval); err != nil {
		return fmt.Errorf("[PowerBasis].GenPower: %w", err)
	}

	// Computes the intermediate powers, starting from the largest, without relinearization if possible
	for i := (1 << p.LogSplit) - 1; i > 2; i-- {
		if !(p.IsEven || p.IsOdd) || (i&1 == 0 && p.IsEven) || (i&1 == 1 && p.IsOdd) {
			if err = pb.GenPower(i, p.Lazy, eval); err != nil {
				return fmt.Errorf("[PowerBasis].GenPower: %w", err)
			}
		}
	}

	return
}

// Evaluate evlauates an [EncodedPolynomialVector] on an [rlwe.Ciphertext] or using a pre-computed [PowerBasis].
func (p *EncodedPolynomialVector) Evaluate(eval EvaluatorForPolynomial, input interface{}) (opOut *rlwe.Ciphertext, err error) {

	var powerbasis *PowerBasis
	switch input := input.(type) {
	case *rlwe.Ciphertext:
		powerbasis = NewPowerBasis(input, p.Basis)
	case *PowerBasis:
		if input.Value[1] == nil {
			return nil, fmt.Errorf("EncodedPolynomialVector.Evaluate: given PowerBasis.Value[1] is empty")
		}
		powerbasis = input
	default:
		return nil, fmt.Errorf("EncodedPolynomialVector.Evaluate: invalid input, must be either *rlwe.Ciphertext or *PowerBasis but is %T", input)
	}

	if level, depth := powerbasis.Value[1].Level(), eval.LevelsConsumedPerRescaling()*p.Depth; level < depth {
		return nil, fmt.Errorf("%d levels < %d log(d) -> cannot evaluate poly", level, depth)
	}

	if err = p.PopulatePowerBasis(eval, powerbasis); err != nil {
		return nil, fmt.Errorf("[EncodedPolynomialVector].PopulatePowerBasis: %w", err)
	}

	babySteps := make([]*BabyStep, len(p.Value))

	X := powerbasis.Value

	for i := range babySteps {

		// Retrieve the degree of the highest degree non-zero coefficient
		minimumDegreeNonZeroCoefficient := len(p.Value[i]) - 1
		if p.IsEven && !p.IsOdd {
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

		pts := p.Value[i]

		babySteps[i] = new(BabyStep)
		babySteps[i].Degree = len(p.Value[i]) - 1

		var ct *rlwe.Ciphertext

		if pts[0] != nil {
			ct = pts[0].AsCiphertext().Clone()
		}

		for j := 1; j < len(pts); j++ {
			if pts[j] != nil {
				if ct == nil {
					if ct, err = eval.MulNew(X[j], pts[j]); err != nil {
						return nil, fmt.Errorf("eval.MulNew: %w", err)
					}
				} else {
					if err = eval.MulThenAdd(X[j], pts[j], ct); err != nil {
						return nil, fmt.Errorf("eval.MulThenAdd: %w", err)
					}
				}
			}
		}

		babySteps[i].Value = ct
	}

	return ProcessBabySteps(eval, babySteps, powerbasis)
}
