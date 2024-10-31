package he

import (
	"fmt"
	"math/big"
	"math/bits"

	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/bignum"
)

// Polynomial is a struct for representing plaintext polynomials
// for their homomorphic evaluation in an encrypted point. The
// type wraps a bignum.Polynomial along with several evaluation-
// related parameters.
type Polynomial struct {
	*bignum.Polynomial
	MaxDeg int        // Always set to len(Coeffs)-1
	Lead   bool       // Always set to true
	Lazy   bool       // Flag for lazy-relinearization
	Level  int        // Metadata for BSGS polynomial evaluation
	Scale  rlwe.Scale // Metadata for BSGS polynomial evaluation
}

// NewPolynomial returns an instantiated Polynomial for the
// provided bignum.Polynomial.
func NewPolynomial(poly *bignum.Polynomial) *Polynomial {
	return &Polynomial{
		Polynomial: poly,
		MaxDeg:     len(poly.Coeffs) - 1,
		Lead:       true,
		Lazy:       false,
	}
}

// Factorize factorizes p as X^{n} * pq + pr.
func (p *Polynomial) Factorize(n int) (pq, pr *Polynomial) {

	pq = &Polynomial{}
	pr = &Polynomial{}

	pq.Polynomial, pr.Polynomial = p.Polynomial.Factorize(n)

	pq.MaxDeg = p.MaxDeg

	if p.MaxDeg == p.Degree() {
		pr.MaxDeg = n - 1
	} else {
		pr.MaxDeg = p.MaxDeg - (p.Degree() - n + 1)
	}

	if p.Lead {
		pq.Lead = true
	}

	return
}

// PatersonStockmeyerPolynomial is a struct that stores
// the Paterson Stockmeyer decomposition of a polynomial.
// The decomposition of P(X) is given as sum pi(X) * X^{2^{n}}
// where degree(pi(X)) =~ sqrt(degree(P(X)))
type PatersonStockmeyerPolynomial struct {
	Degree int
	Base   int
	Level  int
	Scale  rlwe.Scale
	Value  []Polynomial
}

// GetPatersonStockmeyerPolynomial returns the Paterson Stockmeyer polynomial decomposition of the target polynomial.
// The decomposition is done with the power of two basis.
func (p *Polynomial) GetPatersonStockmeyerPolynomial(params rlwe.ParameterProvider, inputLevel int, inputScale, outputScale rlwe.Scale, eval SimEvaluator) *PatersonStockmeyerPolynomial {

	// ceil(log2(degree))
	logDegree := bits.Len64(uint64(p.Degree()))

	// optimal ratio between degree(pi(X)) et degree(P(X))
	logSplit := bignum.OptimalSplit(logDegree)

	// Initializes the simulated polynomial evaluation
	pb := SimPowerBasis{}
	pb[1] = &SimOperand{
		Level: inputLevel,
		Scale: inputScale,
	}

	// Generates the simulated powers (to get the scaling factors)
	pb.GenPower(p.Lazy, 1<<logDegree, eval)
	for i := (1 << logSplit) - 1; i > 2; i-- {
		pb.GenPower(p.Lazy, i, eval)
	}

	/*
		for i := 0; i < 128; i++{
			if p, ok := pb[i]; ok{
				fmt.Println(i, p.Level, p.Degree)
			}
		}
	*/

	// Simulates the homomorphic evaluation with levels and scaling factors to retrieve the scaling factor of each pi(X).
	PSPoly, _ := recursePS(logSplit, inputLevel-eval.PolynomialDepth(p.Degree()), p, pb, outputScale, eval)

	return &PatersonStockmeyerPolynomial{
		Degree: p.Degree(),
		Base:   1 << logSplit,
		Level:  inputLevel,
		Scale:  outputScale,
		Value:  PSPoly,
	}
}

// recursePS is a recursive implementation of a polynomial evaluation via the Paterson Stockmeyer algorithm with a power of two decomposition.
func recursePS(logSplit, targetLevel int, p *Polynomial, pb SimPowerBasis, outputScale rlwe.Scale, eval SimEvaluator) ([]Polynomial, *SimOperand) {

	if p.Degree() < (1 << logSplit) {

		if p.Lead && logSplit > 1 && p.MaxDeg > (1<<bits.Len64(uint64(p.MaxDeg)))-(1<<(logSplit-1)) {

			logDegree := int(bits.Len64(uint64(p.Degree())))
			logSplit := bignum.OptimalSplit(logDegree)

			return recursePS(logSplit, targetLevel, p, pb, outputScale, eval)
		}

		var Degree int
		p.Level, p.Scale, Degree = eval.UpdateLevelAndScaleBabyStep(p.Lead, targetLevel, outputScale, p, pb)

		return []Polynomial{*p}, &SimOperand{Level: p.Level, Scale: p.Scale, Degree: Degree}
	}

	var nextPower = 1 << logSplit
	for nextPower < (p.Degree()>>1)+1 {
		nextPower <<= 1
	}

	XPow := pb[nextPower]

	coeffsq, coeffsr := p.Factorize(nextPower)

	tLevelNew, tScaleNew := eval.UpdateLevelAndScaleGiantStep(p.Lead, targetLevel, outputScale, XPow.Scale, coeffsq)

	bsgsQ, res := recursePS(logSplit, tLevelNew, coeffsq, pb, tScaleNew, eval)

	res.Degree = min(1, res.Degree)
	eval.Rescale(res)

	if XPow.Degree == 2 && res.Degree != 0 {
		XPow.Degree = 1
	}

	res = eval.MulNew(res, XPow)

	bsgsR, tmp := recursePS(logSplit, targetLevel, coeffsr, pb, res.Scale, eval)

	// This checks that the underlying algorithm behaves as expected, which will always be
	// the case, unless the user provides an incorrect custom implementation.
	if !tmp.Scale.InDelta(res.Scale, float64(rlwe.ScalePrecision-12)) {
		panic(fmt.Errorf("recursePS: res.Scale != tmp.Scale: %v != %v", &res.Scale.Value, &tmp.Scale.Value))
	}

	return append(bsgsQ, bsgsR...), res
}

// PolynomialVector is a struct storing a set of polynomials and a mapping that
// indicates on which slot each polynomial has to be independently evaluated.
// For example, if we are given two polynomials P0(X) and P1(X) and the folling mapping: map[int][]int{0:[0, 1, 2], 1:[3, 4, 5]},
// then the polynomial evaluation on a vector [a, b, c, d, e, f, g, h] will evaluate to [P0(a), P0(b), P0(c), P1(d), P1(e), P1(f), 0, 0]
type PolynomialVector struct {
	Value   map[int]*Polynomial
	Mapping []int
}

func (p *PolynomialVector) Evaluate(values interface{}) {

	polys := p.Value
	mapping := p.Mapping

	switch values := values.(type) {
	case []complex128:
		for i, j := range mapping {
			if p, ok := polys[j]; ok {
				values[i] = p.Evaluate(values[i]).Complex128()
			} else {
				values[i] = 0
			}
		}
	case []float64:
		for i, j := range mapping {
			if p, ok := polys[j]; ok {
				values[i], _ = p.Evaluate(values[i])[0].Float64()
			} else {
				values[i] = 0
			}
		}
	case []bignum.Complex:
		for i, j := range mapping {
			if p, ok := polys[j]; ok {
				values[i] = *p.Evaluate(values[i])
			} else {
				values[i][0].SetInt64(0)
				values[i][1].SetInt64(0)
			}
		}
	case []big.Float:
		for i, j := range mapping {
			if p, ok := polys[j]; ok {
				values[i] = p.Evaluate(values[i])[0]
			} else {
				values[i].SetInt64(0)
			}
		}
	default:
		panic(fmt.Errorf("invalid argument 'value': accepted type are []<complex128, float64, bignum.Complex, big.Float> but is %T", values))
	}
}

// NewPolynomialVector instantiates a new PolynomialVector from a set of bignum.Polynomial and a mapping indicating
// which polynomial has to be evaluated on which slot.
// For example, if we are given two polynomials P0(X) and P1(X) and the folling mapping: map[int][]int{0:[0, 1, 2], 1:[3, 4, 5]},
// then the polynomial evaluation on a vector [a, b, c, d, e, f, g, h] will evaluate to [P0(a), P0(b), P0(c), P1(d), P1(e), P1(f), 0, 0]
func NewPolynomialVector(polys map[int]*Polynomial, mapping []int) (*PolynomialVector, error) {
	var maxDeg int
	var basis bignum.Basis
	for i := range polys {
		maxDeg = max(maxDeg, polys[i].Degree())
		basis = polys[i].Basis
	}

	IsEven, IsOdd := true, true
	Lazy := false

	for i := range polys {
		if basis != polys[i].Basis {
			return nil, fmt.Errorf("polynomial basis must be the same for all polynomials in a polynomial vector")
		}

		if maxDeg != polys[i].Degree() {
			return nil, fmt.Errorf("polynomial degree must all be the same")
		}

		IsEven = IsEven && polys[i].IsEven
		IsOdd = IsOdd && polys[i].IsOdd
		Lazy = Lazy || polys[i].Lazy
	}

	for i := range polys {
		polys[i].IsEven = IsEven
		polys[i].IsOdd = IsOdd
		polys[i].Lazy = Lazy
	}

	return &PolynomialVector{
		Value:   polys,
		Mapping: mapping,
	}, nil
}

func (p *PolynomialVector) Degree() int {

	if len(p.Value) == 0 {
		panic(fmt.Errorf("[he.PolynomialVector].Degree(): polynomial list is empty"))
	}

	for _, pi := range p.Value {
		return pi.Degree()
	}

	return 0
}

func (p *PolynomialVector) Basis() bignum.Basis {

	if len(p.Value) == 0 {
		panic(fmt.Errorf("[he.PolynomialVector].Basis(): polynomial list is empty"))
	}

	for _, pi := range p.Value {
		return pi.Basis
	}

	return bignum.Monomial
}

// Depth returns the depth required to evaluate the receiver.
func (p *PolynomialVector) Depth() (depth int) {

	if len(p.Value) == 0 {
		panic(fmt.Errorf("[he.PolynomialVector].Depth(): polynomial list is empty"))
	}

	for _, pi := range p.Value {
		return pi.Depth()
	}

	return 0
}

// IsEven returns true if all underlying polynomials are even,
// i.e. all odd powers are zero.
func (p *PolynomialVector) IsEven() (even bool) {

	if len(p.Value) == 0 {
		panic(fmt.Errorf("[he.PolynomialVector].IsEven(): polynomial list is empty"))
	}

	even = true
	for _, poly := range p.Value {
		even = even && poly.IsEven
	}
	return
}

// IsOdd returns true if all underlying polynomials are odd,
// i.e. all even powers are zero.
func (p *PolynomialVector) IsOdd() (odd bool) {

	if len(p.Value) == 0 {
		panic(fmt.Errorf("[he.PolynomialVector].IsOdd(): polynomial list is empty"))
	}

	odd = true
	for _, poly := range p.Value {
		odd = odd && poly.IsOdd
	}
	return
}

// Lazy return true if at least one polynomial is set to Lazy=true
func (p *PolynomialVector) Lazy() (lazy bool) {

	if len(p.Value) == 0 {
		panic(fmt.Errorf("[he.PolynomialVector].Lazy(): polynomial list is empty"))
	}

	for _, poly := range p.Value {
		lazy = lazy || poly.Lazy
	}
	return
}

func (p *PolynomialVector) ChangeOfBasis(slots int) (scalar, constant []big.Float) {

	if len(p.Value) == 0 {
		panic(fmt.Errorf("[he.PolynomialVector].ChangeOfBasis(): polynomial list is empty"))
	}

	scalar = make([]big.Float, slots)
	constant = make([]big.Float, slots)

	for i, k := range p.Mapping {
		if poly, ok := p.Value[k]; ok {
			s, c := poly.ChangeOfBasis()
			scalar[i].Copy(s)
			constant[i].Copy(c)
		}
	}

	return
}

// Factorize factorizes the underlying Polynomial vector p into p = polyq * X^{n} + polyr.
func (p *PolynomialVector) Factorize(n int) (polyq, polyr *PolynomialVector) {

	if len(p.Value) == 0 {
		panic(fmt.Errorf("[he.PolynomialVector].Factorize(): polynomial list is empty"))
	}

	coeffsq := map[int]*Polynomial{}
	coeffsr := map[int]*Polynomial{}

	for i, p := range p.Value {
		coeffsq[i], coeffsr[i] = p.Factorize(n)
	}

	return &PolynomialVector{Value: coeffsq, Mapping: p.Mapping}, &PolynomialVector{Value: coeffsr, Mapping: p.Mapping}
}

func (p *PolynomialVector) PopulatePowerBasis(eval EvaluatorForPolynomial, pb *PowerBasis) (err error) {

	logDegree := bits.Len64(uint64(p.Degree()))
	logSplit := bignum.OptimalSplit(logDegree)

	var odd, even = false, false
	for _, p := range p.Value {
		odd, even = odd || p.IsOdd, even || p.IsEven
	}

	// Computes all the powers of two with relinearization
	// This will recursively compute and store all powers of two up to 2^logDegree
	if err = pb.GenPower(1<<(logDegree-1), p.Lazy(), eval); err != nil {
		return fmt.Errorf("[PowerBasis].GenPower: %w", err)
	}

	// Computes the intermediate powers, starting from the largest, without relinearization if possible
	for i := (1 << logSplit) - 1; i > 2; i-- {
		if !(even || odd) || (i&1 == 0 && even) || (i&1 == 1 && odd) {
			if err = pb.GenPower(i, p.Lazy(), eval); err != nil {
				return fmt.Errorf("[PowerBasis].GenPower: %w", err)
			}
		}
	}

	return
}

// PatersonStockmeyerPolynomialVector is a struct implementing the
// Paterson Stockmeyer decomposition of a PolynomialVector.
// See PatersonStockmeyerPolynomial for additional information.
type PatersonStockmeyerPolynomialVector struct {
	Value   map[int]*PatersonStockmeyerPolynomial
	Mapping []int
}

// GetPatersonStockmeyerPolynomial returns the Paterson Stockmeyer polynomial decomposition of the target PolynomialVector.
// The decomposition is done with the power of two basis
func (p *PolynomialVector) GetPatersonStockmeyerPolynomial(params rlwe.ParameterProvider, inputLevel int, inputScale, outputScale rlwe.Scale, eval SimEvaluator) *PatersonStockmeyerPolynomialVector {

	Value := map[int]*PatersonStockmeyerPolynomial{}
	for i := range p.Value {
		Value[i] = p.Value[i].GetPatersonStockmeyerPolynomial(params, inputLevel, inputScale, outputScale, eval)
	}

	return &PatersonStockmeyerPolynomialVector{
		Value:   Value,
		Mapping: p.Mapping,
	}
}

// Split returns the number of baby polynomials.
func (p *PatersonStockmeyerPolynomialVector) Split() int {

	if len(p.Value) == 0 {
		panic(fmt.Errorf("[he.PatersonStockmeyerPolynomialVector].Split(): polynomial list is empty"))
	}

	for _, pi := range p.Value {
		return len(pi.Value)
	}

	return 0
}

// Level returns the level of the i-th baby polynomial.
func (p *PatersonStockmeyerPolynomialVector) Level(i int) int {

	if len(p.Value) == 0 {
		panic(fmt.Errorf("[he.PatersonStockmeyerPolynomialVector].Level(): polynomial list is empty"))
	}

	for _, pi := range p.Value {
		return pi.Value[i].Level
	}

	return 0
}

// Scale returns the scale of the i-th baby polynomial.
func (p *PatersonStockmeyerPolynomialVector) Scale(i int) (scale rlwe.Scale) {

	if len(p.Value) == 0 {
		panic(fmt.Errorf("[he.PatersonStockmeyerPolynomialVector].Scale(): polynomial list is empty"))
	}

	for _, pi := range p.Value {
		return pi.Value[i].Scale
	}

	return
}

// Degree returns the degree of the i-th baby polynomial.
func (p *PatersonStockmeyerPolynomialVector) Degree(i int) int {

	if len(p.Value) == 0 {
		panic(fmt.Errorf("[he.PatersonStockmeyerPolynomialVector].Degree(): polynomial list is empty"))
	}

	for _, pi := range p.Value {
		return pi.Value[i].Degree()
	}

	return 0
}
