// Package main implements an example of smooth function approximation using Chebyshev polynomial interpolation.
package main

import (
	"fmt"
	"math"
	"math/big"

	"github.com/Pro7ech/lattigo/he"
	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/bignum"
	"github.com/Pro7ech/lattigo/utils/sampling"
)

func main() {

	var err error
	var params hefloat.Parameters

	// 128-bit secure parameters enabling depth-7 circuits.
	// LogN:14, LogQP: 431.
	if params, err = hefloat.NewParametersFromLiteral(
		hefloat.ParametersLiteral{
			LogN:            5,                                     // log2(ring degree)
			LogQ:            []int{55, 45, 45, 45, 45, 45, 45, 45}, // log2(primes Q) (ciphertext modulus)
			LogP:            []int{61},                             // log2(primes P) (auxiliary modulus)
			LogDefaultScale: 45,                                    // log2(scale)
			RingType:        ring.ConjugateInvariant,
		}); err != nil {
		panic(err)
	}

	// f(x)
	sigmoid := func(x float64) (y float64) {
		return 1 / (math.Exp(-x) + 1)
	}

	interval := 25.0
	degree := 63

	fmt.Println("CHEBYSHEV (SINGLE POLY)")
	evaluate(params, interval, GetChebyshevPoly(interval, degree, sigmoid))
	fmt.Println()

	fmt.Println("MINIMAX (SINGLE POLY)")
	evaluate(params, interval, GetMinimaxPoly(interval, degree, sigmoid))

	fmt.Println("CHEBYSHEV (VECTOR OF POLYS)")

	// g0(x) = f'(x) * (f(x)-0)
	g0 := func(x float64) (y float64) {
		y = sigmoid(x)
		return y * (1 - y) * (y - 0)
	}

	// g1(x) = f'(x) * (f(x)-1)
	g1 := func(x float64) (y float64) {
		y = sigmoid(x)
		return y * (1 - y) * (y - 1)
	}

	// Defines on which slots g0(x) and g1(x) have to be evaluated
	mapping := make([]int, params.MaxSlots())
	for i := range mapping {
		if i&1 == 1 {
			mapping[i] = 1
		}
	}

	// Vectorized Chebyhsev approximation of g0(x) and g1(x) in the domain [-K, K] of degree 63.
	var polys *he.PolynomialVector
	if polys, err = he.NewPolynomialVector(map[int]*he.Polynomial{
		0: GetChebyshevPoly(interval, degree, g0),
		1: GetChebyshevPoly(interval, degree, g1),
	}, mapping); err != nil {
		panic(err)
	}

	evaluate(params, interval, polys)
}

func evaluate(params hefloat.Parameters, K float64, poly interface{}) {

	var err error

	// Key Generator
	kgen := rlwe.NewKeyGenerator(params)

	// Secret Key
	sk := kgen.GenSecretKeyNew()

	// Encoder
	ecd := hefloat.NewEncoder(params)

	// Encryptor
	enc := rlwe.NewEncryptor(params, sk)

	// Decryptor
	dec := rlwe.NewDecryptor(params, sk)

	// Relinearization Key
	rlk := kgen.GenRelinearizationKeyNew(sk)

	// Evaluation Key Set with the Relinearization Key
	evk := rlwe.NewMemEvaluationKeySet(rlk)

	// Evaluator
	eval := hefloat.NewEvaluator(params, evk)

	// Allocates a plaintext at the max level.
	pt := hefloat.NewPlaintext(params, params.MaxLevel())

	// Vector of plaintext values
	values := make([]float64, pt.Slots())

	source := sampling.NewSource([32]byte{})

	// Populates the vector of plaintext values
	for i := range values {
		values[i] = source.Float64(-K, K)
	}

	// Encodes the vector of plaintext values
	if err = ecd.Encode(values, pt); err != nil {
		panic(err)
	}

	// Encrypts the vector of plaintext values
	ct := hefloat.NewCiphertext(params, 1, pt.Level())
	if err = enc.Encrypt(pt, ct); err != nil {
		panic(err)
	}

	// Instantiates the polynomial evaluator
	polyEval := hefloat.NewPolynomialEvaluator(params, eval)

	// Retrieves the change of basis y = scalar * x + constant
	var scalar, constant interface{}
	switch poly := poly.(type) {
	case *he.Polynomial:
		scalar, constant = poly.ChangeOfBasis()
	case *he.PolynomialVector:
		scalar, constant = poly.ChangeOfBasis(ct.Slots())
	default:
		panic(fmt.Errorf("invalid argument 'poly': should be *he.Polynomial or *he.PolynmialVector, but is %T", poly))
	}

	// Performes the change of basis Standard -> Chebyshev
	if err := eval.Mul(ct, scalar, ct); err != nil {
		panic(err)
	}

	if err := eval.Add(ct, constant, ct); err != nil {
		panic(err)
	}

	if err := eval.Rescale(ct, ct); err != nil {
		panic(err)
	}

	// Evaluates the polynomial
	if ct, err = polyEval.Evaluate(ct, poly, params.DefaultScale()); err != nil {
		panic(err)
	}

	// Allocates a vector for the reference values and
	// evaluates the same circuit on the plaintext values
	want := make([]float64, ct.Slots())
	copy(want, values)

	switch poly := poly.(type) {
	case *he.Polynomial:
		for i := range want {
			want[i], _ = poly.Evaluate(values[i])[0].Float64()
		}
	case *he.PolynomialVector:
		poly.Evaluate(want)
	default:
		panic(fmt.Errorf("invalid argument 'poly': should be *he.Polynomial or *he.PolynmialVector, but is %T", poly))
	}

	// Decrypts and print the stats about the precision.
	PrintPrecisionStats(params, ct, want, ecd, dec)
}

// GetChebyshevPoly returns the Chebyshev polynomial approximation of f the
// in the interval [-K, K] for the given degree.
func GetChebyshevPoly(K float64, degree int, f64 func(x float64) (y float64)) *he.Polynomial {

	FBig := func(x *big.Float) (y *big.Float) {
		xF64, _ := x.Float64()
		return new(big.Float).SetPrec(x.Prec()).SetFloat64(f64(xF64))
	}

	var prec uint = 128

	interval := bignum.Interval{
		A:     *bignum.NewFloat(-K, prec),
		B:     *bignum.NewFloat(K, prec),
		Nodes: degree,
	}

	// Returns the polynomial.
	return he.NewPolynomial(bignum.ChebyshevApproximation(FBig, interval))
}

// GetMinimaxPoly returns the minimax polynomial approximation of f the
// in the interval [-K, K] for the given degree.
func GetMinimaxPoly(K float64, degree int, f64 func(x float64) (y float64)) *he.Polynomial {

	FBig := func(x *big.Float) (y *big.Float) {
		xF64, _ := x.Float64()
		return new(big.Float).SetPrec(x.Prec()).SetFloat64(f64(xF64))
	}

	// Bit-precision of the arbitrary precision arithmetic used by the minimax solver
	var prec uint = 160

	// Minimax (Remez) approximation of sigmoid
	r := bignum.NewRemez(bignum.RemezParameters{
		// Function to Approximate
		Function: FBig,

		// Polynomial basis of the approximation
		Basis: bignum.Chebyshev,

		// Approximation in [A, B] of degree Nodes.
		Intervals: []bignum.Interval{
			{
				A:     *bignum.NewFloat(-K, prec),
				B:     *bignum.NewFloat(K, prec),
				Nodes: degree,
			},
		},

		// Bit-precision of the solver
		Prec: prec,
	})

	// Max 10 iters, and normalized min/max error of 1e-15
	fmt.Printf("Minimax Approximation of Degree %d\n", degree)
	r.Approximate(10, 1e-15)
	fmt.Println()

	// Shoes the coeffs with 50 decimals of precision
	fmt.Printf("Minimax Chebyshev Coefficients [%f, %f]\n", -K, K)
	r.ShowCoeffs(16)
	fmt.Println()

	// Shows the min and max error with 50 decimals of precision
	fmt.Println("Minimax Error")
	r.ShowError(16)
	fmt.Println()

	// Returns the polynomial.
	return he.NewPolynomial(bignum.NewPolynomial(bignum.Chebyshev, r.Coeffs, [2]float64{-K, K}))
}

// PrintPrecisionStats decrypts, decodes and prints the precision stats of a ciphertext.
func PrintPrecisionStats(params hefloat.Parameters, ct *rlwe.Ciphertext, want []float64, ecd *hefloat.Encoder, dec *rlwe.Decryptor) {

	var err error

	// Decrypts the vector of plaintext values
	pt := dec.DecryptNew(ct)

	// Decodes the plaintext
	have := make([]float64, ct.Slots())
	if err = ecd.Decode(pt, have); err != nil {
		panic(err)
	}

	// Pretty prints some values
	fmt.Printf("Have: ")
	for i := 0; i < 4; i++ {
		fmt.Printf("%20.15f ", have[i])
	}
	fmt.Printf("...\n")

	fmt.Printf("Want: ")
	for i := 0; i < 4; i++ {
		fmt.Printf("%20.15f ", want[i])
	}
	fmt.Printf("...\n")

	// Pretty prints the precision stats
	fmt.Println(hefloat.GetPrecisionStats(params, ecd, dec, have, want, 0, false).String())
}
