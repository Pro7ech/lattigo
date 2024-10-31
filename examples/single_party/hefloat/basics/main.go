// Package main provides an example showcasing the basics of encrypted fixed-point approximate
// arithmetic over the reals/complexes using the package `hefloat`.
package main

import (
	"fmt"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/sampling"
)

func main() {

	// These parameters are 128-bit secure and enable a depth-7 circuits.
	// LogN:14, LogQP: 431.
	//
	// The ratio between the first prime of size ~2^{55} and the scaling factor 2^{45} is ~2^{10}.
	// This means that these parameter can accommodate for values as large as 2^{9} (signed values).
	// To be able to store larger values, either the scale has to be reduced or the first prime increased.
	paramsLit := hefloat.ParametersLiteral{
		LogN:            14,                                    // log2(ring degree)
		LogQ:            []int{55, 45, 45, 45, 45, 45, 45, 45}, // log2(primes Q) (ciphertext modulus)
		LogP:            []int{61},                             // log2(primes P) (auxiliary modulus)
		LogDefaultScale: 45,                                    // log2(scale)
	}

	sc := NewSchemeContext(paramsLit)

	addition(sc)
	multiplication(sc)
	rotations(sc)
	linearTransformation(sc)
}

type SchemeContext struct {
	hefloat.Parameters
	sk *rlwe.SecretKey
	*rlwe.Encryptor
	*rlwe.Decryptor
	*hefloat.Encoder
	*hefloat.Evaluator
}

func (sc *SchemeContext) GenTestVector(scale rlwe.Scale) (have []complex128, pt *rlwe.Plaintext, ct *rlwe.Ciphertext) {

	var err error

	source := sampling.NewSource(sampling.NewSeed())

	have = make([]complex128, sc.MaxSlots())
	for i := range have {
		have[i] = source.Complex128(-1-1i, 1+1i) // uniform in [-1, 1] U [-1, 1]i
	}

	// Encodes a vector of N/2 []complex128 on the [rlwe.Plaintext]
	pt = hefloat.NewPlaintext(sc.Parameters, sc.MaxLevel())
	pt.Scale = scale
	if err = sc.Encode(have, pt); err != nil {
		panic(err)
	}

	// Encrypts an [rlwe.Plaintext] on an [rlwe.Ciphertext]
	ct = hefloat.NewCiphertext(sc.Parameters, 1, pt.Level())
	if err = sc.Encrypt(pt, ct); err != nil {
		panic(err)
	}

	return
}

func NewSchemeContext(paramsLit hefloat.ParametersLiteral) (sc *SchemeContext) {

	sc = new(SchemeContext)

	var err error
	var params hefloat.Parameters
	if params, err = hefloat.NewParametersFromLiteral(paramsLit); err != nil {
		panic(err)
	}

	sc.Parameters = params

	// Note that the following fields in the `hefloat.ParametersLiteral`are optional, but can be manually specified by advanced users:
	//   - `Xs`: the secret distribution (default uniform ternary)
	//   - `Xe`: the error distribution (default discrete Gaussian with standard deviation of 3.2 and truncated to 19)
	//   - `PowBase`: the log2 of the binary decomposition (default 0, i.e. infinity, i.e. no decomposition)
	//   - `RingType`: the ring to be used, (default Z[X]/(X^{N}+1))
	//
	// >>>>>>>>>> SECURITY WARNING <<<<<<<<<<<<<
	// It is the responsibility of the user to ensure that the generated parameters meet the desired security level.
	// This should be done using the lattice estimator (https://github.com/malb/lattice-estimator).
	//
	// The user can extract the base two logarithm of the modulus with the method [hefloat.Parameters].LogQP().
	// See [rlwe.Parameters] and [hefloat.Parameters] for the related API to extract the necessary value for the
	// estimator.
	// >>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<

	kgen := rlwe.NewKeyGenerator(params)

	sk := kgen.GenSecretKeyNew()

	sc.sk = sk
	sc.Encryptor = rlwe.NewEncryptor(params, sk)
	sc.Decryptor = rlwe.NewDecryptor(params, sk)
	sc.Encoder = hefloat.NewEncoder(params)
	sc.Evaluator = hefloat.NewEvaluator(params, nil)

	return
}

func (sc *SchemeContext) GetPrecisionStats(want []complex128, have interface{}) hefloat.PrecisionStats {
	return hefloat.GetPrecisionStats(sc.Parameters, sc.Encoder, sc.Decryptor, want, have, 0, false)
}

func addition(sc *SchemeContext) {

	fmt.Println("ADDITION")

	// For the purpose of this example we will only use the binary operations e.g. AddNew(a, b) -> c
	// where the result c is returned on a newly allocated ciphertext.
	// However, all homomorphic operations have a corresponding in-place ternary method e.g. Add(a, b, c).

	var err error

	eval := sc.Evaluator

	v0, _, ct0 := sc.GenTestVector(sc.Parameters.DefaultScale())
	v1, pt1, ct1 := sc.GenTestVector(sc.Parameters.DefaultScale())

	want := make([]complex128, sc.MaxSlots())
	for i := range want {
		want[i] = v0[i] + v1[i]
	}

	// Addition is often seen as a trivial operation.
	// However in the case of the full-RNS implementation this is not always the case and
	// the user must be aware of its behavior. Addition is performed as follow:
	//
	// ct[0] * round(max(ct[0].Scale, ct[1].Scale)/ct[0].Scale) + ct[1] * round(max(ct[0].Scale, ct[1].Scale)/ct[1].Scale)
	//
	// Meaning that, when a user is manually calling an addition between a ciphertext and a ciphertext/plaintext,
	// he should ensure that the ratio = max(ct[0].Scale,ct[1].Scale)/min(ct[0].Scale, ct[1].Scale) is an integer.
	// Else the the addition will have an error proportional to the fractional part of the ratio, multiplied by the
	// encrypted values of the ciphertext with the smallest scale.
	//
	// In practice it is always possible to ensure that the quantity ratio is an integer. We will see how to do that
	// in the examples that perform multiplications.

	var res *rlwe.Ciphertext
	if res, err = eval.AddNew(ct0, ct1); err != nil {
		panic(err)
	}
	fmt.Printf("Add      : ct + ct    : %f (L2 -log2 Precsion)\n", sc.GetPrecisionStats(want, res).AvgPrec.L2)

	// ciphertext + plaintext
	if res, err = eval.AddNew(ct0, pt1); err != nil {
		panic(err)
	}
	fmt.Printf("Add      : ct + pt    : %f (L2 -log2 Precsion)\n", sc.GetPrecisionStats(want, res).AvgPrec.L2)

	// ciphertext + vector
	// Note that the evaluator will encode this vector at the scale of the input ciphertext to ensure a noiseless addition.

	if res, err = eval.AddNew(ct0, v1); err != nil {
		panic(err)
	}
	fmt.Printf("Add      : ct + vector: %f (L2 -log2 Precsion)\n", sc.GetPrecisionStats(want, res).AvgPrec.L2)

	// ciphertext + scalar
	scalar := 3.141592653589793 + 1.4142135623730951i
	for i := range want {
		want[i] = v0[i] + scalar
	}

	if res, err = eval.AddNew(ct0, scalar); err != nil {
		panic(err)
	}
	fmt.Printf("Add      : ct + scalar: %f (L2 -log2 Precsion)\n", sc.GetPrecisionStats(want, res).AvgPrec.L2)
	fmt.Println()
}

func multiplication(sc *SchemeContext) {

	fmt.Println("MULTIPLICATION")

	var err error

	v0, _, ct0 := sc.GenTestVector(sc.Parameters.DefaultScale())
	v1, pt1, ct1 := sc.GenTestVector(sc.Parameters.DefaultScale())

	want := make([]complex128, sc.MaxSlots())
	for i := range want {
		want[i] = v0[i] * v1[i]
	}

	// For the purpose of ciphertext x ciphertext we need to generate the [rlwe.RelinerizationKey], which enables
	// ciphertext compactness.
	rlk := rlwe.NewKeyGenerator(sc.Parameters).GenRelinearizationKeyNew(sc.sk)

	evk := rlwe.NewMemEvaluationKeySet(rlk)

	// Creates an instance of the [hefloat.Evaluator] with the corresponding keys.
	// Note: backing arrays are shared between the original and returned evaluator,
	// it is not thread safe to use them concurrently.
	// To use two evaluators concurrently, the user must first call .ShallowCopy()
	// to create a thread safe instance of the original evaluator.
	eval := sc.Evaluator.WithKey(evk)

	var res *rlwe.Ciphertext

	// ciphertext * ciphertext
	if res, err = eval.MulNew(ct0, ct1); err != nil {
		panic(err)
	}
	fmt.Printf("Mul      : ct * ct    : %f (L2 -log2 Precsion)\n", sc.GetPrecisionStats(want, res).AvgPrec.L2)

	// ciphertext * plaintext
	if res, err = eval.MulNew(ct0, pt1); err != nil {
		panic(err)
	}
	fmt.Printf("Mul      : ct * pt    : %f (L2 -log2 Precsion)\n", sc.GetPrecisionStats(want, res).AvgPrec.L2)

	// ciphertext * vector
	// Note that when giving non-encoded vectors, the evaluator will internally encode this vector with the appropriate scale that ensure that
	// the following rescaling operation will make the resulting ciphertext fall back on it's previous scale.
	if res, err = eval.MulNew(ct0, v1); err != nil {
		panic(err)
	}
	fmt.Printf("Mul      : ct * vector: %f (L2 -log2 Precsion)\n", sc.GetPrecisionStats(want, res).AvgPrec.L2)

	// ciphertext * scalar
	scalar := -0.441592653589793 + 0.4142135623730951i
	for i := range want {
		want[i] = v0[i] * scalar
	}

	if res, err = eval.MulNew(ct0, scalar); err != nil {
		panic(err)
	}
	fmt.Printf("Mul      : ct * scalar: %f (L2 -log2 Precsion)\n", sc.GetPrecisionStats(want, res).AvgPrec.L2)

	// Up until now, we have performed multiplication without relinearization: the output ciphertext if of degree 2
	// (can be checked with ct.Degree())
	// Usually a we always relinearize after a multiplication, however there are a few cases where delaying
	// the relinerization can save a lot of CPU time, for example when doing an inner product between two
	// vectors of ciphertexts, where we would evaluate Relinearize(sum ct[i] * ct[j]) instead of sum Relinearize(ct[i] * ct[j]).

	for i := range want {
		want[i] = v0[i] * v1[i]
	}

	// relin(ciphertext * ciphertext)
	// Not that the method MulRelinNew is also compatible with [rlwe.Plaintext], scalar and vectors.
	if res, err = eval.MulRelinNew(ct0, ct1); err != nil {
		panic(err)
	}
	fmt.Printf("MulRelin : ct * ct    : %f (L2 -log2 Precsion)\n", sc.GetPrecisionStats(want, res).AvgPrec.L2)

	// Up until now we have performed multiplication without rescaling, however the plaintext
	// scale must be managed and carefully tracked.
	//
	// This is a very important topic, especially for the full-RNS variant of fixed-point
	// approximate homomorphic encryption over the reals/complexes.
	// Messages are encoded on integer polynomials, and thus to keep the precision real
	// coefficients need to be scaled before being discretized to integers.
	// When two messages are multiplied together, the scaling factor of the resulting message
	// is the product of the two initial scaling factors.
	//
	// Let m0*D0 and m1*D1, be two messages scaled by D0 and D1 respectively, then their
	// multiplication will produce a new messages m0 * m1 * (D0 * D1).
	// This means that without any maintenance, the scaling factor will grow exponentially.
	//
	// The rescaling operations allows to control the magnitude of the scaling factor.
	// It does so by dividing a ciphertext by the last prime of its current moduli chain and
	// returns a new ciphertext at level-1 encrypting round(D0 * D1 * m0 * m1 / q[level]).
	//
	// The main  difficulty of this operation arises from the primes used for the rescaling,
	// since they do not naturally divide the initial scaling factor (which is a power of two).

	// As an example, lets take the last result and rescale it:
	//
	// To control the growth of the scaling factor, we call the rescaling operation.
	// Such rescaling operation should be called at the latest before the next multiplication.
	// Each rescaling operation consumes a level, reducing the homomorphic capacity of the ciphertext.
	// If a ciphertext reaches the level 0, it can no longer be rescaled and any further multiplication
	// risks inducing a plaintext overflow.
	fmt.Println()
	fmt.Println("Without optimal scaling")
	fmt.Printf("Scale before rescaling: %15.13f\n", res.LogScale())
	if err = eval.Rescale(res, res); err != nil {
		panic(err)
	}

	// Observe that the resulting scaling factor is close to the initial scaling factor, but not equal to it
	fmt.Printf("Scale after rescaling : %15.13f != %15.13f: %v\n", res.LogScale(), sc.DefaultScale().Log2(), res.LogScale() != sc.DefaultScale().Log2())
	fmt.Printf("\n")

	// Ensuring that we fall back on the default scaling factor after a rescaling operation can be achieved
	// in multiple ways:
	//
	// 1) Encoding one of the operands with a scaling factor equal to the prime that will be consumed by the
	//    rescaling operation
	v1, _, ct1 = sc.GenTestVector(sc.GetScalingFactor(ct0.Scale, sc.DefaultScale(), ct0.Level()))

	for i := range want {
		want[i] = v0[i] * v1[i]
	}

	if res, err = eval.MulRelinNew(ct0, ct1); err != nil {
		panic(err)
	}

	fmt.Println("With manual optimal scaling (pt or ct)")
	fmt.Printf("Scale before rescaling: %15.13f\n", res.LogScale())

	if err = eval.Rescale(res, res); err != nil {
		panic(err)
	}

	// Observe that the resulting scaling factor is close to the initial scaling factor, but not equal to it
	fmt.Printf("Scale after rescaling : %15.13f == %15.13f\n", res.LogScale(), sc.DefaultScale().Log2())
	fmt.Printf("\n")

	// When providing unencoded values as an operand (i.e. scalar or vectors), the evaluator will automatically scale them
	// to the optimal scaling factor:

	if res, err = eval.MulRelinNew(ct0, scalar); err != nil {
		panic(err)
	}

	fmt.Println("With automatic optimal scaling (scalar or vector)")
	fmt.Printf("Scale before rescaling: %15.13f\n", res.LogScale())

	if err = eval.Rescale(res, res); err != nil {
		panic(err)
	}

	fmt.Printf("Scale after rescaling : %15.13f == %15.13f\n", res.LogScale(), sc.DefaultScale().Log2())
	fmt.Printf("\n")

	// 2) Using the [hefloat.Evaluator] method .SetScale to set the scale of the ciphertext to a specific value.
	//    This consumes a level, but is easier to use as it does not require to anticipate at which level the
	//    rescaling will happen and is appropriate when the next operation involves a ciphertext at a lower level
	//    (the consumed level would have been lost anyway)

	v1, _, ct1 = sc.GenTestVector(sc.DefaultScale())

	for i := range want {
		want[i] = v0[i] * v1[i]
	}

	if res, err = eval.MulRelinNew(ct0, ct1); err != nil {
		panic(err)
	}

	fmt.Println("When using SetScale")
	fmt.Printf("Scale before rescaling: %15.13f\n", res.LogScale())

	if err = eval.Rescale(res, res); err != nil {
		panic(err)
	}

	fmt.Printf("Scale after rescaling : %15.13f != %15.13f\n", res.LogScale(), sc.DefaultScale().Log2())

	if err = eval.SetScale(res, sc.DefaultScale()); err != nil {
		panic(err)
	}
	fmt.Printf("Scale after SetScale  : %15.13f\n", res.LogScale())
	fmt.Println()
}

func rotations(sc *SchemeContext) {

	var err error

	fmt.Printf("ROTATION & CONJUGATION\n")

	// Rotations and conjugation are carried through automorphisms and the enable to perform cyclic shift of an encoded
	// vector and/or to apply a complex conjugation.
	//
	// Before being able to do any rotations, the corresponding Galois keys need to be generated.
	// A Galois key is a special type of `rlwe.EvaluationKey` that enables automorphisms
	// X^{i} -> X^{i*k mod 2N} mod X^{N} + 1 on a ciphertext
	//
	// Galois keys can be large depending on the parameters, and one Galois key is needed per automorphism.
	// Therefore it is important to design circuits that minimize the numbers of these keys.
	//
	// In this example we will rotate a ciphertext by 5 positions to the left, as well as get the complex conjugate.
	// This corresponds to the following values for k which we call "galois elements":

	rot := 5
	galEls := []uint64{
		// The galois element for the cyclic rotations by 5 positions to the left.
		sc.GaloisElement(rot),
		// The galois element for the complex conjugation.
		sc.GaloisElementForComplexConjugation(),
	}

	// Creates an instance of the [hefloat.Evaluator] with the corresponding keys.
	// Note: backing arrays are shared between the original and returned evaluator,
	// it is not thread safe to use them concurrently.
	// To use two evaluators concurrently, the user must first call .ShallowCopy()
	// to create a thread safe instance of the original evaluator.
	eval := sc.Evaluator.WithKey(rlwe.NewMemEvaluationKeySet(nil, rlwe.NewKeyGenerator(sc.Parameters).GenGaloisKeysNew(galEls, sc.sk)...))

	v0, _, ct0 := sc.GenTestVector(sc.DefaultScale())

	slots := ct0.Slots()

	want := make([]complex128, len(v0))

	// Rotation by 5 positions to the left
	for i := range v0 {
		want[i] = v0[(i+rot)&(slots-1)]
	}

	var res *rlwe.Ciphertext
	if res, err = eval.RotateNew(ct0, rot); err != nil {
		panic(err)
	}

	fmt.Printf("Rotation by k=%d: %f \n", rot, sc.GetPrecisionStats(want, res).AvgPrec.L2)

	// Conjugation
	for i := range v0 {
		want[i] = complex(real(v0[i]), -imag(v0[i]))
	}

	if res, err = eval.ConjugateNew(ct0); err != nil {
		panic(err)
	}
	fmt.Printf("Conjugation: %f\n", sc.GetPrecisionStats(want, res).AvgPrec.L2)

}

func linearTransformation(sc *SchemeContext) {
	/*
		fmt.Printf("======================\n")
		fmt.Printf("LINEAR TRANSFORMATIONS\n")
		fmt.Printf("======================\n")
		fmt.Printf("\n")

		// The `he/float` package provides a multiple handy linear transformations.
		// We will start with the inner sum.
		// Thus method allows to aggregate `n` sub-vectors of size `batch`.
		// For example given a vector [x0, x1, x2, x3, x4, x5, x6, x7], batch = 2 and n = 3
		// it will return the vector [x0+x2+x4, x1+x3+x5, x2+x4+x6, x3+x5+x7, x4+x6+x0, x5+x7+x1, x6+x0+x2, x7+x1+x3]
		// Observe that the inner sum wraps around the vector, this behavior must be taken into account.

		batch := 37
		n := 127

		// The innersum operations is carried out with log2(n) + HW(n) automorphisms and we need to
		// generate the corresponding Galois keys and provide them to the `Evaluator`.
		eval = eval.WithKey(rlwe.NewMemEvaluationKeySet(rlk, kgen.GenGaloisKeysNew(params.GaloisElementsForInnerSum(batch, n), sk)...))

		// Plaintext circuit
		copy(want, values1)
		for i := 1; i < n; i++ {
			for j, vi := range utils.RotateSlice(values1, i*batch) {
				want[j] += vi
			}
		}

		if err := eval.InnerSum(ct1, batch, n, res); err != nil {
			panic(err)
		}

		// Note that this method can obviously be used to average values.
		// For a good noise management, it is recommended to first multiply the values by 1/n, then
		// apply the innersum and then only apply the rescaling.
		fmt.Printf("Innersum %s", hefloat.GetPrecisionStats(params, ecd, dec, want, res, 0, false).String())

		// The replicate operation is exactly the same as the innersum operation, but in reverse
		eval = eval.WithKey(rlwe.NewMemEvaluationKeySet(rlk, kgen.GenGaloisKeysNew(params.GaloisElementsForReplicate(batch, n), sk)...))

		// Plaintext circuit
		copy(want, values1)
		for i := 1; i < n; i++ {
			for j, vi := range utils.RotateSlice(values1, -i*batch) { //Note the minus sign
				want[j] += vi
			}
		}

		if err := eval.Replicate(ct1, batch, n, res); err != nil {
			panic(err)
		}

		fmt.Printf("Replicate %s", hefloat.GetPrecisionStats(params, ecd, dec, want, res, 0, false).String())

		// And we arrive to the linear transformation.
		// This method enables to evaluate arbitrary Slots x Slots matrices on a ciphertext.
		// What matters is not the size of the matrix, but the number of non-zero diagonals, as
		// the complexity of this operation is 2sqrt(#non-zero-diags).
		//
		// First lets explain what we mean by non-zero diagonal.
		// As an example, lets take the following 4x4 matrix:
		//   0 1 2 3 (diagonal index)
		// | 1 2 3 0 |
		// | 0 1 2 3 |
		// | 3 0 1 2 |
		// | 2 3 0 1 |
		//
		// This matrix has 3 non zero diagonals at indexes [0, 1, 2]:
		//   - 0: [1, 1, 1, 1]
		//   - 1: [2, 2, 2, 2]
		//   - 2: [3, 3, 3, 3]
		//

		nonZeroDiagonals := []int{-15, -4, -1, 0, 1, 2, 3, 4, 15}

		// We allocate the non-zero diagonals and populate them
		diagonals := make(he.Diagonals[complex128])

		for _, i := range nonZeroDiagonals {
			tmp := make([]complex128, Slots)

			for j := range tmp {
				tmp[j] = complex(2*r.Float64()-1, 2*r.Float64()-1)
			}

			diagonals[i] = tmp
		}

		// We create the linear transformation of type complex128 (float64, *big.Float and *bignum.Complex are also possible)
		// Here we use the default structs of the rlwe package, which is compliant to the rlwe.LinearTransformationParameters interface
		// But a user is free to use any struct compliant to this interface.
		// See the definition of the interface for more information about the parameters.
		ltparams := he.LinearTransformationParameters{
			Indexes:                  diagonals.Indexes(),
			LevelQ:                   ct1.Level(),
			LevelP:                   params.MaxLevelP(),
			Scale:                    rlwe.NewScale(params.Q()[ct1.Level()]),
			LogDimensions:            ct1.LogDimensions,
			LogBabyStepGianStepRatio: 1,
		}

		// We allocated the rlwe.LinearTransformation.
		// The allocation takes into account the parameters of the linear transformation.
		lt := he.NewLinearTransformation(params, ltparams)

		// We encode our linear transformation on the allocated rlwe.LinearTransformation.
		// Not that trying to encode a linear transformation with different non-zero diagonals,
		// plaintext dimensions or baby-step giant-step ratio than the one used to allocate the
		// rlwe.LinearTransformation will return an error.
		if err := he.EncodeLinearTransformation[complex128](ecd, diagonals, lt); err != nil {
			panic(err)
		}

		// Then we generate the corresponding Galois keys.
		// The list of Galois elements can also be obtained with `lt.GaloisElements`
		// but this requires to have it pre-allocated, which is not always desirable.
		galEls = he.GaloisElementsForLinearTransformation(params, ltparams)

		ltEval := he.NewLinearTransformationEvaluator(eval.WithKey(rlwe.NewMemEvaluationKeySet(rlk, kgen.GenGaloisKeysNew(galEls, sk)...)))

		// And we valuate the linear transform
		if err := ltEval.Evaluate(ct1, lt, res); err != nil {
			panic(err)
		}

		// Result is not returned rescaled
		if err = eval.Rescale(res, res); err != nil {
			panic(err)
		}

		want = make([]complex128, len(values1))
		buff := make([]complex128, len(values1))

		// We evaluate the same circuit in plaintext

		zero := func(a []complex128) {
			for i := range a {
				a[i] = 0
			}
		}

		add := func(a, b, c []complex128) {
			for i := range a {
				c[i] = a[i] + b[i]
			}
		}

		muladd := func(a, b, c []complex128) {
			for i := range a {
				c[i] += a[i] * b[i]
			}
		}

		diagonals.Evaluate(values1, buff, want, ltparams, zero, add, muladd)

		fmt.Printf("vector x matrix %s", hefloat.GetPrecisionStats(params, ecd, dec, want, res, 0, false).String())
	*/
}
