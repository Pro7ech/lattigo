package hefloat_test

import (
	"math/big"
	"testing"

	"github.com/Pro7ech/lattigo/he"
	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/utils/bignum"
	"github.com/stretchr/testify/require"
)

func testPolynomialEvaluator(tc *testContext, t *testing.T) {

	params := tc.params

	var err error

	polyEval := hefloat.NewPolynomialEvaluator(params, tc.evaluator)

	t.Run(GetTestName(params, "PolynomialEvaluator/Evaluate/PolySingle/Exp"), func(t *testing.T) {

		if params.MaxLevel() < 3 {
			t.Skip("skipping test for params max level < 3")
		}

		values, _, ciphertext := newTestVectors(tc, tc.encryptorSk, -1, 1, t)

		prec := tc.encoder.Prec()

		coeffs := []big.Float{
			*bignum.NewFloat(1, prec),
			*bignum.NewFloat(1, prec),
			*new(big.Float).Quo(bignum.NewFloat(1, prec), bignum.NewFloat(2, prec)),
			*new(big.Float).Quo(bignum.NewFloat(1, prec), bignum.NewFloat(6, prec)),
			*new(big.Float).Quo(bignum.NewFloat(1, prec), bignum.NewFloat(24, prec)),
			*new(big.Float).Quo(bignum.NewFloat(1, prec), bignum.NewFloat(120, prec)),
			*new(big.Float).Quo(bignum.NewFloat(1, prec), bignum.NewFloat(720, prec)),
			*new(big.Float).Quo(bignum.NewFloat(1, prec), bignum.NewFloat(5040, prec)),
		}

		poly := bignum.NewPolynomial(bignum.Monomial, coeffs, nil)

		for i := range values {
			values[i] = *poly.Evaluate(&values[i])
		}

		if ciphertext, err = polyEval.Evaluate(ciphertext, poly, ciphertext.Scale); err != nil {
			t.Fatal(err)
		}

		hefloat.VerifyTestVectors(params, tc.encoder, tc.decryptor, values, ciphertext, params.LogDefaultScale(), 0, *printPrecisionStats, t)
	})

	t.Run(GetTestName(params, "PolynomialEvaluator/Evaluate/PolyVector/Exp"), func(t *testing.T) {

		if params.MaxLevel() < 3 {
			t.Skip("skipping test for params max level < 3")
		}

		values, _, ciphertext := newTestVectors(tc, tc.encryptorSk, -1, 1, t)

		prec := tc.encoder.Prec()

		coeffs := []big.Float{
			*bignum.NewFloat(1, prec),
			*bignum.NewFloat(1, prec),
			*new(big.Float).Quo(bignum.NewFloat(1, prec), bignum.NewFloat(2, prec)),
			*new(big.Float).Quo(bignum.NewFloat(1, prec), bignum.NewFloat(6, prec)),
			*new(big.Float).Quo(bignum.NewFloat(1, prec), bignum.NewFloat(24, prec)),
			*new(big.Float).Quo(bignum.NewFloat(1, prec), bignum.NewFloat(120, prec)),
			*new(big.Float).Quo(bignum.NewFloat(1, prec), bignum.NewFloat(720, prec)),
			*new(big.Float).Quo(bignum.NewFloat(1, prec), bignum.NewFloat(5040, prec)),
		}

		poly := he.NewPolynomial(bignum.NewPolynomial(bignum.Monomial, coeffs, nil))

		slots := ciphertext.Slots()

		mapping := make([]int, slots)
		for i := range mapping {
			if i&1 == 0 {
				mapping[i] = 1
			}
		}

		polyVector, err := he.NewPolynomialVector(map[int]*he.Polynomial{1: poly}, mapping)
		require.NoError(t, err)

		polyVector.Evaluate(values)

		if ciphertext, err = polyEval.Evaluate(ciphertext, polyVector, ciphertext.Scale); err != nil {
			t.Fatal(err)
		}

		hefloat.VerifyTestVectors(params, tc.encoder, tc.decryptor, values, ciphertext, params.LogDefaultScale(), 0, *printPrecisionStats, t)
	})

	t.Run(GetTestName(params, "PolynomialEvaluator/Evaluate/PolyVectorEncoded/Exp"), func(t *testing.T) {

		if params.MaxLevel() < 3 {
			t.Skip("skipping test for params max level < 3")
		}

		values, _, ciphertext := newTestVectors(tc, tc.encryptorSk, -1, 1, t)

		prec := tc.encoder.Prec()

		coeffs := []big.Float{
			*bignum.NewFloat(1, prec),
			*bignum.NewFloat(1, prec),
			*new(big.Float).Quo(bignum.NewFloat(1, prec), bignum.NewFloat(2, prec)),
			*new(big.Float).Quo(bignum.NewFloat(1, prec), bignum.NewFloat(6, prec)),
			*new(big.Float).Quo(bignum.NewFloat(1, prec), bignum.NewFloat(24, prec)),
			*new(big.Float).Quo(bignum.NewFloat(1, prec), bignum.NewFloat(120, prec)),
			*new(big.Float).Quo(bignum.NewFloat(1, prec), bignum.NewFloat(720, prec)),
			*new(big.Float).Quo(bignum.NewFloat(1, prec), bignum.NewFloat(5040, prec)),
		}

		poly := he.NewPolynomial(bignum.NewPolynomial(bignum.Monomial, coeffs, nil))

		slots := ciphertext.Slots()

		mapping := make([]int, slots)
		for i := range mapping {
			if i&1 == 0 {
				mapping[i] = 1
			}
		}

		polyVector, err := he.NewPolynomialVector(map[int]*he.Polynomial{1: poly}, mapping)
		require.NoError(t, err)

		polyVector.Evaluate(values)

		polyVectorEncoded, err := hefloat.GetEncodedPolynomialVector(params, tc.encoder, polyVector, ciphertext.Level(), ciphertext.Scale, ciphertext.Scale)
		require.NoError(t, err)

		if ciphertext, err = polyVectorEncoded.Evaluate(polyEval, ciphertext); err != nil {
			t.Fatal(err)
		}

		hefloat.VerifyTestVectors(params, tc.encoder, tc.decryptor, values, ciphertext, params.LogDefaultScale(), 0, *printPrecisionStats, t)
	})
}
