package heint_test

import (
	//"fmt"
	"math/big"
	"testing"

	"github.com/Pro7ech/lattigo/he"
	"github.com/Pro7ech/lattigo/he/heint"
	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/utils/bignum"
	"github.com/stretchr/testify/require"
)

func testPolynomialEvaluator(tc *testContext, t *testing.T) {

	t.Run("PolynomialEvaluator", func(t *testing.T) {

		t.Run("Single", func(t *testing.T) {

			if tc.params.MaxLevel() < 4 {
				t.Skip("MaxLevel() to low")
			}

			values, _, ciphertext := newTestVectorsLvl(tc.params.MaxLevel(), tc.params.NewScale(1), tc, tc.encryptorSk)

			coeffs := []uint64{0, 0, 1}

			T := tc.params.PlaintextModulus()
			for i := range values {
				values[i] = ring.EvalPolyModP(values[i], coeffs, T)
			}

			poly := bignum.NewPolynomial(bignum.Monomial, coeffs, nil)

			t.Run(GetTestName("Standard", tc.params, tc.params.MaxLevel()), func(t *testing.T) {
				polyEval := heint.NewPolynomialEvaluator(tc.params, tc.evaluator, false)
				res, err := polyEval.Evaluate(ciphertext, poly, tc.params.DefaultScale())
				require.NoError(t, err)
				require.NoError(t, polyEval.Rescale(res, res))
				require.Equal(t, res.Scale.Cmp(tc.params.DefaultScale()), 0)
				verifyTestVectors(tc, tc.decryptor, values, res, t)
			})

			t.Run(GetTestName("Invariant", tc.params, tc.params.MaxLevel()), func(t *testing.T) {
				polyEval := heint.NewPolynomialEvaluator(tc.params, tc.evaluator, true)
				res, err := polyEval.Evaluate(ciphertext, poly, tc.params.DefaultScale())
				require.NoError(t, err)
				require.Equal(t, res.Level(), ciphertext.Level())
				require.Equal(t, res.Scale.Cmp(tc.params.DefaultScale()), 0)
				verifyTestVectors(tc, tc.decryptor, values, res, t)
			})
		})

		t.Run("Vector", func(t *testing.T) {

			if tc.params.MaxLevel() < 4 {
				t.Skip("MaxLevel() to low")
			}

			values, _, ciphertext := newTestVectorsLvl(tc.params.MaxLevel(), tc.params.NewScale(7), tc, tc.encryptorSk)

			coeffs0 := []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
			coeffs1 := []uint64{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17}

			mapping := make([]int, len(values))
			for i := range mapping {
				if i&1 == 1 {
					mapping[i] = 1
				}
			}

			p0 := he.NewPolynomial(bignum.NewPolynomial(bignum.Monomial, coeffs0, nil))
			p1 := he.NewPolynomial(bignum.NewPolynomial(bignum.Monomial, coeffs1, nil))

			polyVector, err := he.NewPolynomialVector(map[int]*he.Polynomial{
				0: p0,
				1: p1,
			}, mapping)
			require.NoError(t, err)

			TInt := new(big.Int).SetUint64(tc.params.PlaintextModulus())

			for i, j := range mapping {
				if p, ok := polyVector.Value[j]; ok {
					values[i] = p.EvaluateModP(new(big.Int).SetUint64(values[i]), TInt).Uint64()
				} else {
					values[i] = 0
				}
			}

			t.Run(GetTestName("Standard", tc.params, tc.params.MaxLevel()), func(t *testing.T) {

				polyEval := heint.NewPolynomialEvaluator(tc.params, tc.evaluator, false)

				res, err := polyEval.Evaluate(ciphertext, polyVector, tc.params.DefaultScale())
				require.NoError(t, err)

				require.NoError(t, polyEval.Rescale(res, res))

				require.Equal(t, res.Scale.Cmp(tc.params.DefaultScale()), 0)

				verifyTestVectors(tc, tc.decryptor, values, res, t)
			})

			t.Run(GetTestName("Invariant", tc.params, tc.params.MaxLevel()), func(t *testing.T) {

				polyEval := heint.NewPolynomialEvaluator(tc.params, tc.evaluator, true)

				res, err := polyEval.Evaluate(ciphertext, polyVector, tc.params.DefaultScale())
				require.NoError(t, err)

				require.Equal(t, res.Level(), ciphertext.Level())
				require.Equal(t, res.Scale.Cmp(tc.params.DefaultScale()), 0)

				verifyTestVectors(tc, tc.decryptor, values, res, t)
			})
		})
	})
}
