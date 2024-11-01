package hefloat_test

import (
	"math/big"
	"testing"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/he/hefloat/bootstrapping"
	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"

	"github.com/stretchr/testify/require"
)

func testComparisons(tc *testContext, t *testing.T) {

	var err error

	params := tc.params
	enc := tc.encryptorSk
	sk := tc.sk
	ecd := tc.encoder
	dec := tc.decryptor
	kgen := tc.kgen

	btp := bootstrapping.NewSecretKeyBootstrapper(params, sk)

	var galKeys []*rlwe.GaloisKey
	if params.RingType() == ring.Standard {
		galKeys = append(galKeys, kgen.GenGaloisKeyNew(params.GaloisElementForComplexConjugation(), sk))
	}

	eval := tc.evaluator.WithKey(rlwe.NewMemEvaluationKeySet(kgen.GenRelinearizationKeyNew(sk), galKeys...))

	polys := hefloat.NewMinimaxCompositePolynomial(hefloat.DefaultMinimaxCompositePolynomialForSign)

	CmpEval := hefloat.NewComparisonEvaluator(params, eval, btp, polys)

	t.Run(GetTestName(params, "ComparisonEvaluator/Sign"), func(t *testing.T) {

		values, _, ct := newTestVectors(tc, enc, complex(-1, 0), complex(1, 0), t)

		var sign *rlwe.Ciphertext
		sign, err = CmpEval.Sign(ct)
		require.NoError(t, err)

		have := make([]big.Float, params.MaxSlots())

		require.NoError(t, ecd.Decode(dec.DecryptNew(sign), have))

		want := make([]big.Float, params.MaxSlots())

		for i := range have {
			want[i] = polys.Evaluate(values[i])[0]
		}

		hefloat.VerifyTestVectors(params, ecd, nil, want, have, params.LogDefaultScale(), 0, *printPrecisionStats, t)
	})

	t.Run(GetTestName(params, "ComparisonEvaluator/Step"), func(t *testing.T) {

		values, _, ct := newTestVectors(tc, enc, complex(-1, 0), complex(1, 0), t)

		var step *rlwe.Ciphertext
		step, err = CmpEval.Step(ct)
		require.NoError(t, err)

		have := make([]big.Float, params.MaxSlots())

		require.NoError(t, ecd.Decode(dec.DecryptNew(step), have))

		want := make([]big.Float, params.MaxSlots())

		half := new(big.Float).SetFloat64(0.5)

		for i := range have {
			want[i] = polys.Evaluate(values[i])[0]
			want[i].Mul(&want[i], half)
			want[i].Add(&want[i], half)
		}

		hefloat.VerifyTestVectors(params, ecd, nil, want, have, params.LogDefaultScale(), 0, *printPrecisionStats, t)
	})

	t.Run(GetTestName(params, "ComparisonEvaluator/Max"), func(t *testing.T) {

		values0, _, ct0 := newTestVectors(tc, enc, complex(-0.5, 0), complex(0.5, 0), t)
		values1, _, ct1 := newTestVectors(tc, enc, complex(-0.5, 0), complex(0.5, 0), t)

		var max *rlwe.Ciphertext
		max, err = CmpEval.Max(ct0, ct1)
		require.NoError(t, err)

		have := make([]big.Float, params.MaxSlots())

		require.NoError(t, ecd.Decode(dec.DecryptNew(max), have))

		want := make([]big.Float, params.MaxSlots())

		for i := range have {

			if values0[i][0].Cmp(&values1[i][0]) == -1 {
				want[i] = values1[i][0]
			} else {
				want[i] = values0[i][0]
			}
		}

		hefloat.VerifyTestVectors(params, ecd, nil, want, have, params.LogDefaultScale(), 0, *printPrecisionStats, t)
	})

	t.Run(GetTestName(params, "ComparisonEvaluator/Min"), func(t *testing.T) {

		values0, _, ct0 := newTestVectors(tc, enc, complex(-0.5, 0), complex(0.5, 0), t)
		values1, _, ct1 := newTestVectors(tc, enc, complex(-0.5, 0), complex(0.5, 0), t)

		var min *rlwe.Ciphertext
		min, err = CmpEval.Min(ct0, ct1)
		require.NoError(t, err)

		have := make([]big.Float, params.MaxSlots())

		require.NoError(t, ecd.Decode(dec.DecryptNew(min), have))

		want := make([]big.Float, params.MaxSlots())

		for i := range have {

			if values0[i][0].Cmp(&values1[i][0]) == 1 {
				want[i] = values1[i][0]
			} else {
				want[i] = values0[i][0]
			}
		}

		hefloat.VerifyTestVectors(params, ecd, nil, want, have, params.LogDefaultScale(), 0, *printPrecisionStats, t)
	})
}
