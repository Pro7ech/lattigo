package hefloat_test

import (
	"math/big"
	"testing"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/he/hefloat/bootstrapping"
	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/bignum"
	"github.com/stretchr/testify/require"
)

func testinverse(tc *testContext, t *testing.T) {

	params := tc.params
	enc := tc.encryptorSk
	sk := tc.sk
	ecd := tc.encoder
	dec := tc.decryptor
	kgen := tc.kgen

	btp := bootstrapping.NewSecretKeyBootstrapper(params, sk)

	valMin := 1 / 256.0
	valMax := 256.0

	var galKeys []*rlwe.GaloisKey
	if params.RingType() == ring.Standard {
		galKeys = append(galKeys, kgen.GenGaloisKeyNew(params.GaloisElementForComplexConjugation(), sk))
	}

	evk := rlwe.NewMemEvaluationKeySet(kgen.GenRelinearizationKeyNew(sk), galKeys...)

	eval := tc.evaluator.WithKey(evk)
	one := bignum.NewFloat(1, params.EncodingPrecision())

	t.Run(GetTestName(params, "InverseEvaluator/GoldschmidtDivisionNew"), func(t *testing.T) {

		values, _, ct := newTestVectors(tc, tc.encryptorSk, complex(0.5, 0), complex(1.5, 0), t)

		for i := range values {
			values[i][0].Quo(one, &values[i][0])
		}

		invEval := hefloat.NewInverseEvaluator(params, eval, btp)
		require.NoError(t, invEval.GoldschmidtDivision(7, ct))
		hefloat.VerifyTestVectors(params, tc.encoder, tc.decryptor, values, ct, int(ecd.Prec())-15, 0, *printPrecisionStats, t)
	})

	t.Run(GetTestName(params, "InverseEvaluator/PositiveDomain"), func(t *testing.T) {

		values, _, ct := newTestVectors(tc, enc, complex(valMin, 0), complex(valMax, 0), t)

		invEval := hefloat.NewInverseEvaluator(params, eval, btp)
		require.NoError(t, invEval.InversePositiveDomainNew(ct, valMin, valMax))

		have := make([]big.Float, params.MaxSlots())

		require.NoError(t, ecd.Decode(dec.DecryptNew(ct), have))

		want := make([]big.Float, params.MaxSlots())
		for i := range have {
			want[i] = *new(big.Float).Quo(one, &values[i][0])
		}

		hefloat.VerifyTestVectors(params, tc.encoder, nil, want, have, int(ecd.Prec())-6, 0, *printPrecisionStats, t)
	})

	t.Run(GetTestName(params, "InverseEvaluator/NegativeDomain"), func(t *testing.T) {

		values, _, ct := newTestVectors(tc, enc, complex(-valMax, 0), complex(-valMin, 0), t)

		invEval := hefloat.NewInverseEvaluator(params, eval, btp)
		require.NoError(t, invEval.InverseNegativeDomainNew(ct, valMin, valMax))

		have := make([]big.Float, params.MaxSlots())

		require.NoError(t, ecd.Decode(dec.DecryptNew(ct), have))

		want := make([]big.Float, params.MaxSlots())
		for i := range have {
			want[i] = *new(big.Float).Quo(one, &values[i][0])
		}

		hefloat.VerifyTestVectors(params, tc.encoder, nil, want, have, int(ecd.Prec())-6, 0, *printPrecisionStats, t)
	})

	t.Run(GetTestName(params, "InverseEvaluator/FullDomain"), func(t *testing.T) {

		values, _, ct := newTestVectors(tc, enc, complex(-valMax, 0), complex(valMax, 0), t)

		invEval := hefloat.NewInverseEvaluator(params, eval, btp)
		require.NoError(t, invEval.InverseFullDomainNew(ct, valMin, valMax, hefloat.NewMinimaxCompositePolynomial(hefloat.DefaultMinimaxCompositePolynomialForSign)))

		have := make([]big.Float, params.MaxSlots())

		require.NoError(t, ecd.Decode(dec.DecryptNew(ct), have))

		want := make([]big.Float, params.MaxSlots())

		threshold := bignum.NewFloat(valMin, params.EncodingPrecision())
		for i := range have {
			if new(big.Float).Abs(&values[i][0]).Cmp(threshold) == -1 {
				want[i] = have[i] // Ignores values outside of the interval
			} else {
				want[i] = *new(big.Float).Quo(one, &values[i][0])
			}
		}

		hefloat.VerifyTestVectors(params, tc.encoder, nil, want, have, int(ecd.Prec())-6, 0, *printPrecisionStats, t)
	})

	t.Run(GetTestName(params, "InverseEvaluator/InvSqrt"), func(t *testing.T) {

		A := 0.25
		B := 0.75
		r := 11

		values, _, ct := newTestVectors(tc, enc, complex(A, 0), complex(B, 0), t)

		invEval := hefloat.NewInverseEvaluator(params, eval, btp)

		half := ct.Clone()

		require.NoError(t, eval.Mul(half, 0.5, half))
		require.NoError(t, eval.Rescale(half, half))

		require.NoError(t, invEval.InvSqrt(ct, half, r))

		have := make([]big.Float, params.MaxSlots())

		require.NoError(t, ecd.Decode(dec.DecryptNew(ct), have))

		want := make([]big.Float, params.MaxSlots())
		for i := range have {
			want[i].Sqrt(&values[i][0])
			want[i].Quo(one, &want[i])
		}

		hefloat.VerifyTestVectors(params, tc.encoder, nil, want, have, int(ecd.Prec())-10, 0, *printPrecisionStats, t)
	})
}
