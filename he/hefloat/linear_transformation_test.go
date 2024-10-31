package hefloat_test

import (
	"math/big"
	"math/rand/v2"
	"testing"

	"github.com/Pro7ech/lattigo/he"
	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils"
	"github.com/Pro7ech/lattigo/utils/bignum"
	"github.com/Pro7ech/lattigo/utils/sampling"
	"github.com/stretchr/testify/require"
)

func testLinearTransformation(tc *testContext, t *testing.T) {

	params := tc.params

	mul := bignum.NewComplexMultiplier().Mul

	add := func(a, b, c []bignum.Complex) {
		for i := range c {
			c[i].Add(&a[i], &b[i])
		}
	}

	muladd := func(a, b, c []bignum.Complex) {
		d := &bignum.Complex{}
		for i := range c {

			mul(&a[i], &b[i], d)
			c[i].Add(&c[i], d)
		}
	}

	prec := tc.encoder.Prec()

	zero := func(a []bignum.Complex) {
		for i := range a {
			a[i].SetPrec(prec)
			a[i][0].SetInt64(0)
			a[i][1].SetInt64(0)
		}
	}

	source := sampling.NewSource([32]byte{})

	t.Run(GetTestName(params, "Evaluator/Average"), func(t *testing.T) {

		values, _, ciphertext := newTestVectors(tc, tc.encryptorSk, -1, 1, t)

		slots := ciphertext.Slots()

		logBatch := 9
		batch := 1 << logBatch
		n := slots / batch

		eval := tc.evaluator.WithKey(rlwe.NewMemEvaluationKeySet(nil, tc.kgen.GenGaloisKeysNew(rlwe.GaloisElementsForInnerSum(params, batch, n), tc.sk)...))

		buf := eval.NewHoistingBuffer(ciphertext.LevelQ(), params.MaxLevelP())

		require.NoError(t, eval.Average(ciphertext, logBatch, buf, ciphertext))

		tmp0 := make([]bignum.Complex, len(values))
		for i := range tmp0 {
			tmp0[i] = *values[i].Clone()
		}

		for i := 1; i < n; i++ {

			tmp1 := utils.RotateSlice(tmp0, i*batch)

			for j := range values {
				values[j].Add(&values[j], &tmp1[j])
			}
		}

		nB := new(big.Float).SetFloat64(float64(n))

		for i := range values {
			values[i][0].Quo(&values[i][0], nB)
			values[i][1].Quo(&values[i][1], nB)
		}

		hefloat.VerifyTestVectors(params, tc.encoder, tc.decryptor, values, ciphertext, params.LogDefaultScale(), 0, *printPrecisionStats, t)
	})

	t.Run(GetTestName(params, "LinearTransformationEvaluator/BSGS=True"), func(t *testing.T) {

		values, _, ciphertext := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		slots := ciphertext.Slots()

		nonZeroDiags := []int{-15, -4, -1, 0, 1, 2, 3, 4, 15}

		diagonals := make(he.Diagonals[bignum.Complex])
		for _, i := range nonZeroDiags {
			diagonals[i] = make([]bignum.Complex, slots)
			for j := 0; j < slots; j++ {
				diagonals[i][j].SetPrec(prec)
				diagonals[i][j][0].SetFloat64(source.Float64(-1, 1))
			}
		}

		ltparams := he.LinearTransformationParameters{
			Indexes:       diagonals.Indexes(),
			LevelQ:        ciphertext.Level(),
			LevelP:        params.MaxLevelP(),
			Scale:         params.GetScalingFactor(ciphertext.Scale, params.DefaultScale(), ciphertext.Level()),
			LogDimensions: ciphertext.LogDimensions,
		}

		// Allocate the linear transformation
		linTransf := he.NewLinearTransformation(params, ltparams)

		// Encode on the linear transformation
		require.NoError(t, he.EncodeLinearTransformation[bignum.Complex](tc.encoder, diagonals, linTransf))

		galEls := ltparams.GaloisElements(params)

		evk := rlwe.NewMemEvaluationKeySet(nil, tc.kgen.GenGaloisKeysNew(galEls, tc.sk)...)

		ltEval := he.NewLinearTransformationEvaluator(tc.evaluator.WithKey(evk))

		buf := ltEval.NewHoistingBuffer(ciphertext.LevelQ(), params.MaxLevelP())

		require.NoError(t, ltEval.Evaluate(ciphertext, linTransf, buf, ciphertext))

		have := make([]bignum.Complex, len(values))
		buff := make([]bignum.Complex, len(values))

		diagonals.Evaluate(values, buff, have, ltparams, zero, add, muladd)

		hefloat.VerifyTestVectors(params, tc.encoder, tc.decryptor, have, ciphertext, params.LogDefaultScale(), 0, *printPrecisionStats, t)
	})

	t.Run(GetTestName(params, "LinearTransformationEvaluator/BSGS=False"), func(t *testing.T) {

		values, _, ciphertext := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		slots := ciphertext.Slots()

		nonZeroDiags := []int{-15, -4, -1, 0, 1, 2, 3, 4, 15}

		diagonals := make(he.Diagonals[bignum.Complex])
		for _, i := range nonZeroDiags {
			diagonals[i] = make([]bignum.Complex, slots)
			for j := 0; j < slots; j++ {
				diagonals[i][j].SetPrec(prec)
				diagonals[i][j][0].SetFloat64(source.Float64(-1, 1))
			}
		}

		ltparams := he.LinearTransformationParameters{
			Indexes:       diagonals.Indexes(),
			LevelQ:        ciphertext.Level(),
			LevelP:        params.MaxLevelP(),
			Scale:         params.GetScalingFactor(ciphertext.Scale, params.DefaultScale(), ciphertext.Level()),
			LogDimensions: ciphertext.LogDimensions,
			GiantStep:     -1,
		}

		// Allocate the linear transformation
		linTransf := he.NewLinearTransformation(params, ltparams)

		// Encode on the linear transformation
		require.NoError(t, he.EncodeLinearTransformation(tc.encoder, diagonals, linTransf))

		galEls := ltparams.GaloisElements(params)

		evk := rlwe.NewMemEvaluationKeySet(nil, tc.kgen.GenGaloisKeysNew(galEls, tc.sk)...)

		ltEval := he.NewLinearTransformationEvaluator(tc.evaluator.WithKey(evk))

		buf := ltEval.NewHoistingBuffer(ciphertext.LevelQ(), params.MaxLevelP())

		require.NoError(t, ltEval.Evaluate(ciphertext, linTransf, buf, ciphertext))

		have := make([]bignum.Complex, len(values))
		buff := make([]bignum.Complex, len(values))

		diagonals.Evaluate(values, buff, have, ltparams, zero, add, muladd)

		hefloat.VerifyTestVectors(params, tc.encoder, tc.decryptor, have, ciphertext, params.LogDefaultScale(), 0, *printPrecisionStats, t)
	})

	t.Run(GetTestName(params, "LinearTransformationEvaluator/Permutation"), func(t *testing.T) {

		idx := make([]int, params.MaxSlots())
		for i := range idx {
			idx[i] = i
		}

		r := rand.New(source)
		for i := range idx {
			j := r.IntN(i + 1)
			idx[i], idx[j] = idx[j], idx[i]
		}

		idx = idx[:min(64, len(idx)>>1)]

		perm := he.NewPermutation[bignum.Complex](len(idx))

		for i := range perm {
			perm[i].X = i
			perm[i].Y = idx[i]

			C := bignum.Complex{}
			C.SetPrec(prec)
			C[0].SetFloat64(source.Float64(-1, 1))

			perm[i].C = C
		}

		diagonals := perm.Diagonals(params.LogMaxDimensions())

		values, _, ciphertext := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		ltparams := he.LinearTransformationParameters{
			Indexes:       diagonals.Indexes(),
			LevelQ:        ciphertext.Level(),
			LevelP:        params.MaxLevelP(),
			Scale:         params.GetScalingFactor(ciphertext.Scale, params.DefaultScale(), ciphertext.Level()),
			LogDimensions: ciphertext.LogDimensions,
		}

		// Allocate the linear transformation
		linTransf := he.NewLinearTransformation(params, ltparams)

		// Encode on the linear transformation
		require.NoError(t, he.EncodeLinearTransformation[bignum.Complex](tc.encoder, diagonals, linTransf))

		galEls := ltparams.GaloisElements(params)

		evk := rlwe.NewMemEvaluationKeySet(nil, tc.kgen.GenGaloisKeysNew(galEls, tc.sk)...)

		ltEval := he.NewLinearTransformationEvaluator(tc.evaluator.WithKey(evk))

		buf := ltEval.NewHoistingBuffer(ciphertext.LevelQ(), params.MaxLevelP())

		require.NoError(t, ltEval.Evaluate(ciphertext, linTransf, buf, ciphertext))

		have := make([]bignum.Complex, len(values))
		buff := make([]bignum.Complex, len(values))

		diagonals.Evaluate(values, buff, have, ltparams, zero, add, muladd)

		hefloat.VerifyTestVectors(params, tc.encoder, tc.decryptor, have, ciphertext, params.LogDefaultScale(), 0, *printPrecisionStats, t)
	})
}
