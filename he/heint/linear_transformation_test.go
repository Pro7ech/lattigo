package heint_test

import (
	"math/rand/v2"
	"testing"

	"github.com/Pro7ech/lattigo/he"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/sampling"
	"github.com/stretchr/testify/require"
)

func testLinearTransformation(tc *testContext, t *testing.T) {

	params := tc.params

	rT := tc.rT

	add := func(a, b, c []uint64) {
		rT.Add(a, b, c)
	}

	buff := make([]uint64, params.MaxSlots())

	muladd := func(a, b, c []uint64) {
		rT.MForm(a, buff[:len(a)])
		rT.MulCoeffsMontgomeryThenAdd(buff[:len(a)], b, c)
	}

	zero := func(a []uint64) {
		for i := range a {
			a[i] = 0
		}
	}

	source := sampling.NewSource([32]byte{})

	LevelQ := params.MaxLevel()

	t.Run(GetTestName("LinearTransformationEvaluator/BSGS=true", params, LevelQ), func(t *testing.T) {

		values, _, ciphertext := newTestVectorsLvl(LevelQ, params.DefaultScale(), tc, tc.encryptorSk)

		nonZeroDiags := []int{-15, -4, -1, 0, 1, 2, 3, 4, 15}

		diagonals := make(he.Diagonals[uint64])

		slots := len(values)

		for _, i := range nonZeroDiags {
			diagonals[i] = make([]uint64, slots)
			for j := 0; j < slots; j++ {
				diagonals[i][j] = 1
			}
		}

		ltparams := he.LinearTransformationParameters{
			Indexes:       diagonals.Indexes(),
			LevelQ:        ciphertext.Level(),
			LevelP:        params.MaxLevelP(),
			Scale:         params.DefaultScale(),
			LogDimensions: ciphertext.LogDimensions,
			GiantStep:     -1,
		}

		// Allocate the linear transformation
		linTransf := he.NewLinearTransformation(params, ltparams)

		// Encode on the linear transformation
		require.NoError(t, he.EncodeLinearTransformation[uint64](tc.encoder, diagonals, linTransf))

		galEls := ltparams.GaloisElements(params)

		eval := tc.evaluator.WithKey(rlwe.NewMemEvaluationKeySet(nil, tc.kgen.GenGaloisKeysNew(galEls, tc.sk)...))
		ltEval := he.NewLinearTransformationEvaluator(eval)

		buf := ltEval.NewHoistingBuffer(ciphertext.LevelQ(), params.MaxLevelP())

		require.NoError(t, ltEval.Evaluate(ciphertext, linTransf, buf, ciphertext))

		tmp := make([]uint64, slots)
		copy(tmp, values)

		have := make([]uint64, len(values))
		buff := make([]uint64, len(values))

		diagonals.Evaluate(values, buff, have, ltparams, zero, add, muladd)

		verifyTestVectors(tc, tc.decryptor, have, ciphertext, t)
	})

	t.Run(GetTestName("LinearTransformationEvaluator/BSGS=false", params, LevelQ), func(t *testing.T) {

		values, _, ciphertext := newTestVectorsLvl(LevelQ, params.DefaultScale(), tc, tc.encryptorSk)

		nonZeroDiags := []int{-15, -4, -1, 0, 1, 2, 3, 4, 15}

		diagonals := make(he.Diagonals[uint64])

		slots := len(values)

		for _, i := range nonZeroDiags {
			diagonals[i] = make([]uint64, slots)
			for j := 0; j < slots; j++ {
				diagonals[i][j] = 1
			}
		}

		ltparams := he.LinearTransformationParameters{
			Indexes:       diagonals.Indexes(),
			LevelQ:        ciphertext.Level(),
			LevelP:        params.MaxLevelP(),
			Scale:         params.DefaultScale(),
			LogDimensions: ciphertext.LogDimensions,
		}

		// Allocate the linear transformation
		linTransf := he.NewLinearTransformation(params, ltparams)

		// Encode on the linear transformation
		require.NoError(t, he.EncodeLinearTransformation[uint64](tc.encoder, diagonals, linTransf))

		galEls := ltparams.GaloisElements(params)

		eval := tc.evaluator.WithKey(rlwe.NewMemEvaluationKeySet(nil, tc.kgen.GenGaloisKeysNew(galEls, tc.sk)...))
		ltEval := he.NewLinearTransformationEvaluator(eval)

		buf := ltEval.NewHoistingBuffer(ciphertext.LevelQ(), params.MaxLevelP())

		require.NoError(t, ltEval.Evaluate(ciphertext, linTransf, buf, ciphertext))

		tmp := make([]uint64, slots)
		copy(tmp, values)

		have := make([]uint64, len(values))
		buff := make([]uint64, len(values))

		diagonals.Evaluate(values, buff, have, ltparams, zero, add, muladd)

		verifyTestVectors(tc, tc.decryptor, have, ciphertext, t)
	})

	t.Run(GetTestName("LinearTransformationEvaluator/Permutation", params, LevelQ), func(t *testing.T) {

		idx0 := make([]int, params.MaxSlots()>>1)
		idx1 := make([]int, params.MaxSlots()>>1)
		for i := range idx0 {
			idx0[i] = i
			idx1[i] = i
		}

		r := rand.New(source)
		for i := range idx0 {
			j := r.IntN(i + 1)
			idx0[i], idx0[j] = idx0[j], idx0[i]
			j = r.IntN(i + 1)
			idx1[i], idx1[j] = idx1[j], idx1[i]
		}

		idx0 = idx0[:min(64, len(idx0)>>1)]
		idx1 = idx1[:min(64, len(idx1)>>1)]

		perm := he.NewPermutation[uint64](len(idx0) + len(idx1))

		T := params.PlaintextModulus()

		offset := params.MaxSlots() >> 1
		n := len(idx0)

		for i := range idx0 {
			perm[i].X = i
			perm[i].Y = idx0[i]
			perm[i].C = r.Uint64N(T)
			perm[i+n].X = i + offset
			perm[i+n].Y = idx1[i] + offset
			perm[i+n].C = r.Uint64N(T)
		}

		diagonals := perm.Diagonals(params.LogMaxDimensions())

		values, _, ciphertext := newTestVectorsLvl(LevelQ, params.DefaultScale(), tc, tc.encryptorSk)

		ltparams := he.LinearTransformationParameters{
			Indexes:       diagonals.Indexes(),
			LevelQ:        ciphertext.Level(),
			LevelP:        params.MaxLevelP(),
			Scale:         params.DefaultScale(),
			LogDimensions: ciphertext.LogDimensions,
		}

		// Allocate the linear transformation
		linTransf := he.NewLinearTransformation(params, ltparams)

		// Encode on the linear transformation
		require.NoError(t, he.EncodeLinearTransformation[uint64](tc.encoder, diagonals, linTransf))

		galEls := ltparams.GaloisElements(params)

		evk := rlwe.NewMemEvaluationKeySet(nil, tc.kgen.GenGaloisKeysNew(galEls, tc.sk)...)

		ltEval := he.NewLinearTransformationEvaluator(tc.evaluator.WithKey(evk))

		buf := ltEval.NewHoistingBuffer(ciphertext.LevelQ(), params.MaxLevelP())

		require.NoError(t, ltEval.Evaluate(ciphertext, linTransf, buf, ciphertext))

		have := make([]uint64, len(values))
		buff := make([]uint64, len(values))

		diagonals.Evaluate(values, buff, have, ltparams, zero, add, muladd)

		verifyTestVectors(tc, tc.decryptor, have, ciphertext, t)
	})
}
