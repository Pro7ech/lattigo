package hefloat_test

import (
	"testing"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/bignum"
	"github.com/stretchr/testify/require"
)

func testEvaluatorAdd(tc *testContext, t *testing.T) {

	t.Run(GetTestName(tc.params, "Evaluator/AddNew/Ct"), func(t *testing.T) {

		v0, _, ct0 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		v1, _, ct1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		for i := range v0 {
			v0[i].Add(&v0[i], &v1[i])
		}

		ct03, err := tc.evaluator.AddNew(ct0, ct1)
		require.NoError(t, err)

		hefloat.VerifyTestVectors(tc.params, tc.encoder, tc.decryptor, v0, ct03, tc.params.LogDefaultScale(), 0, *printPrecisionStats, t)
	})

	t.Run(GetTestName(tc.params, "Evaluator/Add/Ct"), func(t *testing.T) {

		v0, _, ct0 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		v1, _, ct1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		for i := range v0 {
			v0[i].Add(&v0[i], &v1[i])
		}

		require.NoError(t, tc.evaluator.Add(ct0, ct1, ct0))

		hefloat.VerifyTestVectors(tc.params, tc.encoder, tc.decryptor, v0, ct0, tc.params.LogDefaultScale(), 0, *printPrecisionStats, t)
	})

	t.Run(GetTestName(tc.params, "Evaluator/Add/Pt"), func(t *testing.T) {

		v0, _, ct0 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		v1, plaintext2, _ := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		for i := range v0 {
			v0[i].Add(&v0[i], &v1[i])
		}

		require.NoError(t, tc.evaluator.Add(ct0, plaintext2, ct0))

		hefloat.VerifyTestVectors(tc.params, tc.encoder, tc.decryptor, v0, ct0, tc.params.LogDefaultScale(), 0, *printPrecisionStats, t)
	})

	t.Run(GetTestName(tc.params, "Evaluator/Add/Scalar"), func(t *testing.T) {

		v0, _, ct0 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		constant := randomConst(tc.params.RingType(), tc.encoder.Prec(), -1+1i, -1+1i)

		for i := range v0 {
			v0[i].Add(&v0[i], constant)
		}

		require.NoError(t, tc.evaluator.Add(ct0, constant, ct0))

		hefloat.VerifyTestVectors(tc.params, tc.encoder, tc.decryptor, v0, ct0, tc.params.LogDefaultScale(), 0, *printPrecisionStats, t)
	})

	t.Run(GetTestName(tc.params, "Evaluator/Add/Vector"), func(t *testing.T) {

		v0, _, ct0 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		v1, _, _ := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		for i := range v0 {
			v0[i].Add(&v0[i], &v1[i])
		}

		require.NoError(t, tc.evaluator.Add(ct0, v1, ct0))

		hefloat.VerifyTestVectors(tc.params, tc.encoder, tc.decryptor, v0, ct0, tc.params.LogDefaultScale(), 0, *printPrecisionStats, t)
	})
}

func testEvaluatorSub(tc *testContext, t *testing.T) {

	t.Run(GetTestName(tc.params, "Evaluator/SubNew/Ct"), func(t *testing.T) {

		v0, _, ct0 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		v1, _, ct1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		for i := range v0 {
			v0[i].Sub(&v0[i], &v1[i])
		}

		ct03, err := tc.evaluator.SubNew(ct0, ct1)
		require.NoError(t, err)

		hefloat.VerifyTestVectors(tc.params, tc.encoder, tc.decryptor, v0, ct03, tc.params.LogDefaultScale(), 0, *printPrecisionStats, t)
	})

	t.Run(GetTestName(tc.params, "Evaluator/Sub/Ct"), func(t *testing.T) {

		v0, _, ct0 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		v1, _, ct1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		for i := range v0 {
			v0[i].Sub(&v0[i], &v1[i])
		}

		require.NoError(t, tc.evaluator.Sub(ct0, ct1, ct0))

		hefloat.VerifyTestVectors(tc.params, tc.encoder, tc.decryptor, v0, ct0, tc.params.LogDefaultScale(), 0, *printPrecisionStats, t)
	})

	t.Run(GetTestName(tc.params, "Evaluator/Sub/Pt"), func(t *testing.T) {

		v0, _, ct0 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		v1, plaintext2, ct1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		v0Test := make([]bignum.Complex, len(v0))
		for i := range v0 {
			v0Test[i].Sub(&v0[i], &v1[i])
		}

		require.NoError(t, tc.evaluator.Sub(ct0, plaintext2, ct1))

		hefloat.VerifyTestVectors(tc.params, tc.encoder, tc.decryptor, v0Test, ct1, tc.params.LogDefaultScale(), 0, *printPrecisionStats, t)
	})

	t.Run(GetTestName(tc.params, "Evaluator/Sub/Scalar"), func(t *testing.T) {

		v0, _, ct0 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		constant := randomConst(tc.params.RingType(), tc.encoder.Prec(), -1+1i, -1+1i)

		for i := range v0 {
			v0[i].Sub(&v0[i], constant)
		}

		require.NoError(t, tc.evaluator.Sub(ct0, constant, ct0))

		hefloat.VerifyTestVectors(tc.params, tc.encoder, tc.decryptor, v0, ct0, tc.params.LogDefaultScale(), 0, *printPrecisionStats, t)
	})

	t.Run(GetTestName(tc.params, "Evaluator/Sub/Vector"), func(t *testing.T) {

		v0, _, ct0 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		v1, _, _ := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		for i := range v0 {
			v0[i].Sub(&v0[i], &v1[i])
		}

		require.NoError(t, tc.evaluator.Sub(ct0, v1, ct0))

		hefloat.VerifyTestVectors(tc.params, tc.encoder, tc.decryptor, v0, ct0, tc.params.LogDefaultScale(), 0, *printPrecisionStats, t)
	})
}

func testEvaluatorRescale(tc *testContext, t *testing.T) {

	t.Run(GetTestName(tc.params, "Evaluator/RescaleTo/Single"), func(t *testing.T) {

		if tc.params.MaxLevel() < 2 {
			t.Skip("skipping test for params max level < 2")
		}

		v0, _, ct0 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		constant := tc.ringQ[ct0.Level()].Modulus

		require.NoError(t, tc.evaluator.Mul(ct0, constant, ct0))

		ct0.Scale = ct0.Scale.Mul(rlwe.NewScale(constant))

		if err := tc.evaluator.RescaleTo(ct0, tc.params.DefaultScale(), ct0); err != nil {
			t.Fatal(err)
		}

		hefloat.VerifyTestVectors(tc.params, tc.encoder, tc.decryptor, v0, ct0, tc.params.LogDefaultScale(), 0, *printPrecisionStats, t)
	})

	t.Run(GetTestName(tc.params, "Evaluator/RescaleTo/Many"), func(t *testing.T) {

		if tc.params.MaxLevel() < 2 {
			t.Skip("skipping test for params max level < 2")
		}

		v0, _, ct0 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		nbRescales := tc.params.MaxLevel()
		if nbRescales > 5 {
			nbRescales = 5
		}

		for i := 0; i < nbRescales; i++ {
			constant := tc.ringQ[ct0.Level()-i].Modulus
			require.NoError(t, tc.evaluator.Mul(ct0, constant, ct0))
			ct0.Scale = ct0.Scale.Mul(rlwe.NewScale(constant))
		}

		if err := tc.evaluator.RescaleTo(ct0, tc.params.DefaultScale(), ct0); err != nil {
			t.Fatal(err)
		}

		hefloat.VerifyTestVectors(tc.params, tc.encoder, tc.decryptor, v0, ct0, tc.params.LogDefaultScale(), 0, *printPrecisionStats, t)
	})
}

func testEvaluatorMul(tc *testContext, t *testing.T) {

	t.Run(GetTestName(tc.params, "Evaluator/MulNew/Ct/Pt"), func(t *testing.T) {

		v0, pt0, ct0 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		mul := bignum.NewComplexMultiplier()

		for i := range v0 {
			mul.Mul(&v0[i], &v0[i], &v0[i])
		}

		ct1, err := tc.evaluator.MulNew(ct0, pt0)
		require.NoError(t, err)

		hefloat.VerifyTestVectors(tc.params, tc.encoder, tc.decryptor, v0, ct1, tc.params.LogDefaultScale(), 0, *printPrecisionStats, t)
	})

	t.Run(GetTestName(tc.params, "Evaluator/Mul/Ct/Scalar"), func(t *testing.T) {

		v0, _, ct0 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		constant := randomConst(tc.params.RingType(), tc.encoder.Prec(), -1+1i, -1+1i)

		mul := bignum.NewComplexMultiplier()

		for i := range v0 {
			mul.Mul(&v0[i], constant, &v0[i])
		}

		require.NoError(t, tc.evaluator.Mul(ct0, constant, ct0))

		hefloat.VerifyTestVectors(tc.params, tc.encoder, tc.decryptor, v0, ct0, tc.params.LogDefaultScale(), 0, *printPrecisionStats, t)
	})

	t.Run(GetTestName(tc.params, "Evaluator/Mul/Ct/Vector"), func(t *testing.T) {

		v0, _, ct0 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		v1, _, _ := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		mul := bignum.NewComplexMultiplier()

		for i := range v0 {
			mul.Mul(&v0[i], &v1[i], &v0[i])
		}

		tc.evaluator.Mul(ct0, v1, ct0)

		hefloat.VerifyTestVectors(tc.params, tc.encoder, tc.decryptor, v0, ct0, tc.params.LogDefaultScale(), 0, *printPrecisionStats, t)
	})

	t.Run(GetTestName(tc.params, "Evaluator/Mul/Ct/Pt"), func(t *testing.T) {

		mul := bignum.NewComplexMultiplier()

		// (c00, c01) x (c0) as (x, y, x)
		v0, _, ct0 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		v1, pt1, ct1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		for i := range v0 {
			mul.Mul(&v1[i], &v0[i], &v1[i])
		}
		require.NoError(t, tc.evaluator.MulRelin(ct0, pt1, ct1))
		hefloat.VerifyTestVectors(tc.params, tc.encoder, tc.decryptor, v1, ct1, tc.params.LogDefaultScale(), 0, *printPrecisionStats, t)

		// (c00, c01) x (d0) as (x, y, ct(y))
		v1, pt1, _ = newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		ctpt := pt1.AsCiphertext()
		for i := range v0 {
			mul.Mul(&v1[i], &v0[i], &v1[i])
		}
		require.NoError(t, tc.evaluator.MulRelin(ct0, pt1, ctpt))
		require.Equal(t, ctpt.Degree(), 1)
		hefloat.VerifyTestVectors(tc.params, tc.encoder, tc.decryptor, v1, ctpt, tc.params.LogDefaultScale(), 0, *printPrecisionStats, t)

		// (c00, c01) x (d0) as (ct(y), x, ct(y))
		v1, pt1, _ = newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		ctpt = pt1.AsCiphertext()
		for i := range v0 {
			mul.Mul(&v1[i], &v0[i], &v1[i])
		}
		require.NoError(t, tc.evaluator.MulRelin(ctpt, ct0, ctpt))
		require.Equal(t, ctpt.Degree(), 1)
		hefloat.VerifyTestVectors(tc.params, tc.encoder, tc.decryptor, v1, ctpt, tc.params.LogDefaultScale(), 0, *printPrecisionStats, t)

		// (c00, c01, c02) x (d0) as (x, y, x)
		v0, _, ct0 = newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		require.NoError(t, tc.evaluator.Mul(ct0, ct0, ct0))
		for i := range v0 {
			mul.Mul(&v0[i], &v0[i], &v0[i])
		}
		v1, pt1, _ = newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		require.NoError(t, tc.evaluator.Mul(ct0, pt1, ct0))
		for i := range v0 {
			mul.Mul(&v1[i], &v0[i], &v1[i])
		}
		hefloat.VerifyTestVectors(tc.params, tc.encoder, tc.decryptor, v1, ct0, tc.params.LogDefaultScale(), 0, *printPrecisionStats, t)

		// (c00, c01, c02) x (d0) as (x, y, ct(y))
		v0, _, ct0 = newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		require.NoError(t, tc.evaluator.Mul(ct0, ct0, ct0))
		for i := range v0 {
			mul.Mul(&v0[i], &v0[i], &v0[i])
		}
		v1, pt1, _ = newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		ctpt = pt1.AsCiphertext()
		require.NoError(t, tc.evaluator.Mul(ct0, pt1, ctpt))
		require.Equal(t, ctpt.Degree(), 2)
		for i := range v0 {
			mul.Mul(&v1[i], &v0[i], &v1[i])
		}
		hefloat.VerifyTestVectors(tc.params, tc.encoder, tc.decryptor, v1, ctpt, tc.params.LogDefaultScale(), 0, *printPrecisionStats, t)

		// (c00, c01, c02) x (d0) as (ct(y), x, ct(y))
		v0, _, ct0 = newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		require.NoError(t, tc.evaluator.Mul(ct0, ct0, ct0))
		for i := range v0 {
			mul.Mul(&v0[i], &v0[i], &v0[i])
		}
		v1, pt1, _ = newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		ctpt = pt1.AsCiphertext()
		require.NoError(t, tc.evaluator.Mul(ctpt, ct0, ctpt))
		require.Equal(t, ctpt.Degree(), 2)
		for i := range v0 {
			mul.Mul(&v1[i], &v0[i], &v1[i])
		}
		hefloat.VerifyTestVectors(tc.params, tc.encoder, tc.decryptor, v1, ctpt, tc.params.LogDefaultScale(), 0, *printPrecisionStats, t)

		// (c00, c01, c02) x (d0) as (ct(y), x, ct(y)) with relinearization
		v0, _, ct0 = newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		require.NoError(t, tc.evaluator.Mul(ct0, ct0, ct0))
		for i := range v0 {
			mul.Mul(&v0[i], &v0[i], &v0[i])
		}
		v1, pt1, _ = newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		ctpt = pt1.AsCiphertext()
		require.NoError(t, tc.evaluator.MulRelin(ctpt, ct0, ctpt))
		require.Equal(t, ctpt.Degree(), 1)
		for i := range v0 {
			mul.Mul(&v1[i], &v0[i], &v1[i])
		}
		hefloat.VerifyTestVectors(tc.params, tc.encoder, tc.decryptor, v1, ctpt, tc.params.LogDefaultScale(), 0, *printPrecisionStats, t)

	})

	t.Run(GetTestName(tc.params, "Evaluator/MulRelin/Ct/Ct"), func(t *testing.T) {

		// op0 <- op0 * op1
		v0, _, ct0 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		v1, _, ct1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		mul := bignum.NewComplexMultiplier()

		for i := range v0 {
			mul.Mul(&v0[i], &v1[i], &v0[i])
		}

		require.NoError(t, tc.evaluator.MulRelin(ct0, ct1, ct0))
		require.Equal(t, ct0.Degree(), 1)

		hefloat.VerifyTestVectors(tc.params, tc.encoder, tc.decryptor, v0, ct0, tc.params.LogDefaultScale(), 0, *printPrecisionStats, t)

		// op1 <- op0 * op1
		v0, _, ct0 = newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		v1, _, ct1 = newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		for i := range v0 {
			mul.Mul(&v1[i], &v0[i], &v1[i])
		}

		require.NoError(t, tc.evaluator.MulRelin(ct0, ct1, ct1))
		require.Equal(t, ct1.Degree(), 1)

		hefloat.VerifyTestVectors(tc.params, tc.encoder, tc.decryptor, v1, ct1, tc.params.LogDefaultScale(), 0, *printPrecisionStats, t)

		// op0 <- op0 * op0
		for i := range v0 {
			mul.Mul(&v0[i], &v0[i], &v0[i])
		}

		require.NoError(t, tc.evaluator.MulRelin(ct0, ct0, ct0))
		require.Equal(t, ct0.Degree(), 1)

		hefloat.VerifyTestVectors(tc.params, tc.encoder, tc.decryptor, v0, ct0, tc.params.LogDefaultScale(), 0, *printPrecisionStats, t)
	})
}

func testEvaluatorMulThenAdd(tc *testContext, t *testing.T) {

	t.Run(GetTestName(tc.params, "Evaluator/MulThenAdd/Scalar"), func(t *testing.T) {

		v0, _, ct0 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		v1, _, ct1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		constant := randomConst(tc.params.RingType(), tc.encoder.Prec(), -1+1i, -1+1i)

		mul := bignum.NewComplexMultiplier()

		tmp := new(bignum.Complex)

		for i := range v0 {
			mul.Mul(&v0[i], constant, tmp)
			v1[i].Add(&v1[i], tmp)
		}

		require.NoError(t, tc.evaluator.MulThenAdd(ct0, constant, ct1))

		hefloat.VerifyTestVectors(tc.params, tc.encoder, tc.decryptor, v1, ct1, tc.params.LogDefaultScale(), 0, *printPrecisionStats, t)
	})

	t.Run(GetTestName(tc.params, "Evaluator/MulThenAdd/Vector"), func(t *testing.T) {

		v0, _, ct0 := newTestVectors(tc, tc.encryptorSk, -1, 1, t)
		v1, _, ct1 := newTestVectors(tc, tc.encryptorSk, -1, 1, t)

		require.NoError(t, tc.evaluator.MulThenAdd(ct1, v0, ct0))

		mul := bignum.NewComplexMultiplier()

		tmp := new(bignum.Complex)

		for i := range v0 {
			mul.Mul(&v1[i], &v0[i], tmp)
			v0[i].Add(&v0[i], tmp)
		}

		require.Equal(t, ct0.Degree(), 1)

		hefloat.VerifyTestVectors(tc.params, tc.encoder, tc.decryptor, v0, ct0, tc.params.LogDefaultScale(), 0, *printPrecisionStats, t)
	})

	t.Run(GetTestName(tc.params, "Evaluator/MulThenAdd/Pt"), func(t *testing.T) {

		v0, pt0, ct0 := newTestVectors(tc, tc.encryptorSk, -1, 1, t)
		v1, _, ct1 := newTestVectors(tc, tc.encryptorSk, -1, 1, t)

		mul := bignum.NewComplexMultiplier()

		tmp := new(bignum.Complex)

		for i := range v0 {
			mul.Mul(&v1[i], &v0[i], tmp)
			v0[i].Add(&v0[i], tmp)
		}

		require.NoError(t, tc.evaluator.MulThenAdd(ct1, pt0, ct0))

		require.Equal(t, ct0.Degree(), 1)

		hefloat.VerifyTestVectors(tc.params, tc.encoder, tc.decryptor, v0, ct0, tc.params.LogDefaultScale(), 0, *printPrecisionStats, t)
	})

	t.Run(GetTestName(tc.params, "Evaluator/MulRelinThenAdd/Ct"), func(t *testing.T) {

		// opOut = opOut + op1 * op0
		v0, _, ct0 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		v1, _, ct1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		mul := bignum.NewComplexMultiplier()

		for i := range v0 {
			mul.Mul(&v0[i], &v1[i], &v1[i])
		}

		ct03 := hefloat.NewCiphertext(tc.params, 2, ct0.Level())

		ct03.Scale = ct0.Scale.Mul(ct1.Scale)

		require.NoError(t, tc.evaluator.MulThenAdd(ct0, ct1, ct03))

		require.Equal(t, ct03.Degree(), 2)

		require.NoError(t, tc.evaluator.Relinearize(ct03, ct03))

		require.Equal(t, ct03.Degree(), 1)

		hefloat.VerifyTestVectors(tc.params, tc.encoder, tc.decryptor, v1, ct03, tc.params.LogDefaultScale(), 0, *printPrecisionStats, t)

		// op1 = op1 + op0*op0
		v0, _, ct0 = newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		v1, _, ct1 = newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		var tmp bignum.Complex
		for i := range v0 {
			mul.Mul(&v1[i], &v1[i], &tmp)
			v0[i].Add(&v0[i], &tmp)
		}

		require.NoError(t, tc.evaluator.MulRelinThenAdd(ct1, ct1, ct0))

		require.Equal(t, ct0.Degree(), 1)

		hefloat.VerifyTestVectors(tc.params, tc.encoder, tc.decryptor, v0, ct0, tc.params.LogDefaultScale(), 0, *printPrecisionStats, t)
	})
}
