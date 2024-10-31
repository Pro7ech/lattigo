package rgsw

import (
	"fmt"
	"math/big"
	"runtime"
	"testing"

	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/buffer"

	"github.com/stretchr/testify/require"
)

func testString(params rlwe.Parameters, LevelQ, LevelP int, dd rlwe.DigitDecomposition, opname string) string {
	return fmt.Sprintf("%s/logN=%d/Qi=%d/Pi=%d/Digits=%s",
		opname,
		params.LogN(),
		LevelQ+1,
		LevelP+1,
		dd.ToString())
}

func TestRGSW(t *testing.T) {

	bound := 10.0

	for _, paramsLit := range testInsecure[:] {
		params, err := rlwe.NewParametersFromLiteral(paramsLit.ParametersLiteral)
		require.NoError(t, err)

		var levelsQ []int
		if params.MaxLevelQ() == 0 {
			levelsQ = []int{0}
		} else {
			levelsQ = []int{0, params.MaxLevelQ()}
		}

		testSerialization(t, params, paramsLit.DigitDecomposition)

		for _, LevelQ := range levelsQ {

			for _, testSet := range []func(t *testing.T, params rlwe.Parameters, LevelQ, LevelP int, dd rlwe.DigitDecomposition, bound float64){
				testEncryptorSK,
				testEncryptorPK,
				testFromGadgetCiphertext,
				testExternalProduct,
				testProduct,
			} {
				testSet(t, params, LevelQ, params.MaxLevelP(), paramsLit.DigitDecomposition, bound)
				runtime.GC()
			}
		}

	}
}

func testEncryptorSK(t *testing.T, params rlwe.Parameters, LevelQ, LevelP int, dpp rlwe.DigitDecomposition, bound float64) {
	t.Run(testString(params, LevelQ, LevelP, dpp, "Encryptor/SK"), func(t *testing.T) {

		kgen := rlwe.NewKeyGenerator(params)
		sk := kgen.GenSecretKeyNew()

		// plaintext [-1, 0, 1]
		ptTmp := kgen.GenSecretKeyNew()
		pt := &rlwe.Plaintext{}
		pt.Point = &ring.Point{}
		pt.Q = ptTmp.Q
		pt.MetaData = &rlwe.MetaData{}
		pt.IsNTT = true
		pt.IsMontgomery = true

		ct := NewCiphertext(params, LevelQ, LevelP, dpp)

		NewEncryptor(params, sk).Encrypt(pt, ct)

		left, right := NoiseCiphertext(ct, pt.Q, sk, params)

		require.GreaterOrEqual(t, bound, left)
		require.GreaterOrEqual(t, bound, right)
	})
}

func testEncryptorPK(t *testing.T, params rlwe.Parameters, LevelQ, LevelP int, dpp rlwe.DigitDecomposition, bound float64) {
	t.Run(testString(params, LevelQ, LevelP, dpp, "Encryptor/PK"), func(t *testing.T) {

		kgen := rlwe.NewKeyGenerator(params)
		sk, pk := kgen.GenKeyPairNew()

		// plaintext [-1, 0, 1]
		ptTmp := kgen.GenSecretKeyNew()
		pt := &rlwe.Plaintext{}
		pt.Point = &ring.Point{}
		pt.Q = ptTmp.Q
		pt.MetaData = &rlwe.MetaData{}
		pt.IsNTT = true
		pt.IsMontgomery = true

		ct := NewCiphertext(params, LevelQ, LevelP, dpp)

		NewEncryptor(params, pk).Encrypt(pt, ct)

		left, right := NoiseCiphertext(ct, pt.Q, sk, params)

		require.GreaterOrEqual(t, bound, left)
		require.GreaterOrEqual(t, bound, right)
	})
}

func testFromGadgetCiphertext(t *testing.T, params rlwe.Parameters, LevelQ, LevelP int, dpp rlwe.DigitDecomposition, bound float64) {
	t.Run(testString(params, LevelQ, LevelP, dpp, "Ciphertext/FromGadgetCiphertext"), func(t *testing.T) {

		kgen := rlwe.NewKeyGenerator(params)
		sk := kgen.GenSecretKeyNew()

		var rlk *rlwe.RelinearizationKey

		if LevelP > -1 {
			rlk = kgen.GenRelinearizationKeyNew(sk)
		} else {
			rlk = kgen.GenRelinearizationKeyNew(sk, rlwe.EvaluationKeyParameters{DigitDecomposition: dpp})
		}

		// plaintext [-1, 0, 1]
		ptTmp := kgen.GenSecretKeyNew()
		pt := &rlwe.Plaintext{}
		pt.Point = &ring.Point{}
		pt.Q = ptTmp.Q
		pt.MetaData = &rlwe.MetaData{}
		pt.IsNTT = true
		pt.IsMontgomery = true

		gct := rlwe.NewGadgetCiphertext(params, 1, LevelQ, -1, dpp)

		rlwe.NewEncryptor(params, sk).Encrypt(pt, gct)

		eval := NewEvaluator(params, rlwe.NewMemEvaluationKeySet(rlk))

		ct := new(Ciphertext)

		require.NoError(t, ct.FromGadgetCiphertext(eval, gct))

		left, right := NoiseCiphertext(ct, pt.Q, sk, params)

		require.GreaterOrEqual(t, bound, left)
		require.GreaterOrEqual(t, bound, right)
	})
}

func setPlaintext(params rlwe.Parameters, pt *rlwe.Plaintext, k int) {
	r := params.RingQ().AtLevel(pt.Level())
	for i := range r {
		pt.Q.At(i)[k] = 1
	}
	r.NTT(pt.Q, pt.Q)
}

func testExternalProduct(t *testing.T, params rlwe.Parameters, LevelQ, LevelP int, dpp rlwe.DigitDecomposition, bound float64) {

	t.Run(testString(params, LevelQ, LevelP, dpp, "Evaluator/RLWExRGSW"), func(t *testing.T) {

		rQ := params.RingQ().AtLevel(LevelQ)

		kgen := rlwe.NewKeyGenerator(params)
		sk := kgen.GenSecretKeyNew()

		ptRGSW := rlwe.NewPlaintext(params, LevelQ, -1)
		ptRLWE := rlwe.NewPlaintext(params, LevelQ, -1)

		k0 := 1
		k1 := 1

		setPlaintext(params, ptRGSW, k0) // X^{k0}
		setPlaintext(params, ptRLWE, k1) // X^{k1}

		scale := new(big.Int).SetUint64(params.Q()[0] >> 8)

		// Scale * X^{k1}
		rQ.MulScalarBigint(ptRLWE.Q, scale, ptRLWE.Q)

		ctRGSW := NewCiphertext(params, LevelQ, LevelP, dpp)
		ctRLWE := rlwe.NewCiphertext(params, 1, LevelQ, -1)

		NewEncryptor(params, sk).Encrypt(ptRGSW, ctRGSW)
		rlwe.NewEncryptor(params, sk).Encrypt(ptRLWE, ctRLWE)

		// X^{k0} * Scale * X^{k1}
		NewEvaluator(params, nil).ExternalProduct(ctRLWE, ctRGSW, ctRLWE)

		ptHave := rlwe.NewDecryptor(params, sk).DecryptNew(ctRLWE)

		rQ.MulCoeffsBarrett(ptRLWE.Q, ptRGSW.Q, ptRLWE.Q)

		rQ.Sub(ptHave.Q, ptRLWE.Q, ptHave.Q)
		rQ.INTT(ptHave.Q, ptHave.Q)

		require.GreaterOrEqual(t, 20.0, rQ.Stats(ptHave.Q)[0])
	})
}

func testProduct(t *testing.T, params rlwe.Parameters, LevelQ, LevelP int, dpp rlwe.DigitDecomposition, bound float64) {

	t.Run(testString(params, LevelQ, LevelP, dpp, "Evaluator/RGSWxRGSW"), func(t *testing.T) {

		params0, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
			LogN:    params.LogN(),
			Q:       params.Q(),
			NTTFlag: params.NTTFlag(),
		})

		if err != nil {
			panic(err)
		}

		params1 := params

		dd := rlwe.DigitDecomposition{}
		dd.Type = rlwe.Signed
		dd.Log2Basis = 7

		rQ := params0.RingQ()

		kgen := rlwe.NewKeyGenerator(params1)
		sk := kgen.GenSecretKeyNew()

		pt0 := rlwe.NewPlaintext(params0, params0.MaxLevel(), -1)
		for i := range pt0.Level() + 1 {
			pt0.Q.At(i)[1] = 1
		}
		if params0.NTTFlag() {
			rQ.NTT(pt0.Q, pt0.Q)
		}

		pt1 := rlwe.NewPlaintext(params0, params0.MaxLevel(), -1)
		for i := range pt1.Level() + 1 {
			pt1.Q.At(i)[1] = 1
		}
		if params0.NTTFlag() {
			rQ.NTT(pt1.Q, pt1.Q)
		}

		pt2 := rlwe.NewPlaintext(params0, params0.MaxLevel(), -1)
		for i := range pt2.Level() + 1 {
			pt2.Q.At(i)[0] = 1 << 40
		}
		if params0.NTTFlag() {
			rQ.NTT(pt2.Q, pt2.Q)
		}

		ct0 := NewCiphertext(params0, params0.MaxLevel(), params0.MaxLevelP(), dd)
		ct1 := NewCiphertext(params1, params1.MaxLevel(), params1.MaxLevelP(), dpp)

		tmp := rQ.NewRNSPoly()

		n0 := 1
		n1 := 1
		var std00, std01, std1 float64
		for w := 0; w < n0; w++ {

			if err := NewEncryptor(params0, sk).Encrypt(pt0, ct0); err != nil {
				panic(err)
			}

			if err := NewEncryptor(params1, sk).Encrypt(pt1, ct1); err != nil {
				panic(err)
			}

			eval := NewEvaluator(params1, nil)

			for k := 0; k < n1; k++ {

				require.NoError(t, eval.Product(ct0, ct1, ct0))

				rQ.MForm(pt0.Q, pt0.Q)
				rQ.MulCoeffsMontgomery(pt0.Q, pt1.Q, pt0.Q)

				rQ.MForm(pt0.Q, tmp)
				x00, y00 := NoiseCiphertext(ct0, tmp, sk, params0)
				std00 += x00
				std01 += y00
			}

			ct2 := rlwe.NewCiphertext(params0, 1, pt2.Level(), -1)

			require.NoError(t, rlwe.NewEncryptor(params0, sk).Encrypt(pt2, ct2))

			eval.ExternalProduct(ct2, ct0, ct2)

			rQ.MForm(pt2.Q, pt2.Q)
			rQ.MulCoeffsMontgomery(pt2.Q, pt0.Q, pt2.Q)

			std1 += rlwe.NoiseCiphertext(ct2, pt2, sk, params0)
		}

		std00 /= float64(n0 * n1)
		std01 /= float64(n0 * n1)
		std1 /= float64(n0)

		require.GreaterOrEqual(t, 15.0, std00)
		require.GreaterOrEqual(t, 15.0, std01)
		require.GreaterOrEqual(t, 25.0, std1)

	})
}

func testSerialization(t *testing.T, params rlwe.Parameters, dpp rlwe.DigitDecomposition) {
	t.Run(testString(params, params.MaxLevelQ(), params.MaxLevelP(), dpp, "WriteAndRead"), func(t *testing.T) {
		kgen := rlwe.NewKeyGenerator(params)
		sk := kgen.GenSecretKeyNew()
		ct := NewCiphertext(params, params.MaxLevelQ(), params.MaxLevelP(), dpp)
		NewEncryptor(params, sk).Encrypt(nil, ct)
		buffer.RequireSerializerCorrect(t, ct)
	})
}
