package rlwe

import (
	"encoding/json"
	"runtime"
	"testing"

	"github.com/Pro7ech/lattigo/utils"
	"github.com/Pro7ech/lattigo/utils/sampling"
	"github.com/stretchr/testify/require"
)

func BenchmarkRLWE(b *testing.B) {

	var err error

	defaultParamsLiteral := testInsecure

	if *flagParamString != "" {
		var jsonParams TestParametersLiteral
		if err = json.Unmarshal([]byte(*flagParamString), &jsonParams); err != nil {
			b.Fatal(err)
		}
		defaultParamsLiteral = []TestParametersLiteral{jsonParams} // the custom test suite reads the parameters from the -params flag
	}

	for _, paramsLit := range defaultParamsLiteral[:] {

		var params Parameters
		if params, err = NewParametersFromLiteral(paramsLit.ParametersLiteral); err != nil {
			b.Fatal(err)
		}

		tc, err := NewTestContext(params)
		require.NoError(b, err)

		for _, testSet := range []func(tc *TestContext, dd DigitDecomposition, b *testing.B){
			benchKeyGenerator,
			benchEncryptor,
			benchDecryptor,
			benchEvaluator,
		} {
			testSet(tc, paramsLit.DigitDecomposition, b)
			runtime.GC()
		}
	}
}

func benchKeyGenerator(tc *TestContext, dd DigitDecomposition, b *testing.B) {

	params := tc.params
	kgen := tc.kgen

	b.Run(testString(params, params.MaxLevelQ(), params.MaxLevelP(), dd, "KeyGenerator/GenSecretKey"), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			kgen.GenSecretKey(tc.sk)
		}
	})

	b.Run(testString(params, params.MaxLevelQ(), params.MaxLevelP(), dd, "KeyGenerator/GenPublicKey"), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			kgen.GenPublicKey(tc.sk, tc.pk)
		}

	})

	b.Run(testString(params, params.MaxLevelQ(), params.MaxLevelP(), dd, "KeyGenerator/GenEvaluationKey"), func(b *testing.B) {
		sk0, sk1 := tc.sk, kgen.GenSecretKeyNew()
		evk := NewEvaluationKey(params)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			kgen.GenEvaluationKey(sk0, sk1, evk)
		}
	})
}

func benchEncryptor(tc *TestContext, dd DigitDecomposition, b *testing.B) {

	params := tc.params

	b.Run(testString(params, params.MaxLevelQ(), params.MaxLevelP(), dd, "Encryptor/EncryptZero/SecretKey"), func(b *testing.B) {
		ct := NewCiphertext(params, 1, params.MaxLevel(), -1)
		enc := tc.enc.WithKey(tc.sk)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			enc.EncryptZero(ct)
		}

	})

	b.Run(testString(params, params.MaxLevelQ(), params.MaxLevelP(), dd, "Encryptor/EncryptZero/PublicKey"), func(b *testing.B) {
		ct := NewCiphertext(params, 1, params.MaxLevel(), -1)
		enc := tc.enc.WithKey(tc.pk)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			enc.EncryptZero(ct)
		}
	})
}

func benchDecryptor(tc *TestContext, dd DigitDecomposition, b *testing.B) {

	params := tc.params

	b.Run(testString(params, params.MaxLevelQ(), params.MaxLevelP(), dd, "Decryptor/Decrypt"), func(b *testing.B) {
		dec := tc.dec
		ct := NewCiphertext(params, 1, params.MaxLevelQ(), -1)
		ct.Randomize(params, sampling.NewSource([32]byte{}))
		pt := NewPlaintext(params, ct.LevelQ(), -1)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			dec.Decrypt(ct, pt)
		}
	})
}

func benchEvaluator(tc *TestContext, dd DigitDecomposition, b *testing.B) {

	params := tc.params
	kgen := tc.kgen
	sk := tc.sk
	eval := tc.eval

	levelsP := []int{0}

	if params.MaxLevelP() > 0 {
		levelsP = append(levelsP, params.MaxLevelP())
	}

	for _, levelP := range levelsP {

		b.Run(testString(params, params.MaxLevelQ(), levelP, dd, "Evaluator/GadgetProduct"), func(b *testing.B) {

			ct := NewCiphertext(params, 1, params.MaxLevelQ(), -1)
			ct.Randomize(params, sampling.NewSource([32]byte{}))

			evkParams := EvaluationKeyParameters{LevelQ: utils.Pointy(params.MaxLevelQ()), LevelP: utils.Pointy(levelP), DigitDecomposition: dd}

			evk := kgen.GenEvaluationKeyNew(sk, kgen.GenSecretKeyNew(), evkParams)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				eval.GadgetProduct(ct.Level(), ct.Q[1], ct.IsNTT, &evk.GadgetCiphertext, ct)
			}
		})
	}
}
