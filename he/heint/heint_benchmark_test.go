package heint_test

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"runtime"
	"testing"

	"github.com/Pro7ech/lattigo/he/heint"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/sampling"
	"github.com/stretchr/testify/require"
)

func GetBenchName(params heint.Parameters, opname string) string {
	return fmt.Sprintf("%s/logN=%d/Qi=%d/Pi=%d/LogSlots=%d",
		opname,
		params.LogN(),
		params.QCount(),
		params.PCount(),
		params.LogMaxSlots())
}

func BenchmarkHEInt(b *testing.B) {

	var err error

	var testParams []heint.ParametersLiteral
	switch {
	case *flagParamString != "": // the custom test suite reads the parameters from the -params flag
		testParams = append(testParams, heint.ParametersLiteral{})
		if err = json.Unmarshal([]byte(*flagParamString), &testParams[0]); err != nil {
			b.Fatal(err)
		}
	default:
		testParams = []heint.ParametersLiteral{
			{
				LogN: 14,
				LogQ: []int{50, 40, 40, 40, 40, 40, 40, 40},
				LogP: []int{60},
				T:    0x10001,
				R:    1,
			},
		}
	}

	for _, paramsLiteral := range testParams {

		var params heint.Parameters
		if params, err = heint.NewParametersFromLiteral(paramsLiteral); err != nil {
			b.Error(err)
			b.Fail()
		}

		var tc *testContext
		if tc, err = genTestParams(params); err != nil {
			b.Fatal(err)
		}

		for _, testSet := range []func(tc *testContext, b *testing.B){
			benchKeyGenerator,
			benchEncoder,
			benchEncryptor,
			benchEvaluator,
		} {
			testSet(tc, b)
			runtime.GC()
		}
	}
}

func benchKeyGenerator(tc *testContext, b *testing.B) {

	params := tc.params

	b.Run(GetBenchName(params, "KeyGenerator/GenSecretKey"), func(b *testing.B) {
		sk := rlwe.NewSecretKey(params)
		kgen := tc.kgen
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			kgen.GenSecretKey(sk)
		}
	})

	b.Run(GetBenchName(params, "KeyGenerator/GenPublicKey"), func(b *testing.B) {
		sk := tc.sk
		pk := rlwe.NewPublicKey(params)
		kgen := tc.kgen
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			kgen.GenPublicKey(sk, pk)
		}
	})

	b.Run(GetBenchName(params, "KeyGenerator/GenEvaluationKey"), func(b *testing.B) {
		sk := tc.sk
		kgen := tc.kgen
		evk := rlwe.NewEvaluationKey(params)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			kgen.GenEvaluationKey(sk, sk, evk)
		}
	})
}

func benchEncoder(tc *testContext, b *testing.B) {

	params := tc.params
	encoder := tc.encoder
	T := tc.params.PlaintextModulus()
	r := rand.New(sampling.NewSource([32]byte{0x00}))

	b.Run(GetBenchName(params, "Encoder/Encode/Uint"), func(b *testing.B) {

		values := make([]uint64, params.MaxSlots())
		for i := range values {
			values[i] = r.Uint64N(T)
		}

		plaintext := heint.NewPlaintext(params, params.MaxLevel())
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := encoder.Encode(values, plaintext); err != nil {
				b.Log(err)
				b.Fail()
			}
		}
	})

	b.Run(GetBenchName(params, "Encoder/Encode/Int"), func(b *testing.B) {

		values := make([]int64, params.MaxSlots())
		for i := range values {
			values[i] = r.Int64N(int64(T)) - int64(T>>1)
		}

		plaintext := heint.NewPlaintext(params, params.MaxLevel())
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := encoder.Encode(values, plaintext); err != nil {
				b.Log(err)
				b.Fail()
			}
		}
	})

	b.Run(GetBenchName(params, "Encoder/Decode/Uint"), func(b *testing.B) {

		values := make([]uint64, params.MaxSlots())
		for i := range values {
			values[i] = r.Uint64N(T)
		}

		plaintext := heint.NewPlaintext(params, params.MaxLevel())
		require.NoError(b, encoder.Encode(values, plaintext))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := encoder.Decode(plaintext, values); err != nil {
				b.Log(err)
				b.Fail()
			}
		}
	})

	b.Run(GetBenchName(params, "Encoder/Decode/Int"), func(b *testing.B) {

		values := make([]int64, params.MaxSlots())
		for i := range values {
			values[i] = r.Int64N(int64(T)) - int64(T>>1)
		}

		plaintext := heint.NewPlaintext(params, params.MaxLevel())
		require.NoError(b, encoder.Encode(values, plaintext))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := encoder.Decode(plaintext, values); err != nil {
				b.Log(err)
				b.Fail()
			}
		}
	})
}

func benchEncryptor(tc *testContext, b *testing.B) {

	params := tc.params
	T := params.PlaintextModulus()
	r := rand.New(sampling.NewSource([32]byte{0x00}))

	b.Run(GetBenchName(params, "Encryptor/Encrypt/Sk"), func(b *testing.B) {

		pt := heint.NewPlaintext(params, params.MaxLevel())

		values := make([]uint64, params.MaxSlots())
		for i := range values {
			values[i] = r.Uint64N(T)
		}

		require.NoError(b, tc.encoder.Encode(values, pt))

		ct := heint.NewCiphertext(params, 1, pt.Level())

		enc := tc.encryptorSk

		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			if err := enc.Encrypt(pt, ct); err != nil {
				b.Log(err)
				b.Fail()
			}
		}
	})

	b.Run(GetBenchName(params, "Encryptor/Encrypt/Pk"), func(b *testing.B) {

		pt := heint.NewPlaintext(params, params.MaxLevel())

		values := make([]uint64, params.MaxSlots())
		for i := range values {
			values[i] = r.Uint64N(T)
		}

		require.NoError(b, tc.encoder.Encode(values, pt))

		ct := heint.NewCiphertext(params, 1, pt.Level())

		enc := tc.encryptorPk

		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			if err := enc.Encrypt(pt, ct); err != nil {
				b.Log(err)
				b.Fail()
			}
		}
	})

	b.Run(GetBenchName(params, "Decryptor/Decrypt"), func(b *testing.B) {

		pt := heint.NewPlaintext(params, params.MaxLevel())

		ct := heint.NewCiphertext(params, 1, params.MaxLevel())
		ct.Randomize(params, sampling.NewSource(sampling.NewSeed()))

		*ct.MetaData = *pt.MetaData

		dec := tc.decryptor

		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			dec.Decrypt(ct, pt)
		}
	})
}

func benchEvaluator(tc *testContext, b *testing.B) {

	params := tc.params
	eval := tc.evaluator

	source := sampling.NewSource(sampling.NewSeed())

	plaintext := heint.NewPlaintext(params, params.MaxLevel())
	plaintext.Randomize(params, source)

	ciphertext1 := heint.NewCiphertext(params, 1, params.MaxLevel())
	ciphertext1.Randomize(params, source)

	ciphertext2 := heint.NewCiphertext(params, 1, params.MaxLevel())
	ciphertext2.Randomize(params, source)

	scalar := params.PlaintextModulus() >> 1

	vector := plaintext.Q.At(0)[:params.MaxSlots()]

	b.Run(GetBenchName(params, "Evaluator/Add/Scalar"), func(b *testing.B) {
		receiver := heint.NewCiphertext(params, 1, ciphertext1.Level())
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := eval.Add(ciphertext1, scalar, receiver); err != nil {
				b.Log(err)
				b.Fail()
			}
		}
	})

	b.Run(GetBenchName(params, "Evaluator/Add/Vector"), func(b *testing.B) {
		receiver := heint.NewCiphertext(params, 1, ciphertext1.Level())
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := eval.Add(ciphertext1, vector, receiver); err != nil {
				b.Log(err)
				b.Fail()
			}
		}
	})

	b.Run(GetBenchName(params, "Evaluator/Add/Plaintext"), func(b *testing.B) {
		receiver := heint.NewCiphertext(params, 1, ciphertext1.Level())
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := eval.Add(ciphertext1, plaintext, receiver); err != nil {
				b.Log(err)
				b.Fail()
			}
		}
	})

	b.Run(GetBenchName(params, "Evaluator/Add/Ciphertext"), func(b *testing.B) {
		receiver := heint.NewCiphertext(params, 1, ciphertext1.Level())
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := eval.Add(ciphertext1, ciphertext2, receiver); err != nil {
				b.Log(err)
				b.Fail()
			}
		}
	})

	b.Run(GetBenchName(params, "Evaluator/Mul/Scalar"), func(b *testing.B) {
		receiver := heint.NewCiphertext(params, 1, ciphertext1.Level())
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := eval.Mul(ciphertext1, scalar, receiver); err != nil {
				b.Log(err)
				b.Fail()
			}
		}
	})

	b.Run(GetBenchName(params, "Evaluator/Mul/Plaintext"), func(b *testing.B) {
		receiver := heint.NewCiphertext(params, 1, ciphertext1.Level())
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := eval.Mul(ciphertext1, plaintext, receiver); err != nil {
				b.Log(err)
				b.Fail()
			}
		}
	})

	b.Run(GetBenchName(params, "Evaluator/Mul/Vector"), func(b *testing.B) {
		receiver := heint.NewCiphertext(params, 1, ciphertext1.Level())
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := eval.Mul(ciphertext1, vector, receiver); err != nil {
				b.Log(err)
				b.Fail()
			}
		}
	})

	b.Run(GetBenchName(params, "Evaluator/Mul/Ciphertext"), func(b *testing.B) {
		receiver := heint.NewCiphertext(params, 2, ciphertext1.Level())
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := eval.Mul(ciphertext1, ciphertext2, receiver); err != nil {
				b.Log(err)
				b.Fail()
			}
		}
	})

	b.Run(GetBenchName(params, "Evaluator/MulRelin/Ciphertext"), func(b *testing.B) {
		receiver := heint.NewCiphertext(params, 1, ciphertext1.Level())
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := eval.MulRelin(ciphertext1, ciphertext2, receiver); err != nil {
				b.Log(err)
				b.Fail()
			}
		}
	})

	b.Run(GetBenchName(params, "Evaluator/MulInvariant/Ciphertext"), func(b *testing.B) {
		receiver := heint.NewCiphertext(params, 2, ciphertext1.Level())
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := eval.MulScaleInvariant(ciphertext1, ciphertext2, receiver); err != nil {
				b.Log(err)
				b.Fail()
			}
		}
	})

	b.Run(GetBenchName(params, "Evaluator/MulRelinInvariant/Ciphertext"), func(b *testing.B) {
		receiver := heint.NewCiphertext(params, 1, ciphertext1.Level())
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := eval.MulRelinScaleInvariant(ciphertext1, ciphertext2, receiver); err != nil {
				b.Log(err)
				b.Fail()
			}
		}
	})

	b.Run(GetBenchName(params, "Evaluator/MulThenAdd/Scalar"), func(b *testing.B) {
		receiver := heint.NewCiphertext(params, 1, ciphertext1.Level())
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := eval.MulThenAdd(ciphertext1, scalar, receiver); err != nil {
				b.Log(err)
				b.Fail()
			}
		}
	})

	b.Run(GetBenchName(params, "Evaluator/MulThenAdd/Vector"), func(b *testing.B) {
		receiver := heint.NewCiphertext(params, 1, ciphertext1.Level())
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := eval.MulThenAdd(ciphertext1, vector, receiver); err != nil {
				b.Log(err)
				b.Fail()
			}
		}
	})

	b.Run(GetBenchName(params, "Evaluator/MulThenAdd/Plaintext"), func(b *testing.B) {
		receiver := heint.NewCiphertext(params, 1, ciphertext1.Level())
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := eval.MulThenAdd(ciphertext1, plaintext, receiver); err != nil {
				b.Log(err)
				b.Fail()
			}
		}
	})

	b.Run(GetBenchName(params, "Evaluator/MulThenAdd/Ciphertext"), func(b *testing.B) {
		receiver := heint.NewCiphertext(params, 1, ciphertext1.Level())
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := eval.MulThenAdd(ciphertext1, plaintext, receiver); err != nil {
				b.Log(err)
				b.Fail()
			}
		}
	})

	b.Run(GetBenchName(params, "Evaluator/MulRelinThenAdd/Ciphertext"), func(b *testing.B) {
		receiver := heint.NewCiphertext(params, 2, ciphertext1.Level())
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := eval.MulRelinThenAdd(ciphertext1, ciphertext2, receiver); err != nil {
				b.Log(err)
				b.Fail()
			}
		}
	})

	b.Run(GetBenchName(params, "Evaluator/Rescale"), func(b *testing.B) {
		receiver := heint.NewCiphertext(params, 1, ciphertext1.Level()-1)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := eval.Rescale(ciphertext1, receiver); err != nil {
				b.Log(err)
				b.Fail()
			}
		}
	})

	b.Run(GetBenchName(params, "Evaluator/Rotate"), func(b *testing.B) {
		gk := tc.kgen.GenGaloisKeyNew(5, tc.sk)
		evk := rlwe.NewMemEvaluationKeySet(nil, gk)
		eval := eval.WithKey(evk)
		receiver := heint.NewCiphertext(params, 1, ciphertext2.Level())
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := eval.RotateColumns(ciphertext2, 1, receiver); err != nil {
				b.Log(err)
				b.Fail()
			}
		}
	})
}
