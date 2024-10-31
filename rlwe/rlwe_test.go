package rlwe

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/utils"
	"github.com/Pro7ech/lattigo/utils/buffer"
	"github.com/Pro7ech/lattigo/utils/sampling"
)

var flagParamString = flag.String("params", "", "specify the test cryptographic parameters as a JSON string. Overrides -short and -long.")

func testString(params Parameters, LevelQ, LevelP int, dd DigitDecomposition, opname string) string {
	return fmt.Sprintf("%s/logN=%d/Qi=%d/Pi=%d/Digits=%s/NTT=%t/RingType=%s",
		opname,
		params.LogN(),
		LevelQ+1,
		LevelP+1,
		dd.ToString(),
		params.NTTFlag(),
		params.RingType())
}

func TestRLWE(t *testing.T) {

	var err error

	defaultParamsLiteral := testInsecure

	if *flagParamString != "" {
		var jsonParams TestParametersLiteral
		if err = json.Unmarshal([]byte(*flagParamString), &jsonParams); err != nil {
			t.Fatal(err)
		}
		defaultParamsLiteral = []TestParametersLiteral{jsonParams} // the custom test suite reads the parameters from the -params flag
	}

	for _, paramsLit := range defaultParamsLiteral[:] {

		for _, NTTFlag := range []bool{true, false}[:] {

			for _, RingType := range []ring.Type{ring.Standard, ring.ConjugateInvariant}[:] {

				paramsLit.NTTFlag = NTTFlag
				paramsLit.RingType = RingType

				var params Parameters
				if params, err = NewParametersFromLiteral(paramsLit.ParametersLiteral); err != nil {
					t.Fatal(err)
				}

				tc, err := NewTestContext(params)
				require.NoError(t, err)

				testParameters(tc, t)
				testKeyGenerator(tc, paramsLit.DigitDecomposition, t)
				testMarshaller(tc, t)
				testWriteAndRead(tc, paramsLit.DigitDecomposition, t)

				var LevelQ []int
				if params.MaxLevelQ() > 0 {
					LevelQ = []int{0, params.MaxLevelQ()}
				} else {
					LevelQ = []int{0}
				}

				for _, level := range LevelQ[:] {

					for _, testSet := range []func(tc *TestContext, level int, dd DigitDecomposition, t *testing.T){
						testEncryptor,
						testGadgetProduct,
						testApplyEvaluationKey,
						testAutomorphism,
						testSlotOperations,
					} {
						testSet(tc, level, paramsLit.DigitDecomposition, t)
						runtime.GC()
					}
				}
			}
		}
	}

	testUserDefinedParameters(t)
	testCoalescedGadgetProduct(t)
}

type TestContext struct {
	params Parameters
	kgen   *KeyGenerator
	enc    *Encryptor
	dec    *Decryptor
	sk     *SecretKey
	pk     *PublicKey
	eval   *Evaluator
}

func testUserDefinedParameters(t *testing.T) {

	t.Run("Parameters/QWithLogP", func(t *testing.T) {
		params, err := NewParametersFromLiteral(ParametersLiteral{
			LogN: 4,
			Q:    []uint64{65537},
			LogP: []int{20},
		})
		require.NoError(t, err)
		require.Equal(t, 1, params.QCount())
		require.Equal(t, 1, params.PCount())
	})

	t.Run("Parameters/LogQWithP", func(t *testing.T) {
		params, err := NewParametersFromLiteral(ParametersLiteral{
			LogN: 4,
			LogQ: []int{20},
			P:    []uint64{65537},
		})
		require.NoError(t, err)
		require.Equal(t, 1, params.QCount())
		require.Equal(t, 1, params.PCount())
	})

	t.Run("Parameters/Serialization", func(t *testing.T) {
		params, err := NewParametersFromLiteral(ParametersLiteral{
			LogN: 4,
			LogQ: []int{20},
			P:    []uint64{65537},
		})
		require.NoError(t, err)
		buffer.RequireSerializerCorrect(t, &params)
	})

	t.Run("Parameters/UnmarshalJSON", func(t *testing.T) {

		var err error
		// checks that Parameters can be unmarshalled with log-moduli definition without error
		dataWithLogModuli := []byte(`{"LogN":13,"LogQ":[50,50],"LogP":[60]}`)
		var paramsWithLogModuli Parameters
		err = json.Unmarshal(dataWithLogModuli, &paramsWithLogModuli)
		require.Nil(t, err)
		require.Equal(t, 2, paramsWithLogModuli.QCount())
		require.Equal(t, 1, paramsWithLogModuli.PCount())
		require.Equal(t, ring.Standard, paramsWithLogModuli.RingType()) // Omitting the RingType field should result in a standard instance
		require.True(t, paramsWithLogModuli.Xe().Equal(&DefaultXe))     // Omitting Xe should result in Default being used
		require.True(t, paramsWithLogModuli.Xs().Equal(&DefaultXs))     // Omitting Xs should result in Default being used

		// checks that Parameters can be unmarshalled with log-moduli definition with empty or omitted P without error
		for _, dataWithLogModuliNoP := range [][]byte{
			[]byte(`{"LogN":13,"LogQ":[50,50],"LogP":[],"RingType": "ConjugateInvariant"}`),
			[]byte(`{"LogN":13,"LogQ":[50,50],"RingType": "ConjugateInvariant"}`),
		} {
			var paramsWithLogModuliNoP Parameters
			err = json.Unmarshal(dataWithLogModuliNoP, &paramsWithLogModuliNoP)
			require.Nil(t, err)
			require.Equal(t, 2, paramsWithLogModuliNoP.QCount())
			require.Equal(t, 0, paramsWithLogModuliNoP.PCount())
			require.Equal(t, ring.ConjugateInvariant, paramsWithLogModuliNoP.RingType())
		}

		// checks that one can provide custom parameters for the secret-key and error distributions
		dataWithCustomSecrets := []byte(`{
			"LogN":13,
			"Q":[65537],
			"P":[],
			"LogP":[60],
			"Xs":{"Type":"Ternary", "H":5462, "P":0},
			"Xe":{"Type":"DiscreteGaussian","Sigma":6.4,"Bound":38}
		}`)
		var paramsWithCustomSecrets Parameters
		err = json.Unmarshal(dataWithCustomSecrets, &paramsWithCustomSecrets)
		require.Nil(t, err)
		require.True(t, paramsWithCustomSecrets.Xe().Equal(&ring.DiscreteGaussian{Sigma: 6.4, Bound: 38}))
		require.True(t, paramsWithCustomSecrets.Xs().Equal(&ring.Ternary{H: 5462}))

		var paramsWithBadDist Parameters
		// checks that providing an ambiguous gaussian distribution yields an error
		dataWithBadDist := []byte(`{"LogN":13,"LogQ":[50,50],"LogP":[60],"Xs":{"Type":"DiscreteGaussian", "Sigma":3.2}}`)
		err = json.Unmarshal(dataWithBadDist, &paramsWithBadDist)
		require.NotNil(t, err)
		require.Equal(t, paramsWithBadDist, Parameters{})

		// checks that providing an ambiguous ternary distribution yields an error
		dataWithBadDist = []byte(`{"LogN":13,"LogQ":[50,50],"LogP":[60],"Xs":{"Type":"Ternary", "H":5462,"P":0.3}}`)

		err = json.Unmarshal(dataWithBadDist, &paramsWithBadDist)
		require.NotNil(t, err)
		require.Equal(t, paramsWithBadDist, Parameters{})
	})

}

func NewTestContext(params Parameters) (tc *TestContext, err error) {

	kgen := NewKeyGenerator(params)
	sk := kgen.GenSecretKeyNew()

	pk := kgen.GenPublicKeyNew(sk)

	eval := NewEvaluator(params, nil)

	enc := NewEncryptor(params, sk)

	dec := NewDecryptor(params, sk)

	return &TestContext{
		params: params,
		kgen:   kgen,
		sk:     sk,
		pk:     pk,
		enc:    enc,
		dec:    dec,
		eval:   eval,
	}, nil
}

func testParameters(tc *TestContext, t *testing.T) {

	params := tc.params

	t.Run(testString(params, params.MaxLevelQ(), params.MaxLevelP(), DigitDecomposition{}, "ModInvGaloisElement"), func(t *testing.T) {

		N := params.N()
		mask := params.RingQ().NthRoot() - 1

		for i := 1; i < N>>1; i++ {
			galEl := params.GaloisElement(i)
			inv := params.ModInvGaloisElement(galEl)
			res := (inv * galEl) & mask
			require.Equal(t, uint64(1), res)
		}
	})
}

func testKeyGenerator(tc *TestContext, dd DigitDecomposition, t *testing.T) {

	params := tc.params
	kgen := tc.kgen
	sk := tc.sk
	pk := tc.pk

	// Checks that the secret-key has exactly params.h non-zero coefficients
	t.Run(testString(params, params.MaxLevelQ(), params.MaxLevelP(), dd, "KeyGenerator/GenSecretKey"), func(t *testing.T) {

		switch xs := params.Xs().(type) {
		case *ring.Ternary:
			if xs.P != 0 {
				t.Skip("cannot run test for probabilistic ternary distribution")
			}
		default:
			t.Skip("cannot run test for non ternary distribution")
		}

		skINTT := NewSecretKey(params)

		if params.PCount() > 0 {
			params.RingP().AtLevel(sk.LevelP()).INTT(sk.P, skINTT.P)
			for i := range skINTT.P {
				var zeros int
				for j := range skINTT.P.At(i) {
					if skINTT.P.At(i)[j] == 0 {
						zeros++
					}
				}
				require.Equal(t, params.N(), zeros+params.XsHammingWeight())
			}
		}

		params.RingQ().AtLevel(sk.LevelQ()).INTT(sk.Q, skINTT.Q)
		for i := range skINTT.Q {
			var zeros int
			for j := range skINTT.Q.At(i) {
				if skINTT.Q.At(i)[j] == 0 {
					zeros++
				}
			}
			require.Equal(t, params.N(), zeros+params.XsHammingWeight())
		}
	})

	// Checks that sum([-as + e, a] + [as])) <= N * 6 * sigma
	t.Run(testString(params, params.MaxLevelQ(), params.MaxLevelP(), dd, "KeyGenerator/GenPublicKey"), func(t *testing.T) {
		require.GreaterOrEqual(t, math.Log2(params.NoiseFreshSK())+1, NoisePublicKey(pk, sk, params))
	})

	var levelsQ = []int{0}
	if params.MaxLevelQ() > 0 {
		levelsQ = append(levelsQ, params.MaxLevelQ())
	}

	var levelsP = []int{-1}
	if params.MaxLevelP() >= 0 {
		levelsP[0] = 0
		if params.MaxLevelP() > 0 {
			levelsP = append(levelsP, params.MaxLevelP())
		}
	}

	for _, LevelQ := range levelsQ {

		for _, LevelP := range levelsP {

			evkParams := EvaluationKeyParameters{LevelQ: utils.Pointy(LevelQ), LevelP: utils.Pointy(LevelP), DigitDecomposition: dd}

			// Checks that EvaluationKeys are en encryption under the output key
			// of the RNS decomposition of the input key by
			// 1) Decrypting the RNS decomposed input key
			// 2) Reconstructing the key
			// 3) Checking that the difference with the input key has a small norm
			t.Run(testString(params, LevelQ, LevelP, dd, "KeyGenerator/GenEvaluationKey"), func(t *testing.T) {

				skOut := kgen.GenSecretKeyNew()

				dims := params.DecompositionMatrixDimensions(LevelQ, LevelP, dd)

				evk := NewEvaluationKey(params, evkParams)

				// Generates Decomp([-asIn + w*P*sOut + e, a])
				kgen.GenEvaluationKey(sk, skOut, evk)

				require.Equal(t, dims, evk.Dims())

				require.GreaterOrEqual(t, math.Log2(math.Sqrt(float64(len(dims)))*params.NoiseFreshSK())+1, NoiseEvaluationKey(evk, sk, skOut, params))
			})

			t.Run(testString(params, LevelQ, LevelP, dd, "KeyGenerator/GenRelinearizationKey"), func(t *testing.T) {

				dims := params.DecompositionMatrixDimensions(LevelQ, LevelP, dd)

				rlk := NewRelinearizationKey(params, evkParams)

				// Generates Decomp([-asIn + w*P*sOut + e, a])
				kgen.GenRelinearizationKey(sk, rlk)

				require.Equal(t, dims, rlk.Dims())

				require.GreaterOrEqual(t, math.Log2(math.Sqrt(float64(len(dims)))*params.NoiseFreshSK())+1, NoiseRelinearizationKey(rlk, sk, params))
			})

			t.Run(testString(params, LevelQ, LevelP, dd, "KeyGenerator/GenGaloisKey"), func(t *testing.T) {

				dims := params.DecompositionMatrixDimensions(LevelQ, LevelP, dd)

				gk := NewGaloisKey(params, evkParams)

				// Generates Decomp([-asIn + w*P*sOut + e, a])
				kgen.GenGaloisKey(ring.GaloisGen, sk, gk)

				require.Equal(t, dims, gk.Dims())

				require.GreaterOrEqual(t, math.Log2(math.Sqrt(float64(len(dims)))*params.NoiseFreshSK())+1, NoiseGaloisKey(gk, sk, params))
			})
		}
	}
}

func testEncryptor(tc *TestContext, level int, dd DigitDecomposition, t *testing.T) {

	params := tc.params
	kgen := tc.kgen
	sk, pk := tc.sk, tc.pk
	enc := tc.enc
	dec := tc.dec

	t.Run(testString(params, level, params.MaxLevelP(), dd, "Encryptor/Encrypt/Pk/Random"), func(t *testing.T) {
		ringQ := params.RingQ().AtLevel(level)

		pt := NewPlaintext(params, level, -1)
		ct := NewCiphertext(params, 1, level, -1)

		enc.WithKey(pk).Encrypt(pt, ct)

		dec.Decrypt(ct, pt)

		if pt.IsNTT {
			ringQ.INTT(pt.Q, pt.Q)
		}

		require.GreaterOrEqual(t, math.Log2(params.NoiseFreshPK())+1, ringQ.Stats(pt.Q)[0])
	})

	t.Run(testString(params, level, params.MaxLevelP(), dd, "Encryptor/Encrypt/Pk/WithSources"), func(t *testing.T) {

		seed := [32]byte{0x01}

		ct0 := NewCiphertext(params, 1, level, -1)
		enc.WithKey(pk).WithSeededSecretRandomness(seed).EncryptZero(ct0)

		ct1 := NewCiphertext(params, 1, level, -1)
		enc.WithKey(pk).WithSeededSecretRandomness(seed).EncryptZero(ct1)

		require.True(t, ct0.Equal(ct1))
	})

	t.Run(testString(params, level, params.MaxLevelP(), dd, "Encryptor/Encrypt/Pk/ShallowCopy"), func(t *testing.T) {
		pkEnc1 := enc.WithKey(pk)
		pkEnc2 := pkEnc1.ShallowCopy()
		require.True(t, pkEnc1.params.Equal(&pkEnc2.params))
		require.True(t, pkEnc1.encKey == pkEnc2.encKey)
		require.False(t, pkEnc1.EncryptorBuffers == pkEnc2.EncryptorBuffers)
		require.False(t, pkEnc1.xuSampler == pkEnc2.xuSampler)
		require.False(t, pkEnc1.xeSampler == pkEnc2.xeSampler)
		require.False(t, pkEnc1.xaQSampler == pkEnc2.xaQSampler)
		require.False(t, pkEnc1.xaQSampler == pkEnc2.xaQSampler)
		if pkEnc1.xaPSampler != nil {
			require.False(t, pkEnc1.xaPSampler == pkEnc2.xaPSampler)
		}
	})

	t.Run(testString(params, level, params.MaxLevelP(), dd, "Encryptor/Encrypt/Sk"), func(t *testing.T) {
		ringQ := params.RingQ().AtLevel(level)

		pt := NewPlaintext(params, level, -1)
		ct := NewCiphertext(params, 1, level, -1)

		enc.Encrypt(pt, ct)
		dec.Decrypt(ct, pt)

		if pt.IsNTT {
			ringQ.INTT(pt.Q, pt.Q)
		}
		require.GreaterOrEqual(t, math.Log2(params.NoiseFreshSK())+1, ringQ.Stats(pt.Q)[0])
	})

	t.Run(testString(params, level, params.MaxLevelP(), dd, "Encryptor/Encrypt/Sk/WithSource"), func(t *testing.T) {

		seedXe := [32]byte{0x01}
		seedXa := [32]byte{0x02}

		ct0 := NewCiphertext(params, 1, level, -1)

		enc.WithSeededPublicRandomness(seedXa).WithSeededSecretRandomness(seedXe).EncryptZero(ct0)

		ct1 := NewCiphertext(params, 1, level, -1)

		enc.WithSeededPublicRandomness(seedXa).WithSeededSecretRandomness(seedXe).EncryptZero(ct1)
		require.True(t, ct0.Equal(ct1))

		enc.WithSeededPublicRandomness(seedXe).WithSeededSecretRandomness(seedXe).EncryptZero(ct1)
		require.False(t, ct0.Equal(ct1))
	})

	t.Run(testString(params, level, params.MaxLevelP(), dd, "Encrypt/Sk/ShallowCopy"), func(t *testing.T) {
		skEnc1 := NewEncryptor(params, sk)
		skEnc2 := skEnc1.ShallowCopy()

		require.True(t, skEnc1.params.Equal(&skEnc2.params))
		require.True(t, skEnc1.encKey == skEnc2.encKey)
		require.False(t, skEnc1.EncryptorBuffers == skEnc2.EncryptorBuffers)
		require.False(t, skEnc1.xaQSampler == skEnc2.xaQSampler)
		require.False(t, skEnc1.xeSampler == skEnc2.xeSampler)
		require.False(t, skEnc1.xuSampler == skEnc2.xuSampler)
		if skEnc1.xaPSampler != nil {
			require.False(t, skEnc1.xaPSampler == skEnc2.xaPSampler)
		}
	})

	t.Run(testString(params, level, params.MaxLevelP(), dd, "Encrypt/WithKey/Sk->Sk"), func(t *testing.T) {
		sk2 := kgen.GenSecretKeyNew()
		skEnc1 := NewEncryptor(params, sk)
		skEnc2 := skEnc1.WithKey(sk2)
		require.True(t, skEnc1.params.Equal(&skEnc2.params))
		require.True(t, skEnc1.encKey == sk)
		require.True(t, skEnc2.encKey == sk2)
		require.True(t, skEnc1.EncryptorBuffers == skEnc2.EncryptorBuffers)
		require.True(t, skEnc1.xaQSampler == skEnc2.xaQSampler)
		require.True(t, skEnc1.xeSampler == skEnc2.xeSampler)
		require.True(t, skEnc1.xuSampler == skEnc2.xuSampler)

		if skEnc1.xaPSampler != nil {
			require.True(t, skEnc1.xaPSampler == skEnc2.xaPSampler)
		}
	})
}

func testCoalescedGadgetProduct(t *testing.T) {

	var params Parameters
	var err error
	if params, err = NewParametersFromLiteral(ParametersLiteral{
		LogN:    10,
		LogQ:    []int{50, 40, 40, 40, 40},
		LogP:    []int{60},
		NTTFlag: true,
	}); err != nil {
		t.Fatal(err)
	}

	LevelQ := params.MaxLevelQ() - 1

	kgen := NewKeyGenerator(params)
	sk := kgen.GenSecretKeyNew()
	eval := NewEvaluator(params, nil)

	rQ := params.RingQ().AtLevel(LevelQ)

	sampler := ring.NewUniformSampler(sampling.NewSource([32]byte{'a', 'b', 'c'}), rQ.ModuliChain())

	var NoiseBound = float64(params.LogN())

	t.Run(testString(params, LevelQ, params.MaxLevelP(), DigitDecomposition{}, "Evaluator/GadgetProduct/Coalescing=1"), func(t *testing.T) {

		skOut := kgen.GenSecretKeyNew()

		// Generates a random polynomial
		a := sampler.ReadNew(params.N())

		// Generate the receiver
		ct := NewCiphertext(params, 1, LevelQ, -1)

		// Generate the evaluationkey [-bs1 + s1, b]
		evk := kgen.GenEvaluationKeyNew(sk, skOut)

		// Gadget product: ct = [-cs1 + as0 , c]
		eval.GadgetProduct(ct.Level(), a, ct.IsNTT, &evk.GadgetCiphertext, ct)

		// pt = as0
		dec := NewDecryptor(params, skOut)

		pt := dec.DecryptNew(ct)

		// pt = as1 - as1 = 0 (+ some noise)
		if !pt.IsNTT {
			rQ.NTT(pt.Q, pt.Q)
			rQ.NTT(a, a)
		}

		rQ.MulCoeffsMontgomeryThenSub(a, sk.Q, pt.Q)
		rQ.INTT(pt.Q, pt.Q)

		require.GreaterOrEqual(t, NoiseBound, rQ.Stats(pt.Q)[0])
	})
}

func testGadgetProduct(tc *TestContext, LevelQ int, dd DigitDecomposition, t *testing.T) {

	params := tc.params
	sk := tc.sk
	kgen := tc.kgen
	eval := tc.eval

	ringQ := params.RingQ().AtLevel(LevelQ)

	sampler := ring.NewUniformSampler(sampling.NewSource([32]byte{'a', 'b', 'c'}), ringQ.ModuliChain())

	var NoiseBound = float64(params.LogN() + dd.Log2Basis)

	var levelsP []int

	if params.MaxLevelP() > -1 {
		levelsP = []int{0, params.MaxLevelP()}
	} else {
		levelsP = []int{-1}
	}

	for _, LevelP := range levelsP {

		evkParams := EvaluationKeyParameters{LevelQ: utils.Pointy(LevelQ), LevelP: utils.Pointy(LevelP), DigitDecomposition: dd}

		t.Run(testString(params, LevelQ, LevelP, dd, "Evaluator/GadgetProduct"), func(t *testing.T) {

			skOut := kgen.GenSecretKeyNew()

			// Generates a random polynomial
			a := sampler.ReadNew(params.N())

			// Generate the receiver
			ct := NewCiphertext(params, 1, LevelQ, -1)

			evk := NewEvaluationKey(params, evkParams)

			// Generate the evaluationkey [-bs1 + s1, b]
			kgen.GenEvaluationKey(sk, skOut, evk)

			// Gadget product: ct = [-cs1 + as0 , c]
			eval.GadgetProduct(LevelQ, a, ct.IsNTT, &evk.GadgetCiphertext, ct)

			// pt = as0
			dec := NewDecryptor(params, skOut)

			pt := dec.DecryptNew(ct)

			ringQ := params.RingQ().AtLevel(LevelQ)

			// pt = as1 - as1 = 0 (+ some noise)
			if !pt.IsNTT {
				ringQ.NTT(pt.Q, pt.Q)
				ringQ.NTT(a, a)
			}

			ringQ.MulCoeffsMontgomeryThenSub(a, sk.Q, pt.Q)
			ringQ.INTT(pt.Q, pt.Q)

			require.GreaterOrEqual(t, NoiseBound, ringQ.Stats(pt.Q)[0])
		})

		t.Run(testString(params, LevelQ, LevelP, dd, "Evaluator/GadgetProductHoisted"), func(t *testing.T) {

			if dd.Type != 0 {
				t.Skip("method is unsupported for DigitDecomposition != 0")
			}

			if tc.params.MaxLevelP() == -1 {
				t.Skip("test requires #P > 0")
			}

			skOut := kgen.GenSecretKeyNew()

			// Generates a random polynomial
			a := sampler.ReadNew(params.N())

			// Generate the receiver
			ct := NewCiphertext(params, 1, LevelQ, -1)

			evk := NewEvaluationKey(params, evkParams)

			// Generate the evaluationkey [-bs1 + s1, b]
			kgen.GenEvaluationKey(sk, skOut, evk)

			Hbuf := eval.NewHoistingBuffer(LevelQ, LevelP)

			//Decompose the ciphertext
			eval.FillHoistingBuffer(LevelQ, LevelP, a, ct.IsNTT, Hbuf)

			// Gadget product: ct = [-cs1 + as0 , c]
			eval.GadgetProductHoisted(LevelQ, Hbuf, &evk.GadgetCiphertext, ct)

			// pt = as0
			pt := NewDecryptor(params, skOut).DecryptNew(ct)

			rQ := params.RingQ().AtLevel(LevelQ)

			// pt = as1 - as1 = 0 (+ some noise)
			if !pt.IsNTT {
				rQ.NTT(pt.Q, pt.Q)
				rQ.NTT(a, a)
			}

			rQ.MulCoeffsMontgomeryThenSub(a, sk.Q, pt.Q)
			rQ.INTT(pt.Q, pt.Q)

			require.GreaterOrEqual(t, NoiseBound, rQ.Stats(pt.Q)[0])
		})
	}
}

func testApplyEvaluationKey(tc *TestContext, level int, dd DigitDecomposition, t *testing.T) {

	params := tc.params
	sk := tc.sk
	kgen := tc.kgen
	eval := tc.eval
	enc := tc.enc
	dec := tc.dec

	var NoiseBound = float64(params.LogN() + dd.Log2Basis)

	evkParams := EvaluationKeyParameters{LevelQ: utils.Pointy(level), DigitDecomposition: dd}

	t.Run(testString(params, level, params.MaxLevelP(), dd, "Evaluator/ApplyEvaluationKey/SameDegree"), func(t *testing.T) {

		skOut := kgen.GenSecretKeyNew()

		pt := NewPlaintext(params, level, -1)

		ct := NewCiphertext(params, 1, level, -1)

		enc.Encrypt(pt, ct)

		// Test that Dec(KS(Enc(ct, sk), skOut), skOut) has a small norm
		eval.ApplyEvaluationKey(ct, kgen.GenEvaluationKeyNew(sk, skOut, evkParams), ct)

		NewDecryptor(params, skOut).Decrypt(ct, pt)

		ringQ := params.RingQ().AtLevel(level)

		if pt.IsNTT {
			ringQ.INTT(pt.Q, pt.Q)
		}

		require.GreaterOrEqual(t, NoiseBound, ringQ.Stats(pt.Q)[0])
	})

	t.Run(testString(params, level, params.MaxLevelP(), dd, "Evaluator/ApplyEvaluationKey/LargeToSmall"), func(t *testing.T) {

		paramsLargeDim := params

		paramsSmallDim, err := NewParametersFromLiteral(ParametersLiteral{
			LogN:     paramsLargeDim.LogN() - 1,
			Q:        paramsLargeDim.Q(),
			P:        []uint64{0x1ffffffff6c80001, 0x1ffffffff6140001}[:paramsLargeDim.PCount()], // some other P to test that the modulus is correctly extended in the keygen
			RingType: paramsLargeDim.RingType(),
		})

		require.Nil(t, err)

		kgenLargeDim := kgen
		skLargeDim := sk
		kgenSmallDim := NewKeyGenerator(paramsSmallDim)
		skSmallDim := kgenSmallDim.GenSecretKeyNew()

		evk := kgenLargeDim.GenEvaluationKeyNew(skLargeDim, skSmallDim, evkParams)

		enc := NewEncryptor(paramsLargeDim, skLargeDim)

		ctLargeDim := NewCiphertext(paramsLargeDim, 1, level, -1)
		require.NoError(t, enc.EncryptZero(ctLargeDim))
		ctSmallDim := NewCiphertext(paramsSmallDim, 1, level, -1)

		// skLarge -> skSmall embeded in N
		eval.ApplyEvaluationKey(ctLargeDim, evk, ctSmallDim)

		// Decrypts with smaller dimension key
		dec := NewDecryptor(paramsSmallDim, skSmallDim)

		ptSmallDim := dec.DecryptNew(ctSmallDim)

		ringQSmallDim := paramsSmallDim.RingQ().AtLevel(level)
		if ptSmallDim.IsNTT {
			ringQSmallDim.INTT(ptSmallDim.Q, ptSmallDim.Q)
		}

		require.GreaterOrEqual(t, NoiseBound, ringQSmallDim.Stats(ptSmallDim.Q)[0])
	})

	t.Run(testString(params, level, params.MaxLevelP(), dd, "Evaluator/ApplyEvaluationKey/SmallToLarge"), func(t *testing.T) {

		paramsLargeDim := params

		paramsSmallDim, err := NewParametersFromLiteral(ParametersLiteral{
			LogN:     paramsLargeDim.LogN() - 1,
			Q:        paramsLargeDim.Q(),
			P:        []uint64{0x1ffffffff6c80001, 0x1ffffffff6140001}[:paramsLargeDim.PCount()], // some other P to test that the modulus is correctly extended in the keygen
			RingType: paramsLargeDim.RingType(),
			NTTFlag:  params.NTTFlag(),
		})

		require.Nil(t, err)

		kgenLargeDim := kgen
		skLargeDim := sk
		kgenSmallDim := NewKeyGenerator(paramsSmallDim)
		skSmallDim := kgenSmallDim.GenSecretKeyNew()

		evk := kgenLargeDim.GenEvaluationKeyNew(skSmallDim, skLargeDim, evkParams)

		ctSmallDim := NewCiphertext(paramsSmallDim, 1, level, -1)

		require.NoError(t, NewEncryptor(paramsSmallDim, skSmallDim).EncryptZero(ctSmallDim))

		ctLargeDim := NewCiphertext(paramsLargeDim, 1, level, -1)

		eval.ApplyEvaluationKey(ctSmallDim, evk, ctLargeDim)

		ptLargeDim := dec.DecryptNew(ctLargeDim)

		ringQLargeDim := paramsLargeDim.RingQ().AtLevel(level)
		if ptLargeDim.IsNTT {
			ringQLargeDim.INTT(ptLargeDim.Q, ptLargeDim.Q)
		}

		require.GreaterOrEqual(t, NoiseBound, ringQLargeDim.Stats(ptLargeDim.Q)[0])
	})
}

func testAutomorphism(tc *TestContext, LevelQ int, dd DigitDecomposition, t *testing.T) {

	params := tc.params
	sk := tc.sk
	kgen := tc.kgen
	eval := tc.eval
	enc := tc.enc
	dec := tc.dec

	var NoiseBound = float64(params.LogN() + dd.Log2Basis)

	if dd.Type != 0 {
		NoiseBound += math.Log2(float64(LevelQ)+1) + 1
	}

	var levelsP []int

	if params.MaxLevelP() > -1 {
		levelsP = []int{0, params.MaxLevelP()}
	} else {
		levelsP = []int{-1}
	}

	for _, LevelP := range levelsP {

		evkParams := EvaluationKeyParameters{LevelQ: utils.Pointy(LevelQ), LevelP: utils.Pointy(LevelP), DigitDecomposition: dd}

		t.Run(testString(params, LevelQ, LevelP, dd, "Evaluator/Automorphism"), func(t *testing.T) {

			// Generate a plaintext with values up to 2^30
			pt := genPlaintext(params, LevelQ, 1<<30)

			// Encrypt
			ct := NewCiphertext(params, 1, LevelQ, -1)
			require.NoError(t, enc.Encrypt(pt, ct))

			// Chooses a Galois Element (must be coprime with 2N)
			galEl := params.GaloisElement(-1)

			// Allocate a new EvaluationKeySet and adds the GaloisKey
			evk := NewMemEvaluationKeySet(nil, kgen.GenGaloisKeyNew(galEl, sk, evkParams))

			// Evaluate the automorphism
			eval.WithKey(evk).Automorphism(ct, galEl, ct)

			// Apply the same automorphism on the plaintext
			ringQ := params.RingQ().AtLevel(LevelQ)

			tmp := ringQ.NewRNSPoly()
			if pt.IsNTT {
				ringQ.AutomorphismNTT(pt.Q, galEl, tmp)
			} else {
				ringQ.Automorphism(pt.Q, galEl, tmp)
			}

			// Decrypt
			dec.Decrypt(ct, pt)

			// Subract the permuted plaintext to the decrypted plaintext
			ringQ.Sub(pt.Q, tmp, pt.Q)

			// Switch out of NTT if required
			if pt.IsNTT {
				ringQ.INTT(pt.Q, pt.Q)
			}

			// Logs the noise
			require.GreaterOrEqual(t, NoiseBound, ringQ.Stats(pt.Q)[0])
		})

		t.Run(testString(params, LevelQ, LevelP, dd, "Evaluator/AutomorphismHoisted"), func(t *testing.T) {

			if dd.Type != 0 {
				t.Skip("method is not supported if BaseTwoDecomposition != 0")
			}

			if tc.params.MaxLevelP() == -1 {
				t.Skip("test requires #P > 0")
			}

			// Generate a plaintext with values up to 2^30
			pt := genPlaintext(params, LevelQ, 1<<30)

			// Encrypt
			ct := NewCiphertext(params, 1, LevelQ, -1)
			require.NoError(t, enc.Encrypt(pt, ct))

			// Chooses a Galois Element (must be coprime with 2N)
			galEl := params.GaloisElement(-1)

			// Allocate a new EvaluationKeySet and adds the GaloisKey
			evk := NewMemEvaluationKeySet(nil, kgen.GenGaloisKeyNew(galEl, sk, evkParams))

			Hbuf := eval.NewHoistingBuffer(LevelQ, LevelP)

			// Decompose the ciphertext
			eval.FillHoistingBuffer(LevelQ, LevelP, ct.Q[1], ct.IsNTT, Hbuf)

			// Evaluate the automorphism
			eval.WithKey(evk).AutomorphismHoisted(ct, Hbuf, galEl, ct)

			// Apply the same automorphism on the plaintext
			ringQ := params.RingQ().AtLevel(LevelQ)

			tmp := ringQ.NewRNSPoly()
			if pt.IsNTT {
				ringQ.AutomorphismNTT(pt.Q, galEl, tmp)
			} else {
				ringQ.Automorphism(pt.Q, galEl, tmp)
			}

			// Decrypt
			dec.Decrypt(ct, pt)

			// Subract the permuted plaintext to the decrypted plaintext
			ringQ.Sub(pt.Q, tmp, pt.Q)

			// Switch out of NTT if required
			if pt.IsNTT {
				ringQ.INTT(pt.Q, pt.Q)
			}

			// Logs the noise
			require.GreaterOrEqual(t, NoiseBound, ringQ.Stats(pt.Q)[0])
		})

		t.Run(testString(params, LevelQ, LevelP, dd, "Evaluator/AutomorphismHoistedLazy"), func(t *testing.T) {

			if dd.Type != 0 {
				t.Skip("method is not supported if BaseTwoDecomposition != 0")
			}

			if tc.params.MaxLevelP() == -1 {
				t.Skip("test requires #P > 0")
			}

			// Generate a plaintext with values up to 2^30
			pt := genPlaintext(params, LevelQ, 1<<30)

			// Encrypt
			ct := NewCiphertext(params, 1, LevelQ, -1)
			require.NoError(t, enc.Encrypt(pt, ct))

			// Chooses a Galois Element (must be coprime with 2N)
			galEl := params.GaloisElement(-1)

			// Allocate a new EvaluationKeySet and adds the GaloisKey
			evk := NewMemEvaluationKeySet(nil, kgen.GenGaloisKeyNew(galEl, sk, evkParams))

			Hbuf := eval.NewHoistingBuffer(LevelQ, LevelP)

			//Decompose the ciphertext
			eval.FillHoistingBuffer(LevelQ, LevelP, ct.Q[1], ct.IsNTT, Hbuf)

			ctQP := NewCiphertext(params, 1, LevelQ, LevelP)
			ctQP.MetaData = ct.MetaData.Clone()

			// Evaluate the automorphism
			eval.WithKey(evk).AutomorphismHoistedLazy(LevelQ, ct, Hbuf, galEl, ctQP)

			eval.ModDown(LevelQ, LevelP, ctQP, ct)

			// Apply the same automorphism on the plaintext
			ringQ := params.RingQ().AtLevel(LevelQ)

			tmp := ringQ.NewRNSPoly()
			if pt.IsNTT {
				ringQ.AutomorphismNTT(pt.Q, galEl, tmp)
			} else {
				ringQ.Automorphism(pt.Q, galEl, tmp)
			}

			// Decrypt
			dec.Decrypt(ct, pt)

			// Subract the permuted plaintext to the decrypted plaintext
			ringQ.Sub(pt.Q, tmp, pt.Q)

			// Switch out of NTT if required
			if pt.IsNTT {
				ringQ.INTT(pt.Q, pt.Q)
			}

			// Logs the noise
			require.GreaterOrEqual(t, NoiseBound, ringQ.Stats(pt.Q)[0])
		})
	}
}

func testSlotOperations(tc *TestContext, LevelQ int, dd DigitDecomposition, t *testing.T) {

	params := tc.params
	sk := tc.sk
	kgen := tc.kgen
	eval := tc.eval
	enc := tc.enc
	dec := tc.dec

	t.Run(testString(params, LevelQ, params.MaxLevelP(), dd, "Evaluator/InnerSum"), func(t *testing.T) {

		if params.MaxLevelP() == -1 {
			t.Skip("test requires #P > 0")
		}

		LevelP := params.MaxLevelP()

		batch := 5
		n := 7

		ringQ := tc.params.RingQ().AtLevel(LevelQ)

		pt := genPlaintext(params, LevelQ, 1<<30)
		ptInnerSum := *pt.Q.Clone()
		ct := NewCiphertext(params, 1, LevelQ, -1)
		require.NoError(t, enc.Encrypt(pt, ct))

		// Galois Keys
		evk := NewMemEvaluationKeySet(nil, kgen.GenGaloisKeysNew(GaloisElementsForInnerSum(params, batch, n), sk)...)

		Hbuf := eval.NewHoistingBuffer(LevelQ, LevelP)

		require.NoError(t, eval.WithKey(evk).InnerSum(ct, batch, n, Hbuf, ct))

		dec.Decrypt(ct, pt)

		if pt.IsNTT {
			ringQ.INTT(pt.Q, pt.Q)
			ringQ.INTT(ptInnerSum, ptInnerSum)
		}

		polyTmp := ringQ.NewRNSPoly()

		// Applies the same circuit (naively) on the plaintext
		polyInnerSum := *ptInnerSum.Clone()
		for i := 1; i < n; i++ {
			galEl := params.GaloisElement(i * batch)
			ringQ.Automorphism(ptInnerSum, galEl, polyTmp)
			ringQ.Add(polyInnerSum, polyTmp, polyInnerSum)
		}

		ringQ.Sub(pt.Q, polyInnerSum, pt.Q)

		NoiseBound := float64(params.LogN())

		// Logs the noise
		require.GreaterOrEqual(t, NoiseBound, ringQ.Stats(pt.Q)[0])

	})
}

func genPlaintext(params Parameters, level, max int) (pt *Plaintext) {

	N := params.N()

	step := float64(max) / float64(N)

	pt = NewPlaintext(params, level, -1)

	for i := 0; i < level+1; i++ {
		c := pt.Q.At(i)
		for j := 0; j < N; j++ {
			c[j] = uint64(float64(j) * step)
		}
	}

	if pt.IsNTT {
		params.RingQ().AtLevel(level).NTT(pt.Q, pt.Q)
	}

	return
}

func testWriteAndRead(tc *TestContext, dd DigitDecomposition, t *testing.T) {

	params := tc.params

	sk, pk := tc.sk, tc.pk

	LevelQ := params.MaxLevelQ()
	LevelP := params.MaxLevelP()

	t.Run(testString(params, LevelQ, LevelP, dd, "WriteAndRead/Plaintext"), func(t *testing.T) {
		op := NewPlaintext(params, LevelQ, LevelP)
		op.Randomize(params, sampling.NewSource([32]byte{}))
		buffer.RequireSerializerCorrect(t, op)
	})

	t.Run(testString(params, LevelQ, LevelP, dd, "WriteAndRead/Ciphertext"), func(t *testing.T) {
		for degree := 0; degree < 4; degree++ {
			t.Run(fmt.Sprintf("degree=%d", degree), func(t *testing.T) {
				op := NewCiphertext(params, degree, LevelQ, LevelP)
				op.Randomize(params, sampling.NewSource([32]byte{}))
				buffer.RequireSerializerCorrect(t, op)
			})
		}
	})

	t.Run(testString(params, LevelQ, LevelP, dd, "WriteAndRead/GadgetCiphertext"), func(t *testing.T) {
		rlk := NewRelinearizationKey(params, EvaluationKeyParameters{DigitDecomposition: dd})
		tc.kgen.GenRelinearizationKey(tc.sk, rlk)
		buffer.RequireSerializerCorrect(t, &rlk.GadgetCiphertext)
	})

	t.Run(testString(params, LevelQ, LevelP, dd, "WriteAndRead/Sk"), func(t *testing.T) {
		buffer.RequireSerializerCorrect(t, sk)
	})

	t.Run(testString(params, LevelQ, LevelP, dd, "WriteAndRead/Pk"), func(t *testing.T) {
		buffer.RequireSerializerCorrect(t, pk)
	})

	t.Run(testString(params, LevelQ, LevelP, dd, "WriteAndRead/EvaluationKey"), func(t *testing.T) {
		buffer.RequireSerializerCorrect(t, tc.kgen.GenEvaluationKeyNew(sk, sk))
	})

	t.Run(testString(params, LevelQ, LevelP, dd, "WriteAndRead/RelinearizationKey"), func(t *testing.T) {
		buffer.RequireSerializerCorrect(t, tc.kgen.GenRelinearizationKeyNew(tc.sk))
	})

	t.Run(testString(params, LevelQ, LevelP, dd, "WriteAndRead/GaloisKey"), func(t *testing.T) {
		buffer.RequireSerializerCorrect(t, tc.kgen.GenGaloisKeyNew(5, tc.sk))
	})

	t.Run(testString(params, LevelQ, LevelP, dd, "WriteAndRead/EvaluationKeySet"), func(t *testing.T) {
		galEl := uint64(5)
		buffer.RequireSerializerCorrect(t, &MemEvaluationKeySet{
			RelinearizationKey: tc.kgen.GenRelinearizationKeyNew(tc.sk),
			GaloisKeys:         map[uint64]*GaloisKey{galEl: tc.kgen.GenGaloisKeyNew(galEl, tc.sk)},
		})
	})
}

func testMarshaller(tc *TestContext, t *testing.T) {

	params := tc.params

	t.Run("WriteAndRead/Scale", func(t *testing.T) {
		scale := NewScaleModT(1, 65537)
		buffer.RequireSerializerCorrect(t, &scale)
	})

	t.Run("WriteAndRead/MetaData", func(t *testing.T) {
		m := MetaData{}
		m.Scale = NewScaleModT(1, 65537)
		m.IsNTT = true
		m.IsMontgomery = true
		m.LogDimensions = ring.Dimensions{Rows: 2, Cols: 8}
		m.IsBatched = true
		buffer.RequireSerializerCorrect(t, &m)
	})

	t.Run("WriteAndRead/Parameters", func(t *testing.T) {
		buffer.RequireSerializerCorrect(t, &params)
	})
}
