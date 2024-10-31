package mhe

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"runtime"
	"slices"
	"testing"

	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils"
	"github.com/Pro7ech/lattigo/utils/buffer"
	"github.com/Pro7ech/lattigo/utils/sampling"
	"github.com/stretchr/testify/require"
)

var nbParties = int(5)

var flagParamString = flag.String("params", "", "specify the test cryptographic parameters as a JSON string. Overrides -short and -long.")

func testString(params rlwe.Parameters, opname string, LevelQ, LevelP int, dd rlwe.DigitDecomposition) string {
	return fmt.Sprintf("%s/logN=%d/#Qi=%d/#Pi=%d/Digits=%s/NTT=%t/RingType=%s/Parties=%d",
		opname,
		params.LogN(),
		LevelQ+1,
		LevelP+1,
		dd.ToString(),
		params.NTTFlag(),
		params.RingType(),
		nbParties)
}

type testContext struct {
	params   rlwe.Parameters
	kgen     *rlwe.KeyGenerator
	skShares []*rlwe.SecretKey
	skIdeal  *rlwe.SecretKey
}

func newTestContext(params rlwe.Parameters) *testContext {

	kgen := rlwe.NewKeyGenerator(params)
	skShares := make([]*rlwe.SecretKey, nbParties)
	skIdeal := rlwe.NewSecretKey(params)

	rQ := params.RingQ()
	rP := params.RingP()

	for i := range skShares {
		skShares[i] = kgen.GenSecretKeyNew()
		rQ.Add(skIdeal.Q, skShares[i].Q, skIdeal.Q)
		if rP != nil {
			rP.Add(skIdeal.P, skShares[i].P, skIdeal.P)
		}
	}

	return &testContext{params, kgen, skShares, skIdeal}
}

func (tc testContext) nParties() int {
	return len(tc.skShares)
}

func TestMHE(t *testing.T) {

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

		dd := paramsLit.DigitDecomposition

		for _, RingType := range []ring.Type{ring.Standard, ring.ConjugateInvariant}[:] {

			paramsLit.RingType = RingType

			var params rlwe.Parameters
			if params, err = rlwe.NewParametersFromLiteral(paramsLit.ParametersLiteral); err != nil {
				t.Fatal(err)
			}

			tc := newTestContext(params)

			testPublicKeyProtocol(tc, params.MaxLevelQ(), params.MaxLevelP(), dd, t)
			testThreshold(tc, params.MaxLevelQ(), params.MaxLevelP(), dd, t)
			testRefreshShare(tc, params.MaxLevelQ(), params.MaxLevelP(), dd, t)
			testCircularGadgetCiphertextProtocol(tc, dd, t)
			testCircularCiphertextProtocol(tc, dd, t)

			levelsQ := []int{0}

			if params.MaxLevelQ() > 0 {
				levelsQ = append(levelsQ, params.MaxLevelQ())
			}

			var levelsP []int
			if params.MaxLevelP() > 0 {
				levelsP = []int{0, params.MaxLevelP()}
			} else if params.MaxLevelP() == 0 {
				levelsP = []int{0}
			} else {
				levelsP = []int{-1}
			}
			_ = levelsP

			runtime.GC()

			for _, LevelQ := range levelsQ[:] {
				for _, LevelP := range levelsP[:] {
					for _, testSet := range []func(tc *testContext, LevelQ, LevelP int, dd rlwe.DigitDecomposition, t *testing.T){
						testGadgetCiphertextProtocol,
						testEvaluationKeyProtocol,
						testRelinearizationKeyProtocol,
						testGaloisKeyProtocol,
						testKeySwitchProtocol,
					} {
						testSet(tc, LevelQ, LevelP, dd, t)
						runtime.GC()
					}
				}
			}
		}
	}
}

func testCircularGadgetCiphertextProtocol(tc *testContext, dd rlwe.DigitDecomposition, t *testing.T) {

	params := tc.params
	LevelQ := params.MaxLevelQ()
	LevelP := params.MaxLevelP()

	t.Run(testString(params, "CircularGadgetCiphertextProtocol", LevelQ, LevelP, dd), func(t *testing.T) {

		type Party struct {
			CircularGadgetCiphertextProtocol
			share  *CircularGadgetCiphertextShare
			m      *rlwe.Plaintext
			u      *rlwe.SecretKey
			uShare *GadgetCiphertextShare
		}

		P := make([]*Party, nbParties)

		seedU := [32]byte{0xFF}
		seedM := [32]byte{0xFE}
		ddGRLWEU := rlwe.DigitDecomposition{Type: rlwe.Unsigned, Log2Basis: 13}

		var err error
		for i := range P {

			party := &Party{}

			if i == 0 {
				party.CircularGadgetCiphertextProtocol = *NewCircularGadgetCiphertextProtocol(params, 15)
			} else {
				party.CircularGadgetCiphertextProtocol = *P[0].ShallowCopy()
			}

			party.share = party.Allocate(dd)
			party.u, party.uShare, err = party.GenEphemeralSecret(tc.skShares[i], seedU, ddGRLWEU)
			require.NoError(t, err)
			party.m = tc.skShares[i].AsPlaintext()

			require.NoError(t, party.Gen(tc.skShares[i], party.u, party.m, seedM, party.share))

			P[i] = party
		}

		buffer.RequireSerializerCorrect(t, P[0].share)

		for i := range P {
			if i != 0 {
				require.NoError(t, P[0].uShare.Aggregate(P[0].GetRLWEParameters(), P[0].uShare, P[i].uShare))
				require.NoError(t, P[0].Aggregate(P[0].share, P[i].share, P[0].share))
			}
		}

		GRLWEU := P[0].uShare.AsGadgetCiphertext(P[0].GetRLWEParameters())

		GRLWERLK := rlwe.NewGadgetCiphertext(params, 1, LevelQ, LevelP, dd)
		require.NoError(t, P[0].Finalize(P[0].share, GRLWEU, GRLWERLK))

		// sum(s) * sum(s)
		mGlobal := rlwe.NewPlaintext(params, LevelQ, -1)
		params.RingQ().AtLevel(LevelQ).MulCoeffsMontgomery(tc.skIdeal.Q, tc.skIdeal.Q, mGlobal.Q)

		require.GreaterOrEqual(t, 16.0, rlwe.NoiseGadgetCiphertext(GRLWERLK, mGlobal.Q, tc.skIdeal, params))
	})
}

func testCircularCiphertextProtocol(tc *testContext, dd rlwe.DigitDecomposition, t *testing.T) {

	params := tc.params
	LevelQ := params.MaxLevelQ()
	LevelP := params.MaxLevelP()

	t.Run(testString(params, "CircularCiphertextProtocol", LevelQ, LevelP, dd), func(t *testing.T) {

		type Party struct {
			CircularCiphertextProtocol
			share  *CircularCiphertextShare
			m      *rlwe.Plaintext
			u      *rlwe.SecretKey
			uShare *GadgetCiphertextShare
		}

		seedU := [32]byte{0xFF}
		seedM := [32]byte{0xFE}
		ddGRLWEU := rlwe.DigitDecomposition{Type: rlwe.Signed, Log2Basis: 16}

		P := make([]*Party, nbParties)

		rQ := params.RingQ().AtLevel(LevelQ)

		source := sampling.NewSource(sampling.NewSeed())

		var err error
		for i := range P {

			party := &Party{}

			if i == 0 {
				party.CircularCiphertextProtocol = *NewCircularCiphertextProtocol(params)
			} else {
				party.CircularCiphertextProtocol = *P[0].ShallowCopy()
			}

			party.share = party.Allocate()
			party.u, party.uShare, err = party.GenEphemeralSecret(tc.skShares[i], seedU, ddGRLWEU)
			require.NoError(t, err)

			party.m = rlwe.NewPlaintext(params, LevelQ, -1)
			party.m.Randomize(params, source)

			require.NoError(t, party.Gen(tc.skShares[i], party.u, party.m, seedM, party.share))

			P[i] = party
		}

		buffer.RequireSerializerCorrect(t, P[0].share)

		for i := range P {
			if i != 0 {
				require.NoError(t, P[0].uShare.Aggregate(P[0].GetRLWEParameters(), P[0].uShare, P[i].uShare))
				require.NoError(t, P[0].Aggregate(P[0].share, P[i].share, P[0].share))
			}
		}

		GRLWEU := P[0].uShare.AsGadgetCiphertext(P[0].GetRLWEParameters())

		ct := rlwe.NewCiphertext(params, 1, LevelQ, -1)
		require.NoError(t, P[0].Finalize(P[0].share, GRLWEU, ct))

		// sum(m_{i}) * sum(s)
		mGlobal := rlwe.NewPlaintext(params, LevelQ, -1)
		for i := range P {
			rQ.Add(mGlobal.Q, P[i].m.Q, mGlobal.Q)
		}

		rQ.MulCoeffsMontgomery(mGlobal.Q, tc.skIdeal.Q, mGlobal.Q)

		noise := math.Log2(NoiseCircularCiphertext(params, params.MaxLevelP() > -1, slices.Max(GRLWEU.Dims()), ddGRLWEU.Log2Basis, nbParties))

		require.GreaterOrEqual(t, noise+1, rlwe.NoiseCiphertext(ct, mGlobal, tc.skIdeal, tc.params))

	})
}

func testPublicKeyProtocol(tc *testContext, LevelQ, LevelP int, dd rlwe.DigitDecomposition, t *testing.T) {

	params := tc.params

	t.Run(testString(params, "PublicKeyProtocol", LevelQ, LevelP, dd), func(t *testing.T) {

		type Party struct {
			PublicKeyProtocol
			share *PublicKeyShare
		}

		seed := [32]byte{0xFF}

		P := make([]*Party, nbParties)

		for i := range P {

			party := &Party{}

			if i == 0 {
				party.PublicKeyProtocol = *NewPublicKeyProtocol(params)
			} else {
				party.PublicKeyProtocol = *P[0].ShallowCopy()
			}

			party.share = party.Allocate()

			require.NoError(t, party.Gen(tc.skShares[i], seed, party.share))

			P[i] = party
		}

		buffer.RequireSerializerCorrect(t, P[0].share)

		for i := range P {
			if i != 0 {
				require.NoError(t, P[0].Aggregate(P[0].share, P[i].share, P[0].share))
			}
		}

		pk := rlwe.NewPublicKey(params)
		require.NoError(t, P[0].Finalize(P[0].share, pk))

		require.GreaterOrEqual(t, math.Log2(math.Sqrt(float64(nbParties))*params.NoiseFreshSK())+1, rlwe.NoisePublicKey(pk, tc.skIdeal, params))
	})
}

func testGadgetCiphertextProtocol(tc *testContext, LevelQ, LevelP int, dd rlwe.DigitDecomposition, t *testing.T) {

	params := tc.params

	t.Run(testString(params, "GadgetCiphertextProtocol", LevelQ, LevelP, dd), func(t *testing.T) {

		type Party struct {
			GadgetCiphertextProtocol
			share *GadgetCiphertextShare
			pt    *rlwe.Plaintext
		}

		P := make([]*Party, nbParties)

		kgen := rlwe.NewKeyGenerator(params)

		seed := [32]byte{0xFF}

		for i := range P {

			party := &Party{}

			if i == 0 {
				party.GadgetCiphertextProtocol = *NewGadgetCiphertextProtocol(params)
			} else {
				party.GadgetCiphertextProtocol = *P[0].ShallowCopy()
			}

			party.share = party.Allocate(LevelQ, LevelP, dd)
			party.pt = kgen.GenSecretKeyNew().AsPlaintext()

			require.NoError(t, party.Gen(tc.skShares[i], party.pt, seed, party.share))

			P[i] = party
		}

		buffer.RequireSerializerCorrect(t, P[0].share)

		for i := range P {
			if i != 0 {
				require.NoError(t, P[0].Aggregate(P[0].share, P[i].share, P[0].share))
			}
		}

		gct := rlwe.NewGadgetCiphertext(params, 2, LevelQ, LevelP, dd)
		require.NoError(t, P[0].Finalize(P[0].share, gct))

		ptGlobal := rlwe.NewPlaintext(params, LevelQ, -1)
		rQ := params.RingQ().AtLevel(ptGlobal.Level())
		for i := range P {
			rQ.Add(ptGlobal.Q, P[i].pt.Q, ptGlobal.Q)
		}

		noiseBound := math.Log2(math.Sqrt(float64(len(gct.Dims())))*NoiseGadgetCiphertext(params, nbParties)) + 1

		require.GreaterOrEqual(t, noiseBound, rlwe.NoiseGadgetCiphertext(gct, ptGlobal.Q, tc.skIdeal, params))
	})
}

func testEvaluationKeyProtocol(tc *testContext, LevelQ, LevelP int, dd rlwe.DigitDecomposition, t *testing.T) {

	params := tc.params

	t.Run(testString(params, "EvaluationKeyGen", LevelQ, LevelP, dd), func(t *testing.T) {

		evkParams := rlwe.EvaluationKeyParameters{LevelQ: utils.Pointy(LevelQ), LevelP: utils.Pointy(LevelP), DigitDecomposition: dd}

		type Party struct {
			EvaluationKeyProtocol
			share *EvaluationKeyShare
			skOut *rlwe.SecretKey
		}

		P := make([]*Party, nbParties)

		kgen := rlwe.NewKeyGenerator(params)

		seed := [32]byte{0xFF}

		for i := range P {

			party := &Party{}

			if i == 0 {
				party.EvaluationKeyProtocol = *NewEvaluationKeyProtocol(params)
			} else {
				party.EvaluationKeyProtocol = *P[0].ShallowCopy()
			}

			party.share = party.Allocate(evkParams)
			party.skOut = kgen.GenSecretKeyNew()

			require.NoError(t, party.Gen(tc.skShares[i], party.skOut, seed, party.share))

			P[i] = party
		}

		buffer.RequireSerializerCorrect(t, P[0].share)

		for i := range P {
			if i != 0 {

				require.NoError(t, P[0].Aggregate(P[0].share, P[i].share, P[0].share))
			}
		}

		evk := rlwe.NewEvaluationKey(params, evkParams)
		require.NoError(t, P[0].Finalize(P[0].share, evk))

		skOutIdeal := rlwe.NewSecretKey(params)
		rQ := params.RingQ()
		rP := params.RingP()
		for i := range P {
			rQ.Add(skOutIdeal.Q, P[i].skOut.Q, skOutIdeal.Q)
			if rP != nil {
				rP.Add(skOutIdeal.P, P[i].skOut.P, skOutIdeal.P)
			}
		}

		noiseBound := math.Log2(math.Sqrt(float64(len(evk.Dims())))*NoiseEvaluationKey(params, nbParties)) + 1

		require.GreaterOrEqual(t, noiseBound, rlwe.NoiseEvaluationKey(evk, tc.skIdeal, skOutIdeal, params))
	})
}

func testGaloisKeyProtocol(tc *testContext, LevelQ, LevelP int, dd rlwe.DigitDecomposition, t *testing.T) {

	params := tc.params

	t.Run(testString(params, "GaloisKeyGenProtocol", LevelQ, LevelP, dd), func(t *testing.T) {

		evkParams := rlwe.EvaluationKeyParameters{LevelQ: utils.Pointy(LevelQ), LevelP: utils.Pointy(LevelP), DigitDecomposition: dd}

		type Party struct {
			GaloisKeyProtocol
			share *GaloisKeyShare
		}

		P := make([]*Party, nbParties)

		seed := [32]byte{0xFF}

		galEl := params.GaloisElement(64)

		for i := range P {

			party := &Party{}

			if i == 0 {
				party.GaloisKeyProtocol = *NewGaloisKeyProtocol(params)
			} else {
				party.GaloisKeyProtocol = *P[0].ShallowCopy()
			}

			party.share = party.Allocate(evkParams)

			require.NoError(t, party.Gen(tc.skShares[i], galEl, seed, party.share))

			P[i] = party
		}

		buffer.RequireSerializerCorrect(t, P[0].share)

		for i := range P {
			if i != 0 {
				require.NoError(t, P[0].Aggregate(P[0].share, P[i].share, P[0].share))
			}
		}

		gk := rlwe.NewGaloisKey(params, evkParams)
		require.NoError(t, P[0].Finalize(P[0].share, gk))

		noiseBound := math.Log2(math.Sqrt(float64(len(gk.Dims())))*NoiseGaloisKey(params, nbParties)) + 1

		require.GreaterOrEqual(t, noiseBound, rlwe.NoiseGaloisKey(gk, tc.skIdeal, params))
	})
}

func testRelinearizationKeyProtocol(tc *testContext, LevelQ, LevelP int, dd rlwe.DigitDecomposition, t *testing.T) {

	params := tc.params

	t.Run(testString(params, "RelinearizationKeyProtocol", LevelQ, LevelP, dd), func(t *testing.T) {

		evkParams := rlwe.EvaluationKeyParameters{LevelQ: utils.Pointy(LevelQ), LevelP: utils.Pointy(LevelP), DigitDecomposition: dd}

		type Party struct {
			RelinearizationKeyProtocol
			share *RelinearizationKeyShare
		}

		pk := tc.kgen.GenPublicKeyNew(tc.skIdeal)

		P := make([]*Party, nbParties)

		for i := range P {

			party := &Party{}

			if i == 0 {
				party.RelinearizationKeyProtocol = *NewRelinearizationKeyProtocol(params)
			} else {
				party.RelinearizationKeyProtocol = *P[0].ShallowCopy()
			}

			party.share = party.Allocate(evkParams)

			require.NoError(t, party.Gen(tc.skShares[i], pk, party.share))

			P[i] = party
		}

		buffer.RequireSerializerCorrect(t, P[0].share)

		for i := range P {
			if i != 0 {
				require.NoError(t, P[0].Aggregate(P[0].share, P[i].share, P[0].share))
			}
		}

		rlk := rlwe.NewRelinearizationKey(params, evkParams)
		require.NoError(t, P[0].Finalize(P[0].share, rlk))

		noiseBound := math.Log2(math.Sqrt(float64(len(rlk.Dims())))*NoiseRelinearizationKey(params, nbParties)) + 1

		require.GreaterOrEqual(t, noiseBound, rlwe.NoiseRelinearizationKey(rlk, tc.skIdeal, params))
	})
}

func testKeySwitchProtocol(tc *testContext, LevelQ, LevelP int, dd rlwe.DigitDecomposition, t *testing.T) {

	params := tc.params

	t.Run(testString(params, "KeySwitchingProtocol/Sk", LevelQ, LevelP, dd), func(t *testing.T) {

		type Party struct {
			KeySwitchingProtocol[rlwe.SecretKey]
			share *KeySwitchingShare
			skOut *rlwe.SecretKey
		}

		P := make([]*Party, nbParties)

		ct := rlwe.NewCiphertext(params, 1, LevelQ, -1)
		require.NoError(t, rlwe.NewEncryptor(params, tc.skIdeal).EncryptZero(ct))

		sigmaSmudging := 8.0 * rlwe.DefaultNoise

		for i := range P {

			party := &Party{}

			if i == 0 {
				party.KeySwitchingProtocol = *NewKeySwitchingProtocol[rlwe.SecretKey](params)
			} else {
				party.KeySwitchingProtocol = *P[0].ShallowCopy()
			}

			party.share = party.Allocate(ct.Level())
			party.skOut = tc.kgen.GenSecretKeyNew()

			require.NoError(t, party.Gen(tc.skShares[i], party.skOut, sigmaSmudging, ct, party.share))

			P[i] = party
		}

		buffer.RequireSerializerCorrect(t, P[0].share)

		for i := range P {
			if i != 0 {
				require.NoError(t, P[0].Aggregate(P[0].share, P[i].share, P[0].share))
			}
		}

		require.NoError(t, P[0].Finalize(ct, P[0].share, ct))

		skOutIdeal := rlwe.NewSecretKey(params)
		rQ := params.RingQ().AtLevel(LevelQ)
		for i := range P {
			rQ.Add(skOutIdeal.Q, P[i].skOut.Q, skOutIdeal.Q)
		}

		dec := rlwe.NewDecryptor(params, skOutIdeal)

		pt := rlwe.NewPlaintext(params, ct.Level(), -1)

		dec.Decrypt(ct, pt)

		if pt.IsNTT {
			rQ.INTT(pt.Q, pt.Q)
		}

		require.GreaterOrEqual(t, math.Log2(NoiseKeySwitch(nbParties, params.NoiseFreshSK(), params.NoiseFreshSK(), sigmaSmudging))+1, rQ.Stats(pt.Q)[0])
	})

	t.Run(testString(params, "KeySwitchingProtocol/Pk", LevelQ, LevelP, dd), func(t *testing.T) {

		type Party struct {
			KeySwitchingProtocol[rlwe.PublicKey]
			share *KeySwitchingShare
		}

		P := make([]*Party, nbParties)

		skOut, pkOut := tc.kgen.GenKeyPairNew()

		ct := rlwe.NewCiphertext(params, 1, LevelQ, -1)
		require.NoError(t, rlwe.NewEncryptor(params, tc.skIdeal).EncryptZero(ct))

		sigmaSmudging := 8.0 * rlwe.DefaultNoise

		for i := range P {

			party := &Party{}

			if i == 0 {
				party.KeySwitchingProtocol = *NewKeySwitchingProtocol[rlwe.PublicKey](params)
			} else {
				party.KeySwitchingProtocol = *P[0].ShallowCopy()
			}

			party.share = party.Allocate(ct.Level())
			party.Sk = skOut

			require.NoError(t, party.Gen(tc.skShares[i], pkOut, sigmaSmudging, ct, party.share))

			P[i] = party
		}

		buffer.RequireSerializerCorrect(t, P[0].share)

		for i := range P {
			if i != 0 {
				require.NoError(t, P[0].Aggregate(P[0].share, P[i].share, P[0].share))
			}
		}

		require.NoError(t, P[0].Finalize(ct, P[0].share, ct))

		dec := rlwe.NewDecryptor(params, skOut)

		pt := rlwe.NewPlaintext(params, ct.Level(), -1)

		dec.Decrypt(ct, pt)

		rQ := params.RingQ().AtLevel(LevelQ)

		if pt.IsNTT {
			rQ.INTT(pt.Q, pt.Q)
		}

		require.GreaterOrEqual(t, math.Log2(NoiseKeySwitch(nbParties, params.NoiseFreshSK(), params.NoiseFreshPK(), sigmaSmudging))+1, rQ.Stats(pt.Q)[0])
	})
}

func testThreshold(tc *testContext, LevelQ, LevelP int, dd rlwe.DigitDecomposition, t *testing.T) {
	sk0Shards := tc.skShares

	for _, threshold := range []int{tc.nParties() / 4, tc.nParties() / 2, tc.nParties() - 1} {
		t.Run(testString(tc.params, "Threshold", LevelQ, LevelP, dd)+fmt.Sprintf("/threshold=%d", threshold), func(t *testing.T) {

			type Party struct {
				Thresholdizer
				Combiner
				gen   *ShamirPolynomial
				sk    *rlwe.SecretKey
				share *ShamirSecretShare
				tsk   *rlwe.SecretKey
				tpk   ShamirPublicPoint
			}

			P := make([]*Party, nbParties)
			shamirPks := make([]ShamirPublicPoint, tc.nParties())
			for i := range P {
				p := new(Party)
				p.Thresholdizer = *NewThresholdizer(tc.params)
				p.sk = sk0Shards[i]
				p.tsk = rlwe.NewSecretKey(tc.params)
				p.tpk = ShamirPublicPoint(i + 1)
				p.share = p.Thresholdizer.Allocate()
				P[i] = p
				shamirPks[i] = p.tpk
			}

			buffer.RequireSerializerCorrect(t, P[0].share)

			for _, pi := range P {
				pi.Combiner = *NewCombiner(tc.params, pi.tpk, shamirPks, threshold)
			}

			shares := make(map[*Party]map[*Party]*ShamirSecretShare, tc.nParties())
			var err error
			// Every party generates a share for every other party
			for _, pi := range P {

				pi.gen, err = pi.Thresholdizer.Gen(threshold, pi.sk)
				require.NoError(t, err)

				shares[pi] = make(map[*Party]*ShamirSecretShare)
				for _, pj := range P {
					shares[pi][pj] = pi.Thresholdizer.Allocate()
					share := shares[pi][pj]
					require.NoError(t, pi.Thresholdizer.Finalize(pj.tpk, pi.gen, share))
				}
			}

			//Each party aggregates what it has received into a secret key
			for _, pi := range P {
				for _, pj := range P {
					share := shares[pj][pi]
					require.NoError(t, pi.Thresholdizer.Aggregate(pi.share, share, pi.share))
				}
			}

			// Determining which parties are active. In a distributed context, a party
			// would receive the ids of active players and retrieve (or compute) the corresponding keys.
			activeParties := P[:threshold]
			activeShamirPks := make([]ShamirPublicPoint, threshold)
			for i, p := range activeParties {
				activeShamirPks[i] = p.tpk
			}

			// Combining
			// Slow because each party has to generate its public key on-the-fly. In
			// practice the public key could be precomputed from an id by parties during setup
			rQ := tc.params.RingQ()
			rP := tc.params.RingP()
			recSk := rlwe.NewSecretKey(tc.params)
			for _, pi := range activeParties {
				pi.Combiner.Finalize(activeShamirPks, pi.tpk, pi.share, pi.tsk)
				rQ.Add(recSk.Q, pi.tsk.Q, recSk.Q)
				if rP != nil {
					rP.Add(recSk.P, pi.tsk.P, recSk.P)
				}
			}

			require.True(t, tc.skIdeal.Equal(recSk)) // reconstructed key should match the ideal sk
		})
	}
}

func testRefreshShare(tc *testContext, LevelQ, LevelP int, dd rlwe.DigitDecomposition, t *testing.T) {
	t.Run(testString(tc.params, "RefreshShare", LevelQ, LevelP, dd), func(t *testing.T) {
		p0 := *NewKeySwitchingShare(tc.params, 1, tc.params.MaxLevel())
		p1 := *NewKeySwitchingShare(tc.params, 1, tc.params.MaxLevel())
		source := sampling.NewSource([32]byte{})
		p0.Randomize(tc.params.RingQ(), tc.params.RingP(), source)
		p1.Randomize(tc.params.RingQ(), tc.params.RingP(), source)
		buffer.RequireSerializerCorrect(t, &RefreshShare{EncToShareShare: p0, ShareToEncShare: p1, MetaData: rlwe.MetaData{IsNTT: true}})
	})
}
