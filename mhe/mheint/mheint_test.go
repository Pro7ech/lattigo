package mheint

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"

	"math/rand/v2"
	"runtime"
	"slices"
	"testing"

	"github.com/Pro7ech/lattigo/he/heint"
	"github.com/Pro7ech/lattigo/mhe"
	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"

	"github.com/Pro7ech/lattigo/utils/sampling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var flagParamString = flag.String("params", "", "specify the test cryptographic parameters as a JSON string. Overrides -short and -long.")

func GetTestName(opname string, p heint.Parameters, parties int) string {
	return fmt.Sprintf("%s/LogN=%d/logQ=%d/logP=%d/LogSlots=%dx%d/logT=%d/Qi=%d/Pi=%d/parties=%d",
		opname,
		p.LogN(),
		int(math.Round(p.LogQ())),
		int(math.Round(p.LogP())),
		p.LogMaxDimensions().Rows,
		p.LogMaxDimensions().Cols,
		int(math.Round(p.LogPlaintextModulus())),
		p.QCount(),
		p.PCount(),
		parties)
}

type testContext struct {
	params heint.Parameters

	// Number of parties
	NParties int

	// Polynomial degree
	n int

	// Polynomial contexts
	rT *ring.Ring

	encoder *heint.Encoder

	skShares []*rlwe.SecretKey

	encryptor *rlwe.Encryptor
	decryptor *rlwe.Decryptor
	evaluator *heint.Evaluator
}

func TestInteger(t *testing.T) {

	var err error

	paramsLiterals := testParams

	if *flagParamString != "" {
		var jsonParams heint.ParametersLiteral
		if err = json.Unmarshal([]byte(*flagParamString), &jsonParams); err != nil {
			t.Fatal(err)
		}
		paramsLiterals = []heint.ParametersLiteral{jsonParams} // the custom test suite reads the parameters from the -params flag
	}

	for _, p := range paramsLiterals {

		for _, T := range testPlaintextModulus[:1] {

			p.T = T
			p.R = 1

			var params heint.Parameters
			if params, err = heint.NewParametersFromLiteral(p); err != nil {
				t.Fatal(err)
			}

			nParties := 3

			var tc *testContext
			if tc, err = gentestContext(nParties, params); err != nil {
				t.Fatal(err)
			}
			for _, testSet := range []func(tc *testContext, t *testing.T){
				testEncToShares,
				testRefresh,
				testRefreshAndPermutation,
				testRefreshAndTransformSwitchParams,
			} {
				testSet(tc, t)
				runtime.GC()
			}
		}
	}
}

func gentestContext(nParties int, params heint.Parameters) (tc *testContext, err error) {

	tc = new(testContext)

	tc.params = params

	tc.NParties = nParties

	tc.n = params.N()

	tc.rT = params.RT

	tc.encoder = heint.NewEncoder(tc.params)
	tc.evaluator = heint.NewEvaluator(tc.params, nil)

	kgen := rlwe.NewKeyGenerator(tc.params)

	// SecretKeys
	tc.skShares = make([]*rlwe.SecretKey, nParties)

	sk := rlwe.NewSecretKey(tc.params.Parameters)

	rQ := params.RingQ()
	rP := params.RingP()
	for j := 0; j < nParties; j++ {
		tc.skShares[j] = kgen.GenSecretKeyNew()
		rQ.Add(sk.Q, tc.skShares[j].Q, sk.Q)

		if rP != nil {
			rP.Add(sk.P, tc.skShares[j].P, sk.P)
		}
	}

	tc.encryptor = rlwe.NewEncryptor(tc.params, sk)
	tc.decryptor = rlwe.NewDecryptor(tc.params, sk)

	return
}

func testEncToShares(tc *testContext, t *testing.T) {

	coeffs, _, ciphertext := newTestVectors(tc, tc.encryptor, t)

	type Party struct {
		e2s         EncToShareProtocol
		s2e         ShareToEncProtocol
		sk          *rlwe.SecretKey
		publicShare *mhe.KeySwitchingShare
		secretShare *mhe.AdditiveShare
	}

	params := tc.params
	P := make([]Party, tc.NParties)

	for i := range P {
		if i == 0 {
			P[i].e2s = *NewEncToShareProtocol(params)
			P[i].s2e = *NewShareToEncProtocol(params)
		} else {
			P[i].e2s = *P[0].e2s.ShallowCopy()
			P[i].s2e = *P[0].s2e.ShallowCopy()
		}

		P[i].sk = tc.skShares[i]
		P[i].publicShare = P[i].e2s.Allocate(ciphertext.Level())
		P[i].secretShare = NewAdditiveShare(params)
	}

	// The EncToShare protocol is run in all tests, as a setup to the ShareToEnc test.
	for i, p := range P {
		require.NoError(t, p.e2s.Gen(p.sk, ciphertext, p.secretShare, p.publicShare))
		if i > 0 {
			require.NoError(t, p.e2s.Aggregate(P[0].publicShare, p.publicShare, P[0].publicShare))
		}
	}

	P[0].e2s.Finalize(P[0].secretShare, P[0].publicShare, ciphertext, P[0].secretShare)

	t.Run(GetTestName("EncToShareProtocol", tc.params, tc.NParties), func(t *testing.T) {

		rec := NewAdditiveShare(params)
		for _, p := range P {
			tc.rT.Add(rec.Value, p.secretShare.Value, rec.Value)
		}

		ptRt := make([]uint64, params.MaxSlots())
		copy(ptRt, rec.Value)

		values := make([]uint64, len(coeffs))
		tc.encoder.DecodeRingT(ptRt, ciphertext.Scale, values)

		assert.True(t, slices.Equal(coeffs, values))
	})

	t.Run(GetTestName("ShareToEncProtocol", tc.params, tc.NParties), func(t *testing.T) {

		seed := [32]byte{}

		for i, p := range P {
			require.NoError(t, p.s2e.Gen(p.sk, seed, p.secretShare, p.publicShare))
			if i > 0 {
				require.NoError(t, p.s2e.Aggregate(P[0].publicShare, p.publicShare, P[0].publicShare))
			}
		}

		ctRec := heint.NewCiphertext(tc.params, 1, tc.params.MaxLevel())
		*ctRec.MetaData = *ciphertext.MetaData
		require.NoError(t, P[0].s2e.Finalize(P[0].publicShare, ctRec))

		verifyTestVectors(tc, tc.decryptor, coeffs, ctRec, t)
	})
}

func testRefresh(tc *testContext, t *testing.T) {

	encryptor := tc.encryptor
	skShares := tc.skShares
	encoder := tc.encoder
	decryptor := tc.decryptor

	minLevel := 0
	maxLevel := tc.params.MaxLevel()

	t.Run(GetTestName("Refresh", tc.params, tc.NParties), func(t *testing.T) {

		type Party struct {
			RefreshProtocol
			s     *rlwe.SecretKey
			share *mhe.RefreshShare
		}

		RefreshParties := make([]*Party, tc.NParties)
		for i := 0; i < tc.NParties; i++ {
			p := new(Party)
			if i == 0 {
				p.RefreshProtocol = *NewRefreshProtocol(tc.params)
			} else {
				p.RefreshProtocol = *RefreshParties[0].RefreshProtocol.ShallowCopy()
			}

			p.s = skShares[i]
			p.share = p.Allocate(minLevel, maxLevel)
			RefreshParties[i] = p
		}

		P0 := RefreshParties[0]

		seed := [32]byte{}

		coeffs, _, ciphertext := newTestVectors(tc, encryptor, t)
		ciphertext.ResizeQ(minLevel)

		for i, p := range RefreshParties {
			require.NoError(t, p.Gen(p.s, ciphertext, seed, p.share))
			if i > 0 {
				require.NoError(t, P0.Aggregate(p.share, P0.share, P0.share))
			}
		}

		require.NoError(t, P0.Finalize(ciphertext, P0.share, ciphertext))

		//Decrypts and compare
		require.True(t, ciphertext.Level() == maxLevel)
		have := make([]uint64, tc.params.MaxSlots())
		encoder.Decode(decryptor.DecryptNew(ciphertext), have)
		require.True(t, slices.Equal(coeffs, have))
	})
}

func testRefreshAndPermutation(tc *testContext, t *testing.T) {

	encryptor := tc.encryptor
	skShares := tc.skShares
	encoder := tc.encoder
	decryptor := tc.decryptor

	minLevel := 0
	maxLevel := tc.params.MaxLevel()

	t.Run(GetTestName("RefreshAndPermutation", tc.params, tc.NParties), func(t *testing.T) {

		type Party struct {
			MaskedTransformProtocol
			s     *rlwe.SecretKey
			share *mhe.RefreshShare
		}

		RefreshParties := make([]*Party, tc.NParties)
		for i := 0; i < tc.NParties; i++ {
			p := new(Party)
			if i == 0 {
				p.MaskedTransformProtocol = *NewMaskedTransformProtocol(tc.params, tc.params)
			} else {
				p.MaskedTransformProtocol = *RefreshParties[0].ShallowCopy()
			}

			p.s = skShares[i]
			p.share = p.Allocate(minLevel, maxLevel)
			RefreshParties[i] = p
		}

		P0 := RefreshParties[0]

		seed := [32]byte{}

		coeffs, _, ciphertext := newTestVectors(tc, encryptor, t)
		ciphertext.ResizeQ(minLevel)

		permutation := make([]uint64, len(coeffs))
		N := uint64(len(coeffs))
		r := rand.New(sampling.NewSource(sampling.NewSeed()))
		for i := range permutation {
			permutation[i] = r.Uint64N(N)
		}

		permute := func(coeffs []uint64) {
			coeffsPerm := make([]uint64, len(coeffs))
			for i := range coeffs {
				coeffsPerm[i] = coeffs[permutation[i]]
			}
			copy(coeffs, coeffsPerm)
		}

		maskedTransform := &MaskedTransformFunc{
			Decode: true,
			Func:   permute,
			Encode: true,
		}

		for i, p := range RefreshParties {
			require.NoError(t, p.Gen(p.s, p.s, ciphertext, seed, maskedTransform, p.share))
			if i > 0 {
				require.NoError(t, P0.Aggregate(P0.share, p.share, P0.share))
			}
		}

		require.NoError(t, P0.Finalize(ciphertext, maskedTransform, P0.share, ciphertext))

		coeffsPermute := make([]uint64, len(coeffs))
		for i := range coeffsPermute {
			coeffsPermute[i] = coeffs[permutation[i]]
		}

		coeffsHave := make([]uint64, tc.params.MaxSlots())
		encoder.Decode(decryptor.DecryptNew(ciphertext), coeffsHave)

		//Decrypts and compares
		require.True(t, ciphertext.Level() == maxLevel)
		require.True(t, slices.Equal(coeffsPermute, coeffsHave))
	})
}

func testRefreshAndTransformSwitchParams(tc *testContext, t *testing.T) {

	encryptor := tc.encryptor
	skShares := tc.skShares
	paramsIn := tc.params

	t.Run(GetTestName("RefreshAndTransformSwitchparams", tc.params, tc.NParties), func(t *testing.T) {

		var paramsOut heint.Parameters
		var err error
		paramsOut, err = heint.NewParametersFromLiteral(heint.ParametersLiteral{
			LogN: paramsIn.LogN(),
			LogQ: []int{54, 49, 49, 49},
			LogP: []int{52, 52},
			T:    paramsIn.BasePlaintextModulus(),
			R:    paramsIn.BasePlaintextModulusPower(),
		})

		minLevel := 0
		maxLevel := paramsOut.MaxLevel()

		require.Nil(t, err)

		type Party struct {
			MaskedTransformProtocol
			sIn   *rlwe.SecretKey
			sOut  *rlwe.SecretKey
			share *mhe.RefreshShare
		}

		RefreshParties := make([]*Party, tc.NParties)
		kgenParamsOut := rlwe.NewKeyGenerator(paramsOut.Parameters)
		skIdealOut := rlwe.NewSecretKey(paramsOut.Parameters)
		for i := 0; i < tc.NParties; i++ {
			p := new(Party)
			if i == 0 {
				p.MaskedTransformProtocol = *NewMaskedTransformProtocol(paramsIn, paramsOut)
			} else {
				p.MaskedTransformProtocol = *RefreshParties[0].ShallowCopy()
			}

			p.sIn = skShares[i]

			p.sOut = kgenParamsOut.GenSecretKeyNew() // New shared secret key in target parameters
			paramsOut.RingQ().Add(skIdealOut.Q, p.sOut.Q, skIdealOut.Q)

			p.share = p.Allocate(minLevel, maxLevel)

			RefreshParties[i] = p
		}

		P0 := RefreshParties[0]

		seed := [32]byte{}

		coeffs, _, ciphertext := newTestVectors(tc, encryptor, t)

		permutation := make([]uint64, len(coeffs))
		N := uint64(len(coeffs))
		r := rand.New(sampling.NewSource(sampling.NewSeed()))
		for i := range permutation {
			permutation[i] = r.Uint64N(N)
		}

		transform := &MaskedTransformFunc{
			Decode: true,
			Func: func(coeffs []uint64) {
				coeffsPerm := make([]uint64, len(coeffs))
				for i := range coeffs {
					coeffsPerm[i] = coeffs[permutation[i]]
				}
				copy(coeffs, coeffsPerm)
			},
			Encode: true,
		}

		for i, p := range RefreshParties {
			require.NoError(t, p.Gen(p.sIn, p.sOut, ciphertext, seed, transform, p.share))
			if i > 0 {
				require.NoError(t, P0.Aggregate(P0.share, p.share, P0.share))
			}
		}

		require.NoError(t, P0.Finalize(ciphertext, transform, P0.share, ciphertext))

		transform.Func(coeffs)

		coeffsHave := make([]uint64, tc.params.MaxSlots())
		dec := rlwe.NewDecryptor(paramsOut.Parameters, skIdealOut)
		heint.NewEncoder(paramsOut).Decode(dec.DecryptNew(ciphertext), coeffsHave)

		//Decrypts and compares
		require.True(t, ciphertext.Level() == maxLevel)
		require.True(t, slices.Equal(coeffs, coeffsHave))
	})
}

func newTestVectors(tc *testContext, encryptor *rlwe.Encryptor, t *testing.T) (coeffs []uint64, plaintext *rlwe.Plaintext, ciphertext *rlwe.Ciphertext) {

	coeffs = make([]uint64, tc.params.MaxSlots())
	for i := range coeffs {
		coeffs[i] = uint64(i)
	}

	var err error

	plaintext = heint.NewPlaintext(tc.params, tc.params.MaxLevel())
	plaintext.Scale = tc.params.NewScale(2)
	require.NoError(t, tc.encoder.Encode(coeffs, plaintext))
	ciphertext = heint.NewCiphertext(tc.params, 1, plaintext.Level())
	if encryptor.Encrypt(plaintext, ciphertext); err != nil {
		panic(err)
	}
	return coeffs, plaintext, ciphertext
}

func verifyTestVectors(tc *testContext, decryptor *rlwe.Decryptor, coeffs []uint64, ciphertext *rlwe.Ciphertext, t *testing.T) {
	have := make([]uint64, tc.params.MaxSlots())
	tc.encoder.Decode(decryptor.DecryptNew(ciphertext), have)
	require.True(t, slices.Equal(coeffs, have))
}
