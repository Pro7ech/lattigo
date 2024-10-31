package mhefloat

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/mhe"
	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/bignum"
	"github.com/Pro7ech/lattigo/utils/sampling"
)

var flagParamString = flag.String("params", "", "specify the test cryptographic parameters as a JSON string. Overrides -short and -long.")
var printPrecisionStats = flag.Bool("print-precision", false, "print precision stats")

func GetTestName(opname string, parties int, params hefloat.Parameters) string {
	return fmt.Sprintf("%s/RingType=%s/logN=%d/logQP=%d/Qi=%d/Pi=%d/LogDefaultScale=%d/Parties=%d",
		opname,
		params.RingType(),
		params.LogN(),
		int(math.Round(params.LogQP())),
		params.QCount(),
		params.PCount(),
		int(math.Log2(params.DefaultScale().Float64())),
		parties)
}

type testContext struct {
	params   hefloat.Parameters
	nParties int

	ringQ ring.RNSRing

	encoder   *hefloat.Encoder
	evaluator *hefloat.Evaluator

	encryptor *rlwe.Encryptor
	decryptor *rlwe.Decryptor

	sk       *rlwe.SecretKey
	skShares []*rlwe.SecretKey
}

func TestMHEFloat(t *testing.T) {

	var err error

	var testParams []hefloat.ParametersLiteral
	switch {
	case *flagParamString != "": // the custom test suite reads the parameters from the -params flag
		testParams = append(testParams, hefloat.ParametersLiteral{})
		if err = json.Unmarshal([]byte(*flagParamString), &testParams[0]); err != nil {
			t.Fatal(err)
		}
	default:
		testParams = testParamsLiteral
	}

	for _, ringType := range []ring.Type{ring.Standard, ring.ConjugateInvariant} {

		for _, paramsLiteral := range testParams {

			paramsLiteral.RingType = ringType

			var params hefloat.Parameters
			if params, err = hefloat.NewParametersFromLiteral(paramsLiteral); err != nil {
				t.Fatal(err)
			}
			N := 3
			var tc *testContext
			if tc, err = genTestParams(params, N); err != nil {
				t.Fatal(err)
			}

			for _, testSet := range []func(tc *testContext, t *testing.T){
				testEncToShareProtocol,
				testRefresh,
			} {
				testSet(tc, t)
				runtime.GC()
			}
		}
	}
}

func genTestParams(params hefloat.Parameters, nParties int) (tc *testContext, err error) {

	tc = new(testContext)

	tc.params = params

	tc.nParties = nParties

	tc.ringQ = params.RingQ()

	tc.encoder = hefloat.NewEncoder(tc.params)
	tc.evaluator = hefloat.NewEvaluator(tc.params, nil)

	kgen := rlwe.NewKeyGenerator(tc.params)

	// SecretKeys
	tc.skShares = make([]*rlwe.SecretKey, nParties)
	tc.sk = rlwe.NewSecretKey(tc.params.Parameters)

	rQ := params.RingQ()
	rP := params.RingP()
	for j := 0; j < nParties; j++ {
		tc.skShares[j] = kgen.GenSecretKeyNew()
		rQ.Add(tc.sk.Q, tc.skShares[j].Q, tc.sk.Q)
		if rP != nil {
			rP.Add(tc.sk.P, tc.skShares[j].P, tc.sk.P)
		}
	}

	tc.encryptor = rlwe.NewEncryptor(tc.params, tc.sk)
	tc.decryptor = rlwe.NewDecryptor(tc.params, tc.sk)

	return
}

func testEncToShareProtocol(tc *testContext, t *testing.T) {

	params := tc.params

	t.Run(GetTestName("EncToShareProtocol", tc.nParties, params), func(t *testing.T) {

		var minLevel int
		var logBound uint
		var ok bool
		if minLevel, logBound, ok = GetMinimumLevelForRefresh(128, params.DefaultScale(), tc.nParties, params.Q()); ok != true || minLevel+1 > params.MaxLevel() {
			t.Skip("Not enough levels to ensure correctness and 128 security")
		}

		type Party struct {
			e2s            EncToShareProtocol
			s2e            ShareToEncProtocol
			sk             *rlwe.SecretKey
			publicShareE2S *mhe.KeySwitchingShare
			publicShareS2E *mhe.KeySwitchingShare
			secretShare    *mhe.AdditiveShareBigint
		}

		params := tc.params

		coeffs, _, ciphertext := newTestVectors(tc, tc.encryptor, -1, 1, params.LogMaxSlots())

		tc.evaluator.DropLevel(ciphertext, ciphertext.Level()-minLevel-1)

		P := make([]Party, tc.nParties)
		for i := range P {

			P[i].e2s = *NewEncToShareProtocol(params)
			P[i].s2e = *NewShareToEncProtocol(params)

			P[i].sk = tc.skShares[i]
			P[i].publicShareE2S = P[i].e2s.Allocate(minLevel)
			P[i].publicShareS2E = P[i].s2e.Allocate(params.MaxLevel())
			P[i].secretShare = NewAdditiveShare(params, ciphertext.LogSlots())
		}

		for i, p := range P {
			// Enc(-M_i)
			require.NoError(t, p.e2s.Gen(p.sk, logBound, ciphertext, p.secretShare, p.publicShareE2S))

			if i > 0 {
				// Enc(sum(-M_i))
				require.NoError(t, p.e2s.Aggregate(P[0].publicShareE2S, p.publicShareE2S, P[0].publicShareE2S))
			}
		}

		// sum(-M_i) + x
		require.NoError(t, P[0].e2s.Finalize(P[0].secretShare, P[0].publicShareE2S, ciphertext, P[0].secretShare))

		// sum(-M_i) + x + sum(M_i) = x
		rec := NewAdditiveShare(params, ciphertext.LogSlots())
		for _, p := range P {
			a := rec.Value
			b := p.secretShare.Value

			for i := range a {
				a[i].Add(&a[i], &b[i])
			}
		}

		pt := hefloat.NewPlaintext(params, ciphertext.Level())
		pt.IsNTT = false
		pt.Scale = ciphertext.Scale
		tc.ringQ.AtLevel(pt.Level()).SetCoefficientsBigint(rec.Value, pt.Q)

		hefloat.VerifyTestVectors(params, tc.encoder, nil, coeffs, pt, params.LogDefaultScale(), 0, *printPrecisionStats, t)

		seed := [32]byte{}

		for i, p := range P {
			require.NoError(t, p.s2e.Gen(p.sk, seed, ciphertext.MetaData, p.secretShare, p.publicShareS2E))
			if i > 0 {
				require.NoError(t, p.s2e.Aggregate(P[0].publicShareS2E, p.publicShareS2E, P[0].publicShareS2E))
			}
		}

		ctRec := hefloat.NewCiphertext(params, 1, params.MaxLevel())
		ctRec.Scale = params.DefaultScale()
		require.NoError(t, P[0].s2e.Finalize(P[0].publicShareS2E, ctRec))

		hefloat.VerifyTestVectors(params, tc.encoder, tc.decryptor, coeffs, ctRec, params.LogDefaultScale(), 0, *printPrecisionStats, t)
	})
}

func testRefresh(tc *testContext, t *testing.T) {

	paramsIn := tc.params

	// To get the precision of the linear transformations
	_, logBound, _ := GetMinimumLevelForRefresh(128, paramsIn.DefaultScale(), tc.nParties, paramsIn.Q())

	t.Run(GetTestName("N->N/Transform=nil", tc.nParties, paramsIn), func(t *testing.T) {
		testRefreshParameterized(tc, paramsIn, tc.skShares, nil, t)
	})

	t.Run(GetTestName("N->2N/Transform=nil", tc.nParties, paramsIn), func(t *testing.T) {

		var paramsOut hefloat.Parameters
		var err error
		paramsOut, err = hefloat.NewParametersFromLiteral(hefloat.ParametersLiteral{
			LogN:            paramsIn.LogN() + 1,
			LogQ:            []int{54, 54, 54, 49, 49, 49, 49, 49, 49},
			LogP:            []int{52, 52},
			RingType:        paramsIn.RingType(),
			LogDefaultScale: paramsIn.LogDefaultScale(),
		})

		require.NoError(t, err)

		kgenOut := rlwe.NewKeyGenerator(paramsOut)

		skOut := make([]*rlwe.SecretKey, tc.nParties)
		for i := range skOut {
			skOut[i] = kgenOut.GenSecretKeyNew()
		}

		testRefreshParameterized(tc, paramsOut, skOut, nil, t)
	})

	t.Run(GetTestName("2N->N/Transform=nil", tc.nParties, tc.params), func(t *testing.T) {

		var paramsOut hefloat.Parameters
		var err error
		paramsOut, err = hefloat.NewParametersFromLiteral(hefloat.ParametersLiteral{
			LogN:            paramsIn.LogN() - 1,
			LogQ:            []int{54, 54, 54, 49, 49, 49, 49, 49, 49},
			LogP:            []int{52, 52},
			RingType:        paramsIn.RingType(),
			LogDefaultScale: paramsIn.LogDefaultScale(),
		})

		require.NoError(t, err)

		kgenOut := rlwe.NewKeyGenerator(paramsOut)

		skOut := make([]*rlwe.SecretKey, tc.nParties)
		for i := range skOut {
			skOut[i] = kgenOut.GenSecretKeyNew()
		}

		testRefreshParameterized(tc, paramsOut, skOut, nil, t)
	})

	t.Run(GetTestName("N->N/Transform=true", tc.nParties, paramsIn), func(t *testing.T) {

		transform := &MaskedTransformFunc{
			Decode: true,
			Func: func(coeffs []bignum.Complex) {
				a := bignum.NewFloat(0.9238795325112867, logBound)
				b := bignum.NewFloat(0.7071067811865476, logBound)
				for i := range coeffs {
					coeffs[i][0].Mul(&coeffs[i][0], a)
					coeffs[i][1].Mul(&coeffs[i][1], b)
				}
			},
			Encode: true,
		}

		testRefreshParameterized(tc, paramsIn, tc.skShares, transform, t)
	})

	t.Run(GetTestName("N->2N/Transform=true", tc.nParties, paramsIn), func(t *testing.T) {

		var paramsOut hefloat.Parameters
		var err error
		paramsOut, err = hefloat.NewParametersFromLiteral(hefloat.ParametersLiteral{
			LogN:            paramsIn.LogN() + 1,
			LogQ:            []int{54, 54, 54, 49, 49, 49, 49, 49, 49},
			LogP:            []int{52, 52},
			RingType:        paramsIn.RingType(),
			LogDefaultScale: paramsIn.LogDefaultScale(),
		})

		require.NoError(t, err)

		kgenOut := rlwe.NewKeyGenerator(paramsOut)

		skOut := make([]*rlwe.SecretKey, tc.nParties)
		for i := range skOut {
			skOut[i] = kgenOut.GenSecretKeyNew()
		}

		transform := &MaskedTransformFunc{
			Decode: true,
			Func: func(coeffs []bignum.Complex) {
				a := bignum.NewFloat(0.9238795325112867, logBound)
				b := bignum.NewFloat(0.7071067811865476, logBound)
				for i := range coeffs {
					coeffs[i][0].Mul(&coeffs[i][0], a)
					coeffs[i][1].Mul(&coeffs[i][1], b)
				}
			},
			Encode: true,
		}

		testRefreshParameterized(tc, paramsOut, skOut, transform, t)
	})

	t.Run(GetTestName("2N->N/Transform=true", tc.nParties, tc.params), func(t *testing.T) {

		var paramsOut hefloat.Parameters
		var err error
		paramsOut, err = hefloat.NewParametersFromLiteral(hefloat.ParametersLiteral{
			LogN:            paramsIn.LogN() - 1,
			LogQ:            []int{54, 54, 54, 49, 49, 49, 49, 49, 49},
			LogP:            []int{52, 52},
			RingType:        paramsIn.RingType(),
			LogDefaultScale: paramsIn.LogDefaultScale(),
		})

		require.NoError(t, err)

		kgenOut := rlwe.NewKeyGenerator(paramsOut)

		skOut := make([]*rlwe.SecretKey, tc.nParties)
		for i := range skOut {
			skOut[i] = kgenOut.GenSecretKeyNew()
		}

		transform := &MaskedTransformFunc{
			Decode: true,
			Func: func(coeffs []bignum.Complex) {
				a := bignum.NewFloat(0.9238795325112867, logBound)
				b := bignum.NewFloat(0.7071067811865476, logBound)
				for i := range coeffs {
					coeffs[i][0].Mul(&coeffs[i][0], a)
					coeffs[i][1].Mul(&coeffs[i][1], b)
				}
			},
			Encode: true,
		}

		testRefreshParameterized(tc, paramsOut, skOut, transform, t)
	})
}

func testRefreshParameterized(tc *testContext, paramsOut hefloat.Parameters, skOut []*rlwe.SecretKey, transform *MaskedTransformFunc, t *testing.T) {

	var err error

	paramsIn := tc.params

	encIn := tc.encryptor

	skIdealOut := rlwe.NewSecretKey(paramsOut)
	for i := 0; i < tc.nParties; i++ {
		paramsOut.RingQ().Add(skIdealOut.Q, skOut[i].Q, skIdealOut.Q)
	}

	var minLevel int
	var logBound uint
	var ok bool
	if minLevel, logBound, ok = GetMinimumLevelForRefresh(128, paramsIn.DefaultScale(), tc.nParties, paramsIn.Q()); ok != true || minLevel+1 > paramsIn.MaxLevel() {
		t.Skip("Not enough levels to ensure correctness and 128 security")
	}

	type Party struct {
		MaskedTransformProtocol
		sIn   *rlwe.SecretKey
		sOut  *rlwe.SecretKey
		share *mhe.RefreshShare
	}

	coeffs, _, ciphertext := newTestVectors(tc, encIn, -1, 1, min(paramsIn.LogMaxSlots(), paramsOut.LogMaxSlots()))

	// Drops the ciphertext to the minimum level that ensures correctness and 128-bit security
	tc.evaluator.DropLevel(ciphertext, ciphertext.Level()-minLevel-1)

	levelIn := minLevel

	require.Nil(t, err)

	levelOut := paramsOut.MaxLevel()

	RefreshParties := make([]*Party, tc.nParties)

	for i := 0; i < tc.nParties; i++ {
		p := new(Party)

		if i == 0 {
			p.MaskedTransformProtocol = *NewMaskedTransformProtocol(paramsIn, paramsOut, logBound)
		} else {
			p.MaskedTransformProtocol = *RefreshParties[0].ShallowCopy()
		}

		p.sIn = tc.skShares[i]
		p.sOut = skOut[i]

		p.share = p.Allocate(levelIn, levelOut)
		RefreshParties[i] = p
	}

	P0 := RefreshParties[0]
	seed := [32]byte{}

	for i, p := range RefreshParties {
		require.NoError(t, p.Gen(p.sIn, p.sOut, logBound, ciphertext, seed, transform, p.share))
		if i > 0 {
			require.NoError(t, P0.Aggregate(p.share, P0.share, P0.share))
		}
	}

	require.NoError(t, P0.Finalize(ciphertext, transform, P0.share, ciphertext))

	// Applies transform in plaintext

	if transform != nil {
		transform.Func(coeffs)
	}

	hefloat.VerifyTestVectors(paramsOut, hefloat.NewEncoder(paramsOut), rlwe.NewDecryptor(paramsOut, skIdealOut), coeffs, ciphertext, paramsOut.LogDefaultScale(), 0, *printPrecisionStats, t)
}

func newTestVectors(tc *testContext, encryptor *rlwe.Encryptor, a, b complex128, logSlots int) (values []bignum.Complex, plaintext *rlwe.Plaintext, ciphertext *rlwe.Ciphertext) {
	return newTestVectorsAtScale(tc, encryptor, a, b, tc.params.DefaultScale(), logSlots)
}

func newTestVectorsAtScale(tc *testContext, encryptor *rlwe.Encryptor, a, b complex128, scale rlwe.Scale, logSlots int) (values []bignum.Complex, pt *rlwe.Plaintext, ct *rlwe.Ciphertext) {

	prec := tc.encoder.Prec()

	pt = hefloat.NewPlaintext(tc.params, tc.params.MaxLevel())
	pt.Scale = scale
	pt.LogDimensions.Cols = logSlots

	values = make([]bignum.Complex, pt.Slots())

	r := sampling.NewSource(sampling.NewSeed())

	switch tc.params.RingType() {
	case ring.Standard:
		for i := range values {
			values[i].SetPrec(prec)
			values[i][0].SetFloat64(r.Float64(real(a), real(b)))
			values[i][1].SetFloat64(r.Float64(imag(a), imag(b)))
		}
	case ring.ConjugateInvariant:
		for i := range values {
			values[i].SetPrec(prec)
			values[i][0].SetFloat64(r.Float64(real(a), real(b)))
		}
	default:
		panic("invalid ring type")
	}

	if err := tc.encoder.Encode(values, pt); err != nil {
		panic(err)
	}

	if encryptor != nil {
		ct = hefloat.NewCiphertext(tc.params, 1, pt.Level())
		if err := encryptor.Encrypt(pt, ct); err != nil {
			panic(err)
		}
	}

	return values, pt, ct
}
