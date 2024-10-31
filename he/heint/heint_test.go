package heint_test

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
	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/sampling"
	"github.com/stretchr/testify/require"
)

var flagPrintNoise = flag.Bool("print-noise", false, "print the residual noise")
var flagParamString = flag.String("params", "", "specify the test cryptographic parameters as a JSON string. Overrides -short.")

func GetTestName(opname string, p heint.Parameters, lvl int) string {
	return fmt.Sprintf("%s/LogN=%d/logQ=%d/logP=%d/LogSlots=%dx%d/logT=%d/Qi=%d/Pi=%d/lvl=%d",
		opname,
		p.LogN(),
		int(math.Round(p.LogQ())),
		int(math.Round(p.LogP())),
		p.LogMaxDimensions().Rows,
		p.LogMaxDimensions().Cols,
		int(math.Round(p.LogPlaintextModulus())),
		p.QCount(),
		p.PCount(),
		lvl)
}

func TestHEInt(t *testing.T) {

	var err error

	// insecure parameters used for the sole purpose of fast testing.
	paramsLiterals := heint.ParametersLiteral{
		LogN: 10,
		LogQ: []int{60, 60, 60, 60, 60},
		LogP: []int{61},
	}

	basePlaintextModulus := []uint64{0x101, 0xffc001}
	basePlaintextModulusPower := []int{1, 2}

	if *flagParamString != "" {
		var jsonParams heint.ParametersLiteral
		if err = json.Unmarshal([]byte(*flagParamString), &jsonParams); err != nil {
			t.Fatal(err)
		}
		paramsLiterals = jsonParams // the custom test suite reads the parameters from the -params flag
	}

	for _, T := range basePlaintextModulus[:] {
		for _, R := range basePlaintextModulusPower[:] {

			paramsLiterals.T = T
			paramsLiterals.R = R

			var params heint.Parameters
			if params, err = heint.NewParametersFromLiteral(paramsLiterals); err != nil {
				t.Error(err)
				t.Fail()
			}

			var tc *testContext
			if tc, err = genTestParams(params); err != nil {
				t.Error(err)
				t.Fail()
			}

			for _, testSet := range []func(tc *testContext, t *testing.T){
				testParameters,
				testEncoder,
				testEvaluator,
				testLinearTransformation,
				testPolynomialEvaluator,
			} {
				testSet(tc, t)
				runtime.GC()
			}
		}
	}
}

type testContext struct {
	params      heint.Parameters
	rQ          ring.RNSRing
	rT          *ring.Ring
	encoder     *heint.Encoder
	kgen        *rlwe.KeyGenerator
	sk          *rlwe.SecretKey
	pk          *rlwe.PublicKey
	encryptorPk *rlwe.Encryptor
	encryptorSk *rlwe.Encryptor
	decryptor   *rlwe.Decryptor
	evaluator   *heint.Evaluator
	testLevel   []int
}

func genTestParams(params heint.Parameters) (tc *testContext, err error) {

	tc = new(testContext)
	tc.params = params

	tc.rQ = params.RingQ()
	tc.rT = params.RT

	tc.kgen = rlwe.NewKeyGenerator(tc.params)
	tc.sk, tc.pk = tc.kgen.GenKeyPairNew()
	tc.encoder = heint.NewEncoder(tc.params)

	tc.encryptorPk = rlwe.NewEncryptor(tc.params, tc.pk)
	tc.encryptorSk = rlwe.NewEncryptor(tc.params, tc.sk)
	tc.decryptor = rlwe.NewDecryptor(tc.params, tc.sk)
	tc.evaluator = heint.NewEvaluator(tc.params, rlwe.NewMemEvaluationKeySet(tc.kgen.GenRelinearizationKeyNew(tc.sk)))

	tc.testLevel = []int{0, params.MaxLevel()}

	return
}

func newTestVectorsLvl(level int, scale rlwe.Scale, tc *testContext, encryptor *rlwe.Encryptor) (coeffs []uint64, plaintext *rlwe.Plaintext, ciphertext *rlwe.Ciphertext) {

	r := rand.New(sampling.NewSource(sampling.NewSeed()))
	//T := tc.params.PlaintextModulus()
	_ = r

	coeffs = make([]uint64, tc.params.MaxSlots())
	for i := range coeffs {
		coeffs[i] = uint64(i)
	}

	plaintext = heint.NewPlaintext(tc.params, level)
	plaintext.Scale = scale
	tc.encoder.Encode(coeffs, plaintext)
	if encryptor != nil {
		ciphertext = heint.NewCiphertext(tc.params, 1, plaintext.Level())
		if err := encryptor.Encrypt(plaintext, ciphertext); err != nil {
			panic(err)
		}
	}

	return coeffs, plaintext, ciphertext
}

func verifyTestVectors(tc *testContext, decryptor *rlwe.Decryptor, want []uint64, element rlwe.Element, t *testing.T) {

	have := make([]uint64, tc.params.MaxSlots())

	switch el := element.(type) {
	case *rlwe.Plaintext:
		require.NoError(t, tc.encoder.Decode(el, have))
	case *rlwe.Ciphertext:

		pt := decryptor.DecryptNew(el)

		require.NoError(t, tc.encoder.Decode(pt, have))

		if *flagPrintNoise {
			require.NoError(t, tc.encoder.Encode(have, pt))
			ct, err := tc.evaluator.SubNew(el, pt)
			require.NoError(t, err)
			vartmp, _, _ := rlwe.Norm(ct, decryptor)
			t.Logf("STD(noise): %f\n", vartmp)
		}

	default:
		t.Error("invalid test object to verify")
	}

	/*
		for i := range want[:]{
			fmt.Printf("%3d - %3d - %3d\n", i, want[i], have[i])
		}
	*/

	require.True(t, slices.Equal(want, have))
}
