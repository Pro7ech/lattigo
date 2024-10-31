package hefloat_test

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"math/big"
	"runtime"
	"testing"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/bignum"
	"github.com/Pro7ech/lattigo/utils/sampling"
	"github.com/stretchr/testify/require"
)

var flagParamString = flag.String("params", "", "specify the test cryptographic parameters as a JSON string. Overrides -short and -long.")
var printPrecisionStats = flag.Bool("print-precision", false, "print precision stats")

func GetTestName(params hefloat.Parameters, opname string) string {
	return fmt.Sprintf("%s/RingType=%s/logN=%d/logQP=%d/Qi=%d/Pi=%d/LogScale=%d",
		opname,
		params.RingType(),
		params.LogN(),
		int(math.Round(params.LogQP())),
		params.QCount(),
		params.PCount(),
		int(math.Log2(params.DefaultScale().Float64())))
}

type testContext struct {
	params      hefloat.Parameters
	ringQ       ring.RNSRing
	ringP       ring.RNSRing
	encoder     *hefloat.Encoder
	kgen        *rlwe.KeyGenerator
	sk          *rlwe.SecretKey
	pk          *rlwe.PublicKey
	encryptorPk *rlwe.Encryptor
	encryptorSk *rlwe.Encryptor
	decryptor   *rlwe.Decryptor
	evaluator   *hefloat.Evaluator
}

var (

	// testInsecurePrec45 are insecure parameters used for the sole purpose of fast testing.
	testInsecurePrec45 = hefloat.ParametersLiteral{
		LogN:            10,
		LogQ:            []int{55, 45, 45, 45, 45, 45, 45},
		LogP:            []int{60},
		LogDefaultScale: 45,
	}

	// testInsecurePrec90 are insecure parameters used for the sole purpose of fast testing.
	testInsecurePrec90 = hefloat.ParametersLiteral{
		LogN:            10,
		LogQ:            []int{55, 55, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45},
		LogP:            []int{60, 60},
		LogDefaultScale: 90,
	}

	testParametersLiteral = []hefloat.ParametersLiteral{testInsecurePrec45, testInsecurePrec90}
)

func TestHEFloat(t *testing.T) {

	var err error

	var testParams []hefloat.ParametersLiteral
	switch {
	case *flagParamString != "": // the custom test suite reads the parameters from the -params flag
		testParams = append(testParams, hefloat.ParametersLiteral{})
		if err = json.Unmarshal([]byte(*flagParamString), &testParams[0]); err != nil {
			t.Fatal(err)
		}
	default:
		testParams = testParametersLiteral
	}

	for _, ringType := range []ring.Type{ring.Standard, ring.ConjugateInvariant} {

		for _, paramsLiteral := range testParams {

			paramsLiteral.RingType = ringType

			if testing.Short() {
				paramsLiteral.LogN = 10
			}

			var params hefloat.Parameters
			if params, err = hefloat.NewParametersFromLiteral(paramsLiteral); err != nil {
				t.Fatal(err)
			}

			var tc *testContext
			if tc, err = genTestParams(params); err != nil {
				t.Fatal(err)
			}

			for _, testSet := range []func(tc *testContext, t *testing.T){
				testParameters,
				testEncoder,
				testEvaluatorAdd,
				testEvaluatorSub,
				testEvaluatorRescale,
				testEvaluatorMul,
				testEvaluatorMulThenAdd,
				testBridge,
				testLinearTransformation,
				testPolynomialEvaluator,
				testComparisons,
				testinverse,
			} {
				testSet(tc, t)
				runtime.GC()
			}
		}
	}

	testDFTEvaluator(t)
	testMod1(t)
}

func genTestParams(defaultParam hefloat.Parameters) (tc *testContext, err error) {

	tc = new(testContext)

	tc.params = defaultParam

	tc.kgen = rlwe.NewKeyGenerator(tc.params)

	tc.sk, tc.pk = tc.kgen.GenKeyPairNew()

	tc.ringQ = defaultParam.RingQ()
	if tc.params.PCount() != 0 {
		tc.ringP = defaultParam.RingP()
	}

	tc.encoder = hefloat.NewEncoder(tc.params)

	tc.encryptorPk = rlwe.NewEncryptor(tc.params, tc.pk)
	tc.encryptorSk = rlwe.NewEncryptor(tc.params, tc.sk)
	tc.decryptor = rlwe.NewDecryptor(tc.params, tc.sk)
	tc.evaluator = hefloat.NewEvaluator(tc.params, rlwe.NewMemEvaluationKeySet(tc.kgen.GenRelinearizationKeyNew(tc.sk)))

	return tc, nil

}

func newTestVectors(tc *testContext, encryptor *rlwe.Encryptor, a, b complex128, t *testing.T) (values []bignum.Complex, pt *rlwe.Plaintext, ct *rlwe.Ciphertext) {

	prec := tc.encoder.Prec()

	pt = hefloat.NewPlaintext(tc.params, tc.params.MaxLevel())

	r := sampling.NewSource([32]byte{})

	values = make([]bignum.Complex, pt.Slots())

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
		t.Fatal("invalid ring type")
	}

	require.NoError(t, tc.encoder.Encode(values, pt))

	if encryptor != nil {
		ct = hefloat.NewCiphertext(tc.params, 1, pt.Level())
		require.NoError(t, encryptor.Encrypt(pt, ct))
	}

	return values, pt, ct
}

func randomConst(tp ring.Type, prec uint, a, b complex128) (constant *bignum.Complex) {

	r := sampling.NewSource(sampling.NewSeed())

	switch tp {
	case ring.Standard:
		constant = &bignum.Complex{
			*bignum.NewFloat(r.Float64(real(a), real(b)), prec),
			*bignum.NewFloat(r.Float64(imag(a), imag(b)), prec),
		}
	case ring.ConjugateInvariant:
		constant = &bignum.Complex{
			*bignum.NewFloat(r.Float64(real(a), real(b)), prec),
			*new(big.Float),
		}
	default:
		panic("invalid ring type")
	}
	return
}
