package bootstrapping

import (
	"flag"
	"math"
	"testing"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils"
	"github.com/Pro7ech/lattigo/utils/buffer"
	"github.com/Pro7ech/lattigo/utils/sampling"

	"github.com/stretchr/testify/require"
)

var flagLongTest = flag.Bool("long", false, "run the long test suite (all parameters + secure bootstrapping). Overrides -short and requires -timeout=0.")
var printPrecisionStats = flag.Bool("print-precision", false, "print precision stats")

func TestParametersMarshalling(t *testing.T) {
	paramsLit := NewParametersLiteral()
	buffer.RequireSerializerCorrect(t, &paramsLit)
}

func TestBootstrappingDefaultFullPacking(t *testing.T) {

	schemeParamsLit := hefloat.ParametersLiteral{
		LogN:            10,
		LogQ:            []int{60, 40},
		LogP:            []int{61},
		LogDefaultScale: 40,
	}

	if *flagLongTest {
		schemeParamsLit.LogN = 16
	}

	params, err := hefloat.NewParametersFromLiteral(schemeParamsLit)
	require.Nil(t, err)

	btpParamsLit := NewParametersLiteral()
	btpParamsLit.LogN = params.LogN()
	btpParamsLit.LogSlots = params.LogN() - 1

	// Insecure params for fast testing only
	if !*flagLongTest {
		// Corrects the message ratio to take into account the smaller number of slots and keep the same precision
		btpParamsLit.LogMessageRatio += 16 - params.LogN()
	}

	btpParams, err := NewParametersFromLiteral(params, btpParamsLit)
	require.Nil(t, err)

	t.Logf("Scheme: LogN=%d/LogSlots=%d/LogQP=%f", btpParams.ResidualParameters.LogN(), btpParams.ResidualParameters.LogMaxSlots(), btpParams.ResidualParameters.LogQP())
	t.Logf("Bootstrapping: LogN=%d/LogSlots=%d/LogQP=%f", btpParams.BootstrappingParameters.LogN(), btpParams.BootstrappingParameters.LogMaxSlots(), btpParams.BootstrappingParameters.LogQP())

	sk := rlwe.NewKeyGenerator(btpParams.BootstrappingParameters).GenSecretKeyNew()

	btpKeys, _, err := btpParams.GenEvaluationKeys(sk)
	require.NoError(t, err)

	evaluator, err := NewEvaluator(btpParams, btpKeys)
	require.NoError(t, err)

	ecd := hefloat.NewEncoder(params)
	enc := rlwe.NewEncryptor(params, sk)
	dec := rlwe.NewDecryptor(params, sk)

	r := sampling.NewSource([32]byte{})

	values := make([]complex128, params.MaxSlots())
	for i := range values {
		values[i] = r.Complex128(-1-1i, 1+1i)
	}

	plaintext := hefloat.NewPlaintext(params, 0)
	ecd.Encode(values, plaintext)

	ctQ0 := hefloat.NewCiphertext(params, 1, plaintext.Level())
	require.NoError(t, enc.Encrypt(plaintext, ctQ0))

	// Checks that the input ciphertext is at the level 0
	require.True(t, ctQ0.Level() == 0)

	// Bootstrapps the ciphertext
	ctQL, err := evaluator.Bootstrap(ctQ0)
	require.NoError(t, err)

	// Checks that the output ciphertext is at the max level of paramsN1
	require.True(t, ctQL.Level() == params.MaxLevel())
	require.True(t, ctQL.Scale.Equal(params.DefaultScale()))

	verifyTestVectorsBootstrapping(params, ecd, dec, values, ctQL, t)
}

func TestBootstrappingDefaultSparsePacking(t *testing.T) {

	schemeParamsLit := hefloat.ParametersLiteral{
		LogN:            10,
		LogQ:            []int{60, 40},
		LogP:            []int{61},
		LogDefaultScale: 40,
	}

	if *flagLongTest {
		schemeParamsLit.LogN = 16
	}

	params, err := hefloat.NewParametersFromLiteral(schemeParamsLit)
	require.Nil(t, err)

	LogSlots := params.LogN() - 1

	btpParamsLit := NewParametersLiteral()
	btpParamsLit.LogN = params.LogN()
	btpParamsLit.LogSlots = LogSlots

	// Insecure params for fast testing only
	if !*flagLongTest {
		// Corrects the message ratio to take into account the smaller number of slots and keep the same precision
		btpParamsLit.LogMessageRatio += 16 - params.LogN()
	}

	btpParams, err := NewParametersFromLiteral(params, btpParamsLit)
	require.Nil(t, err)

	t.Logf("Scheme: LogN=%d/LogSlots=%d/LogQP=%f", btpParams.ResidualParameters.LogN(), btpParams.ResidualParameters.LogMaxSlots(), btpParams.ResidualParameters.LogQP())
	t.Logf("Bootstrapping: LogN=%d/LogSlots=%d/LogQP=%f", btpParams.BootstrappingParameters.LogN(), btpParams.BootstrappingParameters.LogMaxSlots(), btpParams.BootstrappingParameters.LogQP())

	sk := rlwe.NewKeyGenerator(btpParams.BootstrappingParameters).GenSecretKeyNew()

	btpKeys, _, err := btpParams.GenEvaluationKeys(sk)
	require.NoError(t, err)

	evaluator, err := NewEvaluator(btpParams, btpKeys)
	require.NoError(t, err)

	ecd := hefloat.NewEncoder(params)
	enc := rlwe.NewEncryptor(params, sk)
	dec := rlwe.NewDecryptor(params, sk)

	r := sampling.NewSource([32]byte{})

	values := make([]complex128, 1<<LogSlots)
	for i := range values {
		values[i] = r.Complex128(-1-1i, 1+1i)
	}

	plaintext := hefloat.NewPlaintext(params, 0)
	ecd.Encode(values, plaintext)

	ctQ0 := hefloat.NewCiphertext(params, 1, plaintext.Level())
	require.NoError(t, enc.Encrypt(plaintext, ctQ0))

	// Checks that the input ciphertext is at the level 0
	require.True(t, ctQ0.Level() == 0)

	// Bootstrapps the ciphertext
	ctQL, err := evaluator.Bootstrap(ctQ0)
	require.NoError(t, err)

	// Checks that the output ciphertext is at the max level of paramsN1
	require.True(t, ctQL.Level() == params.MaxLevel())
	require.True(t, ctQL.Scale.Equal(params.DefaultScale()))

	verifyTestVectorsBootstrapping(params, ecd, dec, values, ctQL, t)
}

func TestBootstrappingWithoutEvalRound(t *testing.T) {

	schemeParamsLit := hefloat.ParametersLiteral{
		LogN:            10,
		LogQ:            []int{60, 40},
		LogP:            []int{61},
		LogDefaultScale: 40,
	}

	if *flagLongTest {
		schemeParamsLit.LogN = 16
	}

	params, err := hefloat.NewParametersFromLiteral(schemeParamsLit)
	require.Nil(t, err)

	btpParamsLit := NewParametersLiteral()
	btpParamsLit.LogN = params.LogN()
	btpParamsLit.LogSlots = params.LogN() - 1
	btpParamsLit.EvalRound = false
	btpParamsLit.C2S = [][]int{{56}, {56}, {56}, {56}}
	btpParamsLit.S2C = [][]int{{39}, {39}, {39}}

	// Insecure params for fast testing only
	if !*flagLongTest {
		// Corrects the message ratio to take into account the smaller number of slots and keep the same precision
		btpParamsLit.LogMessageRatio += 16 - params.LogN()
	}

	btpParams, err := NewParametersFromLiteral(params, btpParamsLit)
	require.Nil(t, err)

	t.Logf("Scheme: LogN=%d/LogSlots=%d/LogQP=%f", btpParams.ResidualParameters.LogN(), btpParams.ResidualParameters.LogMaxSlots(), btpParams.ResidualParameters.LogQP())
	t.Logf("Bootstrapping: LogN=%d/LogSlots=%d/LogQP=%f", btpParams.BootstrappingParameters.LogN(), btpParams.BootstrappingParameters.LogMaxSlots(), btpParams.BootstrappingParameters.LogQP())

	sk := rlwe.NewKeyGenerator(btpParams.BootstrappingParameters).GenSecretKeyNew()

	btpKeys, _, err := btpParams.GenEvaluationKeys(sk)
	require.NoError(t, err)

	evaluator, err := NewEvaluator(btpParams, btpKeys)
	require.NoError(t, err)

	ecd := hefloat.NewEncoder(params)
	enc := rlwe.NewEncryptor(params, sk)
	dec := rlwe.NewDecryptor(params, sk)

	r := sampling.NewSource([32]byte{})

	values := make([]complex128, params.MaxSlots())
	for i := range values {
		values[i] = r.Complex128(-1-1i, 1+1i)
	}

	plaintext := hefloat.NewPlaintext(params, 0)
	ecd.Encode(values, plaintext)

	ctQ0 := hefloat.NewCiphertext(params, 1, plaintext.Level())
	require.NoError(t, enc.Encrypt(plaintext, ctQ0))

	// Checks that the input ciphertext is at the level 0
	require.True(t, ctQ0.Level() == 0)

	// Bootstrapps the ciphertext
	ctQL, err := evaluator.Bootstrap(ctQ0)
	require.NoError(t, err)

	// Checks that the output ciphertext is at the max level of paramsN1
	require.True(t, ctQL.Level() == params.MaxLevel())
	require.True(t, ctQL.Scale.Equal(params.DefaultScale()))

	verifyTestVectorsBootstrapping(params, ecd, dec, values, ctQL, t)
}

func TestBootstrappingWithoutKeyEncapsulation(t *testing.T) {

	schemeParamsLit := hefloat.ParametersLiteral{
		LogN:            13,
		LogQ:            []int{60, 40},
		LogP:            []int{61},
		LogDefaultScale: 40,
	}

	if *flagLongTest {
		schemeParamsLit.LogN = 16
	}

	params, err := hefloat.NewParametersFromLiteral(schemeParamsLit)
	require.Nil(t, err)

	btpParamsLit := NewParametersLiteral()
	btpParamsLit.LogN = params.LogN()
	btpParamsLit.LogSlots = params.LogN() - 1
	btpParamsLit.EphemeralSecretWeight = 0
	btpParamsLit.Mod1Interval = 25
	btpParamsLit.Mod1Degree = 63

	// Insecure params for fast testing only
	if !*flagLongTest {
		// Corrects the message ratio to take into account the smaller number of slots and keep the same precision
		btpParamsLit.LogMessageRatio += 16 - params.LogN()
	}

	btpParams, err := NewParametersFromLiteral(params, btpParamsLit)
	require.Nil(t, err)

	t.Logf("Scheme: LogN=%d/LogSlots=%d/LogQP=%f", btpParams.ResidualParameters.LogN(), btpParams.ResidualParameters.LogMaxSlots(), btpParams.ResidualParameters.LogQP())
	t.Logf("Bootstrapping: LogN=%d/LogSlots=%d/LogQP=%f", btpParams.BootstrappingParameters.LogN(), btpParams.BootstrappingParameters.LogMaxSlots(), btpParams.BootstrappingParameters.LogQP())

	sk := rlwe.NewKeyGenerator(btpParams.BootstrappingParameters).GenSecretKeyNew()

	btpKeys, _, err := btpParams.GenEvaluationKeys(sk)
	require.NoError(t, err)

	evaluator, err := NewEvaluator(btpParams, btpKeys)
	require.NoError(t, err)

	ecd := hefloat.NewEncoder(params)
	enc := rlwe.NewEncryptor(params, sk)
	dec := rlwe.NewDecryptor(params, sk)

	r := sampling.NewSource([32]byte{})

	values := make([]complex128, params.MaxSlots())
	for i := range values {
		values[i] = r.Complex128(-1-1i, 1+1i)
	}

	plaintext := hefloat.NewPlaintext(params, 0)
	ecd.Encode(values, plaintext)

	ctQ0 := hefloat.NewCiphertext(params, 1, plaintext.Level())
	require.NoError(t, enc.Encrypt(plaintext, ctQ0))

	// Checks that the input ciphertext is at the level 0
	require.True(t, ctQ0.Level() == 0)

	// Bootstrapps the ciphertext
	ctQL, err := evaluator.Bootstrap(ctQ0)
	require.NoError(t, err)

	// Checks that the output ciphertext is at the max level of paramsN1
	require.True(t, ctQL.Level() == params.MaxLevel())
	require.True(t, ctQL.Scale.Equal(params.DefaultScale()))

	verifyTestVectorsBootstrapping(params, ecd, dec, values, ctQL, t)
}

func TestBootstrappingWithIterations(t *testing.T) {

	schemeParamsLit := hefloat.ParametersLiteral{
		LogN:            10,
		LogQ:            []int{60, 40, 40, 40},
		LogP:            []int{61},
		LogDefaultScale: 80,
	}

	if *flagLongTest {
		schemeParamsLit.LogN = 16
	}

	params, err := hefloat.NewParametersFromLiteral(schemeParamsLit)
	require.Nil(t, err)

	btpParamsLit := NewParametersLiteral()
	btpParamsLit.LogN = params.LogN()
	btpParamsLit.LogSlots = params.LogN() - 1

	// Insecure params for fast testing only
	if !*flagLongTest {
		// Corrects the message ratio to take into account the smaller number of slots and keep the same precision
		btpParamsLit.LogMessageRatio += 16 - params.LogN()
	}

	btpParamsLit.Iterations.BootstrappingPrecision = []float64{25, 25}
	btpParamsLit.Iterations.ReservedPrimeBitSize = 28

	btpParams, err := NewParametersFromLiteral(params, btpParamsLit)
	require.Nil(t, err)

	t.Logf("Scheme: LogN=%d/LogSlots=%d/LogQP=%f", btpParams.ResidualParameters.LogN(), btpParams.ResidualParameters.LogMaxSlots(), btpParams.ResidualParameters.LogQP())
	t.Logf("Bootstrapping: LogN=%d/LogSlots=%d/LogQP=%f", btpParams.BootstrappingParameters.LogN(), btpParams.BootstrappingParameters.LogMaxSlots(), btpParams.BootstrappingParameters.LogQP())

	sk := rlwe.NewKeyGenerator(btpParams.BootstrappingParameters).GenSecretKeyNew()

	btpKeys, _, err := btpParams.GenEvaluationKeys(sk)
	require.NoError(t, err)

	evaluator, err := NewEvaluator(btpParams, btpKeys)
	require.NoError(t, err)

	ecd := hefloat.NewEncoder(params)
	enc := rlwe.NewEncryptor(params, sk)
	dec := rlwe.NewDecryptor(params, sk)

	r := sampling.NewSource([32]byte{})

	values := make([]complex128, params.MaxSlots())
	for i := range values {
		values[i] = r.Complex128(-1-1i, 1+1i)
	}

	plaintext := hefloat.NewPlaintext(params, 1)
	ecd.Encode(values, plaintext)

	ctQ0 := hefloat.NewCiphertext(params, 1, plaintext.Level())
	require.NoError(t, enc.Encrypt(plaintext, ctQ0))

	// Checks that the input ciphertext is at the level 1
	require.True(t, ctQ0.Level() == 1)

	// Bootstrapps the ciphertext
	ctQL, err := evaluator.Bootstrap(ctQ0)
	require.NoError(t, err)

	// Checks that the output ciphertext is at the max level of paramsN1
	require.True(t, ctQL.Level() == params.MaxLevel())
	require.True(t, ctQL.Scale.Equal(params.DefaultScale()))

	verifyTestVectorsBootstrapping(params, ecd, dec, values, ctQL, t)
}

func TestBootstrappingWithRingDegreeSwitch(t *testing.T) {

	schemeParamsLit := hefloat.ParametersLiteral{
		LogN:            10,
		LogQ:            []int{60, 40},
		LogP:            []int{61},
		LogDefaultScale: 40,
	}

	if *flagLongTest {
		schemeParamsLit.LogN = 16
	}

	schemeParamsLit.LogNthRoot = schemeParamsLit.LogN + 1
	schemeParamsLit.LogN--

	params, err := hefloat.NewParametersFromLiteral(schemeParamsLit)
	require.Nil(t, err)

	btpParamsLit := NewParametersLiteral()
	btpParamsLit.LogN = params.LogN() + 1
	btpParamsLit.LogSlots = params.LogN()

	if !*flagLongTest {
		// Corrects the message ratio to take into account the smaller number of slots and keep the same precision
		btpParamsLit.LogMessageRatio += 16 - params.LogN()
	}

	btpParams, err := NewParametersFromLiteral(params, btpParamsLit)
	require.Nil(t, err)

	t.Logf("Scheme: LogN=%d/LogSlots=%d/LogQP=%f", btpParams.ResidualParameters.LogN(), btpParams.ResidualParameters.LogMaxSlots(), btpParams.ResidualParameters.LogQP())
	t.Logf("Bootstrapping: LogN=%d/LogSlots=%d/LogQP=%f", btpParams.BootstrappingParameters.LogN(), btpParams.BootstrappingParameters.LogMaxSlots(), btpParams.BootstrappingParameters.LogQP())

	sk := rlwe.NewKeyGenerator(params).GenSecretKeyNew()

	btpKeys, _, err := btpParams.GenEvaluationKeys(sk)
	require.Nil(t, err)

	evaluator, err := NewEvaluator(btpParams, btpKeys)
	require.Nil(t, err)

	ecd := hefloat.NewEncoder(params)
	enc := rlwe.NewEncryptor(params, sk)
	dec := rlwe.NewDecryptor(params, sk)

	r := sampling.NewSource([32]byte{})

	values := make([]complex128, params.MaxSlots())
	for i := range values {
		values[i] = r.Complex128(-1-1i, 1+1i)
	}

	plaintext := hefloat.NewPlaintext(params, 0)
	ecd.Encode(values, plaintext)

	ctQ0 := hefloat.NewCiphertext(params, 1, plaintext.Level())
	require.NoError(t, enc.Encrypt(plaintext, ctQ0))

	// Checks that the input ciphertext is at the level 0
	require.True(t, ctQ0.Level() == 0)

	// Bootstrapps the ciphertext
	ctQL, err := evaluator.Bootstrap(ctQ0)

	if err != nil {
		t.Fatal(err)
	}

	// Checks that the output ciphertext is at the max level of params
	require.True(t, ctQL.Level() == params.MaxLevel())
	require.True(t, ctQL.Scale.Equal(params.DefaultScale()))

	verifyTestVectorsBootstrapping(params, ecd, dec, values, ctQL, t)

}

func TestBootstrappingPackedWithRingDegreeSwitch(t *testing.T) {

	schemeParamsLit := hefloat.ParametersLiteral{
		LogN:            10,
		LogQ:            []int{60, 40},
		LogP:            []int{61},
		LogDefaultScale: 40,
	}

	if *flagLongTest {
		schemeParamsLit.LogN = 16
	}

	schemeParamsLit.LogNthRoot = schemeParamsLit.LogN + 1
	schemeParamsLit.LogN -= 3

	params, err := hefloat.NewParametersFromLiteral(schemeParamsLit)
	require.Nil(t, err)

	btpParamsLit := NewParametersLiteral()
	btpParamsLit.LogN = params.LogN() + 3
	btpParamsLit.LogSlots = params.LogN() + 2

	if !*flagLongTest {
		// Corrects the message ratio to take into account the smaller number of slots and keep the same precision
		btpParamsLit.LogMessageRatio += 16 - params.LogN()
	}

	btpParams, err := NewParametersFromLiteral(params, btpParamsLit)
	require.Nil(t, err)

	t.Logf("Scheme: LogN=%d/LogSlots=%d/LogQP=%f", btpParams.ResidualParameters.LogN(), btpParams.ResidualParameters.LogMaxSlots(), btpParams.ResidualParameters.LogQP())
	t.Logf("Bootstrapping: LogN=%d/LogSlots=%d/LogQP=%f", btpParams.BootstrappingParameters.LogN(), btpParams.BootstrappingParameters.LogMaxSlots(), btpParams.BootstrappingParameters.LogQP())

	sk := rlwe.NewKeyGenerator(params).GenSecretKeyNew()

	btpKeys, _, err := btpParams.GenEvaluationKeys(sk)
	require.Nil(t, err)

	evaluator, err := NewEvaluator(btpParams, btpKeys)
	require.Nil(t, err)

	ecd := hefloat.NewEncoder(params)
	enc := rlwe.NewEncryptor(params, sk)
	dec := rlwe.NewDecryptor(params, sk)

	r := sampling.NewSource([32]byte{})

	values := make([]complex128, params.MaxSlots())
	for i := range values {
		values[i] = r.Complex128(-1-1i, 1+1i)
	}

	pt := hefloat.NewPlaintext(params, 0)

	cts := make([]rlwe.Ciphertext, 7)
	for i := range cts {
		require.NoError(t, ecd.Encode(utils.RotateSlice(values, i), pt))
		ct := hefloat.NewCiphertext(params, 1, pt.Level())
		require.NoError(t, enc.Encrypt(pt, ct))
		cts[i] = *ct
	}

	if cts, err = evaluator.BootstrapMany(cts); err != nil {
		t.Fatal(err)
	}

	for i := range cts {
		// Checks that the output ciphertext is at the max level of paramsN1
		require.True(t, cts[i].Level() == params.MaxLevel())
		require.True(t, cts[i].Scale.Equal(params.DefaultScale()))
		require.True(t, cts[i].LogSlots() == params.LogMaxSlots())
		verifyTestVectorsBootstrapping(params, ecd, dec, utils.RotateSlice(values, i), &cts[i], t)
	}
}

func TestBootstrappingWithRingTypeSwitch(t *testing.T) {

	schemeParamsLit := hefloat.ParametersLiteral{
		LogN:            10,
		LogQ:            []int{60, 40},
		LogP:            []int{61},
		LogDefaultScale: 40,
		RingType:        ring.ConjugateInvariant,
	}

	if *flagLongTest {
		schemeParamsLit.LogN = 16
	}

	schemeParamsLit.LogNthRoot = schemeParamsLit.LogN + 1
	schemeParamsLit.LogN--

	params, err := hefloat.NewParametersFromLiteral(schemeParamsLit)
	require.Nil(t, err)

	btpParamsLit := NewParametersLiteral()
	btpParamsLit.LogN = params.LogN() + 1
	btpParamsLit.LogSlots = params.LogN()

	if !*flagLongTest {
		// Corrects the message ratio to take into account the smaller number of slots and keep the same precision
		btpParamsLit.LogMessageRatio += 16 - params.LogN()
	}

	btpParams, err := NewParametersFromLiteral(params, btpParamsLit)
	require.Nil(t, err)

	t.Logf("Scheme: LogN=%d/LogSlots=%d/LogQP=%f", btpParams.ResidualParameters.LogN(), btpParams.ResidualParameters.LogMaxSlots(), btpParams.ResidualParameters.LogQP())
	t.Logf("Bootstrapping: LogN=%d/LogSlots=%d/LogQP=%f", btpParams.BootstrappingParameters.LogN(), btpParams.BootstrappingParameters.LogMaxSlots(), btpParams.BootstrappingParameters.LogQP())

	sk := rlwe.NewKeyGenerator(params).GenSecretKeyNew()

	btpKeys, _, err := btpParams.GenEvaluationKeys(sk)
	require.Nil(t, err)

	evaluator, err := NewEvaluator(btpParams, btpKeys)
	require.Nil(t, err)

	ecd := hefloat.NewEncoder(params)
	enc := rlwe.NewEncryptor(params, sk)
	dec := rlwe.NewDecryptor(params, sk)

	r := sampling.NewSource([32]byte{})

	values := make([]float64, params.MaxSlots())
	for i := range values {
		values[i] = r.Float64(-1, 1)
	}

	plaintext := hefloat.NewPlaintext(params, 0)
	require.NoError(t, ecd.Encode(values, plaintext))

	ctLeftQ0 := hefloat.NewCiphertext(params, 1, plaintext.Level())
	require.NoError(t, enc.Encrypt(plaintext, ctLeftQ0))

	ctRightQ0 := hefloat.NewCiphertext(params, 1, plaintext.Level())
	require.NoError(t, enc.Encrypt(plaintext, ctRightQ0))

	// Checks that the input ciphertext is at the level 0
	require.True(t, ctLeftQ0.Level() == 0)
	require.True(t, ctRightQ0.Level() == 0)

	// Bootstraps the ciphertext
	ctLeftQL, ctRightQL, err := evaluator.EvaluateConjugateInvariant(ctLeftQ0, ctRightQ0)
	require.NoError(t, err)

	// Checks that the output ciphertext is at the max level of paramsN1
	require.True(t, ctLeftQL.Level() == params.MaxLevel())
	require.True(t, ctLeftQL.Scale.Equal(params.DefaultScale()))
	verifyTestVectorsBootstrapping(params, ecd, dec, values, ctLeftQL, t)

	require.True(t, ctRightQL.Level() == params.MaxLevel())
	require.True(t, ctRightQL.Scale.Equal(params.DefaultScale()))
	verifyTestVectorsBootstrapping(params, ecd, dec, values, ctRightQL, t)
}

func verifyTestVectorsBootstrapping(params hefloat.Parameters, encoder *hefloat.Encoder, decryptor *rlwe.Decryptor, valuesWant, element interface{}, t *testing.T) {

	precStats := hefloat.GetPrecisionStats(params, encoder, decryptor, valuesWant, element, 0, false)
	if *printPrecisionStats {
		t.Log(precStats.String())
	}

	minPrec := math.Log2(params.DefaultScale().Float64()) - float64(params.LogN()+2)
	if minPrec < 0 {
		minPrec = 0
	}

	minPrec -= 10

	require.GreaterOrEqual(t, precStats.AvgPrec.Real, minPrec)
	require.GreaterOrEqual(t, precStats.AvgPrec.Imag, minPrec)
}
