package hefloat_test

import (
	"testing"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/stretchr/testify/require"
)

func testBridge(tc *testContext, t *testing.T) {

	t.Run(GetTestName(tc.params, "Bridge"), func(t *testing.T) {

		if tc.params.RingType() != ring.ConjugateInvariant {
			t.Skip("only tested for params.RingType() == ring.ConjugateInvariant")
		}

		ciParams := tc.params
		var err error
		if _, err = ciParams.StandardParameters(); err != nil {
			t.Fatalf("all Conjugate Invariant parameters should have a standard counterpart but got: %f", err)
		}

		// Create equivalent parameters with RingStandard ring type and different auxiliary modulus P
		stdParamsLit := ciParams.ParametersLiteral()
		stdParamsLit.LogN = ciParams.LogN() + 1
		stdParamsLit.P = []uint64{0x1ffffffff6c80001, 0x1ffffffff6140001} // Assigns new P to ensure that independence from auxiliary P is tested
		stdParamsLit.RingType = ring.Standard
		stdParams, err := hefloat.NewParametersFromLiteral(stdParamsLit)
		require.Nil(t, err)

		stdKeyGen := rlwe.NewKeyGenerator(stdParams)
		stdSK := stdKeyGen.GenSecretKeyNew()
		stdDecryptor := rlwe.NewDecryptor(stdParams, stdSK)
		stdEncoder := hefloat.NewEncoder(stdParams)
		stdEvaluator := hefloat.NewEvaluator(stdParams, nil)

		evkCtR, evkRtC := stdKeyGen.GenEvaluationKeysForRingSwapNew(stdSK, tc.sk)

		switcher, err := hefloat.NewDomainSwitcher(stdParams, evkCtR, evkRtC)
		if err != nil {
			t.Fatal(err)
		}

		evalStandar := hefloat.NewEvaluator(stdParams, nil)

		values, _, ctCI := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		stdCTHave := hefloat.NewCiphertext(stdParams, ctCI.Degree(), ctCI.Level())

		switcher.RealToComplex(evalStandar, ctCI, stdCTHave)

		hefloat.VerifyTestVectors(stdParams, stdEncoder, stdDecryptor, values, stdCTHave, tc.params.LogDefaultScale(), 0, *printPrecisionStats, t)

		stdCTImag, err := stdEvaluator.MulNew(stdCTHave, 1i)
		require.NoError(t, err)
		require.NoError(t, stdEvaluator.Add(stdCTHave, stdCTImag, stdCTHave))

		ciCTHave := hefloat.NewCiphertext(ciParams, 1, stdCTHave.Level())
		switcher.ComplexToReal(evalStandar, stdCTHave, ciCTHave)

		hefloat.VerifyTestVectors(tc.params, tc.encoder, tc.decryptor, values, ciCTHave, tc.params.LogDefaultScale(), 0, *printPrecisionStats, t)
	})
}
