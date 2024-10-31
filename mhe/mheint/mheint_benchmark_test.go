package mheint

import (
	"encoding/json"
	"testing"

	"github.com/Pro7ech/lattigo/he/heint"
	"github.com/Pro7ech/lattigo/mhe"
	"github.com/Pro7ech/lattigo/rlwe"
)

func BenchmarkInteger(b *testing.B) {

	var err error

	paramsLiterals := testParams

	if *flagParamString != "" {
		var jsonParams heint.ParametersLiteral
		if err = json.Unmarshal([]byte(*flagParamString), &jsonParams); err != nil {
			b.Fatal(err)
		}
		paramsLiterals = []heint.ParametersLiteral{jsonParams} // the custom test suite reads the parameters from the -params flag
	}

	for _, p := range paramsLiterals {

		for _, T := range testPlaintextModulus[:] {

			p.T = T
			p.R = 1

			var params heint.Parameters
			if params, err = heint.NewParametersFromLiteral(p); err != nil {
				b.Fatal(err)
			}

			nParties := 3

			var tc *testContext
			if tc, err = gentestContext(nParties, params); err != nil {
				b.Fatal(err)
			}

			benchRefresh(tc, b)
		}
	}
}

func benchRefresh(tc *testContext, b *testing.B) {

	skShares := tc.skShares

	minLevel := 0
	maxLevel := tc.params.MaxLevel()

	type Party struct {
		RefreshProtocol
		s     *rlwe.SecretKey
		share *mhe.RefreshShare
	}

	p := new(Party)
	p.RefreshProtocol = *NewRefreshProtocol(tc.params)
	p.s = skShares[0]
	p.share = p.Allocate(minLevel, maxLevel)

	ciphertext := heint.NewCiphertext(tc.params, 1, minLevel)

	seed := [32]byte{}

	b.Run(GetTestName("Refresh/Round1/Gen", tc.params, tc.NParties), func(b *testing.B) {

		for i := 0; i < b.N; i++ {
			p.Gen(p.s, ciphertext, seed, p.share)
		}
	})

	b.Run(GetTestName("Refresh/Round1/Agg", tc.params, tc.NParties), func(b *testing.B) {

		for i := 0; i < b.N; i++ {
			p.Aggregate(p.share, p.share, p.share)
		}
	})

	b.Run(GetTestName("Refresh/Finalize", tc.params, tc.NParties), func(b *testing.B) {
		opOut := heint.NewCiphertext(tc.params, 1, maxLevel)
		for i := 0; i < b.N; i++ {
			p.Finalize(ciphertext, p.share, opOut)
		}
	})
}
