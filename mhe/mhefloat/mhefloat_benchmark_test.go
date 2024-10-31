package mhefloat

import (
	"encoding/json"
	"testing"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/mhe"
	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/bignum"
)

func BenchmarkMHEFloat(b *testing.B) {

	var err error

	var testParams []hefloat.ParametersLiteral
	switch {
	case *flagParamString != "": // the custom test suite reads the parameters from the -params flag
		testParams = append(testParams, hefloat.ParametersLiteral{})
		if err = json.Unmarshal([]byte(*flagParamString), &testParams[0]); err != nil {
			b.Fatal(err)
		}
	default:
		testParams = testParamsLiteral
	}

	for _, ringType := range []ring.Type{ring.Standard, ring.ConjugateInvariant} {

		for _, paramsLiteral := range testParams {

			paramsLiteral.RingType = ringType

			var params hefloat.Parameters
			if params, err = hefloat.NewParametersFromLiteral(paramsLiteral); err != nil {
				b.Fatal(err)
			}
			N := 3
			var tc *testContext
			if tc, err = genTestParams(params, N); err != nil {
				b.Fatal(err)
			}

			benchRefresh(tc, b)
			benchMaskedTransform(tc, b)
		}
	}
}

func benchRefresh(tc *testContext, b *testing.B) {

	params := tc.params

	minLevel, logBound, ok := GetMinimumLevelForRefresh(128, params.DefaultScale(), tc.nParties, params.Q())

	if ok {

		skShares := tc.skShares

		type Party struct {
			RefreshProtocol
			s     *rlwe.SecretKey
			share *mhe.RefreshShare
		}

		p := new(Party)
		p.RefreshProtocol = *NewRefreshProtocol(params, logBound)
		p.s = skShares[0]
		p.share = p.Allocate(minLevel, params.MaxLevel())

		ciphertext := hefloat.NewCiphertext(params, 1, minLevel)

		seed := [32]byte{}

		b.Run(GetTestName("Refresh/Gen", tc.nParties, params), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				p.Gen(p.s, logBound, ciphertext, seed, p.share)
			}
		})

		b.Run(GetTestName("Refresh/Agg", tc.nParties, params), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				p.Aggregate(p.share, p.share, p.share)
			}
		})

		b.Run(GetTestName("Refresh/Finalize", tc.nParties, params), func(b *testing.B) {
			opOut := hefloat.NewCiphertext(params, 1, params.MaxLevel())
			for i := 0; i < b.N; i++ {
				p.Finalize(ciphertext, p.share, opOut)
			}
		})

	} else {
		b.Log("bench skipped : not enough level to ensure correctness and 128 bit security")
	}
}

func benchMaskedTransform(tc *testContext, b *testing.B) {

	params := tc.params

	minLevel, logBound, ok := GetMinimumLevelForRefresh(128, params.DefaultScale(), tc.nParties, params.Q())

	if ok {

		skShares := tc.skShares

		type Party struct {
			MaskedTransformProtocol
			s     *rlwe.SecretKey
			share *mhe.RefreshShare
		}

		ciphertext := hefloat.NewCiphertext(params, 1, minLevel)

		p := new(Party)
		p.MaskedTransformProtocol = *NewMaskedTransformProtocol(params, params, logBound)
		p.s = skShares[0]
		p.share = p.Allocate(ciphertext.Level(), params.MaxLevel())

		seed := [32]byte{}

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

		b.Run(GetTestName("Refresh&Transform/Gen", tc.nParties, params), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				p.Gen(p.s, p.s, logBound, ciphertext, seed, transform, p.share)
			}
		})

		b.Run(GetTestName("Refresh&Transform/Agg", tc.nParties, params), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				p.Aggregate(p.share, p.share, p.share)
			}
		})

		b.Run(GetTestName("Refresh&Transform/Finalize", tc.nParties, params), func(b *testing.B) {
			opOut := hefloat.NewCiphertext(params, 1, params.MaxLevel())
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				p.Finalize(ciphertext, transform, p.share, opOut)
			}
		})

	} else {
		b.Log("bench skipped : not enough level to ensure correctness and 128 bit security")
	}
}
