package heint_test

import (
	"slices"
	"testing"

	"github.com/Pro7ech/lattigo/he/heint"
	"github.com/stretchr/testify/require"
)

func testEncoder(tc *testContext, t *testing.T) {

	for _, lvl := range tc.testLevel {
		t.Run(GetTestName("Encoder/Uint/IsBatched=true", tc.params, lvl), func(t *testing.T) {
			values, plaintext, _ := newTestVectorsLvl(lvl, tc.params.DefaultScale(), tc, nil)
			verifyTestVectors(tc, nil, values, plaintext, t)
		})
	}

	for _, lvl := range tc.testLevel {
		t.Run(GetTestName("Encoder/Int/IsBatched=true", tc.params, lvl), func(t *testing.T) {

			T := tc.params.PlaintextModulus()
			THalf := T >> 1
			coeffs := make([]int64, tc.params.MaxSlots())
			for i := range coeffs {
				if i > int(THalf) {
					coeffs[i] = int64(-i)
				} else {
					coeffs[i] = int64(i)
				}
			}

			plaintext := heint.NewPlaintext(tc.params, lvl)
			require.NoError(t, tc.encoder.Encode(coeffs, plaintext))
			have := make([]int64, tc.params.MaxSlots())
			require.NoError(t, tc.encoder.Decode(plaintext, have))
			require.True(t, slices.Equal(coeffs, have))
		})
	}

	for _, lvl := range tc.testLevel {
		t.Run(GetTestName("Encoder/Uint/IsBatched=false", tc.params, lvl), func(t *testing.T) {
			coeffs := make([]uint64, tc.params.N())
			T := tc.params.PlaintextModulus()
			for i := range coeffs {
				coeffs[i] = uint64(i) % T
			}

			plaintext := heint.NewPlaintext(tc.params, lvl)
			plaintext.IsBatched = false
			require.NoError(t, tc.encoder.Encode(coeffs, plaintext))
			have := make([]uint64, tc.params.N())
			require.NoError(t, tc.encoder.Decode(plaintext, have))
			require.True(t, slices.Equal(coeffs, have))
		})
	}

	for _, lvl := range tc.testLevel {
		t.Run(GetTestName("Encoder/Int/IsBatched=false", tc.params, lvl), func(t *testing.T) {

			T := int64(tc.params.PlaintextModulus())
			THalf := T >> 1
			coeffs := make([]int64, tc.params.N())
			for i := range coeffs {
				c := int64(i) % T
				if c >= THalf {
					coeffs[i] = c - T
				} else {
					coeffs[i] = c
				}
			}
			plaintext := heint.NewPlaintext(tc.params, lvl)
			plaintext.IsBatched = false
			require.NoError(t, tc.encoder.Encode(coeffs, plaintext))
			have := make([]int64, tc.params.N())
			require.NoError(t, tc.encoder.Decode(plaintext, have))
			require.True(t, slices.Equal(coeffs, have))
		})
	}
}
