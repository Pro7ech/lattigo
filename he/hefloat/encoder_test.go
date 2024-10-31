package hefloat_test

import (
	"math"
	"math/big"
	"testing"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/bignum"
	"github.com/Pro7ech/lattigo/utils/sampling"
	"github.com/stretchr/testify/require"
)

func testEncoder(tc *testContext, t *testing.T) {

	logprec := float64(tc.params.LogDefaultScale()) / 2

	t.Run(GetTestName(tc.params, "Encoder/IsBatched=true"), func(t *testing.T) {

		values, plaintext, _ := newTestVectors(tc, nil, -1-1i, 1+1i, t)

		hefloat.VerifyTestVectors(tc.params, tc.encoder, nil, values, plaintext, tc.params.LogDefaultScale(), 0, *printPrecisionStats, t)
	})

	t.Run(GetTestName(tc.params, "Encoder/IsBatched=true/DecodePublic/[]float64"), func(t *testing.T) {

		values, plaintext, _ := newTestVectors(tc, nil, -1-1i, 1+1i, t)

		have := make([]float64, len(values))

		require.NoError(t, tc.encoder.DecodePublic(plaintext, have, logprec))

		want := make([]float64, len(values))
		for i := range want {
			want[i], _ = values[i][0].Float64()
			want[i] -= have[i]
		}

		// Allows for a 10% error over the expected standard deviation of the error
		require.GreaterOrEqual(t, hefloat.StandardDeviation(want, rlwe.NewScale(1)), math.Exp2(-logprec)/math.Sqrt(12)*0.9)
	})

	t.Run(GetTestName(tc.params, "Encoder/IsBatched=true/DecodePublic/[]complex128"), func(t *testing.T) {

		if tc.params.RingType() == ring.ConjugateInvariant {
			t.Skip("skipping: []complex128 not supported when RingType == ring.ConjugateInvariant")
		}

		values, plaintext, _ := newTestVectors(tc, nil, -1-1i, 1+1i, t)

		have := make([]complex128, len(values))
		require.NoError(t, tc.encoder.DecodePublic(plaintext, have, logprec))

		wantReal := make([]float64, len(values))
		wantImag := make([]float64, len(values))

		for i := range have {
			wantReal[i], _ = values[i][0].Float64()
			wantImag[i], _ = values[i][1].Float64()

			wantReal[i] -= real(have[i])
			wantImag[i] -= imag(have[i])
		}

		// Allows for a 10% error over the expected standard deviation of the error
		require.GreaterOrEqual(t, hefloat.StandardDeviation(wantReal, rlwe.NewScale(1)), math.Exp2(-logprec)/math.Sqrt(12)*0.9)
		require.GreaterOrEqual(t, hefloat.StandardDeviation(wantImag, rlwe.NewScale(1)), math.Exp2(-logprec)/math.Sqrt(12)*0.9)
	})

	t.Run(GetTestName(tc.params, "Encoder/IsBatched=true/DecodePublic/[]big.Float"), func(t *testing.T) {
		values, plaintext, _ := newTestVectors(tc, nil, -1-1i, 1+1i, t)
		have := make([]big.Float, len(values))
		require.NoError(t, tc.encoder.DecodePublic(plaintext, have, logprec))

		want := make([]big.Float, len(values))
		for i := range want {
			want[i].Sub(&values[i][0], &have[i])
		}

		// Allows for a 10% error over the expected standard deviation of the error
		require.GreaterOrEqual(t, hefloat.StandardDeviation(want, rlwe.NewScale(1)), math.Exp2(-logprec)/math.Sqrt(12)*0.9)
	})

	t.Run(GetTestName(tc.params, "Encoder/IsBatched=true/DecodePublic/[]bignum.Complex"), func(t *testing.T) {

		if tc.params.RingType() == ring.ConjugateInvariant {
			t.Skip("skipping: []complex128 not supported when RingType == ring.ConjugateInvariant")
		}

		values, plaintext, _ := newTestVectors(tc, nil, -1-1i, 1+1i, t)
		have := make([]bignum.Complex, len(values))
		require.NoError(t, tc.encoder.DecodePublic(plaintext, have, logprec))

		wantReal := make([]big.Float, len(values))
		wantImag := make([]big.Float, len(values))

		for i := range have {
			wantReal[i].Sub(&values[i][0], &have[i][0])
			wantImag[i].Sub(&values[i][1], &have[i][1])
		}

		// Allows for a 10% error over the expected standard deviation of the error
		require.GreaterOrEqual(t, hefloat.StandardDeviation(wantReal, rlwe.NewScale(1)), math.Exp2(-logprec)/math.Sqrt(12)*0.9)
		require.GreaterOrEqual(t, hefloat.StandardDeviation(wantImag, rlwe.NewScale(1)), math.Exp2(-logprec)/math.Sqrt(12)*0.9)
	})

	t.Run(GetTestName(tc.params, "Encoder/IsBatched=false"), func(t *testing.T) {

		slots := tc.params.N()

		valuesWant := make([]float64, slots)

		r := sampling.NewSource([32]byte{})

		for i := 0; i < slots; i++ {
			valuesWant[i] = r.Float64(-1, 1)
		}

		valuesWant[0] = 0.607538

		pt := hefloat.NewPlaintext(tc.params, tc.params.MaxLevel())
		pt.IsBatched = false

		require.NoError(t, tc.encoder.Encode(valuesWant, pt))

		valuesTest := make([]float64, len(valuesWant))

		require.NoError(t, tc.encoder.Decode(pt, valuesTest))

		var meanprec float64

		for i := range valuesWant {
			meanprec += math.Abs(valuesTest[i] - valuesWant[i])
		}

		meanprec /= float64(slots)

		if *printPrecisionStats {
			t.Logf("\nMean    precision : %.2f \n", math.Log2(1/meanprec))
		}

		minPrec := math.Log2(tc.params.DefaultScale().Float64()) - float64(tc.params.LogN()+2)
		if minPrec < 0 {
			minPrec = 0
		}

		require.GreaterOrEqual(t, math.Log2(1/meanprec), minPrec)

		// Also tests at level 0
		pt = hefloat.NewPlaintext(tc.params, tc.params.LevelsConsumedPerRescaling()-1)
		pt.IsBatched = false

		require.NoError(t, tc.encoder.Encode(valuesWant, pt))

		require.NoError(t, tc.encoder.Decode(pt, valuesTest))

		meanprec = 0
		for i := range valuesWant {
			meanprec += math.Abs(valuesTest[i] - valuesWant[i])
		}

		meanprec /= float64(slots)

		if *printPrecisionStats {
			t.Logf("\nMean    precision : %.2f \n", math.Log2(1/meanprec))
		}

		require.GreaterOrEqual(t, math.Log2(1/meanprec), minPrec)
	})
}
