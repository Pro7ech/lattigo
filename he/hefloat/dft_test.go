package hefloat_test

import (
	"math/big"
	"runtime"
	"testing"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils"
	"github.com/Pro7ech/lattigo/utils/bignum"
	"github.com/Pro7ech/lattigo/utils/sampling"
	"github.com/stretchr/testify/require"
)

func testDFTEvaluator(t *testing.T) {
	var err error

	if runtime.GOARCH == "wasm" {
		t.Skip("skipping homomorphic DFT tests for GOARCH=wasm")
	}

	testDFTMatrixLiteralMarshalling(t)

	for _, paramsLiteral := range testParametersLiteral {

		var params hefloat.Parameters
		if params, err = hefloat.NewParametersFromLiteral(paramsLiteral); err != nil {
			t.Fatal(err)
		}

		for _, logSlots := range []int{params.LogMaxDimensions().Cols - 1, params.LogMaxDimensions().Cols} {
			for _, testSet := range []func(params hefloat.Parameters, logSlots int, t *testing.T){
				testHomomorphicEncoding,
				testHomomorphicDecoding,
			} {
				testSet(params, logSlots, t)
				runtime.GC()
			}
		}
	}
}

func testDFTMatrixLiteralMarshalling(t *testing.T) {
	t.Run("DFTMatrixLiteral/Marshalling", func(t *testing.T) {
		m := hefloat.DFTMatrixLiteral{
			LogSlots:    15,
			Type:        hefloat.HomomorphicDecode,
			Format:      hefloat.RepackImagAsReal,
			LevelQ:      12,
			LevelP:      1,
			Levels:      []int{1, 1, 1},
			BitReversed: true,
		}

		data, err := m.MarshalBinary()
		require.Nil(t, err)

		mNew := new(hefloat.DFTMatrixLiteral)
		if err := mNew.UnmarshalBinary(data); err != nil {
			require.Nil(t, err)
		}
		require.Equal(t, m, *mNew)
	})
}

func testHomomorphicEncoding(params hefloat.Parameters, LogSlots int, t *testing.T) {

	slots := 1 << LogSlots

	var sparse bool = LogSlots < params.LogMaxDimensions().Cols

	packing := "FullPacking"
	if sparse {
		packing = "SparsePacking"
	}

	var params2N hefloat.Parameters
	var err error
	if params2N, err = hefloat.NewParametersFromLiteral(hefloat.ParametersLiteral{
		LogN:            params.LogN() + 1,
		LogQ:            []int{60},
		LogP:            []int{61},
		LogDefaultScale: params.LogDefaultScale(),
	}); err != nil {
		t.Fatal(err)
	}

	ecd2N := hefloat.NewEncoder(params2N)

	t.Run("DFTEvaluator/IDFT/"+packing, func(t *testing.T) {

		// This test tests the homomorphic encoding
		// It first generates a vector of complex values of size slots
		//
		// vReal + i*vImag
		//
		// Then encode coefficient-wise and encrypts the vectors :
		//
		// Enc(bitReverse(vReal)||bitReverse(vImg))
		//
		// And applies the homomorphic Encoding (will merge both vectors if there was two)
		//
		// Enc(iFFT(vReal+ i*vImag))
		//
		// And returns the result in one ciphextext if the ciphertext can store it else in two ciphertexts
		//
		// Enc(Ecd(vReal) || Ecd(vImag)) or Enc(Ecd(vReal)) and Enc(Ecd(vImag))
		//
		// Then checks that Dcd(Dec(Enc(Ecd(vReal)))) = vReal and Dcd(Dec(Enc(Ecd(vImag)))) = vImag

		Levels := make([]int, min(LogSlots, (params.MaxLevel()-(params.LevelsConsumedPerRescaling()-1)))/params.LevelsConsumedPerRescaling())
		for i := range Levels {
			Levels[i] = 1
		}

		CoeffsToSlotsParametersLiteral := hefloat.DFTMatrixLiteral{
			LogSlots: LogSlots,
			Type:     hefloat.HomomorphicEncode,
			Format:   hefloat.RepackImagAsReal,
			LevelQ:   params.MaxLevel(),
			LevelP:   params.MaxLevelP(),
			Levels:   Levels,
		}

		kgen := rlwe.NewKeyGenerator(params)
		sk := kgen.GenSecretKeyNew()
		encoder := hefloat.NewEncoder(params, 90) // Required to force roots.(type) to be []bignum.Complex instead of []complex128
		encryptor := rlwe.NewEncryptor(params, sk)
		decryptor := rlwe.NewDecryptor(params, sk)

		// Generates the encoding matrices
		CoeffsToSlotMatrices, err := hefloat.NewDFTMatrixFromLiteral(params, CoeffsToSlotsParametersLiteral, encoder)
		require.NoError(t, err)

		// Gets Galois elements
		galEls := append(CoeffsToSlotsParametersLiteral.GaloisElements(params), params.GaloisElementOrderTwoOrthogonalSubgroup())

		// Generates and adds the keys
		// Instantiates the EvaluationKeySet
		evk := rlwe.NewMemEvaluationKeySet(nil, kgen.GenGaloisKeysNew(galEls, sk)...)

		// Creates an evaluator with the rotation keys
		eval := hefloat.NewEvaluator(params, evk)
		hdftEval := hefloat.NewDFTEvaluator(params, eval)

		prec := params.EncodingPrecision()

		// Generates the vector of random complex values
		values := make([]bignum.Complex, slots)
		r := sampling.NewSource([32]byte{})
		for i := range values {
			values[i].SetPrec(prec)
			values[i][0].SetFloat64(r.Float64(-1, 1))
			values[i][1].SetFloat64(r.Float64(-1, 1))
		}

		// Splits between real and imaginary
		valuesReal := make([]big.Float, slots)
		for i := range valuesReal {
			valuesReal[i].Set(&values[i][0])
		}

		valuesImag := make([]big.Float, slots)
		for i := range valuesImag {
			valuesImag[i].Set(&values[i][1])
		}

		// Applies bit-reverse on the original complex vector
		utils.BitReverseInPlaceSlice(values, slots)

		// Maps to a float vector
		// Add gaps if sparse packing
		valuesFloat := make([]big.Float, params.N())
		gap := params.N() / (2 * slots)
		for i, jdx, idx := 0, params.N()>>1, 0; i < slots; i, jdx, idx = i+1, jdx+gap, idx+gap {
			valuesFloat[idx].Set(&values[i][0])
			valuesFloat[jdx].Set(&values[i][1])
		}

		// Encodes coefficient-wise and encrypts the test vector
		pt := hefloat.NewPlaintext(params, params.MaxLevel())
		pt.LogDimensions = ring.Dimensions{Rows: 0, Cols: LogSlots}
		pt.IsBatched = false

		if err = encoder.Encode(valuesFloat, pt); err != nil {
			t.Fatal(err)
		}
		pt.IsBatched = true

		ct := hefloat.NewCiphertext(params, 1, params.MaxLevel())
		require.NoError(t, encryptor.Encrypt(pt, ct))

		buf := hdftEval.NewHoistingBuffer(ct.Level(), params.MaxLevelP())

		// Applies the homomorphic DFT
		ct0, ct1, err := hdftEval.CoeffsToSlotsNew(ct, CoeffsToSlotMatrices, buf)
		require.NoError(t, err)

		// Checks against the original coefficients
		if sparse {

			ct0.IsBatched = false

			have := make([]big.Float, params.N())
			if err = encoder.Decode(decryptor.DecryptNew(ct0), have); err != nil {
				t.Fatal(err)
			}

			// Plaintext circuit
			vec := make([]bignum.Complex, 2*slots)

			// Embed real vector into the complex vector (trivial)
			for i, j := 0, slots; i < slots; i, j = i+1, j+1 {
				vec[i][0].Set(&valuesReal[i])
				vec[j][0].Set(&valuesImag[i])
			}

			// IFFT
			if err = encoder.IFFT(vec, LogSlots+1); err != nil {
				t.Fatal(err)
			}

			// Extract complex vector into real vector
			want := make([]big.Float, params.N())
			for i, idx, jdx := 0, 0, params.N()>>1; i < 2*slots; i, idx, jdx = i+1, idx+gap/2, jdx+gap/2 {
				want[idx].Set(&vec[i][0])
				want[jdx].Set(&vec[i][1])
			}

			// Compares
			hefloat.VerifyTestVectors(params, ecd2N, nil, want, have, params.LogDefaultScale(), 0, *printPrecisionStats, t)

		} else {

			ct0.IsBatched = false
			ct1.IsBatched = false

			haveReal := make([]big.Float, params.N())
			if err = encoder.Decode(decryptor.DecryptNew(ct0), haveReal); err != nil {
				t.Fatal(err)
			}

			haveImag := make([]big.Float, params.N())
			if err = encoder.Decode(decryptor.DecryptNew(ct1), haveImag); err != nil {
				t.Fatal(err)
			}

			vec0 := make([]bignum.Complex, slots)
			vec1 := make([]bignum.Complex, slots)

			// Embed real vector into the complex vector (trivial)
			for i := 0; i < slots; i++ {
				vec0[i][0].Set(&valuesReal[i])
				vec1[i][0].Set(&valuesImag[i])
			}

			// IFFT
			if err = encoder.IFFT(vec0, LogSlots); err != nil {
				t.Fatal(err)
			}
			if err = encoder.IFFT(vec1, LogSlots); err != nil {
				t.Fatal(err)
			}

			// Extract complex vectors into real vectors
			wantReal := make([]big.Float, params.N())
			wantImag := make([]big.Float, params.N())
			for i, j := 0, slots; i < slots; i, j = i+1, j+1 {
				wantReal[i].Set(&vec0[i][0])
				wantReal[j].Set(&vec0[i][1])
				wantImag[i].Set(&vec1[i][0])
				wantImag[j].Set(&vec1[i][1])
			}

			hefloat.VerifyTestVectors(params, ecd2N, nil, wantReal, haveReal, params.LogDefaultScale(), 0, *printPrecisionStats, t)
			hefloat.VerifyTestVectors(params, ecd2N, nil, wantImag, haveImag, params.LogDefaultScale(), 0, *printPrecisionStats, t)
		}
	})
}

func testHomomorphicDecoding(params hefloat.Parameters, LogSlots int, t *testing.T) {

	slots := 1 << LogSlots

	var sparse bool = LogSlots < params.LogMaxDimensions().Cols

	packing := "FullPacking"
	if sparse {
		packing = "SparsePacking"
	}

	t.Run("DFTEvaluator/DFT/"+packing, func(t *testing.T) {

		// This test tests the homomorphic decoding
		// It first generates a complex vector of size 2*slots
		// if 2*slots == N, then two vectors are generated, one for the real part, one for the imaginary part :
		//
		// vReal and vReal (both floating point vectors because the encoding always result in a real vector)
		//
		// Then encode and encrypts the vectors :
		//
		// Enc(Ecd(vReal)) and Enc(Ecd(vImag))
		//
		// And applies the homomorphic decoding (will merge both vectors if there was two)
		//
		// Enc(FFT(Ecd(vReal) + i*Ecd(vImag)))
		//
		// The result should be the decoding of the initial vectors bit-reversed
		//
		// Enc(FFT(Ecd(vReal) + i*Ecd(vImag))) = Enc(BitReverse(Dcd(Ecd(vReal + i*vImag))))
		//
		// The first N/2 slots of the plaintext will be the real part while the last N/2 the imaginary part
		// In case of 2*slots < N, then there is a gap of N/(2*slots) between each values

		Levels := make([]int, min(LogSlots, (params.MaxLevel()-(params.LevelsConsumedPerRescaling()-1)))/params.LevelsConsumedPerRescaling())
		for i := range Levels {
			Levels[i] = 1
		}

		SlotsToCoeffsParametersLiteral := hefloat.DFTMatrixLiteral{
			LogSlots: LogSlots,
			Type:     hefloat.HomomorphicDecode,
			Format:   hefloat.RepackImagAsReal,
			LevelQ:   params.MaxLevel(),
			LevelP:   params.MaxLevelP(),
			Levels:   Levels,
		}

		kgen := rlwe.NewKeyGenerator(params)
		sk := kgen.GenSecretKeyNew()
		encoder := hefloat.NewEncoder(params)
		encryptor := rlwe.NewEncryptor(params, sk)
		decryptor := rlwe.NewDecryptor(params, sk)

		// Generates the encoding matrices
		SlotsToCoeffsMatrix, err := hefloat.NewDFTMatrixFromLiteral(params, SlotsToCoeffsParametersLiteral, encoder)
		require.NoError(t, err)

		// Gets the Galois elements
		galEls := append(SlotsToCoeffsParametersLiteral.GaloisElements(params), params.GaloisElementOrderTwoOrthogonalSubgroup())

		// Generates and adds the keys
		// Instantiates the EvaluationKeySet
		evk := rlwe.NewMemEvaluationKeySet(nil, kgen.GenGaloisKeysNew(galEls, sk)...)

		// Creates an evaluator with the rotation keys
		eval := hefloat.NewEvaluator(params, evk)
		hdftEval := hefloat.NewDFTEvaluator(params, eval)

		prec := params.EncodingPrecision()

		r := sampling.NewSource([32]byte{})

		// Generates the n first slots of the test vector (real part to encode)
		valuesReal := make([]bignum.Complex, slots)
		for i := range valuesReal {
			valuesReal[i].SetPrec(prec)
			valuesReal[i][0].SetFloat64(r.Float64(-1, 1))
		}

		// Generates the n first slots of the test vector (imaginary part to encode)
		valuesImag := make([]bignum.Complex, slots)
		for i := range valuesImag {
			valuesImag[i].SetPrec(prec)
			valuesImag[i][0].SetFloat64(r.Float64(-1, 1))
		}

		// If sparse, there there is the space to store both vectors in one
		if sparse {
			for i := range valuesReal {
				valuesReal[i][1].Set(&valuesImag[i][0])
			}
			LogSlots++
		}

		// Encodes and encrypts the test vectors
		plaintext := hefloat.NewPlaintext(params, params.MaxLevel())
		plaintext.LogDimensions = ring.Dimensions{Rows: 0, Cols: LogSlots}
		if err = encoder.Encode(valuesReal, plaintext); err != nil {
			t.Fatal(err)
		}

		ct0 := hefloat.NewCiphertext(params, 1, params.MaxLevel())
		require.NoError(t, encryptor.Encrypt(plaintext, ct0))

		var ct1 *rlwe.Ciphertext
		if !sparse {
			if err = encoder.Encode(valuesImag, plaintext); err != nil {
				t.Fatal(err)
			}
			ct1 = hefloat.NewCiphertext(params, 1, params.MaxLevel())
			require.NoError(t, encryptor.Encrypt(plaintext, ct1))
		}

		buf := hdftEval.NewHoistingBuffer(ct0.Level(), params.MaxLevelP())

		// Applies the homomorphic DFT
		res, err := hdftEval.SlotsToCoeffsNew(ct0, ct1, SlotsToCoeffsMatrix, buf)
		require.NoError(t, err)

		// Decrypt and decode in the coefficient domain
		coeffsFloat := make([]big.Float, params.N())
		res.IsBatched = false

		if err = encoder.Decode(decryptor.DecryptNew(res), coeffsFloat); err != nil {
			t.Fatal(err)
		}

		// Extracts the coefficients and construct the complex vector
		// This is simply coefficient ordering
		valuesTest := make([]bignum.Complex, slots)
		gap := params.N() / (2 * slots)
		for i, idx := 0, 0; i < slots; i, idx = i+1, idx+gap {
			valuesTest[i][0].Set(&coeffsFloat[idx])
			valuesTest[i][1].Set(&coeffsFloat[idx+(params.N()>>1)])
		}

		// The result is always returned as a single complex vector, so if full-packing (2 initial vectors)
		// then repacks both vectors together
		if !sparse {
			for i := range valuesReal {
				valuesReal[i][1].Set(&valuesImag[i][0])
			}
		}

		// Result is bit-reversed, so applies the bit-reverse permutation on the reference vector
		utils.BitReverseInPlaceSlice(valuesReal, slots)

		hefloat.VerifyTestVectors(params, encoder, decryptor, valuesReal, valuesTest, params.LogDefaultScale(), 0, *printPrecisionStats, t)
	})
}
