package heint_test

import (
	"fmt"
	"testing"

	"github.com/Pro7ech/lattigo/he/heint"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/stretchr/testify/require"
)

func testEvaluator(tc *testContext, t *testing.T) {

	for _, lvl := range tc.testLevel {
		t.Run(GetTestName("Evaluator/Add/Ct/Ct/New", tc.params, lvl), func(t *testing.T) {

			v0, _, ct0 := newTestVectorsLvl(lvl, tc.params.NewScale(3), tc, tc.encryptorSk)
			v1, _, ciphertext1 := newTestVectorsLvl(lvl, tc.params.NewScale(7), tc, tc.encryptorSk)

			require.True(t, ct0.Scale.Cmp(ciphertext1.Scale) != 0)

			ciphertext2, err := tc.evaluator.AddNew(ct0, ciphertext1)
			require.NoError(t, err)
			tc.rT.Add(v0, v1, v0)

			verifyTestVectors(tc, tc.decryptor, v0, ciphertext2, t)

		})
	}

	for _, lvl := range tc.testLevel {
		t.Run(GetTestName("Evaluator/Add/Ct/Ct/Inplace", tc.params, lvl), func(t *testing.T) {

			v0, _, ct0 := newTestVectorsLvl(lvl, tc.params.NewScale(3), tc, tc.encryptorSk)
			v1, _, ciphertext1 := newTestVectorsLvl(lvl, tc.params.NewScale(7), tc, tc.encryptorSk)

			require.True(t, ct0.Scale.Cmp(ciphertext1.Scale) != 0)

			require.NoError(t, tc.evaluator.Add(ct0, ciphertext1, ct0))
			tc.rT.Add(v0, v1, v0)

			verifyTestVectors(tc, tc.decryptor, v0, ct0, t)

		})
	}

	for _, lvl := range tc.testLevel {
		t.Run(GetTestName("Evaluator/Add/Ct/Pt/Inplace", tc.params, lvl), func(t *testing.T) {

			v0, _, ct0 := newTestVectorsLvl(lvl, tc.params.NewScale(3), tc, tc.encryptorSk)
			v1, pt, _ := newTestVectorsLvl(lvl, tc.params.NewScale(7), tc, tc.encryptorSk)

			require.True(t, ct0.Scale.Cmp(pt.Scale) != 0)

			require.NoError(t, tc.evaluator.Add(ct0, pt, ct0))
			tc.rT.Add(v0, v1, v0)

			verifyTestVectors(tc, tc.decryptor, v0, ct0, t)

		})
	}

	for _, lvl := range tc.testLevel {
		t.Run(GetTestName("Evaluator/Add/Ct/Scalar/Inplace", tc.params, lvl), func(t *testing.T) {

			values, _, ciphertext := newTestVectorsLvl(lvl, tc.params.DefaultScale(), tc, tc.encryptorSk)

			scalar := tc.params.PlaintextModulus() >> 1

			require.NoError(t, tc.evaluator.Add(ciphertext, scalar, ciphertext))
			tc.rT.AddScalar(values, scalar, values)

			verifyTestVectors(tc, tc.decryptor, values, ciphertext, t)

		})
	}

	for _, lvl := range tc.testLevel {
		t.Run(GetTestName("Evaluator/Add/Ct/Vector/Inplace", tc.params, lvl), func(t *testing.T) {

			values, _, ciphertext := newTestVectorsLvl(lvl, tc.params.DefaultScale(), tc, tc.encryptorSk)

			require.NoError(t, tc.evaluator.Add(ciphertext, values, ciphertext))
			tc.rT.Add(values, values, values)

			verifyTestVectors(tc, tc.decryptor, values, ciphertext, t)

		})
	}

	for _, lvl := range tc.testLevel {
		t.Run(GetTestName("Evaluator/Sub/Ct/Ct/New", tc.params, lvl), func(t *testing.T) {

			v0, _, ct0 := newTestVectorsLvl(lvl, tc.params.NewScale(3), tc, tc.encryptorSk)
			v1, _, ciphertext1 := newTestVectorsLvl(lvl, tc.params.NewScale(7), tc, tc.encryptorSk)

			require.True(t, ct0.Scale.Cmp(ciphertext1.Scale) != 0)

			ct0, err := tc.evaluator.SubNew(ct0, ciphertext1)
			require.NoError(t, err)
			tc.rT.Sub(v0, v1, v0)

			verifyTestVectors(tc, tc.decryptor, v0, ct0, t)

		})
	}

	for _, lvl := range tc.testLevel {
		t.Run(GetTestName("Evaluator/Sub/Ct/Ct/Inplace", tc.params, lvl), func(t *testing.T) {

			v0, _, ct0 := newTestVectorsLvl(lvl, tc.params.NewScale(3), tc, tc.encryptorSk)
			v1, _, ciphertext1 := newTestVectorsLvl(lvl, tc.params.NewScale(7), tc, tc.encryptorSk)

			require.True(t, ct0.Scale.Cmp(ciphertext1.Scale) != 0)

			require.NoError(t, tc.evaluator.Sub(ct0, ciphertext1, ct0))
			tc.rT.Sub(v0, v1, v0)

			verifyTestVectors(tc, tc.decryptor, v0, ct0, t)

		})
	}

	for _, lvl := range tc.testLevel {
		t.Run(GetTestName("Evaluator/Sub/Ct/Pt/Inplace", tc.params, lvl), func(t *testing.T) {

			v0, _, ct0 := newTestVectorsLvl(lvl, tc.params.NewScale(3), tc, tc.encryptorSk)
			v1, pt, _ := newTestVectorsLvl(lvl, tc.params.NewScale(7), tc, tc.encryptorSk)

			require.True(t, ct0.Scale.Cmp(pt.Scale) != 0)

			require.NoError(t, tc.evaluator.Sub(ct0, pt, ct0))
			tc.rT.Sub(v0, v1, v0)

			verifyTestVectors(tc, tc.decryptor, v0, ct0, t)

		})
	}

	for _, lvl := range tc.testLevel {
		t.Run(GetTestName("Evaluator/Sub/Ct/Scalar/Inplace", tc.params, lvl), func(t *testing.T) {

			values, _, ciphertext := newTestVectorsLvl(lvl, tc.params.DefaultScale(), tc, tc.encryptorSk)

			scalar := tc.params.PlaintextModulus() >> 1

			require.NoError(t, tc.evaluator.Sub(ciphertext, scalar, ciphertext))
			tc.rT.SubScalar(values, scalar, values)

			verifyTestVectors(tc, tc.decryptor, values, ciphertext, t)

		})
	}

	for _, lvl := range tc.testLevel {
		t.Run(GetTestName("Evaluator/Sub/Ct/Vector/Inplace", tc.params, lvl), func(t *testing.T) {

			values, _, ciphertext := newTestVectorsLvl(lvl, tc.params.DefaultScale(), tc, tc.encryptorSk)

			require.NoError(t, tc.evaluator.Sub(ciphertext, values, ciphertext))
			tc.rT.Sub(values, values, values)

			verifyTestVectors(tc, tc.decryptor, values, ciphertext, t)

		})
	}

	for _, lvl := range tc.testLevel {
		t.Run(GetTestName("Evaluator/Mul/Ct/Pt/Inplace", tc.params, lvl), func(t *testing.T) {

			if lvl == 0 {
				t.Skip("Skipping: Level = 0")
			}

			// (c00, c01) x (c0) as (x, y, x)
			v0, _, ct0 := newTestVectorsLvl(lvl, tc.params.NewScale(3), tc, tc.encryptorSk)
			v1, pt, ct1 := newTestVectorsLvl(lvl, tc.params.NewScale(7), tc, tc.encryptorSk)
			require.True(t, ct0.Scale.Cmp(pt.Scale) != 0)
			require.NoError(t, tc.evaluator.Mul(ct0, pt, ct1))
			tc.rT.MulCoeffsBarrett(v1, v0, v1)
			verifyTestVectors(tc, tc.decryptor, v1, ct1, t)

			// (c00, c01) x (d0) as (x, y, ct(y))
			v1, pt, _ = newTestVectorsLvl(lvl, tc.params.NewScale(7), tc, tc.encryptorSk)
			ctpt := pt.AsCiphertext()
			require.NoError(t, tc.evaluator.Mul(ct0, pt, ctpt))
			require.Equal(t, ctpt.Degree(), 1)
			tc.rT.MulCoeffsBarrett(v1, v0, v1)
			verifyTestVectors(tc, tc.decryptor, v1, ctpt, t)

			// (c00, c01) x (d0) as (ct(y), x, ct(y))
			v1, pt, _ = newTestVectorsLvl(lvl, tc.params.NewScale(7), tc, tc.encryptorSk)
			ctpt = pt.AsCiphertext()
			require.NoError(t, tc.evaluator.Mul(ctpt, ct0, ctpt))
			require.Equal(t, ctpt.Degree(), 1)
			tc.rT.MulCoeffsBarrett(v1, v0, v1)
			verifyTestVectors(tc, tc.decryptor, v1, ctpt, t)

			// (c00, c01, c02) x (d0) as (x, y, x)
			v0, _, ct0 = newTestVectorsLvl(lvl, tc.params.NewScale(3), tc, tc.encryptorSk)
			require.NoError(t, tc.evaluator.Mul(ct0, ct0, ct0))
			tc.rT.MulCoeffsBarrett(v0, v0, v0)
			v1, pt, _ = newTestVectorsLvl(lvl, tc.params.NewScale(7), tc, tc.encryptorSk)
			require.NoError(t, tc.evaluator.Mul(ct0, pt, ct0))
			tc.rT.MulCoeffsBarrett(v1, v0, v1)
			verifyTestVectors(tc, tc.decryptor, v1, ct0, t)

			// (c00, c01, c02) x (d0) as (x, y, ct(y))
			v0, _, ct0 = newTestVectorsLvl(lvl, tc.params.NewScale(3), tc, tc.encryptorSk)
			require.NoError(t, tc.evaluator.Mul(ct0, ct0, ct0))
			tc.rT.MulCoeffsBarrett(v0, v0, v0)
			v1, pt, _ = newTestVectorsLvl(lvl, tc.params.NewScale(7), tc, tc.encryptorSk)
			ctpt = pt.AsCiphertext()
			require.NoError(t, tc.evaluator.Mul(ct0, pt, ctpt))
			require.Equal(t, ctpt.Degree(), 2)
			tc.rT.MulCoeffsBarrett(v1, v0, v1)
			verifyTestVectors(tc, tc.decryptor, v1, ctpt, t)

			// (c00, c01, c02) x (d0) as (ct(y), x, ct(y))
			v0, _, ct0 = newTestVectorsLvl(lvl, tc.params.NewScale(3), tc, tc.encryptorSk)
			require.NoError(t, tc.evaluator.Mul(ct0, ct0, ct0))
			tc.rT.MulCoeffsBarrett(v0, v0, v0)
			v1, pt, _ = newTestVectorsLvl(lvl, tc.params.NewScale(7), tc, tc.encryptorSk)
			ctpt = pt.AsCiphertext()
			require.NoError(t, tc.evaluator.Mul(ctpt, ct0, ctpt))
			require.Equal(t, ctpt.Degree(), 2)
			tc.rT.MulCoeffsBarrett(v1, v0, v1)
			verifyTestVectors(tc, tc.decryptor, v1, ctpt, t)

			// (c00, c01, c02) x (d0) as (ct(y), x, ct(y)) with relinearization
			v0, _, ct0 = newTestVectorsLvl(lvl, tc.params.NewScale(3), tc, tc.encryptorSk)
			require.NoError(t, tc.evaluator.Mul(ct0, ct0, ct0))
			tc.rT.MulCoeffsBarrett(v0, v0, v0)
			v1, pt, _ = newTestVectorsLvl(lvl, tc.params.NewScale(7), tc, tc.encryptorSk)
			ctpt = pt.AsCiphertext()
			require.NoError(t, tc.evaluator.MulRelin(ctpt, ct0, ctpt))
			require.Equal(t, ctpt.Degree(), 1)
			tc.rT.MulCoeffsBarrett(v1, v0, v1)
			verifyTestVectors(tc, tc.decryptor, v1, ctpt, t)
		})
	}

	for _, lvl := range tc.testLevel {
		t.Run(GetTestName("Evaluator/Mul/Degree=0/Degree=1/Inplace", tc.params, lvl), func(t *testing.T) {

			if lvl == 0 {
				t.Skip("Skipping: Level = 0")
			}

			v0, _, ct0 := newTestVectorsLvl(lvl, tc.params.NewScale(3), tc, tc.encryptorSk)
			v1, pt, _ := newTestVectorsLvl(lvl, tc.params.NewScale(7), tc, tc.encryptorSk)

			require.True(t, ct0.Scale.Cmp(pt.Scale) != 0)

			require.NoError(t, tc.evaluator.Mul(ct0, pt, ct0))
			tc.rT.MulCoeffsBarrett(v0, v1, v0)

			verifyTestVectors(tc, tc.decryptor, v0, ct0, t)

		})
	}

	for _, lvl := range tc.testLevel {
		t.Run(GetTestName("Evaluator/Mul/Degree=1/Degree=1/Inplace", tc.params, lvl), func(t *testing.T) {

			if lvl == 0 {
				t.Skip("Skipping: Level = 0")
			}

			v0, _, ct0 := newTestVectorsLvl(lvl, tc.params.NewScale(3), tc, tc.encryptorSk)
			v1, _, ciphertext1 := newTestVectorsLvl(lvl, tc.params.NewScale(7), tc, tc.encryptorSk)

			require.True(t, ct0.Scale.Cmp(ciphertext1.Scale) != 0)

			require.NoError(t, tc.evaluator.Mul(ct0, ciphertext1, ct0))
			tc.rT.MulCoeffsBarrett(v0, v1, v0)

			verifyTestVectors(tc, tc.decryptor, v0, ct0, t)

		})
	}

	for _, lvl := range tc.testLevel {
		t.Run(GetTestName("Evaluator/Mul/Ct/Scalar/Inplace", tc.params, lvl), func(t *testing.T) {

			if lvl == 0 {
				t.Skip("Skipping: Level = 0")
			}

			values, _, ciphertext := newTestVectorsLvl(lvl, tc.params.DefaultScale(), tc, tc.encryptorSk)

			scalar := tc.params.PlaintextModulus() >> 1

			require.NoError(t, tc.evaluator.Mul(ciphertext, scalar, ciphertext))
			tc.rT.MulScalar(values, scalar, values)

			verifyTestVectors(tc, tc.decryptor, values, ciphertext, t)
		})
	}

	for _, lvl := range tc.testLevel {
		t.Run(GetTestName("Evaluator/Mul/Ct/Vector/Inplace", tc.params, lvl), func(t *testing.T) {

			if lvl == 0 {
				t.Skip("Skipping: Level = 0")
			}

			values, _, ciphertext := newTestVectorsLvl(lvl, tc.params.DefaultScale(), tc, tc.encryptorSk)

			require.NoError(t, tc.evaluator.Mul(ciphertext, values, ciphertext))
			tc.rT.MulCoeffsBarrett(values, values, values)

			verifyTestVectors(tc, tc.decryptor, values, ciphertext, t)
		})
	}

	for _, lvl := range tc.testLevel {
		t.Run(GetTestName("Evaluator/Square/Ct/Ct/Inplace", tc.params, lvl), func(t *testing.T) {

			if lvl == 0 {
				t.Skip("Skipping: Level = 0")
			}

			v0, _, ct0 := newTestVectorsLvl(lvl, tc.params.NewScale(3), tc, tc.encryptorSk)

			require.NoError(t, tc.evaluator.Mul(ct0, ct0, ct0))
			tc.rT.MulCoeffsBarrett(v0, v0, v0)

			verifyTestVectors(tc, tc.decryptor, v0, ct0, t)
		})
	}

	for _, lvl := range tc.testLevel {
		t.Run(GetTestName("Evaluator/MulRelin/Ct/Ct/Inplace", tc.params, lvl), func(t *testing.T) {

			if lvl == 0 {
				t.Skip("Skipping: Level = 0")
			}

			v0, _, ct0 := newTestVectorsLvl(lvl, tc.params.NewScale(3), tc, tc.encryptorSk)
			v1, _, ciphertext1 := newTestVectorsLvl(lvl, tc.params.NewScale(7), tc, tc.encryptorSk)

			tc.rT.MulCoeffsBarrett(v0, v1, v0)

			require.True(t, ct0.Scale.Cmp(ciphertext1.Scale) != 0)

			receiver := heint.NewCiphertext(tc.params, 1, lvl)

			require.NoError(t, tc.evaluator.MulRelin(ct0, ciphertext1, receiver))

			require.NoError(t, tc.evaluator.Rescale(receiver, receiver))

			verifyTestVectors(tc, tc.decryptor, v0, receiver, t)
		})
	}

	for _, lvl := range tc.testLevel {
		t.Run(GetTestName("Evaluator/MulThenAdd/Ct/Ct/Inplace", tc.params, lvl), func(t *testing.T) {

			if lvl == 0 {
				t.Skip("Skipping: Level = 0")
			}

			v0, _, ct0 := newTestVectorsLvl(lvl, tc.params.DefaultScale(), tc, tc.encryptorSk)
			v1, _, ciphertext1 := newTestVectorsLvl(lvl, rlwe.NewScale(2), tc, tc.encryptorSk)
			values2, _, ciphertext2 := newTestVectorsLvl(lvl, tc.params.NewScale(7), tc, tc.encryptorSk)

			require.True(t, ct0.Scale.Cmp(ciphertext1.Scale) != 0)
			require.True(t, ct0.Scale.Cmp(ciphertext2.Scale) != 0)

			require.NoError(t, tc.evaluator.MulThenAdd(ct0, ciphertext1, ciphertext2))
			tc.rT.MulCoeffsBarrettThenAdd(v0, v1, values2)

			verifyTestVectors(tc, tc.decryptor, values2, ciphertext2, t)
		})
	}

	for _, lvl := range tc.testLevel {
		t.Run(GetTestName("Evaluator/MulThenAdd/Ct/Pt/Inplace", tc.params, lvl), func(t *testing.T) {

			if lvl == 0 {
				t.Skip("Skipping: Level = 0")
			}

			v0, _, ct0 := newTestVectorsLvl(lvl, tc.params.DefaultScale(), tc, tc.encryptorSk)
			v1, pt1, _ := newTestVectorsLvl(lvl, rlwe.NewScale(2), tc, tc.encryptorSk)
			values2, _, ciphertext2 := newTestVectorsLvl(lvl, tc.params.NewScale(7), tc, tc.encryptorSk)

			require.True(t, ct0.Scale.Cmp(pt1.Scale) != 0)
			require.True(t, ct0.Scale.Cmp(ciphertext2.Scale) != 0)

			require.NoError(t, tc.evaluator.MulThenAdd(ct0, pt1, ciphertext2))
			tc.rT.MulCoeffsBarrettThenAdd(v0, v1, values2)

			verifyTestVectors(tc, tc.decryptor, values2, ciphertext2, t)
		})
	}

	for _, lvl := range tc.testLevel {
		t.Run(GetTestName("Evaluator/MulThenAdd/Ct/Scalar/Inplace", tc.params, lvl), func(t *testing.T) {

			if lvl == 0 {
				t.Skip("Skipping: Level = 0")
			}

			v0, _, ct0 := newTestVectorsLvl(lvl, tc.params.NewScale(7), tc, tc.encryptorSk)
			v1, _, ciphertext1 := newTestVectorsLvl(lvl, tc.params.NewScale(3), tc, tc.encryptorSk)

			require.True(t, ct0.Scale.Cmp(ciphertext1.Scale) != 0)

			scalar := tc.params.PlaintextModulus() >> 1

			require.NoError(t, tc.evaluator.MulThenAdd(ct0, scalar, ciphertext1))
			tc.rT.MulScalar(v0, scalar, v0)
			tc.rT.Add(v1, v0, v1)

			verifyTestVectors(tc, tc.decryptor, v1, ciphertext1, t)
		})
	}

	for _, lvl := range tc.testLevel {
		t.Run(GetTestName("Evaluator/MulThenAdd/Ct/Vector/Inplace", tc.params, lvl), func(t *testing.T) {

			if lvl == 0 {
				t.Skip("Skipping: Level = 0")
			}

			v0, _, ct0 := newTestVectorsLvl(lvl, tc.params.NewScale(7), tc, tc.encryptorSk)
			v1, _, ciphertext1 := newTestVectorsLvl(lvl, tc.params.NewScale(3), tc, tc.encryptorSk)

			require.True(t, ct0.Scale.Cmp(ciphertext1.Scale) != 0)

			scale := ciphertext1.Scale

			require.NoError(t, tc.evaluator.MulThenAdd(ct0, v1, ciphertext1))
			tc.rT.MulCoeffsBarrett(v0, v1, v0)
			tc.rT.Add(v1, v0, v1)

			// Checks that output scale isn't changed
			require.True(t, scale.Equal(ciphertext1.Scale))

			verifyTestVectors(tc, tc.decryptor, v1, ciphertext1, t)
		})
	}

	for _, lvl := range tc.testLevel {
		t.Run(GetTestName("Evaluator/MulRelinThenAdd/Ct/Ct/Inplace", tc.params, lvl), func(t *testing.T) {

			if lvl == 0 {
				t.Skip("Skipping: Level = 0")
			}

			v0, _, ct0 := newTestVectorsLvl(lvl, tc.params.DefaultScale(), tc, tc.encryptorSk)
			v1, _, ciphertext1 := newTestVectorsLvl(lvl, rlwe.NewScale(2), tc, tc.encryptorSk)
			values2, _, ciphertext2 := newTestVectorsLvl(lvl, tc.params.NewScale(7), tc, tc.encryptorSk)

			require.True(t, ct0.Scale.Cmp(ciphertext1.Scale) != 0)
			require.True(t, ct0.Scale.Cmp(ciphertext2.Scale) != 0)

			require.NoError(t, tc.evaluator.MulRelinThenAdd(ct0, ciphertext1, ciphertext2))
			tc.rT.MulCoeffsBarrettThenAdd(v0, v1, values2)

			verifyTestVectors(tc, tc.decryptor, values2, ciphertext2, t)
		})
	}

	for _, lvl := range tc.testLevel[:] {
		t.Run(GetTestName("Evaluator/Rescale", tc.params, lvl), func(t *testing.T) {

			rT := tc.params.RT

			v0, _, ct0 := newTestVectorsLvl(lvl, tc.params.DefaultScale(), tc, tc.encryptorPk)

			printNoise := func(msg string, values []uint64, ct *rlwe.Ciphertext) {
				pt := heint.NewPlaintext(tc.params, ct.Level())
				pt.MetaData = ct0.MetaData
				require.NoError(t, tc.encoder.Encode(v0, pt))
				ct, err := tc.evaluator.SubNew(ct, pt)
				require.NoError(t, err)
				vartmp, _, _ := rlwe.Norm(ct, tc.decryptor)
				t.Logf("STD(noise) %s: %f\n", msg, vartmp)
			}

			if lvl != 0 {

				v1, _, ciphertext1 := newTestVectorsLvl(lvl, tc.params.DefaultScale(), tc, tc.encryptorSk)

				if *flagPrintNoise {
					printNoise("0x", v0, ct0)
				}

				for i := 0; i < lvl; i++ {
					tc.evaluator.MulRelin(ct0, ciphertext1, ct0)

					rT.MulCoeffsBarrett(v0, v1, v0)

					if *flagPrintNoise {
						printNoise(fmt.Sprintf("%dx", i+1), v0, ct0)
					}

				}

				verifyTestVectors(tc, tc.decryptor, v0, ct0, t)

				require.Nil(t, tc.evaluator.Rescale(ct0, ct0))

				verifyTestVectors(tc, tc.decryptor, v0, ct0, t)

			} else {
				require.NotNil(t, tc.evaluator.Rescale(ct0, ct0))
			}
		})
	}
}
