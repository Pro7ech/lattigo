package ring

import (
	"runtime"
	"slices"
	"testing"

	"github.com/Pro7ech/lattigo/utils/buffer"
	"github.com/Pro7ech/lattigo/utils/sampling"
	"github.com/stretchr/testify/require"
)

func TestStructs(t *testing.T) {

	N := 1024

	LevelQ := 2
	LevelP := 2

	rQ, err := NewRNSRing(N, Qi60[:LevelQ+1])
	require.NoError(t, err)

	rP, err := NewRNSRing(N, Pi60[:LevelP+1])
	require.NoError(t, err)

	t.Run("Point", func(t *testing.T) {

		point := NewPoint(N, LevelQ, LevelP)
		point.Randomize(rQ, rP, sampling.NewSource([32]byte{}))

		t.Run("Serialization", func(t *testing.T) {
			buffer.RequireSerializerCorrect(t, point)
		})

		t.Run("ConcatPtoQ", func(t *testing.T) {
			for n := 0; n < max(2, LevelP+1); n++ {
				pTmp := point.ConcatPtoQ(n)
				require.Equal(t, pTmp.LevelQ(), LevelQ+n)
				require.Equal(t, pTmp.LevelP(), LevelP-n)

				for i := 0; i < LevelQ+1; i++ {
					require.True(t, slices.Equal(pTmp.Q.At(i), point.Q.At(i)))
				}

				for i := 0; i < n; i++ {
					require.True(t, slices.Equal(pTmp.Q.At(i+LevelQ+1), point.P.At(i)))
				}

				for i := 0; i < LevelP+1-n; i++ {
					require.True(t, slices.Equal(pTmp.P.At(i), point.P.At(i+n)))
				}
			}
		})

		t.Run("ConcatQtoP", func(t *testing.T) {

			for n := 0; n < max(2, LevelP+1); n++ {

				pTmp := point.ConcatQtoP(n)

				require.Equal(t, pTmp.LevelQ(), LevelQ-n)
				require.Equal(t, pTmp.LevelP(), LevelP+n)

				for i := 0; i < LevelQ+1-n; i++ {
					require.True(t, slices.Equal(pTmp.Q.At(i), point.Q.At(i)))
				}

				for i := 0; i < n; i++ {
					require.True(t, slices.Equal(pTmp.P.At(i), point.Q.At(i+LevelQ+1-n)))
				}

				for i := 0; i < LevelP+1; i++ {
					require.True(t, slices.Equal(pTmp.P.At(i+n), point.P.At(i)))
				}
			}
		})
	})

	t.Run("Vector", func(t *testing.T) {

		vector := NewVector(N, LevelQ, LevelP, 2)
		vector.Randomize(rQ, rP, sampling.NewSource([32]byte{}))

		t.Run("Serialization", func(t *testing.T) {
			buffer.RequireSerializerCorrect(t, vector)
		})

		t.Run("ConcatPtoQ", func(t *testing.T) {

			for n := 0; n < max(2, LevelP+1); n++ {

				vTmp := vector.ConcatPtoQ(n)

				require.Equal(t, vTmp.LevelQ(), LevelQ+n)
				require.Equal(t, vTmp.LevelP(), LevelP-n)

				for j := 0; j < vector.Size(); j++ {

					for i := 0; i < LevelQ+1; i++ {
						require.True(t, slices.Equal(vTmp.Q[j].At(i), vector.Q[j].At(i)))
					}

					for i := 0; i < n; i++ {
						require.True(t, slices.Equal(vTmp.Q[j].At(i+LevelQ+1), vector.P[j].At(i)))
					}

					for i := 0; i < LevelP+1-n; i++ {
						require.True(t, slices.Equal(vTmp.P[j].At(i), vector.P[j].At(i+n)))
					}
				}
			}
		})

		t.Run("ConcatQtoP", func(t *testing.T) {

			for n := 0; n < max(2, LevelP+1); n++ {

				vTmp := vector.ConcatQtoP(n)
				require.Equal(t, vTmp.LevelQ(), LevelQ-n)
				require.Equal(t, vTmp.LevelP(), LevelP+n)

				for j := 0; j < vector.Size(); j++ {

					for i := 0; i < LevelQ+1-n; i++ {
						require.True(t, slices.Equal(vTmp.Q[j].At(i), vector.Q[j].At(i)))
					}

					for i := 0; i < n; i++ {
						require.True(t, slices.Equal(vTmp.P[j].At(i), vector.Q[j].At(i+LevelQ+1-n)))
					}

					for i := 0; i < LevelP+1; i++ {
						require.True(t, slices.Equal(vTmp.P[j].At(i+n), vector.P[j].At(i)))
					}
				}
			}
		})
	})

	t.Run("Matrix", func(t *testing.T) {

		matrix := NewMatrix(N, LevelQ, LevelP, []int{1, 2, 3})
		matrix.Randomize(rQ, rP, sampling.NewSource([32]byte{}))

		t.Run("Serialization", func(t *testing.T) {
			buffer.RequireSerializerCorrect(t, matrix)
		})

		t.Run("ConcatPtoQ", func(t *testing.T) {

			for n := 0; n < max(2, LevelP+1); n++ {

				mTmp := matrix.ConcatPtoQ(n)

				require.Equal(t, mTmp.LevelQ(), LevelQ+n)
				require.Equal(t, mTmp.LevelP(), LevelP-n)

				dims := matrix.Dims()

				for k := range dims {
					for j := range dims[k] {

						for i := 0; i < LevelQ+1; i++ {
							require.True(t, slices.Equal(mTmp.Q[k][j].At(i), matrix.Q[k][j].At(i)))
						}

						for i := 0; i < n; i++ {
							require.True(t, slices.Equal(mTmp.Q[k][j].At(i+LevelQ+1), matrix.P[k][j].At(i)))
						}

						for i := 0; i < LevelP+1-n; i++ {
							require.True(t, slices.Equal(mTmp.P[k][j].At(i), matrix.P[k][j].At(i+n)))
						}
					}
				}
			}
		})

		t.Run("ConcatQtoP", func(t *testing.T) {

			for n := 0; n < max(2, LevelP+1); n++ {

				mTmp := matrix.ConcatQtoP(n)

				require.Equal(t, mTmp.LevelQ(), LevelQ-n)
				require.Equal(t, mTmp.LevelP(), LevelP+n)

				dims := matrix.Dims()

				for k := range dims {
					for j := range dims[k] {

						for i := 0; i < LevelQ+1-n; i++ {
							require.True(t, slices.Equal(mTmp.Q[k][j].At(i), matrix.Q[k][j].At(i)))
						}

						for i := 0; i < n; i++ {
							require.True(t, slices.Equal(mTmp.P[k][j].At(i), matrix.Q[k][j].At(i+LevelQ+1-n)))
						}

						for i := 0; i < LevelP+1; i++ {
							require.True(t, slices.Equal(mTmp.P[k][j].At(i+n), matrix.P[k][j].At(i)))
						}
					}
				}
			}
		})
	})

	runtime.GC()
}
