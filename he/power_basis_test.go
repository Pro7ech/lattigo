package he

import (
	"testing"

	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/bignum"
	"github.com/Pro7ech/lattigo/utils/buffer"
	"github.com/Pro7ech/lattigo/utils/sampling"
)

func TestPowerBasis(t *testing.T) {
	t.Run("WriteAndRead", func(t *testing.T) {
		var err error
		var params rlwe.Parameters
		if params, err = rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
			LogN: 10,
			Q:    []uint64{0x200000440001, 0x7fff80001},
			P:    []uint64{0x3ffffffb80001, 0x4000000800001},
		}); err != nil {
			t.Fatal(err)
		}

		levelQ := params.MaxLevelQ()

		source := sampling.NewSource(sampling.NewSeed())

		ct := rlwe.NewCiphertext(params, 1, levelQ, -1)
		ct.Randomize(params, source)

		basis := NewPowerBasis(ct, bignum.Chebyshev)

		basis.Value[2] = rlwe.NewCiphertext(params, 1, levelQ, -1)
		basis.Value[3] = rlwe.NewCiphertext(params, 2, levelQ, -1)
		basis.Value[4] = rlwe.NewCiphertext(params, 1, levelQ, -1)
		basis.Value[8] = rlwe.NewCiphertext(params, 1, levelQ, -1)

		basis.Value[2].Randomize(params, source)
		basis.Value[3].Randomize(params, source)
		basis.Value[4].Randomize(params, source)
		basis.Value[8].Randomize(params, source)

		buffer.RequireSerializerCorrect(t, basis)
	})
}
