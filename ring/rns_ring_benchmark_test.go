package ring

import (
	"fmt"
	"testing"

	"github.com/Pro7ech/lattigo/utils/bignum"
	"github.com/Pro7ech/lattigo/utils/sampling"
	"github.com/stretchr/testify/require"
)

func BenchmarkRNSRing(b *testing.B) {

	var err error

	for _, params := range testParameters[:] {

		var tc *testParams
		if tc, err = genTestParams(params); err != nil {
			b.Fatal(err)
		}

		benchNewRNSRing(tc, b)
		benchMarshalling(tc, b)
		benchSampling(tc, b)
		benchMontgomery(tc, b)
		benchMulCoeffs(tc, b)
		benchAddCoeffs(tc, b)
		benchSubCoeffs(tc, b)
		benchNegCoeffs(tc, b)
		benchMulScalar(tc, b)
		benchExtendBasis(tc, b)
		benchDivByLastModulus(tc, b)
		benchMRed(tc, b)
		benchBRed(tc, b)
		benchBRedAdd(tc, b)
	}
}

func benchNewRNSRing(tc *testParams, b *testing.B) {

	b.Run(testString("NewRNSRing", tc.ringQ), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if _, err := NewRNSRing(tc.ringQ.N(), tc.ringQ.ModuliChain()); err != nil {
				b.Error(err)
			}
		}
	})
}

func benchMarshalling(tc *testParams, b *testing.B) {

	var err error

	p := tc.uniformSamplerQ.ReadNew(tc.ringQ.N())

	b.Run(testString("Marshalling/MarshalPoly", tc.ringQ), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if _, err = p.MarshalBinary(); err != nil {
				b.Error(err)
			}
		}
	})

	var data []byte
	if data, err = p.MarshalBinary(); err != nil {
		b.Error(err)
	}

	b.Run(testString("Marshalling/UnmarshalPoly", tc.ringQ), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if err = p.UnmarshalBinary(data); err != nil {
				b.Error(err)
			}
		}
	})
}

func benchSampling(tc *testParams, b *testing.B) {

	pol := tc.ringQ.NewRNSPoly()

	b.Run(testString("Sampling/Gaussian", tc.ringQ), func(b *testing.B) {

		sampler, err := NewSampler(sampling.NewSource([32]byte{}), tc.ringQ.ModuliChain(), &DiscreteGaussian{Sigma: DefaultSigma, Bound: DefaultBound})
		require.NoError(b, err)

		for i := 0; i < b.N; i++ {
			sampler.Read(pol)
		}
	})

	b.Run(testString("Sampling/Ternary/0.3", tc.ringQ), func(b *testing.B) {

		sampler, err := NewSampler(sampling.NewSource([32]byte{}), tc.ringQ.ModuliChain(), &Ternary{P: 1.0 / 3})
		require.NoError(b, err)

		for i := 0; i < b.N; i++ {
			sampler.Read(pol)
		}
	})

	b.Run(testString("Sampling/Ternary/0.5", tc.ringQ), func(b *testing.B) {

		sampler, err := NewSampler(sampling.NewSource([32]byte{}), tc.ringQ.ModuliChain(), &Ternary{P: 0.5})
		require.NoError(b, err)

		for i := 0; i < b.N; i++ {
			sampler.Read(pol)
		}
	})

	b.Run(testString("Sampling/Ternary/sparse128", tc.ringQ), func(b *testing.B) {

		sampler, err := NewSampler(sampling.NewSource([32]byte{}), tc.ringQ.ModuliChain(), &Ternary{H: 128})
		require.NoError(b, err)

		for i := 0; i < b.N; i++ {
			sampler.Read(pol)
		}
	})

	b.Run(testString("Sampling/Uniform", tc.ringQ), func(b *testing.B) {

		sampler, err := NewSampler(sampling.NewSource([32]byte{}), tc.ringQ.ModuliChain(), &Uniform{})
		require.NoError(b, err)

		for i := 0; i < b.N; i++ {
			sampler.Read(pol)
		}
	})
}

func benchMontgomery(tc *testParams, b *testing.B) {

	p := tc.uniformSamplerQ.ReadNew(tc.ringQ.N())

	b.Run(testString("Montgomery/MForm", tc.ringQ), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tc.ringQ.MForm(p, p)
		}
	})

	b.Run(testString("Montgomery/InvMForm", tc.ringQ), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tc.ringQ.IMForm(p, p)
		}
	})
}

func benchMulCoeffs(tc *testParams, b *testing.B) {

	p0 := tc.uniformSamplerQ.ReadNew(tc.ringQ.N())
	p1 := tc.uniformSamplerQ.ReadNew(tc.ringQ.N())

	b.Run(testString("MulCoeffs/Montgomery", tc.ringQ), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tc.ringQ.MulCoeffsMontgomery(p0, p1, p0)
		}
	})

	b.Run(testString("MulCoeffs/MontgomeryLazy", tc.ringQ), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tc.ringQ.MulCoeffsMontgomeryLazy(p0, p1, p0)
		}
	})

	b.Run(testString("MulCoeffs/Barrett", tc.ringQ), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tc.ringQ.MulCoeffsBarrett(p0, p1, p0)
		}
	})

	b.Run(testString("MulCoeffs/BarrettLazy", tc.ringQ), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tc.ringQ.MulCoeffsBarrettLazy(p0, p1, p0)
		}
	})
}

func benchAddCoeffs(tc *testParams, b *testing.B) {

	p0 := tc.uniformSamplerQ.ReadNew(tc.ringQ.N())
	p1 := tc.uniformSamplerQ.ReadNew(tc.ringQ.N())

	b.Run(testString("AddCoeffs/Add", tc.ringQ), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tc.ringQ.Add(p0, p1, p0)
		}
	})

	b.Run(testString("AddCoeffs/AddLazy", tc.ringQ), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tc.ringQ.AddLazy(p0, p1, p0)
		}
	})
}

func benchSubCoeffs(tc *testParams, b *testing.B) {

	p0 := tc.uniformSamplerQ.ReadNew(tc.ringQ.N())
	p1 := tc.uniformSamplerQ.ReadNew(tc.ringQ.N())

	b.Run(testString("SubCoeffs/Sub", tc.ringQ), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tc.ringQ.Sub(p0, p1, p0)
		}
	})

	b.Run(testString("SubCoeffs/SubLazy", tc.ringQ), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tc.ringQ.SubLazy(p0, p1, p0)
		}
	})
}

func benchNegCoeffs(tc *testParams, b *testing.B) {

	p0 := tc.uniformSamplerQ.ReadNew(tc.ringQ.N())

	b.Run(testString("NegCoeffs", tc.ringQ), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tc.ringQ.Neg(p0, p0)
		}
	})
}

func benchMulScalar(tc *testParams, b *testing.B) {

	p := tc.uniformSamplerQ.ReadNew(tc.ringQ.N())

	rand1 := tc.uniformSamplerQ.Source.Uint64()
	rand2 := tc.uniformSamplerQ.Source.Uint64()

	scalarBigint := bignum.NewInt(rand1)
	scalarBigint.Mul(scalarBigint, bignum.NewInt(rand2))

	b.Run(testString("MulScalar/uint64", tc.ringQ), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tc.ringQ.MulScalar(p, rand1, p)
		}
	})

	b.Run(testString("MulScalar/big.Int", tc.ringQ), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tc.ringQ.MulScalarBigint(p, scalarBigint, p)
		}
	})
}

func benchExtendBasis(tc *testParams, b *testing.B) {

	p0 := tc.uniformSamplerQ.ReadNew(tc.ringQ.N())
	p1 := tc.uniformSamplerP.ReadNew(tc.ringQ.N())

	buffQ := tc.ringQ.NewRNSPoly()
	buffP := tc.ringP.NewRNSPoly()

	b.Run(fmt.Sprintf("ExtendBasis/ModUp/N=%d/limbsQ=%d/limbsP=%d", tc.ringQ.N(), tc.ringQ.ModuliChainLength(), tc.ringP.ModuliChainLength()), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tc.ringQ.ModUp(tc.ringP, p0, buffQ, p1)
		}
	})

	b.Run(fmt.Sprintf("ExtendBasis/ModDown/N=%d/limbsQ=%d/limbsP=%d", tc.ringQ.N(), tc.ringQ.ModuliChainLength(), tc.ringP.ModuliChainLength()), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tc.ringQ.ModDown(tc.ringP, p0, p1, buffQ, buffP, p0)
		}
	})

	b.Run(fmt.Sprintf("ExtendBasis/ModDownNTT/N=%d/limbsQ=%d/limbsP=%d", tc.ringQ.N(), tc.ringQ.ModuliChainLength(), tc.ringP.ModuliChainLength()), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tc.ringQ.ModDownNTT(tc.ringP, p0, p1, buffQ, buffP, p0)
		}
	})
}

func benchDivByLastModulus(tc *testParams, b *testing.B) {

	p0 := tc.uniformSamplerQ.ReadNew(tc.ringQ.N())
	p1 := tc.ringQ.AtLevel(p0.Level() - 1).NewRNSPoly()

	buff := tc.ringQ.NewRNSPoly()

	b.Run(testString("DivByLastModulus/Floor", tc.ringQ), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tc.ringQ.DivFloorByLastModulus(p0, p1)
		}
	})

	b.Run(testString("DivByLastModulus/FloorNTT", tc.ringQ), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tc.ringQ.DivFloorByLastModulusNTT(p0, buff, p1)
		}
	})

	b.Run(testString("DivByLastModulus/Round", tc.ringQ), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tc.ringQ.DivRoundByLastModulus(p0, p1)
		}
	})

	b.Run(testString("DivByLastModulus/RoundNTT", tc.ringQ), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tc.ringQ.DivRoundByLastModulusNTT(p0, buff, p1)
		}
	})
}

func benchBRed(tc *testParams, b *testing.B) {

	var q, x, y uint64 = 1033576114481528833, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF

	brc := GetBRedConstant(q)

	b.ResetTimer()

	b.Run("BRed", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			x = BRed(x, y, q, brc)
		}
	})
}

func benchMRed(tc *testParams, b *testing.B) {

	var q, x, y uint64 = 1033576114481528833, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF

	y = MForm(y, q, GetBRedConstant(q))

	mrc := GetMRedConstant(q)

	b.ResetTimer()

	b.Run("MRed", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			x = MRed(x, y, q, mrc)
		}
	})
}

func benchBRedAdd(tc *testParams, b *testing.B) {

	var q, x uint64 = 1033576114481528833, 0xFFFFFFFFFFFFFFFF

	brc := GetBRedConstant(q)

	b.ResetTimer()

	b.Run("BRedAdd", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			BRedAdd(x, q, brc)
		}
	})
}
