package ring

import (
	"bytes"
	"fmt"
	"math"
	"math/big"
	"testing"

	"github.com/Pro7ech/lattigo/utils/buffer"
	"github.com/Pro7ech/lattigo/utils/sampling"
	"github.com/Pro7ech/lattigo/utils/structs"

	"github.com/Pro7ech/lattigo/utils/bignum"
	"github.com/stretchr/testify/require"
)

var T = uint64(0x3ee0001)
var DefaultSigma = 3.2
var DefaultBound = 6.0 * DefaultSigma

func testString(opname string, ringQ RNSRing) string {
	return fmt.Sprintf("%s/N=%d/limbs=%d", opname, ringQ.N(), ringQ.ModuliChainLength())
}

type testParams struct {
	ringQ           RNSRing
	ringP           RNSRing
	uniformSamplerQ *UniformSampler
	uniformSamplerP *UniformSampler
}

func genTestParams(defaultParams Parameters) (tc *testParams, err error) {

	tc = new(testParams)

	if tc.ringQ, err = NewRNSRing(1<<defaultParams.logN, defaultParams.qi); err != nil {
		return nil, err
	}
	if tc.ringP, err = NewRNSRing(1<<defaultParams.logN, defaultParams.pi); err != nil {
		return nil, err
	}

	tc.uniformSamplerQ = NewUniformSampler(sampling.NewSource([32]byte{}), tc.ringQ.ModuliChain())
	tc.uniformSamplerP = NewUniformSampler(sampling.NewSource([32]byte{}), tc.ringP.ModuliChain())
	return
}

func TestPrimePowerRing(t *testing.T) {
	r, err := NewRing(1024, 65537, 3)
	require.NoError(t, err)
	require.NoError(t, r.GenNTTTable())

	k := 1

	p0 := make([]uint64, r.N)
	p0[k] = 1
	p1 := make([]uint64, r.N)
	p1[k] = 1

	r.NTT(p0, p0)
	r.NTT(p1, p1)
	r.MForm(p0, p0)
	r.MulCoeffsMontgomery(p0, p1, p0)
	r.INTT(p0, p0)

	want := make([]uint64, r.N)
	want[2*k] = 1
	require.Equal(t, p0, want)
}

func TestRNSRing(t *testing.T) {

	var err error

	var defaultParams = testParameters[:] // the default test

	testNewRNSRing(t)
	testShift(t)

	for _, defaultParam := range defaultParams[:] {

		var tc *testParams
		if tc, err = genTestParams(defaultParam); err != nil {
			t.Fatal(err)
		}

		testNTTConjugateInvariant(tc, t)
		testUniformSampler(tc, t)
		testGenerateNTTPrimes(tc, t)
		testDivFloorByLastModulusMany(tc, t)
		testDivRoundByLastModulusMany(tc, t)
		testMarshalBinary(tc, t)
		testWriterAndReader(tc, t)
		testSampler(tc, t)
		testModularReduction(tc, t)
		testMForm(tc, t)
		testMulScalarBigint(tc, t)
		testExtendBasis(tc, t)
		testMultByMonomial(tc, t)

	}
}

func testNTTConjugateInvariant(tc *testParams, t *testing.T) {

	t.Run(testString("NTTConjugateInvariant", tc.ringQ), func(t *testing.T) {

		ringQ := tc.ringQ
		Q := ringQ.ModuliChain()
		N := ringQ.N()
		ringQ2N, _ := NewRNSRing(N<<1, Q)
		ringQConjugateInvariant, _ := NewRNSRingFromType(N, Q, ConjugateInvariant)

		p1 := tc.uniformSamplerQ.ReadNew(N)
		p2 := ringQ2N.NewRNSPoly()

		for i, qi := range Q {
			copy(p2.At(i), p1.At(i))
			for j := 1; j < N; j++ {
				p2.At(i)[N*2-j] = qi - p2.At(i)[j]
			}
		}

		ringQ2N.NTT(p2, p2)
		ringQ2N.MForm(p2, p2)
		ringQ2N.MulCoeffsMontgomery(p2, p2, p2)
		ringQ2N.IMForm(p2, p2)
		ringQ2N.INTT(p2, p2)

		p1tmp := ringQ2N.NewRNSPoly()

		ringQConjugateInvariant.NTT(p1, p1tmp)
		ringQConjugateInvariant.MForm(p1tmp, p1tmp)
		ringQConjugateInvariant.MulCoeffsMontgomery(p1tmp, p1tmp, p1tmp)
		ringQConjugateInvariant.IMForm(p1tmp, p1tmp)
		ringQConjugateInvariant.INTT(p1tmp, p1)

		for j := range Q {
			for i := 0; i < N; i++ {
				require.Equal(t, p1.At(j)[i], p2.At(j)[i])
			}
		}
	})
}

func testNewRNSRing(t *testing.T) {
	t.Run("NewRNSRing", func(t *testing.T) {
		r, err := NewRNSRing(0, nil)
		require.Nil(t, r)
		require.Error(t, err)

		r, err = NewRNSRing(0, []uint64{})
		require.Nil(t, r)
		require.Error(t, err)

		r, err = NewRNSRing(4, []uint64{})
		require.Nil(t, r)
		require.Error(t, err)

		r, err = NewRNSRing(8, []uint64{})
		require.Nil(t, r)
		require.Error(t, err)

		r, err = NewRNSRing(16, []uint64{7}) // Passing non NTT-enabling coeff modulus
		require.NotNil(t, r)                 // Should still return a Ring instance
		require.Error(t, err)                // Should also return an error due to non NTT

		r, err = NewRNSRing(16, []uint64{4}) // Passing non prime moduli
		require.NotNil(t, r)                 // Should still return a Ring instance
		require.Error(t, err)                // Should also return an error due to non NTT

		r, err = NewRNSRing(16, []uint64{97, 7}) // Passing a NTT-enabling and a non NTT-enabling coeff modulus
		require.NotNil(t, r)                     // Should still return a Ring instance
		require.Error(t, err)                    // Should also return an error due to non NTT

		r, err = NewRNSRing(16, []uint64{97, 97}) // Passing non CRT-enabling coeff modulus
		require.Nil(t, r)                         // Should not return a Ring instance
		require.Error(t, err)

		r, err = NewRNSRing(16, []uint64{97}) // Passing NTT-enabling coeff modulus
		require.NotNil(t, r)
		require.NoError(t, err)

	})
}

func testUniformSampler(tc *testParams, t *testing.T) {

	t.Run(testString("PRNG", tc.ringQ), func(t *testing.T) {

		crsGenerator1 := NewUniformSampler(sampling.NewSource([32]byte{}), tc.ringQ.ModuliChain())
		crsGenerator2 := NewUniformSampler(sampling.NewSource([32]byte{}), tc.ringQ.ModuliChain())

		p0 := crsGenerator1.ReadNew(tc.ringQ.N())
		p1 := crsGenerator2.ReadNew(tc.ringQ.N())

		require.True(t, tc.ringQ.Equal(p0, p1))
	})

}

func testGenerateNTTPrimes(tc *testParams, t *testing.T) {

	t.Run(testString("GenerateNTTPrimes", tc.ringQ), func(t *testing.T) {

		NthRoot := tc.ringQ.NthRoot()

		g := NewNTTFriendlyPrimesGenerator(55, NthRoot)

		primes, err := g.NextAlternatingPrimes(tc.ringQ.ModuliChainLength())

		require.NoError(t, err)

		// Checks that all returned are unique pair-wise
		// primes with an Nth-primitive root.
		list := map[uint64]bool{}
		for _, q := range primes {
			require.Equal(t, q&uint64(NthRoot-1), uint64(1))
			require.True(t, IsPrime(q), q)
			_, ok := list[q]
			require.False(t, ok)
			list[q] = true
		}

		upstreamPrimes, err := g.NextUpstreamPrimes(tc.ringQ.ModuliChainLength())
		require.NoError(t, err)
		for i := range upstreamPrimes {
			if i == 0 {
				require.True(t, IsPrime(upstreamPrimes[i]))
			} else {
				require.True(t, IsPrime(upstreamPrimes[i]) && upstreamPrimes[i] > upstreamPrimes[i-1])
			}

		}

		downstreamPrimes, err := g.NextDownstreamPrimes(tc.ringQ.ModuliChainLength())
		require.NoError(t, err)
		for i := range downstreamPrimes {
			if i == 0 {
				require.True(t, IsPrime(downstreamPrimes[i]))
			} else {
				require.True(t, IsPrime(downstreamPrimes[i]) && downstreamPrimes[i] < downstreamPrimes[i-1])
			}
		}
	})
}

func testDivFloorByLastModulusMany(tc *testParams, t *testing.T) {

	t.Run(testString("DivFloorByLastModulusMany", tc.ringQ), func(t *testing.T) {

		source := sampling.NewSource(sampling.NewSeed())

		N := tc.ringQ.N()

		level := tc.ringQ.Level()

		ringQ := tc.ringQ.AtLevel(level)

		coeffs := make([]big.Int, N)
		Q := tc.ringQ.Modulus()
		for i := 0; i < N; i++ {
			coeffs[i] = *bignum.RandInt(source, Q)
			coeffs[i].Quo(&coeffs[i], bignum.NewInt(10))
		}

		nbRescales := level

		coeffsWant := make([]big.Int, N)
		for i := range coeffs {
			coeffsWant[i].Set(&coeffs[i])
			for j := 0; j < nbRescales; j++ {
				coeffsWant[i].Quo(&coeffsWant[i], bignum.NewInt(tc.ringQ[level-j].Modulus))
			}
		}

		polTest0 := tc.ringQ.NewRNSPoly()
		polTest1 := tc.ringQ.NewRNSPoly()
		polWant := tc.ringQ.NewRNSPoly()
		buff := tc.ringQ.NewRNSPoly()

		ringQ.SetCoefficientsBigint(coeffs, polTest0)
		ringQ.SetCoefficientsBigint(coeffsWant, polWant)
		ringQ.DivFloorByLastModulusMany(nbRescales, polTest0, buff, polTest1)

		for i := 0; i < N; i++ {
			for j := 0; j < polTest0.Level()-nbRescales+1; j++ {
				require.Equalf(t, polWant.At(j)[i], polTest1.At(j)[i], "coeff %v Qi%v = %s", i, j, coeffs[i].String())
			}
		}
	})
}

func testDivRoundByLastModulusMany(tc *testParams, t *testing.T) {

	t.Run(testString("bignum.DivRoundByLastModulusMany", tc.ringQ), func(t *testing.T) {

		source := sampling.NewSource(sampling.NewSeed())

		N := tc.ringQ.N()

		level := tc.ringQ.Level()

		ringQ := tc.ringQ.AtLevel(level)

		coeffs := make([]big.Int, N)
		Q := tc.ringQ.Modulus()
		for i := 0; i < N; i++ {
			coeffs[i] = *bignum.RandInt(source, Q)
			coeffs[i].Quo(&coeffs[i], bignum.NewInt(10))
		}

		nbRescals := level

		coeffsWant := make([]big.Int, N)
		for i := range coeffs {
			coeffsWant[i].Set(&coeffs[i])
			for j := 0; j < nbRescals; j++ {
				bignum.DivRound(&coeffsWant[i], bignum.NewInt(tc.ringQ[level-j].Modulus), &coeffsWant[i])
			}
		}

		polTest0 := tc.ringQ.NewRNSPoly()
		polTest1 := tc.ringQ.NewRNSPoly()
		polWant := tc.ringQ.NewRNSPoly()
		buff := tc.ringQ.NewRNSPoly()

		ringQ.SetCoefficientsBigint(coeffs, polTest0)
		ringQ.SetCoefficientsBigint(coeffsWant, polWant)

		ringQ.DivRoundByLastModulusMany(nbRescals, polTest0, buff, polTest1)

		for i := 0; i < N; i++ {
			for j := 0; j < polTest0.Level()-nbRescals+1; j++ {
				require.Equalf(t, polWant.At(j)[i], polTest1.At(j)[i], "coeff %v Qi%v = %s", i, j, coeffs[i].String())
			}
		}
	})
}

func testMarshalBinary(tc *testParams, t *testing.T) {

	t.Run(testString("MarshalBinary/Ring", tc.ringQ), func(t *testing.T) {

		var err error

		var data []byte
		if data, err = tc.ringQ.MarshalBinary(); err != nil {
			t.Fatal(err)
		}

		var ringQTest RNSRing
		if err = ringQTest.UnmarshalBinary(data); err != nil {
			t.Fatal(err)
		}

		require.Equal(t, ringQTest, tc.ringQ)
	})

	t.Run(testString("MarshalBinary/RNSPoly", tc.ringQ), func(t *testing.T) {
		poly := tc.uniformSamplerQ.ReadNew(tc.ringQ.N())
		buffer.RequireSerializerCorrect(t, &poly)
	})

	t.Run(testString("structs/PolyVector", tc.ringQ), func(t *testing.T) {

		polys := make([]RNSPoly, 4)

		for i := range polys {
			polys[i] = tc.uniformSamplerQ.ReadNew(tc.ringQ.N())
		}

		v := structs.Vector[RNSPoly](polys)

		buffer.RequireSerializerCorrect(t, &v)
	})

	t.Run(testString("structs/PolyMatrix", tc.ringQ), func(t *testing.T) {

		polys := make([][]RNSPoly, 4)

		for i := range polys {
			polys[i] = make([]RNSPoly, 4)

			for j := range polys {
				polys[i][j] = tc.uniformSamplerQ.ReadNew(tc.ringQ.N())
			}
		}

		m := structs.Matrix[RNSPoly](polys)

		buffer.RequireSerializerCorrect(t, &m)
	})

	t.Run(testString("structs/PolyMap", tc.ringQ), func(t *testing.T) {

		m := make(structs.Map[int, RNSPoly], 4)

		for i := 0; i < 4; i++ {
			p := tc.uniformSamplerQ.ReadNew(tc.ringQ.N())
			m[i] = &p
		}

		buffer.RequireSerializerCorrect(t, &m)
	})
}

func testWriterAndReader(tc *testParams, t *testing.T) {

	t.Run(testString("WriterAndReader/RNSPoly", tc.ringQ), func(t *testing.T) {

		p := tc.uniformSamplerQ.ReadNew(tc.ringQ.N())

		data := make([]byte, 0, p.BinarySize())

		buf := bytes.NewBuffer(data) // Complient to io.Writer and io.Reader

		if n, err := p.WriteTo(buf); err != nil {
			t.Fatal(err)
		} else {
			if int(n) != p.BinarySize() {
				t.Fatal()
			}
		}

		if data2, err := p.MarshalBinary(); err != nil {
			t.Fatal(err)
		} else {
			if !bytes.Equal(buf.Bytes(), data2) {
				t.Fatal()
			}
		}

		pTest := new(RNSPoly)
		if n, err := pTest.ReadFrom(buf); err != nil {
			t.Fatal(err)
		} else {
			if int(n) != p.BinarySize() {
				t.Fatal()
			}
		}

		for i := range tc.ringQ {
			require.Equal(t, p.At(i)[:tc.ringQ.N()], pTest.At(i)[:tc.ringQ.N()])
		}
	})
}

func testSampler(tc *testParams, t *testing.T) {

	N := tc.ringQ.N()

	t.Run(testString("Sampler/Uniform", tc.ringQ), func(t *testing.T) {
		pol := tc.ringQ.NewRNSPoly()
		tc.uniformSamplerQ.Read(pol)

		for i, qi := range tc.ringQ.ModuliChain() {
			coeffs := pol.At(i)
			for j := 0; j < N; j++ {
				require.False(t, coeffs[j] > qi)
			}
		}
	})

	t.Run(testString("Sampler/Gaussian/SmallSigma", tc.ringQ), func(t *testing.T) {

		dist := &DiscreteGaussian{Sigma: DefaultSigma, Bound: DefaultBound}

		sampler, err := NewSampler(sampling.NewSource([32]byte{}), tc.ringQ.ModuliChain(), dist)
		require.NoError(t, err)

		noiseBound := uint64(dist.Bound)

		pol := sampler.ReadNew(tc.ringQ.N())

		for i := 0; i < N; i++ {
			for j, s := range tc.ringQ {
				require.False(t, noiseBound < pol.At(j)[i] && pol.At(j)[i] < (s.Modulus-noiseBound))
			}
		}
	})

	t.Run(testString("Sampler/Gaussian/LargeSigma", tc.ringQ), func(t *testing.T) {

		dist := &DiscreteGaussian{Sigma: 1e21, Bound: 1e25}

		sampler, err := NewSampler(sampling.NewSource([32]byte{}), tc.ringQ.ModuliChain(), dist)
		require.NoError(t, err)

		pol := sampler.ReadNew(tc.ringQ.N())

		require.InDelta(t, math.Log2(1e21), tc.ringQ.Stats(pol)[0], 1)
	})

	for _, p := range []float64{.5, 1. / 3., 128. / 65536.} {
		t.Run(testString(fmt.Sprintf("Sampler/Ternary/p=%1.2f", p), tc.ringQ), func(t *testing.T) {

			sampler, err := NewSampler(sampling.NewSource([32]byte{}), tc.ringQ.ModuliChain(), &Ternary{P: p})
			require.NoError(t, err)

			pol := sampler.ReadNew(tc.ringQ.N())

			for i, s := range tc.ringQ {
				minOne := s.Modulus - 1
				for _, c := range pol.At(i) {
					require.True(t, c == 0 || c == minOne || c == 1)
				}
			}
		})
	}

	for _, h := range []int{64, 96, 128, 256} {
		t.Run(testString(fmt.Sprintf("Sampler/Ternary/hw=%d", h), tc.ringQ), func(t *testing.T) {

			sampler, err := NewSampler(sampling.NewSource([32]byte{}), tc.ringQ.ModuliChain(), &Ternary{H: h})
			require.NoError(t, err)

			checkPoly := func(pol RNSPoly) {
				for i := range tc.ringQ {
					hw := 0
					for _, c := range pol.At(i) {
						if c != 0 {
							hw++
						}
					}

					require.True(t, hw == h)
				}
			}

			pol := sampler.ReadNew(tc.ringQ.N())

			checkPoly(pol)

			sampler.Read(pol)

			checkPoly(pol)
		})
	}
}

func testModularReduction(tc *testParams, t *testing.T) {

	t.Run(testString("ModularReduction/BRed", tc.ringQ), func(t *testing.T) {

		var x, y uint64
		var bigQ, result *big.Int

		for j, q := range tc.ringQ.ModuliChain() {

			bigQ = bignum.NewInt(q)

			brc := tc.ringQ[j].BRedConstant

			x = 1
			y = 1

			result = bignum.NewInt(x)
			result.Mul(result, bignum.NewInt(y))
			result.Mod(result, bigQ)

			require.Equalf(t, BRed(x, y, q, brc), result.Uint64(), "x = %v, y=%v", x, y)

			x = 1
			y = q - 1

			result = bignum.NewInt(x)
			result.Mul(result, bignum.NewInt(y))
			result.Mod(result, bigQ)

			require.Equalf(t, BRed(x, y, q, brc), result.Uint64(), "x = %v, y=%v", x, y)

			x = 1
			y = 0xFFFFFFFFFFFFFFFF

			result = bignum.NewInt(x)
			result.Mul(result, bignum.NewInt(y))
			result.Mod(result, bigQ)

			require.Equalf(t, BRed(x, y, q, brc), result.Uint64(), "x = %v, y=%v", x, y)

			x = q - 1
			y = q - 1

			result = bignum.NewInt(x)
			result.Mul(result, bignum.NewInt(y))
			result.Mod(result, bigQ)

			require.Equalf(t, BRed(x, y, q, brc), result.Uint64(), "x = %v, y=%v", x, y)

			x = q - 1
			y = 0xFFFFFFFFFFFFFFFF

			result = bignum.NewInt(x)
			result.Mul(result, bignum.NewInt(y))
			result.Mod(result, bigQ)

			require.Equalf(t, BRed(x, y, q, brc), result.Uint64(), "x = %v, y=%v", x, y)

			x = 0xFFFFFFFFFFFFFFFF
			y = 0xFFFFFFFFFFFFFFFF

			result = bignum.NewInt(x)
			result.Mul(result, bignum.NewInt(y))
			result.Mod(result, bigQ)

			require.Equalf(t, BRed(x, y, q, brc), result.Uint64(), "x = %v, y=%v", x, y)
		}
	})

	t.Run(testString("ModularReduction/MRed", tc.ringQ), func(t *testing.T) {

		var x, y uint64
		var bigQ, result *big.Int

		for j, q := range tc.ringQ.ModuliChain() {

			bigQ = bignum.NewInt(q)

			brc := tc.ringQ[j].BRedConstant
			mrc := tc.ringQ[j].MRedConstant

			x = 1
			y = 1

			result = bignum.NewInt(x)
			result.Mul(result, bignum.NewInt(y))
			result.Mod(result, bigQ)

			require.Equalf(t, MRed(x, MForm(y, q, brc), q, mrc), result.Uint64(), "x = %v, y=%v", x, y)

			x = 1
			y = q - 1

			result = bignum.NewInt(x)
			result.Mul(result, bignum.NewInt(y))
			result.Mod(result, bigQ)

			require.Equalf(t, MRed(x, MForm(y, q, brc), q, mrc), result.Uint64(), "x = %v, y=%v", x, y)

			x = 1
			y = 0xFFFFFFFFFFFFFFFF

			result = bignum.NewInt(x)
			result.Mul(result, bignum.NewInt(y))
			result.Mod(result, bigQ)

			require.Equalf(t, MRed(x, MForm(y, q, brc), q, mrc), result.Uint64(), "x = %v, y=%v", x, y)

			x = q - 1
			y = q - 1

			result = bignum.NewInt(x)
			result.Mul(result, bignum.NewInt(y))
			result.Mod(result, bigQ)

			require.Equalf(t, MRed(x, MForm(y, q, brc), q, mrc), result.Uint64(), "x = %v, y=%v", x, y)

			x = q - 1
			y = 0xFFFFFFFFFFFFFFFF

			result = bignum.NewInt(x)
			result.Mul(result, bignum.NewInt(y))
			result.Mod(result, bigQ)

			require.Equalf(t, MRed(x, MForm(y, q, brc), q, mrc), result.Uint64(), "x = %v, y=%v", x, y)

			x = 0xFFFFFFFFFFFFFFFF
			y = 0xFFFFFFFFFFFFFFFF

			result = bignum.NewInt(x)
			result.Mul(result, bignum.NewInt(y))
			result.Mod(result, bigQ)

			require.Equalf(t, MRed(x, MForm(y, q, brc), q, mrc), result.Uint64(), "x = %v, y=%v", x, y)
		}
	})
}

func testMForm(tc *testParams, t *testing.T) {

	t.Run(testString("MForm", tc.ringQ), func(t *testing.T) {

		polWant := tc.uniformSamplerQ.ReadNew(tc.ringQ.N())
		polTest := tc.ringQ.NewRNSPoly()

		tc.ringQ.MForm(polWant, polTest)
		tc.ringQ.IMForm(polTest, polTest)

		require.True(t, tc.ringQ.Equal(polWant, polTest))
	})
}

func testMulScalarBigint(tc *testParams, t *testing.T) {

	t.Run(testString("MulScalarBigint", tc.ringQ), func(t *testing.T) {

		polWant := tc.uniformSamplerQ.ReadNew(tc.ringQ.N())
		polTest := *polWant.Clone()

		rand1 := tc.uniformSamplerQ.Source.Uint64()
		rand2 := tc.uniformSamplerQ.Source.Uint64()

		scalarBigint := bignum.NewInt(rand1)
		scalarBigint.Mul(scalarBigint, bignum.NewInt(rand2))

		tc.ringQ.MulScalar(polWant, rand1, polWant)
		tc.ringQ.MulScalar(polWant, rand2, polWant)
		tc.ringQ.MulScalarBigint(polTest, scalarBigint, polTest)

		require.True(t, tc.ringQ.Equal(polWant, polTest))
	})
}

func testExtendBasis(tc *testParams, t *testing.T) {

	N := tc.ringQ.N()

	t.Run(testString("ModUp", tc.ringQ), func(t *testing.T) {

		source := sampling.NewSource(sampling.NewSeed())

		rQ := tc.ringQ
		rP := tc.ringP

		buffQ := rQ.NewRNSPoly()

		Q := rQ.Modulus()

		QHalf := new(big.Int).Set(Q)
		QHalf.Rsh(QHalf, 1)

		coeffs := make([]big.Int, N)
		for i := 0; i < N; i++ {
			coeffs[i] = *bignum.RandInt(source, Q)
			coeffs[i].Sub(&coeffs[i], QHalf)
		}

		PolQHave := rQ.NewRNSPoly()
		PolPTest := rP.NewRNSPoly()
		PolPWant := rP.NewRNSPoly()

		rQ.SetCoefficientsBigint(coeffs, PolQHave)
		rP.SetCoefficientsBigint(coeffs, PolPWant)

		rQ.ModUp(rP, PolQHave, buffQ, PolPTest)
		rP.Reduce(PolPTest, PolPTest)

		for i := 0; i < PolPWant.Level()+1; i++ {
			for j := 0; j < N; j++ {
				require.Equal(t, PolPWant.At(i)[j], PolPTest.At(i)[j])
			}
		}
	})

	t.Run(testString("ModDown", tc.ringQ), func(t *testing.T) {

		source := sampling.NewSource(sampling.NewSeed())

		rQ := tc.ringQ
		rP := tc.ringP

		buffQ := rQ.NewRNSPoly()
		buffP := rP.NewRNSPoly()

		Q := rQ.Modulus()
		P := rP.Modulus()

		QP := new(big.Int).Mul(Q, P)

		coeffs := make([]big.Int, N)
		for i := 0; i < N; i++ {
			coeffs[i] = *bignum.RandInt(source, QP)
			coeffs[i].Quo(&coeffs[i], bignum.NewInt(10))
		}

		coeffsWant := make([]big.Int, N)
		for i := range coeffs {
			coeffsWant[i].Set(&coeffs[i])
			bignum.DivRound(&coeffsWant[i], P, &coeffsWant[i])
		}

		PolQHave := rQ.NewRNSPoly()
		PolPHave := rP.NewRNSPoly()
		PolQWant := rQ.NewRNSPoly()

		rQ.SetCoefficientsBigint(coeffs, PolQHave)
		rP.SetCoefficientsBigint(coeffs, PolPHave)
		rQ.SetCoefficientsBigint(coeffsWant, PolQWant)

		rQ.ModDown(rP, PolQHave, PolPHave, buffQ, buffP, PolQHave)
		rQ.Reduce(PolQHave, PolQHave)

		for i := 0; i < PolQHave.Level()+1; i++ {
			for j := 0; j < N; j++ {
				require.Equal(t, PolQHave.At(i)[j], PolQWant.At(i)[j])
			}
		}
	})
}

func testMultByMonomial(tc *testParams, t *testing.T) {

	t.Run(testString("MultByMonomial", tc.ringQ), func(t *testing.T) {

		p1 := tc.uniformSamplerQ.ReadNew(tc.ringQ.N())

		p3Test := tc.ringQ.NewRNSPoly()
		p3Want := tc.ringQ.NewRNSPoly()

		tc.ringQ.MultByMonomial(p1, 1, p3Test)
		tc.ringQ.MultByMonomial(p3Test, 8, p3Test)

		tc.ringQ.MultByMonomial(p1, 9, p3Want)

		require.Equal(t, p3Want.At(0)[:tc.ringQ.N()], p3Test.At(0)[:tc.ringQ.N()])
	})
}

func testShift(t *testing.T) {

	r, _ := NewRNSRing(16, []uint64{97})
	p1, p2 := r.NewRNSPoly(), r.NewRNSPoly()

	for i := range p1.At(0) {
		p1.At(0)[i] = uint64(i)
	}

	r.Shift(p1, 3, p2)
	require.Equal(t, p2.At(0), Poly([]uint64{3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2}))

}
