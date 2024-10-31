package he

import (
	"fmt"
	"math"
	"math/big"
	"math/bits"
	"math/rand"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils"
)

const (
	LogNLarge = 10
	LogNSmall = 8
)

func testString(params rlwe.Parameters, opname string) string {
	return fmt.Sprintf("%s/logN=%d/Qi=%d/Pi=%d/NTT=%t",
		opname,
		params.LogN(),
		params.QCount(),
		params.PCount(),
		params.NTTFlag())
}

func TestRLWE(t *testing.T) {

	var err error

	paramsLit := rlwe.ParametersLiteral{
		LogN:    LogNLarge,
		LogQ:    []int{60},
		LogP:    []int{60},
		NTTFlag: true,
	}

	for _, NTTFlag := range []bool{true, false} {

		paramsLit.NTTFlag = NTTFlag

		var params rlwe.Parameters
		if params, err = rlwe.NewParametersFromLiteral(paramsLit); err != nil {
			t.Fatal(err)
		}

		tc, err := NewTestContext(params)
		require.NoError(t, err)

		for _, testSet := range []func(tc *TestContext, t *testing.T){
			testRingPacking,
		} {
			testSet(tc, t)
			runtime.GC()
		}
	}
}

type TestContext struct {
	params rlwe.Parameters
	kgen   *rlwe.KeyGenerator
	enc    *rlwe.Encryptor
	dec    *rlwe.Decryptor
	sk     *rlwe.SecretKey
	pk     *rlwe.PublicKey
}

func NewTestContext(params rlwe.Parameters) (tc *TestContext, err error) {
	kgen := rlwe.NewKeyGenerator(params)
	sk := kgen.GenSecretKeyNew()

	pk := kgen.GenPublicKeyNew(sk)

	enc := rlwe.NewEncryptor(params, sk)

	dec := rlwe.NewDecryptor(params, sk)

	return &TestContext{
		params: params,
		kgen:   kgen,
		sk:     sk,
		pk:     pk,
		enc:    enc,
		dec:    dec,
	}, nil
}

func testRingPacking(tc *TestContext, t *testing.T) {

	params := tc.params
	sk := tc.sk
	enc := tc.enc
	dec := tc.dec
	level := params.MaxLevel()

	evkParams := rlwe.EvaluationKeyParameters{
		LevelQ: utils.Pointy(params.MaxLevelQ()),
		LevelP: utils.Pointy(params.MaxLevelP()),
	}

	evkRP := RingPackingEvaluationKey{}

	ski, err := evkRP.GenRingSwitchingKeys(params, sk, LogNSmall, evkParams)
	require.NoError(t, err)

	evkRP.GenRepackEvaluationKeys(evkRP.Parameters[LogNSmall], ski[LogNSmall], evkParams)
	evkRP.GenRepackEvaluationKeys(evkRP.Parameters[params.LogN()], ski[params.LogN()], evkParams)
	evkRP.GenExtractEvaluationKeys(evkRP.Parameters[LogNSmall], ski[LogNSmall], evkParams)

	eval := NewRingPackingEvaluator(&evkRP)

	t.Run(testString(params, "Split"), func(t *testing.T) {

		pt := genPlaintextNTT(params, level, 1<<40)
		ct := rlwe.NewCiphertext(params, 1, level, -1)

		require.NoError(t, enc.Encrypt(pt, ct))

		ctEvenNHalf, ctOddNHalf, err := eval.SplitNew(ct)

		if eval.MaxLogN() == eval.MinLogN() {
			require.Error(t, err)
			t.Skip("eval.MaxLogN() = eval.MinLogN()")
		} else {
			require.NoError(t, err)

			paramsNHalf := eval.Parameters[ctEvenNHalf.LogN()].GetRLWEParameters()
			rQ := paramsNHalf.RingQAtLevel(ct.Level())

			decNHalf := rlwe.NewDecryptor(paramsNHalf, ski[paramsNHalf.LogN()])

			ptEve := decNHalf.DecryptNew(ctEvenNHalf)
			ptOdd := decNHalf.DecryptNew(ctOddNHalf)

			if ptEve.IsNTT {
				rQ.INTT(ptEve.Q, ptEve.Q)
			}

			if ptOdd.IsNTT {
				rQ.INTT(ptOdd.Q, ptOdd.Q)
			}

			if pt.IsNTT {
				params.RingQAtLevel(ct.Level()).INTT(pt.Q, pt.Q)
			}

			for i := 0; i < level+1; i++ {

				Q := rQ[i].Modulus
				ref := pt.Q.At(i)
				eve := ptEve.Q.At(i)
				odd := ptOdd.Q.At(i)

				for j := 0; j < paramsNHalf.N(); j++ {
					eve[j] = ring.CRed(eve[j]+Q-ref[j*2+0], Q)
					odd[j] = ring.CRed(odd[j]+Q-ref[j*2+1], Q)
				}
			}

			require.GreaterOrEqual(t, float64(paramsNHalf.LogN()+1), rQ.Stats(ptEve.Q)[0])
			require.GreaterOrEqual(t, float64(paramsNHalf.LogN()+1), rQ.Stats(ptOdd.Q)[0])
		}
	})

	t.Run(testString(params, "Merge"), func(t *testing.T) {

		if eval.MaxLogN() == eval.MinLogN() {
			t.Skip("eval.MaxLogN() = eval.MinLogN()")
		}

		paramsNHalf := *eval.Parameters[params.LogN()-1].GetRLWEParameters()
		encNHalf := rlwe.NewEncryptor(paramsNHalf, ski[paramsNHalf.LogN()])

		ptEve := genPlaintextNTT(paramsNHalf, level, 1<<40)
		ptOdd := genPlaintextNTT(paramsNHalf, level, 1<<40)

		ctEve := rlwe.NewCiphertext(paramsNHalf, 1, ptEve.Level(), -1)
		require.NoError(t, encNHalf.Encrypt(ptEve, ctEve))

		ctOdd := rlwe.NewCiphertext(paramsNHalf, 1, ptOdd.Level(), -1)
		require.NoError(t, encNHalf.Encrypt(ptOdd, ctOdd))

		ct, err := eval.MergeNew(ctEve, ctOdd)
		require.NoError(t, err)

		pt := dec.DecryptNew(ct)

		if pt.IsNTT {
			params.RingQAtLevel(level).INTT(pt.Q, pt.Q)
		}

		if ptEve.IsNTT {
			paramsNHalf.RingQAtLevel(level).INTT(ptEve.Q, ptEve.Q)
		}

		if ptOdd.IsNTT {
			paramsNHalf.RingQAtLevel(level).INTT(ptOdd.Q, ptOdd.Q)
		}

		for i := 0; i < level+1; i++ {
			Q := params.RingQ()[i].Modulus
			ref := pt.Q.At(i)
			eve := ptEve.Q.At(i)
			odd := ptOdd.Q.At(i)
			for j := 0; j < paramsNHalf.N(); j++ {
				ref[2*j+0] = ring.CRed(ref[2*j+0]+Q-eve[j], Q)
				ref[2*j+1] = ring.CRed(ref[2*j+1]+Q-odd[j], Q)
			}
		}

		require.GreaterOrEqual(t, float64(params.LogN()+1), params.RingQAtLevel(level).Stats(pt.Q)[0])
	})

	t.Run(testString(params, "Extract/Naive=False"), func(t *testing.T) {

		if params.RingType() != ring.Standard {
			t.Skip("Expand not supported for ring.Type = ring.ConjugateInvariant")
		}

		ringQ := params.RingQAtLevel(level)

		pt := genPlaintextNTT(params, level, 1<<40)

		ct := rlwe.NewCiphertext(params, 1, pt.Level(), -1)
		require.NoError(t, enc.Encrypt(pt, ct))

		gap := 17
		logGap := bits.Len64(uint64(gap))
		idx := map[int]bool{}
		for i := 0; i < params.N()/gap; i++ {
			idx[i*gap] = true
		}

		ciphertexts, err := eval.Extract(ct, idx)
		require.NoError(t, err)

		// Checks that the number of returned ciphertexts is equal
		// to the size of the index and that each element in the
		// index list has a corresponding extracted ciphertext.
		require.Equal(t, len(ciphertexts), len(idx))
		for i := range idx {
			_, ok := ciphertexts[i]
			require.True(t, ok)
		}

		// Decrypts & Checks
		if pt.IsNTT {
			ringQ.INTT(pt.Q, pt.Q)
		}

		paramsSmallN := evkRP.Parameters[ciphertexts[0].LogN()].GetRLWEParameters()

		ptDec := rlwe.NewPlaintext(paramsSmallN, level, -1)

		rQSmallN := paramsSmallN.RingQAtLevel(level)
		Q := rQSmallN.ModuliChain()

		decSmallN := rlwe.NewDecryptor(paramsSmallN, ski[paramsSmallN.LogN()])

		for i := range idx {

			require.Equal(t, ciphertexts[i].LogN(), paramsSmallN.LogN())

			decSmallN.Decrypt(ciphertexts[i], ptDec)

			if ptDec.IsNTT {
				rQSmallN.INTT(ptDec.Q, ptDec.Q)
			}

			for j := 0; j < level+1; j++ {
				ptDec.Q.At(j)[0] = ring.CRed(ptDec.Q.At(j)[0]+Q[j]-pt.Q.At(j)[i], Q[j])
			}

			// Logs the noise
			require.GreaterOrEqual(t, float64(params.LogN()+logGap+1), rQSmallN.Stats(ptDec.Q)[0])
		}
	})

	t.Run(testString(params, "Extract/Naive=True"), func(t *testing.T) {

		if params.RingType() != ring.Standard {
			t.Skip("Expand not supported for ring.Type = ring.ConjugateInvariant")
		}

		rQ := params.RingQAtLevel(level)

		pt := genPlaintextNTT(params, level, 1<<40)

		ct := rlwe.NewCiphertext(params, 1, pt.Level(), -1)
		require.NoError(t, enc.Encrypt(pt, ct))

		// Generates some extraction index map that contains
		// elements which are both not power and where the
		// smallest gap is not a power of two (to test the
		// worst case)
		gap := 17
		idx := map[int]bool{}
		for i := 0; i < params.N()/gap; i++ {
			idx[i*gap] = true
		}

		// Extract & returns a map containing the extracted RLWE ciphertexts.
		ciphertexts, err := eval.ExtractNaive(ct, idx)
		require.NoError(t, err)

		// Checks that the number of returned ciphertexts is equal
		// to the size of the index and that each element in the
		// index list has a corresponding extracted ciphertext.
		require.Equal(t, len(ciphertexts), len(idx))
		for i := range idx {
			_, ok := ciphertexts[i]
			require.True(t, ok)
		}

		// Decrypts & Checks
		if pt.IsNTT {
			rQ.INTT(pt.Q, pt.Q)
		}

		paramsSmallN := evkRP.Parameters[ciphertexts[0].LogN()].GetRLWEParameters()

		ptDec := rlwe.NewPlaintext(paramsSmallN, level, -1)

		rQSmallN := paramsSmallN.RingQAtLevel(level)
		Q := rQSmallN.ModuliChain()

		decSmallN := rlwe.NewDecryptor(paramsSmallN, ski[paramsSmallN.LogN()])

		for i := range idx {

			require.Equal(t, ciphertexts[i].LogN(), paramsSmallN.LogN())

			decSmallN.Decrypt(ciphertexts[i], ptDec)

			if ptDec.IsNTT {
				rQSmallN.INTT(ptDec.Q, ptDec.Q)
			}

			for j := 0; j < level+1; j++ {
				ptDec.Q.At(j)[0] = ring.CRed(ptDec.Q.At(j)[0]+Q[j]-pt.Q.At(j)[i], Q[j])
			}

			// Logs the noise
			coeffs := make([]big.Int, 1)
			rQSmallN.PolyToBigintCentered(ptDec.Q, rQ.N(), coeffs)
			noise := math.Log2(math.Abs(float64(coeffs[0].Int64())))

			require.GreaterOrEqual(t, float64(params.LogN()), noise)
		}
	})

	t.Run(testString(params, "Repack"), func(t *testing.T) {

		if params.RingType() != ring.Standard {
			t.Skip("Pack not supported for ring.Type = ring.ConjugateInvariant")
		}

		pt := rlwe.NewPlaintext(params, level, -1)
		rQ := tc.params.RingQAtLevel(level)

		ptPacked := genPlaintextNTT(params, level, 1<<40)
		ciphertexts := make(map[int]*rlwe.Ciphertext)

		// Generates ciphertexts where the i-th ciphertext
		// having as constant coefficients the i-th coefficient
		// of the plaintext.
		// Generates a list of ciphertexts indexed by non-power-of-two
		// and where the smallest gap is not a power of two to test
		// the worst case.
		XInvNTT := GenXPow2NTT(rQ, 1, true)[0]
		gap := 3
		for i := 0; i < params.N(); i++ {

			if i%gap == 0 {
				ciphertexts[i] = rlwe.NewCiphertext(params, 1, ptPacked.Level(), -1)
				if err = enc.Encrypt(ptPacked, ciphertexts[i]); err != nil {
					t.Fatal(err)
				}
			}

			rQ.MulCoeffsMontgomery(ptPacked.Q, XInvNTT, ptPacked.Q)
		}

		// Resets plaintext as it has been modified by being sequentially multiplied with X^-1
		ptPacked = genPlaintextNTT(params, level, 1<<40)

		// Repacks the ciphertexts
		ct, err := eval.Repack(ciphertexts)
		require.NoError(t, err)

		// Decrypts & Checks
		dec.Decrypt(ct, pt)

		if pt.IsNTT {
			rQ.INTT(pt.Q, pt.Q)
		}

		if ptPacked.IsNTT {
			rQ.INTT(ptPacked.Q, ptPacked.Q)
		}

		for i := 0; i < level+1; i++ {
			Q := rQ[i].Modulus
			have := pt.Q.At(i)
			ref := ptPacked.Q.At(i)
			for j := 0; j < params.N(); j += gap {
				have[j] = ring.CRed(have[j]+Q-ref[j], Q)
			}
		}

		// Logs the noise
		require.GreaterOrEqual(t, float64(params.LogN()+5), rQ.Stats(pt.Q)[0])
	})

	t.Run(testString(params, "Extract[naive=false]->Permute->Repack[naive=true]"), func(t *testing.T) {
		testExtractPermuteRepack(params, level, enc, dec, eval, false, true, t)
	})

	t.Run(testString(params, "Extract[naive=true]->Permute->Repack[naive=false]"), func(t *testing.T) {
		testExtractPermuteRepack(params, level, enc, dec, eval, true, false, t)
	})
}

func testExtractPermuteRepack(params rlwe.Parameters, level int, enc *rlwe.Encryptor, dec *rlwe.Decryptor, eval *RingPackingEvaluator, ExtractNaive, RepackNaive bool, t *testing.T) {
	if params.RingType() != ring.Standard {
		t.Skip("Expand not supported for ring.Type = ring.ConjugateInvariant")
	}

	rQ := params.RingQAtLevel(level)

	N := params.N()

	pt := genPlaintextNTT(params, level, 1<<40)

	ct := rlwe.NewCiphertext(params, 1, pt.Level(), -1)
	require.NoError(t, enc.Encrypt(pt, ct))

	// Ensures that ct is encrypted at the max
	// defined ring degree
	require.Equal(t, ct.LogN(), eval.MaxLogN())

	// Generates a random index selection
	// of size N/2 (to test that omitted
	// elements output zero coefficients)
	r := rand.New(rand.NewSource(0))
	list := make([]int, params.N())
	for i := range list {
		list[i] = i
	}
	r.Shuffle(len(list), func(i, j int) { list[i], list[j] = list[j], list[i] })

	idx := map[int]bool{}
	for _, i := range list[:params.N()>>1] {
		idx[i] = true
	}

	var err error

	// Extract the coefficients at the given index
	var cts map[int]*rlwe.Ciphertext
	if ExtractNaive {
		cts, err = eval.ExtractNaive(ct, idx)
	} else {
		cts, err = eval.Extract(ct, idx)
	}

	require.NoError(t, err)

	// Checks that the output ciphertext match the smallest
	// defined ring degree
	for i := range cts {
		require.Equal(t, cts[i].LogN(), eval.MinLogN())
	}

	// Defines a new mapping
	permute := func(x int) (y int) {
		return ((x + N/2) & (N - 1))
	}

	// Applies the mapping
	ctsPermute := map[int]*rlwe.Ciphertext{}
	for i := range cts {
		ctsPermute[permute(i)] = cts[i]
	}

	// Repacks with the new permutation
	if RepackNaive {
		ct, err = eval.RepackNaive(ctsPermute)
	} else {
		ct, err = eval.Repack(ctsPermute)
	}
	require.NoError(t, err)

	// Decrypts & Checks
	ptHave := dec.DecryptNew(ct)

	if pt.IsNTT {
		rQ.INTT(pt.Q, pt.Q)
	}

	if ptHave.IsNTT {
		rQ.INTT(ptHave.Q, ptHave.Q)
	}

	for i := 0; i < level+1; i++ {
		Q := rQ[i].Modulus
		have := ptHave.Q.At(i)
		ref := pt.Q.At(i)
		for k0 := range idx {
			k1 := permute(k0)
			have[k1] = ring.CRed(have[k1]+Q-ref[k0], Q)
		}
	}

	// Logs the noise
	require.GreaterOrEqual(t, float64(params.LogN()+5), rQ.Stats(ptHave.Q)[0])
}

func genPlaintextNTT(params rlwe.Parameters, level, max int) (pt *rlwe.Plaintext) {

	N := params.N()

	step := float64(max) / float64(N)

	pt = rlwe.NewPlaintext(params, level, -1)

	for i := 0; i < level+1; i++ {
		c := pt.Q.At(i)
		for j := 0; j < N; j++ {
			c[j] = uint64(float64(j) * step)
		}
	}

	params.RingQAtLevel(level).NTT(pt.Q, pt.Q)
	pt.IsNTT = true

	return
}
