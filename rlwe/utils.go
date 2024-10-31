package rlwe

import (
	"math"
	"math/big"
	"slices"

	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/utils/bignum"
)

// NoiseCiphertext returns the log2 of the standard deviation of the input ciphertext
// with respect to the given secret-key and parameters.
// Function expects:
// - ct and pt NTT domain to match
// - pt to not be in the Montgomery domain
func NoiseCiphertext(ct *Ciphertext, pt *Plaintext, sk *SecretKey, params Parameters) (noise float64) {

	ct = ct.Clone()

	rQ := params.RingQ().AtLevel(ct.LevelQ())

	if !ct.IsNTT {
		rQ.NTT(ct.Q[1], ct.Q[1])
		rQ.NTT(ct.Q[0], ct.Q[0])
	}

	rQ.MulCoeffsMontgomeryThenAdd(sk.Q, ct.Q[1], ct.Q[0])

	if ct.IsMontgomery {
		rQ.IMForm(ct.Q[0], ct.Q[0])
	}

	if ct.IsNTT && pt != nil {
		rQ.Sub(ct.Q[0], pt.Q, ct.Q[0])
	}

	rQ.INTT(ct.Q[0], ct.Q[0])

	if !ct.IsNTT && pt != nil {
		rQ.Sub(ct.Q[0], pt.Q, ct.Q[0])
	}

	values := make([]big.Int, ct.N())

	if rP := params.RingP(); rP != nil && ct.LevelP() > -1 {
		rP = rP.AtLevel(ct.LevelP())

		if !ct.IsNTT {
			rP.NTT(ct.P[1], ct.P[1])
			rP.NTT(ct.Q[0], ct.Q[0])
		}

		rP.MulCoeffsMontgomeryThenAdd(sk.P, ct.P[1], ct.P[0])

		if ct.IsMontgomery {
			rP.IMForm(ct.P[0], ct.P[0])
		}

		if ct.IsNTT && pt != nil {
			rP.Sub(ct.P[0], pt.P, ct.P[0])
		}

		rP.INTT(ct.P[0], ct.P[0])

		if !ct.IsNTT && pt != nil {
			rP.Sub(ct.P[0], pt.P, ct.P[0])
		}

		ring.PolyToBigintCentered(rQ, rP, ct.Q[0], &ct.P[0], 1, values)
	} else {
		ring.PolyToBigintCentered(rQ, nil, ct.Q[0], nil, 1, values)
	}

	return bignum.Stats(values, 128)[0]
}

// NoisePublicKey returns the log2 of the standard deviation of the input public-key with respect to the given secret-key and parameters.
func NoisePublicKey(pk *PublicKey, sk *SecretKey, params Parameters) (noise float64) {
	return NoiseCiphertext(pk.AsCiphertext(), nil, sk, params)
}

// NoiseRelinearizationKey the log2 of the standard deviation of the noise of the input relinearization key with respect to the given secret-key and parameters.
func NoiseRelinearizationKey(rlk *RelinearizationKey, sk *SecretKey, params Parameters) float64 {
	sk2 := sk.Clone()

	params.RingQ().AtLevel(rlk.LevelQ()).MulCoeffsMontgomery(sk2.Q, sk2.Q, sk2.Q)

	if rP := params.RingP(); rP != nil && rlk.LevelP() > -1 {
		rP = rP.AtLevel(rlk.LevelP())
		rP.MulCoeffsMontgomery(sk2.P, sk2.P, sk2.P)
	}

	return NoiseEvaluationKey(&rlk.EvaluationKey, sk2, sk, params)
}

// NoiseGaloisKey the log2 of the standard deviation of the noise of the input Galois key key with respect to the given secret-key and parameters.
func NoiseGaloisKey(gk *GaloisKey, sk *SecretKey, params Parameters) float64 {

	skIn := sk.Clone()
	skOut := sk.Clone()

	nthRoot := params.RingQ().NthRoot()

	galElInv := ring.ModExp(gk.GaloisElement, nthRoot-1, nthRoot)

	params.RingQ().AtLevel(gk.LevelQ()).AutomorphismNTT(sk.Q, galElInv, skOut.Q)

	if rP := params.RingP(); rP != nil && gk.LevelP() > -1 {
		rP = rP.AtLevel(gk.LevelP())
		rP.AutomorphismNTT(sk.P, galElInv, skOut.P)
	}

	return NoiseEvaluationKey(&gk.EvaluationKey, skIn, skOut, params)
}

// NoiseGadgetCiphertext returns the log2 of the standard deviation of the noise of the input gadget ciphertext with respect to the given plaintext, secret-key and parameters.
// The polynomial pt is expected to be in the NTT and Montgomery domain.
func NoiseGadgetCiphertext(gct *GadgetCiphertext, pt ring.RNSPoly, sk *SecretKey, params Parameters) float64 {

	gct = gct.Clone()
	pt = *pt.Clone()

	LevelQ, LevelP := gct.LevelQ(), gct.LevelP()

	rQ := params.RingQAtLevel(LevelQ)
	rP := params.RingPAtLevel(LevelP)

	dims := gct.Dims()

	// Decrypts
	// [-asIn + w*P*sOut + e, a] + [asIn]
	for i := range dims {
		for j := range dims[i] {
			rQ.MulCoeffsMontgomeryThenAdd(gct.Vector[1].Q[i][j], sk.Q, gct.Vector[0].Q[i][j])
			if rP != nil {
				rP.MulCoeffsMontgomeryThenAdd(gct.Vector[1].P[i][j], sk.P, gct.Vector[0].P[i][j])
			}
		}
	}

	elQ := gct.Vector[0].Q[0]

	var elP []ring.RNSPoly

	if LevelP != -1 {
		elP = gct.Vector[0].P[0]
	}

	// Sums all bases together (equivalent to multiplying with CRT decomposition of 1)
	// sum([1]_w * [RNS*PW2*P*sOut + e]) = PWw*P*sOut + sum(e)
	for i := range dims {
		if i > 0 {
			for j := range dims[i] {
				rQ.Add(elQ[j], gct.Vector[0].Q[i][j], elQ[j])
				if rP != nil {
					rP.Add(elP[j], gct.Vector[0].P[i][j], elP[j])
				}
			}
		}
	}

	// sOut * P
	if LevelP != -1 {
		rQ.MulScalarBigint(pt, rP.Modulus(), pt)
	}

	var maxLog2Std float64

	values := make([]big.Int, params.N())

	for j := range slices.Min(dims) { // required else the check becomes very complicated

		// P*s^i + sum(e) - P*s^i = sum(e)
		rQ.Sub(elQ[j], pt, elQ[j])

		// Checks that the error is below the bound
		// Worst error bound is N * floor(6*sigma) * #Keys
		rQ.INTT(elQ[j], elQ[j])
		rQ.IMForm(elQ[j], elQ[j])

		if rP != nil {
			rP.INTT(elP[j], elP[j])
			rP.IMForm(elP[j], elP[j])
			ring.PolyToBigintCentered(rQ, rP, elQ[j], &elP[j], 1, values)
		} else {
			ring.PolyToBigintCentered(rQ, nil, elQ[j], nil, 1, values)
		}

		//fmt.Printf("[")
		//for i := range values{
		//	fmt.Printf("%d, ", &values[i])
		//}
		//fmt.Println("]")

		maxLog2Std = max(maxLog2Std, bignum.Stats(values, 128)[0])

		// sOut * P * PW2
		rQ.MulScalar(pt, 1<<gct.Log2Basis, pt)
	}

	return maxLog2Std
}

// NoiseEvaluationKey the log2 of the standard deviation of the noise of the input Galois key key with respect to the given secret-key and parameters.
func NoiseEvaluationKey(evk *EvaluationKey, skIn, skOut *SecretKey, params Parameters) float64 {
	return NoiseGadgetCiphertext(&evk.GadgetCiphertext, skIn.Q, skOut, params)
}

// Norm returns the log2 of the standard deviation, minimum and maximum absolute norm of
// the decrypted Ciphertext, before the decoding (i.e. including the error).
func Norm(ct *Ciphertext, dec *Decryptor) (std, min, max float64) {

	params := dec.params

	pt := NewPlaintext(params, ct.Level(), -1)

	dec.Decrypt(ct, pt)

	rQ := params.RingQ().AtLevel(ct.Level())

	if pt.IsNTT {
		rQ.INTT(pt.Q, pt.Q)
	}

	values := make([]big.Int, params.N())
	ring.PolyToBigintCentered(rQ, nil, pt.Q, nil, 1, values)

	return NormStats(values)
}

func NormStats(vec []big.Int) (float64, float64, float64) {

	vecfloat := make([]big.Float, len(vec))
	minErr := new(big.Float).SetFloat64(0)
	maxErr := new(big.Float).SetFloat64(0)
	tmp := new(big.Float)
	minErr.SetInt(&vec[0])
	minErr.Abs(minErr)
	for i := range vec {

		vecfloat[i].SetInt(&vec[i])

		tmp.Abs(&vecfloat[i])

		if minErr.Cmp(tmp) == 1 {
			minErr.Set(tmp)
		}

		if maxErr.Cmp(tmp) == -1 {
			maxErr.Set(tmp)
		}
	}

	n := new(big.Float).SetFloat64(float64(len(vec)))

	mean := new(big.Float).SetFloat64(0)

	for i := range vecfloat {
		mean.Add(mean, &vecfloat[i])
	}

	mean.Quo(mean, n)

	err := new(big.Float).SetFloat64(0)
	for i := range vecfloat {
		tmp.Sub(&vecfloat[i], mean)
		tmp.Mul(tmp, tmp)
		err.Add(err, tmp)
	}

	err.Quo(err, n)
	err.Sqrt(err)

	x, _ := err.Float64()
	y, _ := minErr.Float64()
	z, _ := maxErr.Float64()

	return math.Log2(x), math.Log2(y), math.Log2(z)
}

// NTTSparseAndMontgomery takes a polynomial Z[Y] outside of the NTT domain and maps it to a polynomial Z[X] in the NTT domain where Y = X^(gap).
// This method is used to accelerate the NTT of polynomials that encode sparse polynomials.
func NTTSparseAndMontgomery(r ring.RNSRing, metadata *MetaData, pol ring.RNSPoly) {

	if 1<<metadata.LogDimensions.Cols == r.NthRoot()>>2 {

		if metadata.IsNTT {
			r.NTT(pol, pol)
		}

		if metadata.IsMontgomery {
			r.MForm(pol, pol)
		}

	} else {

		var n int
		var NTT func(p1, p2 []uint64, N int, Q, QInv uint64, BRedConstant [2]uint64, nttPsi []uint64)
		switch r.Type() {
		case ring.Standard:
			n = 2 << metadata.LogDimensions.Cols
			NTT = ring.NTTStandard
		case ring.ConjugateInvariant:
			n = 1 << metadata.LogDimensions.Cols
			NTT = ring.NTTConjugateInvariant
		}

		N := r.N()
		gap := N / n
		for i, s := range r {

			coeffs := pol.At(i)

			if metadata.IsMontgomery {
				s.MForm(coeffs[:n], coeffs[:n])
			}

			if metadata.IsNTT {
				// NTT in dimension n but with roots of N
				// This is a small hack to perform at reduced cost an NTT of dimension N on a vector in Y = X^{N/n}, i.e. sparse polynomials.
				NTT(coeffs[:n], coeffs[:n], n, s.Modulus, s.MRedConstant, s.BRedConstant, s.RootsForward)

				// Maps NTT in dimension n to NTT in dimension N
				for j := n - 1; j >= 0; j-- {
					c := coeffs[j]
					for w := 0; w < gap; w++ {
						coeffs[j*gap+w] = c
					}
				}
			} else {
				for j := n - 1; j >= 0; j-- {
					coeffs[j*gap] = coeffs[j]
					for j := 1; j < gap; j++ {
						coeffs[j*gap-j] = 0
					}
				}
			}
		}
	}
}
