package rlwe

import (
	"fmt"

	"github.com/Pro7ech/lattigo/ring"
)

// KeyGenerator is a structure that stores the elements required to create new keys,
// as well as a memory buffer for intermediate values.
type KeyGenerator struct {
	*Encryptor
	Point ring.Point
}

// NewKeyGenerator creates a new KeyGenerator, from which the secret and public keys, as well as EvaluationKeys.
func NewKeyGenerator(params ParameterProvider) *KeyGenerator {
	p := params.GetRLWEParameters()
	return &KeyGenerator{
		Encryptor: NewEncryptor(params, nil),
		Point:     *ring.NewPoint(p.N(), p.MaxLevelQ(), p.MaxLevelP()),
	}
}

// ShallowCopy creates a shallow copy of the receiver in which ll athe read-only data-structures are
// shared with the receiver and the temporary buffers are reallocated. The receiver and the returned
// object can be used concurrently.
func (kgen KeyGenerator) ShallowCopy() *KeyGenerator {
	return &KeyGenerator{
		Encryptor: kgen.Encryptor.ShallowCopy(),
		Point:     *kgen.Point.Clone(),
	}
}

// GenSecretKeyNew generates a new SecretKey.
// Distribution is set according to `rlwe.Parameters.HammingWeight()`.
func (kgen KeyGenerator) GenSecretKeyNew() (sk *SecretKey) {
	sk = NewSecretKey(kgen.params)
	kgen.GenSecretKey(sk)
	return
}

// GenSecretKey generates a SecretKey.
// Distribution is set according to `rlwe.Parameters.HammingWeight()`.
func (kgen KeyGenerator) GenSecretKey(sk *SecretKey) {
	kgen.GenSecretKeyFromSampler(kgen.xuSampler, sk)
}

// GenSecretKeyWithHammingWeightNew generates a new SecretKey with exactly hw non-zero coefficients.
func (kgen *KeyGenerator) GenSecretKeyWithHammingWeightNew(hw int) (sk *SecretKey) {
	sk = NewSecretKey(kgen.params)
	kgen.GenSecretKeyWithHammingWeight(hw, sk)
	return
}

// GenSecretKeyWithHammingWeight generates a SecretKey with exactly hw non-zero coefficients.
func (kgen KeyGenerator) GenSecretKeyWithHammingWeight(hw int, sk *SecretKey) {

	Xs, err := ring.NewSampler(kgen.xuSampler.GetSource(), kgen.params.RingQ().ModuliChain(), &ring.Ternary{H: hw})
	if err != nil {
		// Sanity check, this error should not happen.
		panic(err)
	}

	kgen.GenSecretKeyFromSampler(Xs, sk)
}

func (kgen KeyGenerator) GenSecretKeyFromSampler(sampler ring.Sampler, sk *SecretKey) {

	LevelQ := sk.LevelQ()
	LevelP := sk.LevelP()

	rQ := kgen.params.RingQ().AtLevel(LevelQ)

	var rP ring.RNSRing
	if rP = kgen.params.RingP(); rP.Level() != -1 && LevelP > -1 {
		rP = rP.AtLevel(LevelP)
	}

	sampler.AtLevel(LevelQ).Read(sk.Q)

	if LevelP > -1 {
		ring.ExtendBasisSmallNorm(rQ[0].Modulus, rP.ModuliChain(), sk.Q, sk.P)
	}

	rQ.NTT(sk.Q, sk.Q)
	rQ.MForm(sk.Q, sk.Q)

	if LevelP > -1 {
		rP.NTT(sk.P, sk.P)
		rP.MForm(sk.P, sk.P)
	}
}

// GenPublicKeyNew generates a new public key from the provided SecretKey.
func (kgen KeyGenerator) GenPublicKeyNew(sk *SecretKey) (pk *PublicKey) {
	pk = NewPublicKey(kgen.params)
	kgen.GenPublicKey(sk, pk)
	return
}

// GenPublicKey generates a public key from the provided SecretKey.
func (kgen KeyGenerator) GenPublicKey(sk *SecretKey, pk *PublicKey) {
	if err := kgen.WithKey(sk).EncryptZero(pk.AsCiphertext()); err != nil {
		// Sanity check, this error should not happen.
		panic(err)
	}
}

// GenKeyPairNew generates a new SecretKey and a corresponding public key.
// Distribution is of the SecretKey set according to `rlwe.Parameters.HammingWeight()`.
func (kgen KeyGenerator) GenKeyPairNew() (sk *SecretKey, pk *PublicKey) {
	sk = kgen.GenSecretKeyNew()
	pk = kgen.GenPublicKeyNew(sk)
	return
}

// GenRelinearizationKeyNew generates a new EvaluationKey that will be used to relinearize Ciphertexts during multiplication.
func (kgen KeyGenerator) GenRelinearizationKeyNew(sk *SecretKey, evkParams ...EvaluationKeyParameters) (rlk *RelinearizationKey) {
	levelQ, levelP, dd := ResolveEvaluationKeyParameters(kgen.params, evkParams)
	rlk = &RelinearizationKey{EvaluationKey: EvaluationKey{GadgetCiphertext: *NewGadgetCiphertext(kgen.params, 1, levelQ, levelP, dd)}}
	kgen.GenRelinearizationKey(sk, rlk)
	return
}

// GenRelinearizationKey generates an EvaluationKey that will be used to relinearize Ciphertexts during multiplication.
func (kgen KeyGenerator) GenRelinearizationKey(sk *SecretKey, rlk *RelinearizationKey) {
	kgen.params.RingQ().AtLevel(rlk.LevelQ()).MulCoeffsMontgomery(sk.Q, sk.Q, kgen.BuffQ[2])
	kgen.genEvaluationKey(kgen.BuffQ[2], sk.Point, &rlk.EvaluationKey)
}

// GenGaloisKeyNew generates a new GaloisKey, enabling the automorphism X^{i} -> X^{i * galEl}.
func (kgen KeyGenerator) GenGaloisKeyNew(galEl uint64, sk *SecretKey, evkParams ...EvaluationKeyParameters) (gk *GaloisKey) {
	levelQ, levelP, dd := ResolveEvaluationKeyParameters(kgen.params, evkParams)
	gk = &GaloisKey{
		EvaluationKey: EvaluationKey{GadgetCiphertext: *NewGadgetCiphertext(kgen.params, 1, levelQ, levelP, dd)},
		NthRoot:       kgen.params.GetRLWEParameters().RingQ().NthRoot(),
	}
	kgen.GenGaloisKey(galEl, sk, gk)
	return
}

// GenGaloisKey generates a GaloisKey, enabling the automorphism X^{i} -> X^{i * galEl}.
func (kgen KeyGenerator) GenGaloisKey(galEl uint64, sk *SecretKey, gk *GaloisKey) {

	skIn := sk.Point
	skOut := kgen.Point

	// We encrypt [-a * pi_{k^-1}(sk) + sk, a]
	// This enables to first apply the gadget product, re-encrypting
	// a ciphetext from sk to pi_{k^-1}(sk) and then we apply pi_{k}
	// on the ciphertext.
	galElInv := kgen.params.ModInvGaloisElement(galEl)

	rQ := kgen.params.RingQ().AtLevel(gk.LevelQ())
	index, err := ring.AutomorphismNTTIndex(rQ.N(), rQ.NthRoot(), galElInv)

	// Sanity check, this error should not happen unless the
	// evaluator's buffer thave been improperly tempered with.
	if err != nil {
		panic(err)
	}

	rQ.AutomorphismNTTWithIndex(skIn.Q, index, skOut.Q)

	LevelP := gk.LevelP()
	if rP := kgen.params.RingP(); rP != nil {
		rP = rP.AtLevel(LevelP)
		rP.AutomorphismNTTWithIndex(skIn.P, index, skOut.P)
	}

	kgen.genEvaluationKey(skIn.Q, skOut, &gk.EvaluationKey)

	gk.GaloisElement = galEl
	gk.NthRoot = rQ.NthRoot()
}

// GenGaloisKeys generates the GaloisKey objects for all galois elements in galEls, and stores
// the resulting key for galois element i in gks[i].
// The galEls and gks parameters must have the same length.
func (kgen KeyGenerator) GenGaloisKeys(galEls []uint64, sk *SecretKey, gks []*GaloisKey) {

	// Sanity check
	if len(galEls) != len(gks) {
		panic(fmt.Errorf("galEls and gks must have the same length"))
	}

	for i, galEl := range galEls {
		if gks[i] == nil {
			gks[i] = kgen.GenGaloisKeyNew(galEl, sk)
		} else {
			kgen.GenGaloisKey(galEl, sk, gks[i])
		}
	}
}

// GenGaloisKeysNew generates the GaloisKey objects for all galois elements in galEls, and
// returns the resulting keys in a newly allocated []*GaloisKey.
func (kgen KeyGenerator) GenGaloisKeysNew(galEls []uint64, sk *SecretKey, evkParams ...EvaluationKeyParameters) (gks []*GaloisKey) {
	gks = make([]*GaloisKey, len(galEls))
	for i, galEl := range galEls {
		gks[i] = NewGaloisKey(kgen.params, evkParams...)
		kgen.GenGaloisKey(galEl, sk, gks[i])
	}
	return
}

// GenEvaluationKeysForRingSwapNew generates the necessary EvaluationKeys to switch from a standard ring to to a conjugate invariant ring and vice-versa.
func (kgen KeyGenerator) GenEvaluationKeysForRingSwapNew(skStd, skConjugateInvariant *SecretKey, evkParams ...EvaluationKeyParameters) (stdToci, ciToStd *EvaluationKey) {

	LevelQ := min(skStd.LevelQ(), skConjugateInvariant.LevelQ())

	rQ := kgen.params.RingQ().AtLevel(LevelQ)
	rP := kgen.params.RingP()

	skCIMappedToStandard := &SecretKey{}
	skCIMappedToStandard.Q = rQ.NewRNSPoly()
	if rP.Level() != -1 {
		skCIMappedToStandard.P = rP.NewRNSPoly()
	}

	rQ.UnfoldConjugateInvariantToStandard(skConjugateInvariant.Q, skCIMappedToStandard.Q)

	if rP != nil {
		rQ.INTT(skCIMappedToStandard.Q, kgen.BuffQ[1])
		rQ.IMForm(kgen.BuffQ[1], kgen.BuffQ[1])
		ring.ExtendBasisSmallNorm(rQ[0].Modulus, rP.ModuliChain(), kgen.BuffQ[1], skCIMappedToStandard.P)
		rP.NTT(skCIMappedToStandard.P, skCIMappedToStandard.P)
		rP.MForm(skCIMappedToStandard.P, skCIMappedToStandard.P)
	}

	stdToci = NewEvaluationKey(kgen.params, evkParams...)
	kgen.GenEvaluationKey(skStd, skCIMappedToStandard, stdToci)

	ciToStd = NewEvaluationKey(kgen.params, evkParams...)
	kgen.GenEvaluationKey(skCIMappedToStandard, skStd, ciToStd)

	return
}

// GenEvaluationKeyNew generates a new EvaluationKey, that will re-encrypt a Ciphertext encrypted under the input key into the output key.
// If the ringDegree(skOutput) > ringDegree(skInput),  generates [-a*SkOut + w*P*skIn_{Y^{N/n}} + e, a] in X^{N}.
// If the ringDegree(skOutput) < ringDegree(skInput),  generates [-a*skOut_{Y^{N/n}} + w*P*skIn + e_{N}, a_{N}] in X^{N}.
// Else generates [-a*skOut + w*P*skIn + e, a] in X^{N}.
// The output EvaluationKey is always given in max(N, n) and in the moduli of the output EvaluationKey.
// When re-encrypting a Ciphertext from Y^{N/n} to X^{N}, the Ciphertext must first be mapped to X^{N}
// using SwitchCiphertextRingDegreeNTT(ctSmallDim, nil, ctLargeDim).
// When re-encrypting a Ciphertext from X^{N} to Y^{N/n}, the output of the re-encryption is in still X^{N} and
// must be mapped Y^{N/n} using SwitchCiphertextRingDegreeNTT(ctLargeDim, ringQLargeDim, ctSmallDim).
func (kgen KeyGenerator) GenEvaluationKeyNew(skInput, skOutput *SecretKey, evkParams ...EvaluationKeyParameters) (evk *EvaluationKey) {
	evk = NewEvaluationKey(kgen.params, evkParams...)
	kgen.GenEvaluationKey(skInput, skOutput, evk)
	return
}

// GenEvaluationKey generates an EvaluationKey, that will re-encrypt a Ciphertext encrypted under the input key into the output key.
// If the ringDegree(skOutput) > ringDegree(skInput),  generates [-a*SkOut + w*P*skIn_{Y^{N/n}} + e, a] in X^{N}.
// If the ringDegree(skOutput) < ringDegree(skInput),  generates [-a*skOut_{Y^{N/n}} + w*P*skIn + e_{N}, a_{N}] in X^{N}.
// Else generates [-a*skOut + w*P*skIn + e, a] in X^{N}.
// The output EvaluationKey is always given in max(N, n) and in the moduli of the output EvaluationKey.
// When re-encrypting a Ciphertext from Y^{N/n} to X^{N}, the Ciphertext must first be mapped to X^{N}
// using SwitchCiphertextRingDegreeNTT(ctSmallDim, nil, ctLargeDim).
// When re-encrypting a Ciphertext from X^{N} to Y^{N/n}, the output of the re-encryption is in still X^{N} and
// must be mapped Y^{N/n} using SwitchCiphertextRingDegreeNTT(ctLargeDim, ringQLargeDim, ctSmallDim).
func (kgen KeyGenerator) GenEvaluationKey(skInput, skOutput *SecretKey, evk *EvaluationKey) {

	rQ := kgen.params.RingQ().AtLevel(evk.LevelQ())
	rP := kgen.params.RingP()

	pQ := kgen.BuffQ[0]

	skOut := kgen.Point

	// Maps the smaller key to the largest with Y = X^{N/n}.
	rQ.SwitchRingDegreeNTT(skOutput.Q, kgen.BuffQ[1].At(0), skOut.Q)

	// Extends the modulus P of skOutput to the one of skInput
	if LevelP := evk.LevelP(); LevelP != -1 {
		rQ.INTT(skOut.Q, pQ)
		rQ.IMForm(pQ, pQ)
		ring.ExtendBasisSmallNorm(rQ[0].Modulus, rP.ModuliChain(), pQ, skOut.P)
		rP.NTT(skOut.P, skOut.P)
		rP.MForm(skOut.P, skOut.P)
	}

	// Maps the smaller key to the largest dimension with Y = X^{N/n}.
	rQ.SwitchRingDegreeNTT(skInput.Q, kgen.BuffQ[1].At(0), pQ)

	rQ.INTT(pQ, kgen.BuffQ[1])
	rQ.IMForm(kgen.BuffQ[1], kgen.BuffQ[1])
	ring.ExtendBasisSmallNorm(rQ[0].Modulus, rQ.ModuliChain(), kgen.BuffQ[1], pQ)
	rQ.NTT(pQ, pQ)
	rQ.MForm(pQ, pQ)

	kgen.genEvaluationKey(pQ, skOut, evk)
}

func (kgen KeyGenerator) genEvaluationKey(skIn ring.RNSPoly, skOut ring.Point, evk *EvaluationKey) {

	enc := kgen.WithKey(&SecretKey{Point: skOut})

	pt := &Plaintext{}
	pt.Point = &ring.Point{}
	pt.MetaData = &MetaData{}
	pt.IsNTT = true
	pt.IsMontgomery = true
	pt.Q = skIn

	if err := enc.Encrypt(pt, &evk.GadgetCiphertext); err != nil {
		// Sanity check, this error should not happen.
		panic(err)
	}
}
