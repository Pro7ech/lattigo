package rgsw

import (
	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
)

// NoiseCiphertext returns the base two logarithm of the standard deviation of the noise of each component of an [rgsw.Ciphertext].
// pt must be in the NTT and Montgomery domain
func NoiseCiphertext(ct *Ciphertext, pt ring.RNSPoly, sk *rlwe.SecretKey, params rlwe.Parameters) (float64, float64) {
	ptsk := *pt.Clone()
	params.RingQ().AtLevel(ct.LevelQ()).MulCoeffsMontgomery(ptsk, sk.Q, ptsk)
	return rlwe.NoiseGadgetCiphertext(ct.At(0), pt, sk, params), rlwe.NoiseGadgetCiphertext(ct.At(1), ptsk, sk, params)
}
