package mhe

import (
	"math"

	"github.com/Pro7ech/lattigo/rlwe"
)

// NoiseRelinearizationKey returns the standard deviation of the noise of each individual elements in the collective RelinearizationKey.
func NoiseRelinearizationKey(params rlwe.Parameters, nbParties int) (std float64) {

	// rlk noise = [s*e0 + u*e1 + e2 + e3]
	//
	// s  = sum(s_i)
	// u  = sum(u_i)
	// e0 = sum(e_i0)
	// e1 = sum(e_i1)
	// e2 = sum(e_i2)
	// e3 = sum(e_i3)

	H := float64(nbParties * params.XsHammingWeight())                      // var(sk) and var(u)
	e := float64(nbParties) * params.NoiseFreshSK() * params.NoiseFreshSK() // var(e0), var(e1), var(e2), var(e3)

	// var([s*e0 + u*e1 + e2 + e3]) = H*e + H*e + e + e = e(2H+2) = 2e(H+1)
	return math.Sqrt(2 * e * (H + 1))
}

func NoiseCircularCiphertext(params rlwe.Parameters, hasP bool, d, Log2Basis, nbParties int) (std float64) {

	B := math.Exp2(float64(Log2Basis))
	n := float64(nbParties)
	N := float64(params.N())
	Xs := float64(params.XsHammingWeight()+1) / N
	Xe := params.NoiseFreshSK() * params.NoiseFreshSK()

	var noiseKS float64
	if hasP {
		noiseKS = 1 / (n * 12.0)
	} else {
		noiseKS = float64(d) * B * B / (n * 12)
	}

	return math.Sqrt(N * n * n * Xe * (2*Xs + noiseKS))
}

// NoiseGadgetCiphertext returns the standard deviation of the noise of each individual elements in a gadget ciphertext
// encrypted with the collective key.
func NoiseGadgetCiphertext(params rlwe.Parameters, nbParties int) (std float64) {
	return math.Sqrt(float64(nbParties)) * params.NoiseFreshSK()
}

// NoiseEvaluationKey returns the standard deviation of the noise of each individual elements in a collective EvaluationKey.
func NoiseEvaluationKey(params rlwe.Parameters, nbParties int) (std float64) {
	return NoiseGadgetCiphertext(params, nbParties)
}

// NoiseGaloisKey returns the standard deviation of the noise of each individual elements in a collective GaloisKey.
func NoiseGaloisKey(params rlwe.Parameters, nbParties int) (std float64) {
	return NoiseEvaluationKey(params, nbParties)
}

func NoiseKeySwitch(nbParties int, noisect, noisefresh, noiseflood float64) (std float64) {
	std = noisefresh * noisefresh
	std += noiseflood * noiseflood
	std *= float64(nbParties)
	std += noisect * noisect
	return math.Sqrt(std)
}
