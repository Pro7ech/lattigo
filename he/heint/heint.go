// Package heint provides Homomorphic Encryption for encrypted modular arithmetic over the integers.
// It is implemented as an unified RNS-accelerated version of the Fan-Vercauteren version of the
// Brakerski's scale invariant homomorphic encryption scheme (BFV) and
// Brakerski-Gentry-Vaikuntanathan (BGV) homomorphic encryption scheme.
package heint

import (
	"github.com/Pro7ech/lattigo/rlwe"
)

// NewPlaintext allocates a new rlwe.Plaintext.
//
// inputs:
//   - params: an rlwe.ParameterProvider interface
//   - level: the level of the plaintext
//
// output: a newly allocated rlwe.Plaintext at the specified level.
//
// Note: the user can update the field `MetaData` to set a specific scaling factor,
// plaintext dimensions (if applicable) or encoding domain, before encoding values
// on the created plaintext.
func NewPlaintext(params Parameters, level int) (pt *rlwe.Plaintext) {
	pt = rlwe.NewPlaintext(params, level, -1)
	pt.IsBatched = true
	pt.Scale = params.DefaultScale()
	pt.LogDimensions = params.LogMaxDimensions()
	return
}

// NewCiphertext allocates a new rlwe.Ciphertext.
//
// inputs:
//   - params: an rlwe.ParameterProvider interface
//   - degree: the degree of the ciphertext
//   - level: the level of the Ciphertext
//
// output: a newly allocated rlwe.Ciphertext of the specified degree and level.
func NewCiphertext(params Parameters, degree, level int) (ct *rlwe.Ciphertext) {
	ct = rlwe.NewCiphertext(params, degree, level, -1)
	ct.IsBatched = true
	ct.Scale = params.DefaultScale()
	ct.LogDimensions = params.LogMaxDimensions()
	return
}
