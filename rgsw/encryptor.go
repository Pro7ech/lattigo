package rgsw

import (
	"fmt"

	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
)

// Encryptor is a type for encrypting RGSW ciphertexts. It implements the rlwe.Encryptor
// interface overriding the `Encrypt` and `EncryptZero` methods to accept rgsw.Ciphertext
// types in addition to ciphertexts types in the rlwe package.
type Encryptor struct {
	*rlwe.Encryptor
}

// NewEncryptor creates a new Encryptor type. Note that only secret-key encryption is
// supported at the moment.
func NewEncryptor(params rlwe.ParameterProvider, key rlwe.EncryptionKey) *Encryptor {
	return &Encryptor{rlwe.NewEncryptor(params, key)}
}

// Encrypt encrypts a plaintext pt into an [rgsw.Ciphertext].
func (enc Encryptor) Encrypt(pt *rlwe.Plaintext, ct *Ciphertext) (err error) {

	if err = enc.EncryptZero(ct); err != nil {
		return
	}

	if pt != nil {

		params := enc.GetRLWEParameters()

		levelQ := ct.LevelQ()
		rQ := params.RingQ().AtLevel(levelQ)

		if pt.Level() < ct.LevelQ() {
			return fmt.Errorf("invalid [%T]: [%T].Level() < [%T].LevelQ()", pt, pt, ct)
		}

		var ptTmp ring.RNSPoly

		if !pt.IsNTT {

			ptTmp = enc.BuffQ[0]

			rQ.NTT(pt.Q, ptTmp)

			if !pt.IsMontgomery {
				rQ.MForm(ptTmp, ptTmp)
			}

		} else {

			if !pt.IsMontgomery {
				ptTmp = enc.BuffQ[0]
				rQ.MForm(pt.Q, ptTmp)
			} else {
				ptTmp = pt.Q
			}
		}

		if err := rlwe.AddPlaintextToMatrix(rQ, params.RingP(), ptTmp, enc.BuffQ[1], ct.Matrix[0][0], ct.DigitDecomposition); err != nil {
			// Sanity check, this error should not happen.
			panic(err)
		}

		if err := rlwe.AddPlaintextToMatrix(rQ, params.RingP(), ptTmp, enc.BuffQ[1], ct.Matrix[1][1], ct.DigitDecomposition); err != nil {
			// Sanity check, this error should not happen.
			panic(err)
		}
	}

	return nil
}

// EncryptZero generates an [rgsw.Ciphertext] encrypting zero.
func (enc Encryptor) EncryptZero(ct *Ciphertext) (err error) {

	if err = enc.Encryptor.EncryptZero(ct.At(0)); err != nil {
		return
	}

	if err = enc.Encryptor.EncryptZero(ct.At(1)); err != nil {
		return
	}

	return nil
}

// ShallowCopy creates a shallow copy of this Encryptor in which all the read-only data-structures are
// shared with the receiver and the temporary buffers are reallocated. The receiver and the returned
// Encryptors can be used concurrently.
func (enc Encryptor) ShallowCopy() *Encryptor {
	return &Encryptor{Encryptor: enc.Encryptor.ShallowCopy()}
}
