package rlwe

import (
	"fmt"

	"github.com/Pro7ech/lattigo/ring"
)

// Decryptor is a structure used to decrypt [rlwe.Ciphertext].
// It stores the secret-key.
type Decryptor struct {
	params Parameters
	buff   ring.RNSPoly
	sk     *SecretKey
}

// NewDecryptor instantiates a new [rlwe.Decryptor].
func NewDecryptor(params ParameterProvider, sk *SecretKey) *Decryptor {

	p := params.GetRLWEParameters()

	if sk != nil && sk.N() != p.N() {
		panic(fmt.Errorf("secret_key ring degree does not match parameters ring degree"))
	}

	return &Decryptor{
		params: *p,
		buff:   p.RingQ().NewRNSPoly(),
		sk:     sk,
	}
}

// GetRLWEParameters returns the underlying [rlwe.Parameters] of the receiver..
func (d Decryptor) GetRLWEParameters() *Parameters {
	return &d.params
}

// DecryptNew decrypts an [rlwe.Ciphertext] and returns the result in a new [rlwe.Plaintext].
// Output plaintext [rlwe.MetaData] will match the input ciphertext [rlwe.MetaData].
func (d Decryptor) DecryptNew(ct *Ciphertext) (pt *Plaintext) {
	pt = NewPlaintext(d.params, ct.Level(), -1)
	d.Decrypt(ct, pt)
	return
}

// Decrypt decrypts an [rlwe.Ciphertext] and writes the result on an [rlwe.Plaintext].
// The level of the output plaintext is min(ct.Level(), pt.Level()).
// Output plaintext [rlwe.MetaData] will match the input ciphertext [rlwe.MetaData].
func (d Decryptor) Decrypt(ct *Ciphertext, pt *Plaintext) {

	if d.sk == nil {
		panic(fmt.Errorf("decryption key is nil"))
	}

	LevelQ := min(ct.LevelQ(), pt.LevelQ())
	LevelP := min(ct.LevelP(), pt.LevelP())

	pt.ResizeQ(LevelQ)
	pt.ResizeP(LevelP)

	*pt.MetaData = *ct.MetaData

	d.decrypt(d.params.RingQ().AtLevel(LevelQ), ct.Q, pt.Q, d.sk.Q, ct.IsNTT)

	if rP := d.params.RingP(); rP != nil && LevelP > -1 {
		d.decrypt(rP.AtLevel(LevelP), ct.P, pt.P, d.sk.P, ct.IsNTT)
	}
}

func (d *Decryptor) decrypt(r ring.RNSRing, ct []ring.RNSPoly, pt, sk ring.RNSPoly, isNTT bool) {

	degree := len(ct) - 1

	if isNTT {
		pt.CopyLvl(pt.Level(), &ct[degree])
	} else {
		r.NTTLazy(ct[degree], pt)
	}

	for i := degree; i > 0; i-- {

		r.MulCoeffsMontgomery(pt, sk, pt)

		if !isNTT {
			r.NTTLazy(ct[i-1], d.buff)
			r.Add(pt, d.buff, pt)
		} else {
			r.Add(pt, ct[i-1], pt)
		}

		if i&7 == 7 {
			r.Reduce(pt, pt)
		}
	}

	if degree&7 != 7 {
		r.Reduce(pt, pt)
	}

	if !isNTT {
		r.INTT(pt, pt)
	}
}

// ShallowCopy creates a shallow copy of the receiver in which all the read-only data-
// structures are shared with the receiver and the temporary buffers are reallocated.
// The receiver and the returned object can be used concurrently.
func (d Decryptor) ShallowCopy() *Decryptor {
	return &Decryptor{
		params: d.params,
		buff:   d.params.RingQ().NewRNSPoly(),
		sk:     d.sk,
	}
}

// WithKey returns an instance of the receiver with a new decryption key.
// The returned object cannot be used concurrently with the receiver.
func (d Decryptor) WithKey(sk *SecretKey) *Decryptor {

	if sk == nil {
		panic(fmt.Errorf("key is nil"))
	}

	if sk.N() != d.params.N() {
		panic(fmt.Errorf("key ring degree does not match parameters ring degree"))
	}

	return &Decryptor{
		params: d.params,
		buff:   d.buff,
		sk:     sk,
	}
}
