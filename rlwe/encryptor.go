package rlwe

import (
	"fmt"

	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/utils/sampling"
)

// EncryptionKey is an interface for encryption keys.
// Valid encryption keys are [rlwe.SecretKey] and
// [rlwe.Publickey] types.
type EncryptionKey interface {
	isEncryptionKey()
}

// NewEncryptor creates a new [rlwe.Encryptor] from either an [rlwe.EncryptionKey].
func NewEncryptor(params ParameterProvider, key EncryptionKey) *Encryptor {

	p := *params.GetRLWEParameters()

	enc := newEncryptor(p)
	var err error
	switch key := key.(type) {
	case *PublicKey:
		if key == nil {
			return newEncryptor(p)
		}
		err = enc.checkPk(key)
	case *SecretKey:
		if key == nil {
			return newEncryptor(p)
		}
		err = enc.checkSk(key)
	case nil:
		return newEncryptor(p)
	default:
		// Sanity check
		panic(fmt.Errorf("key must be either *rlwe.PublicKey, *rlwe.SecretKey or nil but have %T", key))
	}

	if err != nil {
		// Sanity check, this error should not happen.
		panic(fmt.Errorf("key is not correct: %w", err))
	}

	enc.encKey = key
	return enc
}

// Encryptor is a struct dedicated to encrypting
// - [rlwe.Ciphertext]
// - [rlwe.GadgetCiphertext]
type Encryptor struct {
	params Parameters
	*EncryptorBuffers

	encKey     EncryptionKey
	xeSampler  ring.Sampler
	xuSampler  ring.Sampler
	xaQSampler ring.Sampler
	xaPSampler ring.Sampler
}

// GetRLWEParameters returns the underlying [rlwe.Parameters] of the receiver.
func (enc Encryptor) GetRLWEParameters() *Parameters {
	return &enc.params
}

func newEncryptor(params Parameters) *Encryptor {

	xeSampler, err := ring.NewSampler(sampling.NewSource(sampling.NewSeed()), params.RingQ().ModuliChain(), params.Xe())

	// Sanity check, this error should not happen.
	if err != nil {
		panic(fmt.Errorf("newEncryptor: %w", err))
	}

	xuSampler, err := ring.NewSampler(sampling.NewSource(sampling.NewSeed()), params.RingQ().ModuliChain(), params.Xs())

	// Sanity check, this error should not happen.
	if err != nil {
		panic(fmt.Errorf("newEncryptor: %w", err))
	}

	var xaPSampler ring.Sampler

	if params.RingP() != nil {
		xaPSampler = ring.NewUniformSampler(sampling.NewSource(sampling.NewSeed()), params.RingP().ModuliChain())
	}

	return &Encryptor{
		params:           params,
		EncryptorBuffers: newEncryptorBuffers(params),
		xeSampler:        xeSampler,
		xuSampler:        xuSampler,
		xaQSampler:       ring.NewUniformSampler(sampling.NewSource(sampling.NewSeed()), params.RingQ().ModuliChain()),
		xaPSampler:       xaPSampler,
	}
}

// EncryptorBuffers is a struct storing the read and write buffers
// of an encryptor.
type EncryptorBuffers struct {
	BuffQ [3]ring.RNSPoly
	BuffP [4]ring.RNSPoly
}

func newEncryptorBuffers(params Parameters) *EncryptorBuffers {

	ringQ := params.RingQ()
	ringP := params.RingP()

	var BuffP [4]ring.RNSPoly
	if params.PCount() != 0 {
		BuffP = [4]ring.RNSPoly{ringP.NewRNSPoly(), ringP.NewRNSPoly(), ringP.NewRNSPoly(), ringP.NewRNSPoly()}
	}

	return &EncryptorBuffers{
		BuffQ: [3]ring.RNSPoly{ringQ.NewRNSPoly(), ringQ.NewRNSPoly(), ringQ.NewRNSPoly()},
		BuffP: BuffP,
	}
}

// Encrypt encrypts the input [rlwe.Plaintext] using the stored encryption key and writes the result on ct.
//
// The following types are accepted for ct:
//
// - [rlwe.Ciphertext]
// - [rlwe.GadgetCiphertext]
//
// Plaintext informations:
//
// - If no [rlwe.Plaintext] is given (nil pointer), the method will produce an encryption of zero.
// - If an [rlwe.Plaintext] is given, then the output ciphertext [rlwe.MetaData] will match the plaintext [rlwe.MetaData].
//
// The encryption procedure masks the plaintext by adding a fresh encryption of zero.
// The encryption procedure depends on the parameters: If an auxiliary modulus P is defined and the encryption key is
// an [rlwe.PublicKey], the encryption of zero is sampled in QP before being rescaled by P;
// otherwise, it is directly sampled in Q.
//
// The method returns an error if:
//
// - The ciphertext is of an unsupported type
// - No encryption key is stored
// - The input ciphertext is of degree 0 and the encryption key is an [rlwe.PublicKey]
func (enc Encryptor) Encrypt(pt *Plaintext, ct interface{}) (err error) {

	if pt == nil {
		return enc.EncryptZero(ct)
	}

	switch ct := ct.(type) {
	case *Ciphertext:

		*ct.MetaData = *pt.MetaData

		level := min(pt.Level(), ct.Level())

		ct.ResizeQ(level)

		if err = enc.EncryptZero(ct); err != nil {
			return
		}

		enc.addtToCt(level, pt, ct)

	case *GadgetCiphertext:

		if pt.Level() < ct.LevelQ() {
			return fmt.Errorf("invalid [%T]: [%T].Level() < [%T].LevelQ()", pt, pt, ct)
		}

		if err = enc.EncryptZero(ct); err != nil {
			return
		}

		rQ := enc.params.RingQ().AtLevel(min(pt.Level(), ct.LevelQ()))

		var ptTmp ring.RNSPoly

		if !pt.IsNTT {

			ptTmp = enc.BuffQ[1]

			rQ.NTT(pt.Q, ptTmp)

			if !pt.IsMontgomery {
				rQ.MForm(ptTmp, ptTmp)
			}

		} else {

			if !pt.IsMontgomery {
				ptTmp = enc.BuffQ[1]
				rQ.MForm(pt.Q, ptTmp)
			} else {
				ptTmp = pt.Q
			}
		}

		if err := AddPlaintextToMatrix(rQ, enc.params.RingP(), ptTmp, enc.BuffQ[0], ct.Vector[0], ct.DigitDecomposition); err != nil {
			// Sanity check, this error should not happen.
			panic(err)
		}

	default:
		return fmt.Errorf("invalid argument: ct must be [*rlwe.GadgetCiphertext] or [*rlwe.Ciphertext] but is [%T]", ct)
	}

	return
}

// KeySwitch decrypts the ciphertext using the provided key and re-encrypts is using the
// encryptor's key and adds a flooding noise with standard deviation eFlood.
//
// Method will return an error if the input ciphertext is not of degree 1.
//
// Re-encryption is performed as follow:
// - sk -> sk : (c0, c1) -> (c0, 0) + (c1*(sIn-sOut) + eFlood, c1)
// - sk -> pk : (c0, c1) -> (c0, 0) + (c1*sIn + pk[0]*u + e + eFlood, pk[1]*u + e')
// - sk -> nil: (c0, c1) -> (c0, 0) + (c1*sIn + eFlood, 0)
func (enc Encryptor) KeySwitch(key *SecretKey, eFlood float64, ct *Ciphertext) (err error) {

	if ct.Degree() != 1 {
		return fmt.Errorf("ciphertext degree must be 1 but is %d", ct.Degree())
	}

	rQ := enc.GetRLWEParameters().RingQ().AtLevel(ct.Level())

	// ct = (-a*sIn + m + e, a)
	if !ct.IsNTT {
		rQ.NTT(ct.Q[1], ct.Q[1])
	}

	// ct = (m + e, a)
	rQ.MulCoeffsMontgomery(ct.Q[1], key.Q, enc.BuffQ[1])

	switch encKey := enc.encKey.(type) {
	case *SecretKey:
		//ct = (-a * sOut + m + e, a)
		rQ.MulCoeffsMontgomeryThenSub(ct.Q[1], encKey.Q, enc.BuffQ[1])

		if !ct.IsNTT {
			rQ.INTT(enc.BuffQ[1], enc.BuffQ[1])
		}

		rQ.Add(ct.Q[0], enc.BuffQ[1], ct.Q[0])

	case *PublicKey:

		var encZero *Ciphertext
		if encZero, err = NewCiphertextAtLevelFromPoly(ct.Level(), -1, []ring.RNSPoly{enc.BuffQ[2], ct.Q[1]}, nil); err != nil {
			return
		}
		encZero.IsNTT = true

		// encZero = (-b * sOut + e', b + e'')
		if err = enc.EncryptZero(encZero); err != nil {
			return
		}

		if !ct.IsNTT {
			rQ.INTT(encZero.Q[0], encZero.Q[0])
			rQ.INTT(encZero.Q[1], encZero.Q[1])
			rQ.INTT(enc.BuffQ[1], enc.BuffQ[1])
		}

		// ct = (-b * sOut + m + e + e', b + e'')
		rQ.Add(ct.Q[0], enc.BuffQ[1], ct.Q[0])
		rQ.Add(ct.Q[0], encZero.Q[0], ct.Q[0])

	case nil:
		ct.Q[1].Zero()
	}

	if eFlood != 0 {

		// This is lightweight, no pre-computation
		sampler := ring.NewGaussianSampler(enc.xeSampler.GetSource(), rQ.ModuliChain(), ring.DiscreteGaussian{Sigma: eFlood, Bound: 6 * eFlood}).AtLevel(ct.Level())

		if !ct.IsNTT {
			sampler.ReadAndAdd(ct.Q[0])
		} else {
			sampler.Read(enc.BuffQ[1])
			rQ.NTT(enc.BuffQ[1], enc.BuffQ[1])
			rQ.Add(ct.Q[0], enc.BuffQ[1], ct.Q[0])
		}
	}

	return
}

// EncryptZero generates an encryption of zero under the stored encryption key and writes the result on ct.
// The method returns an error if no encryption key is stored in the Encryptor.
//
// The encryption procedure depends on the parameters:
// - If the auxiliary modulus P is defined, the encryption of zero is sampled in QP before being rescaled by P;
// - otherwise, it is directly sampled in Q.
// The zero encryption is generated according to the given Element MetaData.
func (enc Encryptor) EncryptZero(ct interface{}) (err error) {

	switch ct := ct.(type) {
	case *Ciphertext:
		return enc.encryptZero(ct)
	case *GadgetCiphertext:

		dims := ct.Dims()

		for i := range dims {
			for j := range dims[i] {
				if err = enc.encryptZero(ct.At(i, j)); err != nil {
					return
				}
			}
		}

	default:
		return fmt.Errorf("unsuported operand: requires [*rlwe.Ciphertext] or [*rlwe.GadgetCiphertext] but is %T", ct)
	}

	return
}

func (enc Encryptor) encryptZero(ct *Ciphertext) (err error) {

	switch enc.encKey.(type) {
	case *SecretKey:
		return enc.encryptZeroSk(ct)
	case *PublicKey:
		if enc.params.PCount() == 0 {
			return enc.encryptZeroPkNoP(ct)
		} else {
			return enc.encryptZeroPk(ct)
		}
	default:
		return fmt.Errorf("encryption key is nil")
	}
}

func (enc Encryptor) encryptZeroPk(ct *Ciphertext) (err error) {

	if ct.Degree() == 0 {
		return fmt.Errorf("invalid [rlwe.Ciphertext]: Degree must be 1")
	}

	pk := enc.encKey.(*PublicKey)

	LevelQ := ct.LevelQ()
	LevelP := ct.LevelP()

	c0Q := ct.Q[0]
	c1Q := ct.Q[1]

	var c0P, c1P ring.RNSPoly

	if LevelP == -1 {
		c0P = enc.BuffP[0]
		c1P = enc.BuffP[1]
		LevelP = 0
	} else {
		c0P = ct.P[0]
		c1P = ct.P[1]
	}

	rQ := enc.params.RingQ().AtLevel(LevelQ)
	rP := enc.params.RingP().AtLevel(LevelP)

	uQ := enc.BuffQ[0]
	uP := enc.BuffP[2]

	// We sample a RLWE instance (encryption of zero) over the extended ring (ciphertext ring + special prime)
	enc.xuSampler.AtLevel(LevelQ).Read(uQ)
	ring.ExtendBasisSmallNorm(rQ[0].Modulus, rP.ModuliChain(), uQ, uP)

	// (#Q + #P) NTT
	rQ.NTT(uQ, uQ)
	rP.NTT(uP, uP)

	// c0 = u*pk0
	// c1 = u*pk1
	rQ.MulCoeffsMontgomery(uQ, pk.Q[0], c0Q)
	rQ.MulCoeffsMontgomery(uQ, pk.Q[1], c1Q)
	rP.MulCoeffsMontgomery(uP, pk.P[0], c0P)
	rP.MulCoeffsMontgomery(uP, pk.P[1], c1P)

	// 2*(#Q + #P) NTT
	rQ.INTT(c0Q, c0Q)
	rQ.INTT(c1Q, c1Q)
	rP.INTT(c0P, c0P)
	rP.INTT(c1P, c1P)

	eQ := uQ
	eP := uP

	// c0 + e
	enc.xeSampler.AtLevel(LevelQ).Read(eQ)
	ring.ExtendBasisSmallNorm(rQ[0].Modulus, rP.ModuliChain(), eQ, eP)
	rQ.Add(c0Q, eQ, c0Q)
	rP.Add(c0P, eP, c0P)

	// c1 + e
	enc.xeSampler.AtLevel(LevelQ).Read(eQ)
	ring.ExtendBasisSmallNorm(rQ[0].Modulus, rP.ModuliChain(), eQ, eP)
	rQ.Add(c1Q, eQ, c1Q)
	rP.Add(c1P, eP, c1P)

	if len(ct.P) == 0 {

		// ct0 = (u*pk0 + e0)/P
		rQ.ModDown(rP, c0Q, c0P, eQ, eP, ct.Q[0])

		// ct1 = (u*pk1 + e1)/P
		rQ.ModDown(rP, c1Q, c1P, eQ, eP, ct.Q[1])

		if ct.IsNTT {
			rQ.NTT(ct.Q[0], ct.Q[0])
			rQ.NTT(ct.Q[1], ct.Q[1])
		}

		if ct.IsMontgomery {
			rQ.MForm(ct.Q[0], ct.Q[0])
			rQ.MForm(ct.Q[1], ct.Q[1])
		}

	} else {
		if ct.IsNTT {
			rQ.NTT(ct.Q[0], ct.Q[0])
			rQ.NTT(ct.Q[1], ct.Q[1])
			rP.NTT(ct.P[0], ct.P[0])
			rP.NTT(ct.P[1], ct.P[1])
		}

		if ct.IsMontgomery {
			rQ.MForm(ct.Q[0], ct.Q[0])
			rQ.MForm(ct.Q[1], ct.Q[1])
			rP.MForm(ct.P[0], ct.P[0])
			rP.MForm(ct.P[1], ct.P[1])
		}
	}

	return
}

func (enc Encryptor) encryptZeroPkNoP(ct *Ciphertext) (err error) {

	if ct.Degree() == 0 {
		return fmt.Errorf("invalid [rlwe.Ciphertext]: Degree must be 1")
	}

	pk := enc.encKey.(*PublicKey)

	LevelQ := ct.LevelQ()

	rQ := enc.params.RingQ().AtLevel(LevelQ)

	BuffQ := enc.BuffQ[0]

	enc.xuSampler.AtLevel(LevelQ).Read(BuffQ)
	rQ.NTT(BuffQ, BuffQ)

	// ct0 = NTT(u*pk0)
	rQ.MulCoeffsMontgomery(BuffQ, pk.Q[0], ct.Q[0])
	// ct1 = NTT(u*pk1)
	rQ.MulCoeffsMontgomery(BuffQ, pk.Q[1], ct.Q[1])

	xe := enc.xeSampler.AtLevel(LevelQ)

	if ct.IsNTT {
		xe.Read(BuffQ)
		rQ.NTT(BuffQ, BuffQ)
		rQ.Add(ct.Q[0], BuffQ, ct.Q[0])
		xe.Read(BuffQ)
		rQ.NTT(BuffQ, BuffQ)
		rQ.Add(ct.Q[1], BuffQ, ct.Q[1])
	} else {
		rQ.INTT(ct.Q[0], ct.Q[0])
		xe.ReadAndAdd(ct.Q[0])
		rQ.INTT(ct.Q[1], ct.Q[1])
		xe.ReadAndAdd(ct.Q[1])
	}

	if ct.IsMontgomery {
		rQ.MForm(ct.Q[0], ct.Q[0])
		rQ.MForm(ct.Q[1], ct.Q[1])
	}

	return
}

func (enc Encryptor) encryptZeroSk(ct *Ciphertext) (err error) {

	sk := enc.encKey.(*SecretKey)

	LevelQ := ct.LevelQ()
	LevelP := ct.LevelP()

	rQ := enc.params.RingQ().AtLevel(LevelQ)

	var rP ring.RNSRing
	if rP = enc.params.RingP(); LevelP > -1 && rP.Level() == -1 {
		return fmt.Errorf("invalid [rlwe.Ciphertext]: has non empty modulus P while params have empty modulus P")
	} else if rP.Level() > -1 && LevelP > -1 {
		rP = rP.AtLevel(LevelP)
	}

	var c0Q, c0P, c1Q, c1P ring.RNSPoly

	c0Q = ct.Q[0]

	if LevelP != -1 {
		c0P = ct.P[0]
	}

	if ct.Degree() == 1 {
		c1Q = ct.Q[1]

		if LevelP != -1 {
			c1P = ct.P[1]
		}

	} else {
		c1Q = enc.BuffQ[2]

		if LevelP != -1 {
			c1P = enc.BuffP[3]
		}
	}

	// c1 = (0, NTT(a))
	enc.xaQSampler.AtLevel(LevelQ).Read(c1Q)
	if LevelP != -1 {
		enc.xaPSampler.AtLevel(LevelP).Read(c1P)
	}

	if ct.Degree() == 0 && !ct.IsNTT {
		rQ.NTT(c1Q, c1Q)
		if LevelP > -1 {
			rP.NTT(c1P, c1P)
		}
	}

	// c0 = (e, 0)
	enc.xeSampler.AtLevel(LevelQ).Read(c0Q)
	if LevelP > -1 {
		ring.ExtendBasisSmallNorm(rQ[0].Modulus, rP.ModuliChain(), c0Q, c0P)
	}

	// c1 = (NTT(e), 0)
	rQ.NTT(c0Q, c0Q)
	if ct.IsMontgomery {
		rQ.MForm(c0Q, c0Q)
	}

	// c0 = (NTT(-a*sk + e))
	rQ.MulCoeffsMontgomeryThenSub(c1Q, sk.Q, c0Q)

	if !ct.IsNTT {
		rQ.INTT(c0Q, c0Q)

		if ct.Degree() != 0 {
			rQ.INTT(c1Q, c1Q)
		}
	}

	if LevelP != -1 {

		rP.NTT(c0P, c0P)
		if ct.IsMontgomery {
			rP.MForm(c0P, c0P)
		}

		rP.MulCoeffsMontgomeryThenSub(c1P, sk.P, c0P)

		if !ct.IsNTT {
			rP.INTT(c0P, c0P)
			if ct.Degree() != 0 {
				rP.INTT(c1P, c1P)
			}
		}
	}

	return
}

// WithSeededSecretRandomness returns an instance of the receiver were the secre randomness:
// - Xe: noise when encrypting with [rlwe.SecretKey] or [rlwe.PublicKey]
// - Xu: small vector when encrypting with [rlwe.PublicKey]
// are seeded with a seed derived from the provided seed.
func (enc *Encryptor) WithSeededSecretRandomness(seed [32]byte) *Encryptor {
	source := sampling.NewSource(seed)
	return &Encryptor{
		params:           enc.params,
		EncryptorBuffers: enc.EncryptorBuffers,
		encKey:           enc.encKey,
		xeSampler:        enc.xeSampler.WithSource(source.NewSource()),
		xuSampler:        enc.xeSampler.WithSource(source.NewSource()),
		xaQSampler:       enc.xaQSampler,
		xaPSampler:       enc.xaPSampler,
	}
}

// WithSeededPublicRandomness returns an instance of the receiver were Xa
// - Xu: public randomness when encrypting with [rlwe.SecretKey]
// is seeded with the provided seed.
func (enc *Encryptor) WithSeededPublicRandomness(seed [32]byte) *Encryptor {
	source := sampling.NewSource(seed)

	var xaPSampler ring.Sampler
	if enc.xaPSampler != nil {
		xaPSampler = enc.xaPSampler.WithSource(source)
	}

	return &Encryptor{
		params:           enc.params,
		EncryptorBuffers: enc.EncryptorBuffers,
		encKey:           enc.encKey,
		xeSampler:        enc.xeSampler,
		xuSampler:        enc.xuSampler,
		xaQSampler:       enc.xaQSampler.WithSource(source),
		xaPSampler:       xaPSampler,
	}
}

// ShallowCopy creates a shallow copy of the receiver in which all the read-only data-structures are
// shared with the receiver and the temporary buffers are reallocated. The receiver and the returned
// object can be used concurrently.
func (enc Encryptor) ShallowCopy() *Encryptor {
	return NewEncryptor(enc.params, enc.encKey)
}

// WithKey returns an instance of the receiver with a new [rlwe.EncryptionKey].
func (enc Encryptor) WithKey(key EncryptionKey) *Encryptor {
	switch key := key.(type) {
	case *SecretKey:
		if err := enc.checkSk(key); err != nil {
			// Sanity check, this error should not happen.
			panic(fmt.Errorf("cannot WithKey: %w", err))
		}
	case *PublicKey:
		if err := enc.checkPk(key); err != nil {
			// Sanity check, this error should not happen.
			panic(fmt.Errorf("cannot WithKey: %w", err))
		}
	case nil:
		return &enc
	default:
		// Sanity check, this error should not happen.
		panic(fmt.Errorf("invalid key type, want *rlwe.SecretKey, *rlwe.PublicKey or nil but have %T", key))
	}
	enc.encKey = key
	return &enc
}

// checkPk checks that a given pk is correct for the parameters.
func (enc Encryptor) checkPk(pk *PublicKey) (err error) {
	if pk.N() != enc.params.N() {
		return fmt.Errorf("pk ring degree does not match params ring degree")
	}
	return
}

// checkPk checks that a given pk is correct for the parameters.
func (enc Encryptor) checkSk(sk *SecretKey) (err error) {
	if sk.N() != enc.params.N() {
		return fmt.Errorf("sk ring degree does not match params ring degree")
	}
	return
}

func (enc Encryptor) addtToCt(level int, pt *Plaintext, ct *Ciphertext) {

	ringQ := enc.params.RingQ().AtLevel(level)
	var buff ring.RNSPoly
	if pt.IsNTT {
		if ct.IsNTT {
			buff = pt.Q
		} else {
			buff = enc.BuffQ[0]
			ringQ.NTT(pt.Q, buff)
		}
	} else {
		if ct.IsNTT {
			buff = enc.BuffQ[0]
			ringQ.INTT(pt.Q, buff)
		} else {
			buff = pt.Q
		}
	}

	ringQ.Add(ct.Q[0], buff, ct.Q[0])
}
