package mhefloat

import (
	"fmt"
	"math/big"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/mhe"
	"github.com/Pro7ech/lattigo/ring"

	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/bignum"
	"github.com/Pro7ech/lattigo/utils/sampling"
)

// EncToShareProtocol is the structure storing the parameters and temporary buffers
// required by the encryption-to-shares protocol.
type EncToShareProtocol struct {
	mhe.KeySwitchingProtocol[rlwe.SecretKey]
	params     hefloat.Parameters
	zero       *rlwe.SecretKey
	maskBigint []big.Int
	buff       ring.RNSPoly
}

func NewAdditiveShare(params hefloat.Parameters, logSlots int) *mhe.AdditiveShareBigint {

	nValues := 1 << logSlots
	if params.RingType() == ring.Standard {
		nValues <<= 1
	}

	return mhe.NewAdditiveShareBigint(nValues)
}

// ShallowCopy creates a shallow copy of EncToShareProtocol in which all the read-only data-structures are
// shared with the receiver and the temporary buffers are reallocated. The receiver and the returned
// EncToShareProtocol can be used concurrently.
func (e2s EncToShareProtocol) ShallowCopy() *EncToShareProtocol {
	return &EncToShareProtocol{
		KeySwitchingProtocol: *e2s.KeySwitchingProtocol.ShallowCopy(),
		params:               e2s.params,
		zero:                 e2s.zero,
		maskBigint:           make([]big.Int, len(e2s.maskBigint)),
		buff:                 e2s.params.RingQ().NewRNSPoly(),
	}
}

// NewEncToShareProtocol creates a new EncToShareProtocol struct from the passed parameters.
func NewEncToShareProtocol(params hefloat.Parameters) *EncToShareProtocol {
	return &EncToShareProtocol{
		KeySwitchingProtocol: *mhe.NewKeySwitchingProtocol[rlwe.SecretKey](params.Parameters),
		params:               params,
		zero:                 rlwe.NewSecretKey(params.Parameters),
		maskBigint:           make([]big.Int, params.N()),
		buff:                 params.RingQ().NewRNSPoly(),
	}
}

// Allocate allocates a share of the EncToShare protocol
func (e2s EncToShareProtocol) Allocate(level int) (share *mhe.KeySwitchingShare) {
	return e2s.KeySwitchingProtocol.Allocate(level)
}

// Gen generates a party's share in the encryption-to-shares protocol. This share consist in the additive secret-share of the party
// which is written in secretShareOut and in the public masked-decryption share written in publicShareOut.
// This protocol requires additional inputs which are :
// logBound : the bit length of the masks
// ct: the ciphertext to share
// publicShareOut is always returned in the NTT domain.
// The method "GetMinimumLevelForBootstrapping" should be used to get the minimum level at which EncToShare can be called while still ensure 128-bits of security, as well as the
// value for logBound.
func (e2s EncToShareProtocol) Gen(sk *rlwe.SecretKey, logBound uint, ct *rlwe.Ciphertext, secretShareOut *mhe.AdditiveShareBigint, publicShareOut *mhe.KeySwitchingShare) (err error) {

	levelQ := min(ct.Q[1].Level(), publicShareOut.Level())

	rQ := e2s.params.RingQ().AtLevel(levelQ)

	// Get the upperbound on the norm
	// Ensures that bound >= 2^{128+logbound}
	bound := bignum.NewInt(1)
	bound.Lsh(bound, uint(logBound))

	boundMax := new(big.Int).Set(rQ.Modulus())

	var sign int

	sign = bound.Cmp(boundMax)

	if sign == 1 || bound.Cmp(boundMax) == 1 {
		return fmt.Errorf("ciphertext level is not large enough for refresh correctness")
	}

	boundHalf := new(big.Int).Rsh(bound, 1)

	source := sampling.NewSource(sampling.NewSeed())

	dslots := ct.Slots()
	if rQ.Type() == ring.Standard {
		dslots *= 2
	}

	// Generate the mask in Z[Y] for Y = X^{N/(2*slots)}
	for i := 0; i < dslots; i++ {
		e2s.maskBigint[i] = *bignum.RandInt(source, bound)
		sign = e2s.maskBigint[i].Cmp(boundHalf)
		if sign == 1 || sign == 0 {
			e2s.maskBigint[i].Sub(&e2s.maskBigint[i], bound)
		}

		secretShareOut.Value[i].Set(&e2s.maskBigint[i])
	}

	// Encrypt the mask
	// Generates an encryption of zero and subtracts the mask
	if err = e2s.KeySwitchingProtocol.Gen(sk, e2s.zero, 0, ct, publicShareOut); err != nil {
		return fmt.Errorf("e2s.KeySwitchingProtocol.Gen: %w", err)
	}

	// Positional -> RNS -> NTT
	rQ.SetCoefficientsBigint(secretShareOut.Value[:dslots], e2s.buff)
	rlwe.NTTSparseAndMontgomery(rQ, ct.MetaData, e2s.buff)

	// Subtracts the mask to the encryption of zero
	rQ.Sub(publicShareOut.Q[0], e2s.buff, publicShareOut.Q[0])

	return
}

// Finalize is the final step of the encryption-to-share protocol. It performs the masked decryption of the target ciphertext followed by a
// the removal of the caller's secretShare as generated in the GenShare method.
// If the caller is not secret-key-share holder (i.e., didn't generate a decryption share), `secretShare` can be set to nil.
// Therefore, in order to obtain an additive sharing of the message, only one party should call this method, and the other parties should use
// the secretShareOut output of the GenShare method.
func (e2s EncToShareProtocol) Finalize(secretShare *mhe.AdditiveShareBigint, aggregatePublicShare *mhe.KeySwitchingShare, ct *rlwe.Ciphertext, secretShareOut *mhe.AdditiveShareBigint) (err error) {

	levelQ := min(ct.Level(), aggregatePublicShare.Level())

	rQ := e2s.params.RingQ().AtLevel(levelQ)

	// Adds the decryption share on the ciphertext and stores the result in a buff
	rQ.Add(aggregatePublicShare.Q[0], ct.Q[0], e2s.buff)

	// INTT -> RNS -> Positional
	rQ.INTT(e2s.buff, e2s.buff)

	dslots := ct.Slots()
	if rQ.Type() == ring.Standard {
		dslots *= 2
	}

	gap := rQ.N() / dslots

	rQ.PolyToBigintCentered(e2s.buff, gap, e2s.maskBigint)

	// Subtracts the last mask
	if secretShare != nil {
		a := secretShareOut.Value
		b := e2s.maskBigint
		c := secretShare.Value
		for i := range secretShareOut.Value[:dslots] {
			a[i].Add(&c[i], &b[i])
		}
	} else {
		a := secretShareOut.Value
		b := e2s.maskBigint
		for i := range secretShareOut.Value[:dslots] {
			a[i].Set(&b[i])
		}
	}

	return
}

// ShareToEncProtocol is the structure storing the parameters and temporary buffers
// required by the shares-to-encryption protocol.
type ShareToEncProtocol struct {
	mhe.KeySwitchingProtocol[rlwe.SecretKey]
	params   hefloat.Parameters
	tmp      ring.RNSPoly
	ssBigint []big.Int
	zero     *rlwe.SecretKey
}

// ShallowCopy creates a shallow copy of ShareToEncProtocol in which all the read-only data-structures are
// shared with the receiver and the temporary buffers are reallocated. The receiver and the returned
// ShareToEncProtocol can be used concurrently.
func (s2e ShareToEncProtocol) ShallowCopy() *ShareToEncProtocol {
	return &ShareToEncProtocol{
		KeySwitchingProtocol: *s2e.KeySwitchingProtocol.ShallowCopy(),
		params:               s2e.params,
		tmp:                  s2e.params.RingQ().NewRNSPoly(),
		ssBigint:             make([]big.Int, s2e.params.N()),
		zero:                 s2e.zero,
	}
}

// NewShareToEncProtocol creates a new ShareToEncProtocol struct from the passed parameters.
func NewShareToEncProtocol(params hefloat.Parameters) *ShareToEncProtocol {
	return &ShareToEncProtocol{
		KeySwitchingProtocol: *mhe.NewKeySwitchingProtocol[rlwe.SecretKey](params.Parameters),
		params:               params,
		tmp:                  params.RingQ().NewRNSPoly(),
		ssBigint:             make([]big.Int, params.N()),
		zero:                 rlwe.NewSecretKey(params.Parameters),
	}
}

// Allocate allocates a share of the ShareToEnc protocol
func (s2e ShareToEncProtocol) Allocate(level int) (share *mhe.KeySwitchingShare) {
	return s2e.KeySwitchingProtocol.Allocate(level)
}

// Gen generates a party's in the shares-to-encryption protocol given the party's secret-key share `sk`, a common
// polynomial sampled from the CRS `crs` and the party's secret share of the message.
func (s2e ShareToEncProtocol) Gen(sk *rlwe.SecretKey, seed [32]byte, metadata *rlwe.MetaData, secretShare *mhe.AdditiveShareBigint, publicShare *mhe.KeySwitchingShare) (err error) {

	// Generates an encryption share
	ct := &rlwe.Ciphertext{}
	ct.Vector = &publicShare.Vector
	ct.MetaData = &rlwe.MetaData{}
	ct.MetaData.IsNTT = true

	if err = s2e.WithKey(sk).WithSeededPublicRandomness(seed).EncryptZero(ct); err != nil {
		return
	}
	publicShare.Seed = seed

	rQ := s2e.params.RingQ().AtLevel(ct.Level())

	dslots := metadata.Slots()
	if rQ.Type() == ring.Standard {
		dslots *= 2
	}

	// Positional -> RNS -> NTT
	rQ.SetCoefficientsBigint(secretShare.Value[:dslots], s2e.tmp)

	rlwe.NTTSparseAndMontgomery(rQ, metadata, s2e.tmp)

	rQ.Add(publicShare.Q[0], s2e.tmp, publicShare.Q[0])

	return
}

// Finalize computes the final encryption of the secret-shared message when provided with the aggregation `c0Agg` of the parties'
// share in the protocol and with the common, CRS-sampled polynomial `crs`.
func (s2e ShareToEncProtocol) Finalize(share *mhe.KeySwitchingShare, opOut *rlwe.Ciphertext) (err error) {
	if opOut.Degree() != 1 {
		return fmt.Errorf("opOut must have degree 1")
	}
	opOut.Q[0].Copy(&share.Q[0])
	p := ring.Point{Q: opOut.Q[1]}
	p.Randomize(s2e.params.RingQ(), s2e.params.RingP(), sampling.NewSource(share.Seed))

	return
}
