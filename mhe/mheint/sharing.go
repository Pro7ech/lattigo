package mheint

import (
	"fmt"
	"math/rand/v2"

	"github.com/Pro7ech/lattigo/he/heint"
	"github.com/Pro7ech/lattigo/mhe"
	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/sampling"
)

// EncToShareProtocol is the structure storing the parameters and temporary buffers
// required by the encryption-to-shares protocol.
type EncToShareProtocol struct {
	mhe.KeySwitchingProtocol[rlwe.SecretKey]
	params heint.Parameters

	xTSampler func(n uint64) uint64
	encoder   *heint.Encoder

	zero *rlwe.SecretKey
	bufT []uint64
	bufQ ring.RNSPoly
}

func NewAdditiveShare(params heint.Parameters) *mhe.AdditiveShare {
	return mhe.NewAdditiveShare(params.RT.N)
}

// ShallowCopy creates a shallow copy of EncToShareProtocol in which all the read-only data-structures are
// shared with the receiver and the temporary buffers are reallocated. The receiver and the returned
// EncToShareProtocol can be used concurrently.
func (e2s EncToShareProtocol) ShallowCopy() *EncToShareProtocol {

	params := e2s.params

	return &EncToShareProtocol{
		KeySwitchingProtocol: *e2s.KeySwitchingProtocol.ShallowCopy(),
		params:               params,
		/* #nosec G404 -- source is cryptographically secure  */
		xTSampler: rand.New(sampling.NewSource(sampling.NewSeed())).Uint64N,
		encoder:   e2s.encoder.ShallowCopy(),
		zero:      e2s.zero,
		bufQ:      params.RingQ().NewRNSPoly(),
		bufT:      make([]uint64, params.MaxSlots()),
	}
}

// NewEncToShareProtocol creates a new EncToShareProtocol struct from the passed heint.Parameters.
func NewEncToShareProtocol(params heint.Parameters) *EncToShareProtocol {
	return &EncToShareProtocol{
		KeySwitchingProtocol: *mhe.NewKeySwitchingProtocol[rlwe.SecretKey](params.Parameters),
		params:               params,
		encoder:              heint.NewEncoder(params),
		/* #nosec G404 -- source is cryptographically secure  */
		xTSampler: rand.New(sampling.NewSource(sampling.NewSeed())).Uint64N,
		zero:      rlwe.NewSecretKey(params.Parameters),
		bufQ:      params.RingQ().NewRNSPoly(),
		bufT:      make([]uint64, params.MaxSlots()),
	}
}

// Allocate allocates a share of the EncToShare protocol
func (e2s EncToShareProtocol) Allocate(level int) (share *mhe.KeySwitchingShare) {
	return e2s.KeySwitchingProtocol.Allocate(level)
}

// Gen generates a party's share in the encryption-to-shares protocol. This share consist in the additive secret-share of the party
// which is written in secretShareOut and in the public masked-decryption share written in publicShareOut.
// ct1 is degree 1 element of a rlwe.Ciphertext, i.e. rlwe.Ciphertext.Value[1].
func (e2s EncToShareProtocol) Gen(sk *rlwe.SecretKey, ct *rlwe.Ciphertext, secretShareOut *mhe.AdditiveShare, publicShareOut *mhe.KeySwitchingShare) (err error) {
	level := min(ct.Level(), publicShareOut.Vector.Level())
	if err = e2s.KeySwitchingProtocol.Gen(sk, e2s.zero, 0, ct, publicShareOut); err != nil {
		return
	}

	s := e2s.xTSampler
	v := secretShareOut.Value
	t := e2s.params.PlaintextModulus()

	for i := range v {
		v[i] = s(t)
	}

	e2s.encoder.RingT2Q(level, true, secretShareOut.Value, e2s.bufQ)
	ringQ := e2s.params.RingQ().AtLevel(level)
	ringQ.NTT(e2s.bufQ, e2s.bufQ)
	ringQ.Sub(publicShareOut.Vector.Q[0], e2s.bufQ, publicShareOut.Vector.Q[0])

	return
}

// Finalize is the final step of the encryption-to-share protocol. It performs the masked decryption of the target ciphertext followed by a
// the removal of the caller's secretShare as generated in the GenShare method.
// If the caller is not secret-key-share holder (i.e., didn't generate a decryption share), `secretShare` can be set to nil.
// Therefore, in order to obtain an additive sharing of the message, only one party should call this method, and the other parties should use
// the secretShareOut output of the GenShare method.
func (e2s EncToShareProtocol) Finalize(secretShare *mhe.AdditiveShare, aggregatePublicShare *mhe.KeySwitchingShare, ct *rlwe.Ciphertext, secretShareOut *mhe.AdditiveShare) {
	level := min(ct.Level(), aggregatePublicShare.Vector.Level())
	ringQ := e2s.params.RingQ().AtLevel(level)
	ringQ.Add(aggregatePublicShare.Vector.Q[0], ct.Q[0], e2s.bufQ)
	ringQ.INTT(e2s.bufQ, e2s.bufQ)
	e2s.encoder.RingQ2T(level, true, e2s.bufQ, e2s.bufT)
	if secretShare != nil {
		e2s.params.RT.Add(secretShare.Value, e2s.bufT, secretShareOut.Value)
	} else {
		copy(secretShareOut.Value, e2s.bufT)
	}
}

// ShareToEncProtocol is the structure storing the parameters and temporary buffers
// required by the shares-to-encryption protocol.
type ShareToEncProtocol struct {
	mhe.KeySwitchingProtocol[rlwe.SecretKey]
	params heint.Parameters

	encoder *heint.Encoder

	zero *rlwe.SecretKey
	bufQ ring.RNSPoly
}

// NewShareToEncProtocol creates a new ShareToEncProtocol struct from the passed integer parameters.
func NewShareToEncProtocol(params heint.Parameters) *ShareToEncProtocol {
	return &ShareToEncProtocol{
		KeySwitchingProtocol: *mhe.NewKeySwitchingProtocol[rlwe.SecretKey](params.Parameters),
		params:               params,
		encoder:              heint.NewEncoder(params),
		zero:                 rlwe.NewSecretKey(params.Parameters),
		bufQ:                 params.RingQ().NewRNSPoly(),
	}
}

// Allocate allocates a share of the ShareToEnc protocol
func (s2e ShareToEncProtocol) Allocate(level int) (share *mhe.KeySwitchingShare) {
	return s2e.KeySwitchingProtocol.Allocate(level)
}

// ShallowCopy creates a shallow copy of ShareToEncProtocol in which all the read-only data-structures are
// shared with the receiver and the temporary buffers are reallocated. The receiver and the returned
// ShareToEncProtocol can be used concurrently.
func (s2e ShareToEncProtocol) ShallowCopy() *ShareToEncProtocol {
	params := s2e.params
	return &ShareToEncProtocol{
		KeySwitchingProtocol: *s2e.KeySwitchingProtocol.ShallowCopy(),
		encoder:              s2e.encoder.ShallowCopy(),
		params:               params,
		zero:                 s2e.zero,
		bufQ:                 params.RingQ().NewRNSPoly(),
	}
}

// Gen generates a party's in the shares-to-encryption protocol given the party's secret-key share `sk`, a common
// polynomial sampled from the CRS `crp` and the party's secret share of the message.
func (s2e ShareToEncProtocol) Gen(sk *rlwe.SecretKey, seed [32]byte, secretShare *mhe.AdditiveShare, publicShare *mhe.KeySwitchingShare) (err error) {

	ct := &rlwe.Ciphertext{}
	ct.Vector = &publicShare.Vector
	ct.MetaData = &rlwe.MetaData{}
	ct.MetaData.IsNTT = true

	if err = s2e.WithKey(sk).WithSeededPublicRandomness(seed).EncryptZero(ct); err != nil {
		return
	}
	publicShare.Seed = seed

	s2e.encoder.RingT2Q(ct.Level(), true, secretShare.Value, s2e.bufQ)
	rQ := s2e.params.RingQ().AtLevel(ct.Level())
	rQ.NTT(s2e.bufQ, s2e.bufQ)
	rQ.Add(publicShare.Q[0], s2e.bufQ, publicShare.Q[0])
	return
}

// Finalize computes the final encryption of the secret-shared message when provided with the aggregation `c0Agg` of the parties'
// shares in the protocol and with the common, CRS-sampled polynomial `crp`.
func (s2e ShareToEncProtocol) Finalize(share *mhe.KeySwitchingShare, opOut *rlwe.Ciphertext) (err error) {
	if opOut.Degree() != 1 {
		return fmt.Errorf("opOut must have degree 1")
	}
	opOut.Q[0].Copy(&share.Q[0])
	p := ring.Point{Q: opOut.Q[1]}
	p.Randomize(s2e.params.RingQ(), s2e.params.RingP(), sampling.NewSource(share.Seed))

	return
}
