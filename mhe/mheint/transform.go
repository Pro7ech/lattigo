package mheint

import (
	"fmt"

	"github.com/Pro7ech/lattigo/he/heint"
	"github.com/Pro7ech/lattigo/mhe"
	"github.com/Pro7ech/lattigo/ring"

	"github.com/Pro7ech/lattigo/rlwe"
)

// MaskedTransformProtocol is a struct storing the parameters for the MaskedTransformProtocol protocol.
type MaskedTransformProtocol struct {
	e2s EncToShareProtocol
	s2e ShareToEncProtocol

	tmpPt       ring.RNSPoly
	tmpMask     []uint64
	tmpMaskPerm []uint64
}

// WithParams creates a shallow copy of the target MaskedTransformProtocol but with new output parameters.
// The expected input parameters remain unchanged.
func (p MaskedTransformProtocol) WithParams(params heint.Parameters) *MaskedTransformProtocol {
	return &MaskedTransformProtocol{
		e2s:         *p.e2s.ShallowCopy(),
		s2e:         *NewShareToEncProtocol(params),
		tmpPt:       params.RingQ().NewRNSPoly(),
		tmpMask:     make([]uint64, params.MaxSlots()),
		tmpMaskPerm: make([]uint64, params.MaxSlots()),
	}
}

// ShallowCopy creates a shallow copy of MaskedTransformProtocol in which all the read-only data-structures are
// shared with the receiver and the temporary buffers are reallocated. The receiver and the returned
// MaskedTransformProtocol can be used concurrently.
func (p MaskedTransformProtocol) ShallowCopy() *MaskedTransformProtocol {
	return &MaskedTransformProtocol{
		e2s:         *p.e2s.ShallowCopy(),
		s2e:         *p.s2e.ShallowCopy(),
		tmpPt:       p.e2s.params.RingQ().NewRNSPoly(),
		tmpMask:     make([]uint64, p.e2s.params.MaxSlots()),
		tmpMaskPerm: make([]uint64, p.e2s.params.MaxSlots()),
	}
}

// MaskedTransformFunc is a struct containing a user-defined in-place function that can be applied to masked integer plaintexts, as a part of the
// Masked Transform Protocol.
// The function is called with a vector of integers modulo heint.Parameters.TK() of size heint.Parameters.N() as input, and must write
// its output on the same buffer.
// Transform can be the identity.
// Decode: if true, then the masked BFV plaintext will be decoded before applying Transform.
// Recode: if true, then the masked BFV plaintext will be recoded after applying Transform.
// i.e. : Decode (true/false) -> Transform -> Recode (true/false).
type MaskedTransformFunc struct {
	Decode bool
	Func   func(coeffs []uint64)
	Encode bool
}

// NewMaskedTransformProtocol creates a new instance of the PermuteProtocol.
func NewMaskedTransformProtocol(paramsIn, paramsOut heint.Parameters) *MaskedTransformProtocol {
	return &MaskedTransformProtocol{
		e2s:         *NewEncToShareProtocol(paramsIn),
		s2e:         *NewShareToEncProtocol(paramsOut),
		tmpPt:       paramsOut.RingQ().NewRNSPoly(),
		tmpMask:     make([]uint64, paramsIn.MaxSlots()),
		tmpMaskPerm: make([]uint64, paramsIn.MaxSlots()),
	}
}

// Allocate allocates the shares of the PermuteProtocol
func (p MaskedTransformProtocol) Allocate(levelDecrypt, levelRecrypt int) *mhe.RefreshShare {
	return &mhe.RefreshShare{
		EncToShareShare: *p.e2s.Allocate(levelDecrypt),
		ShareToEncShare: *p.s2e.Allocate(levelRecrypt)}
}

// Gen generates the shares of the PermuteProtocol.
// ct1 is the degree 1 element of a rlwe.Ciphertext, i.e. rlwe.Ciphertext.Value[1].
func (p MaskedTransformProtocol) Gen(skIn, skOut *rlwe.SecretKey, ct *rlwe.Ciphertext, seed [32]byte, transform *MaskedTransformFunc, shareOut *mhe.RefreshShare) (err error) {

	if ct.Level() < shareOut.EncToShareShare.LevelQ() {
		return fmt.Errorf("cannot Gen: ct[1] level must be at least equal to EncToShareShare level")
	}

	if err = p.e2s.Gen(skIn, ct, &mhe.AdditiveShare{Value: p.tmpMask}, &shareOut.EncToShareShare); err != nil {
		return fmt.Errorf("p.e2s.Gen: %w", err)
	}

	mask := p.tmpMask
	if transform != nil {
		coeffs := make([]uint64, len(mask))

		if transform.Decode {

			if err := p.e2s.encoder.DecodeRingT(mask, ct.Scale, coeffs); err != nil {
				return fmt.Errorf("cannot Gen: %w", err)
			}
		} else {
			copy(coeffs, mask)
		}

		transform.Func(coeffs)

		if transform.Encode {
			if err := p.s2e.encoder.EncodeRingT(coeffs, ct.Scale, p.tmpMaskPerm); err != nil {
				return fmt.Errorf("cannot Gen: %w", err)
			}
		} else {
			copy(p.tmpMaskPerm, coeffs)
		}

		mask = p.tmpMaskPerm
	}

	// Stores the ciphertext metadata on the public share
	shareOut.MetaData = *ct.MetaData

	return p.s2e.Gen(skOut, seed, &mhe.AdditiveShare{Value: mask}, &shareOut.ShareToEncShare)
}

// Aggregate aggregates the public aggregatable transcripts: share3 = share1 + share2.
func (p MaskedTransformProtocol) Aggregate(share1, share2, share3 *mhe.RefreshShare) (err error) {

	if !share1.MetaData.Equal(&share2.MetaData) {
		return fmt.Errorf("shares metadata do not match")
	}

	if err = share3.EncToShareShare.VectorShare.Aggregate(p.e2s.params, &share1.EncToShareShare.VectorShare, &share2.EncToShareShare.VectorShare); err != nil {
		return
	}

	return share3.ShareToEncShare.VectorShare.Aggregate(p.s2e.params, &share1.ShareToEncShare.VectorShare, &share2.ShareToEncShare.VectorShare)
}

// Finalize applies Decrypt, Recode and Recrypt on the input ciphertext.
func (p MaskedTransformProtocol) Finalize(ct *rlwe.Ciphertext, transform *MaskedTransformFunc, share *mhe.RefreshShare, ciphertextOut *rlwe.Ciphertext) (err error) {

	if !ct.MetaData.Equal(&share.MetaData) {
		return fmt.Errorf("input ct.MetaData != share.MetaData")
	}

	if ct.Level() < share.EncToShareShare.LevelQ() {
		return fmt.Errorf("input ciphertext level must be at least equal to e2s level")
	}

	maxLevel := share.ShareToEncShare.LevelQ()

	p.e2s.Finalize(nil, &share.EncToShareShare, ct, &mhe.AdditiveShare{Value: p.tmpMask}) // tmpMask RingT(m - sum M_i)
	mask := p.tmpMask
	if transform != nil {
		coeffs := make([]uint64, len(mask))

		if transform.Decode {
			if err := p.e2s.encoder.DecodeRingT(mask, ciphertextOut.Scale, coeffs); err != nil {
				return fmt.Errorf("cannot Transform: %w", err)
			}
		} else {
			copy(coeffs, mask)
		}

		transform.Func(coeffs)

		if transform.Encode {
			if err := p.s2e.encoder.EncodeRingT(coeffs, ciphertextOut.Scale, p.tmpMaskPerm); err != nil {
				return fmt.Errorf("cannot Transform: %w", err)
			}
		} else {
			copy(p.tmpMaskPerm, coeffs)
		}

		mask = p.tmpMaskPerm
	}

	ciphertextOut.ResizeQ(maxLevel)

	p.s2e.encoder.RingT2Q(maxLevel, true, mask, p.tmpPt)
	p.s2e.params.RingQ().AtLevel(maxLevel).NTT(p.tmpPt, p.tmpPt)
	p.s2e.params.RingQ().AtLevel(maxLevel).Add(p.tmpPt, share.ShareToEncShare.Q[0], ciphertextOut.Q[0])

	shareOut := &mhe.KeySwitchingShare{}
	shareOut.Q = []ring.RNSPoly{ciphertextOut.Q[0]}
	shareOut.Seed = share.ShareToEncShare.Seed

	return p.s2e.Finalize(shareOut, ciphertextOut)
}
