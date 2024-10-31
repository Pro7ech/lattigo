package mhefloat

import (
	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/mhe"

	"github.com/Pro7ech/lattigo/rlwe"
)

// RefreshProtocol is a struct storing the relevant parameters for the Refresh protocol.
type RefreshProtocol struct {
	MaskedTransformProtocol
}

// NewRefreshProtocol creates a new Refresh protocol instance.
// prec : the log2 of decimal precision of the internal encoder.
func NewRefreshProtocol(params hefloat.Parameters, prec uint) *RefreshProtocol {
	return &RefreshProtocol{*NewMaskedTransformProtocol(params, params, prec)}
}

// ShallowCopy creates a shallow copy of RefreshProtocol in which all the read-only data-structures are
// shared with the receiver and the temporary buffers are reallocated. The receiver and the returned
// RefreshProtocol can be used concurrently.
func (rfp RefreshProtocol) ShallowCopy() *RefreshProtocol {
	return &RefreshProtocol{*rfp.MaskedTransformProtocol.ShallowCopy()}
}

// Allocate allocates the shares of the PermuteProtocol
func (rfp RefreshProtocol) Allocate(inputLevel, outputLevel int) *mhe.RefreshShare {
	return rfp.MaskedTransformProtocol.Allocate(inputLevel, outputLevel)
}

// Gen generates a share for the Refresh protocol.
// This protocol requires additional inputs which are :
// logBound : the bit length of the masks
// ct1      : the degree 1 element the ciphertext to refresh, i.e. ct1 = ckk.Ciphetext.Value[1].
// scale    : the scale of the ciphertext entering the refresh.
// The method "GetMinimumLevelForBootstrapping" should be used to get the minimum level at which the refresh can be called while still ensure 128-bits of security, as well as the
// value for logBound.
func (rfp RefreshProtocol) Gen(sk *rlwe.SecretKey, logBound uint, ct *rlwe.Ciphertext, seed [32]byte, shareOut *mhe.RefreshShare) (err error) {
	return rfp.MaskedTransformProtocol.Gen(sk, sk, logBound, ct, seed, nil, shareOut)
}

// Aggregate aggregates two parties' shares in the Refresh protocol.
func (rfp RefreshProtocol) Aggregate(share1, share2, shareOut *mhe.RefreshShare) (err error) {
	return rfp.MaskedTransformProtocol.Aggregate(share1, share2, shareOut)
}

// Finalize applies Decrypt, Recode and Recrypt on the input ciphertext.
// The ciphertext scale is reset to the default scale.
func (rfp RefreshProtocol) Finalize(ctIn *rlwe.Ciphertext, share *mhe.RefreshShare, opOut *rlwe.Ciphertext) (err error) {
	return rfp.MaskedTransformProtocol.Finalize(ctIn, nil, share, opOut)
}
