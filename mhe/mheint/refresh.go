package mheint

import (
	"github.com/Pro7ech/lattigo/he/heint"
	"github.com/Pro7ech/lattigo/mhe"

	"github.com/Pro7ech/lattigo/rlwe"
)

// RefreshProtocol is a struct storing the relevant parameters for the Refresh protocol.
type RefreshProtocol struct {
	MaskedTransformProtocol
}

// ShallowCopy creates a shallow copy of RefreshProtocol in which all the read-only data-structures are
// shared with the receiver and the temporary buffers are reallocated. The receiver and the returned
// RefreshProtocol can be used concurrently.
func (rfp RefreshProtocol) ShallowCopy() *RefreshProtocol {
	return &RefreshProtocol{*rfp.MaskedTransformProtocol.ShallowCopy()}
}

// NewRefreshProtocol creates a new Refresh protocol instance.
func NewRefreshProtocol(params heint.Parameters) *RefreshProtocol {
	return &RefreshProtocol{*NewMaskedTransformProtocol(params, params)}
}

// Allocate allocates the shares of the PermuteProtocol
func (rfp RefreshProtocol) Allocate(inputLevel, outputLevel int) *mhe.RefreshShare {
	return rfp.MaskedTransformProtocol.Allocate(inputLevel, outputLevel)
}

// Gen generates a share for the Refresh protocol.
// ct1 is degree 1 element of a rlwe.Ciphertext, i.e. rlwe.Ciphertext.Value[1].
func (rfp RefreshProtocol) Gen(sk *rlwe.SecretKey, ct *rlwe.Ciphertext, seed [32]byte, share *mhe.RefreshShare) (err error) {
	return rfp.MaskedTransformProtocol.Gen(sk, sk, ct, seed, nil, share)
}

// Aggregate aggregates two parties' shares in the Refresh protocol.
func (rfp RefreshProtocol) Aggregate(share1, share2, share3 *mhe.RefreshShare) (err error) {
	return rfp.MaskedTransformProtocol.Aggregate(share1, share2, share3)
}

// Finalize applies Decrypt, Recode and Recrypt on the input ciphertext.
func (rfp RefreshProtocol) Finalize(ctIn *rlwe.Ciphertext, share *mhe.RefreshShare, opOut *rlwe.Ciphertext) (err error) {
	return rfp.MaskedTransformProtocol.Finalize(ctIn, nil, share, opOut)
}
