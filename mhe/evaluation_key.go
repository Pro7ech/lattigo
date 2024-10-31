package mhe

import (
	"fmt"

	"github.com/Pro7ech/lattigo/rlwe"
)

// EvaluationKeyProtocol is the structure storing the parameters for the collective EvaluationKey generation.
type EvaluationKeyProtocol struct {
	GadgetCiphertextProtocol
}

// ShallowCopy creates a shallow copy of the receiver in which all the read-only data-structures are
// shared with the receiver and the temporary buffers are reallocated. The receiver and the returned
// object can be used concurrently.
func (p EvaluationKeyProtocol) ShallowCopy() *EvaluationKeyProtocol {
	return &EvaluationKeyProtocol{*p.GadgetCiphertextProtocol.ShallowCopy()}
}

// NewEvaluationKeyProtocol instantiates a new [mhe.EvaluationKeyProtocol].
func NewEvaluationKeyProtocol(params rlwe.ParameterProvider) (p *EvaluationKeyProtocol) {
	return &EvaluationKeyProtocol{*NewGadgetCiphertextProtocol(params)}
}

// Allocate allocates a party's share in the [mhe.EvaluationKeyProtocol].
func (p EvaluationKeyProtocol) Allocate(evkParams ...rlwe.EvaluationKeyParameters) *EvaluationKeyShare {
	params := *p.GetRLWEParameters()
	LevelQ, LevelP, dd := rlwe.ResolveEvaluationKeyParameters(params, evkParams)
	return &EvaluationKeyShare{GadgetCiphertextShare: *p.GadgetCiphertextProtocol.Allocate(LevelQ, LevelP, dd)}
}

// Gen generates a party's share in the [mhe.EvaluationKeyProtocol].
func (p EvaluationKeyProtocol) Gen(skIn, skOut *rlwe.SecretKey, seed [32]byte, share *EvaluationKeyShare) (err error) {
	return p.GadgetCiphertextProtocol.Gen(skOut, skIn.AsPlaintext(), seed, &share.GadgetCiphertextShare)
}

// Aggregate sets share3 to share1 + share2.
func (p EvaluationKeyProtocol) Aggregate(share1, share2, share3 *EvaluationKeyShare) (err error) {
	return share3.Aggregate(p.GetRLWEParameters(), share1, share2)
}

// Finalize finalizes the protocol and populates the input computed collective [rlwe.EvaluationKey].
func (p EvaluationKeyProtocol) Finalize(share *EvaluationKeyShare, evk *rlwe.EvaluationKey) (err error) {
	return share.Get(p.GetRLWEParameters(), evk)
}

// FinalizeNew finalizes the protocol and returns the computed collective [rlwe.EvaluationKey].
func (p EvaluationKeyProtocol) FinalizeNew(share *EvaluationKeyShare) (evk *rlwe.EvaluationKey) {
	return share.GetNew(p.GetRLWEParameters())
}

type EvaluationKeyShare struct {
	GadgetCiphertextShare
}

// Equal performs a deep equal between the receiver and the operand.
func (share EvaluationKeyShare) Equal(other *EvaluationKeyShare) bool {
	return share.GadgetCiphertextShare.Equal(&other.GadgetCiphertextShare)
}

// Aggregate sets the receiver to a + b.
func (share *EvaluationKeyShare) Aggregate(params rlwe.ParameterProvider, a, b *EvaluationKeyShare) (err error) {

	if a.Seed != b.Seed {
		return fmt.Errorf("shares seed do not match")
	}

	if a.DigitDecomposition != b.DigitDecomposition {
		return fmt.Errorf("shares digit decomposition do not match")
	}

	share.Seed = a.Seed
	share.DigitDecomposition = a.DigitDecomposition

	p := params.GetRLWEParameters()

	return share.Vector[0].Aggregate(p.RingQ(), p.RingP(), &a.Vector[0], &b.Vector[0])
}

// Get copies the data of the receiver on a pre-allocated [rlwe.EvaluationKey].
func (share EvaluationKeyShare) Get(params rlwe.ParameterProvider, evk *rlwe.EvaluationKey) (err error) {
	return share.GadgetCiphertextShare.Get(params, &evk.GadgetCiphertext)
}

// AsEvaluationKey wraps the receiver into an [rlwe.EvaluationKey].
func (share EvaluationKeyShare) AsEvaluationKey(params rlwe.ParameterProvider) (evk *rlwe.EvaluationKey) {
	return &rlwe.EvaluationKey{GadgetCiphertext: *share.GadgetCiphertextShare.AsGadgetCiphertext(params)}
}

// GetNew copies the data of the receiver on a new [rlwe.EvaluationKey].
func (share EvaluationKeyShare) GetNew(params rlwe.ParameterProvider) (evk *rlwe.EvaluationKey) {
	return &rlwe.EvaluationKey{GadgetCiphertext: *share.GadgetCiphertextShare.GetNew(params)}
}
