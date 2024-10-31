package mhe

import (
	"github.com/Pro7ech/lattigo/rlwe"
)

// RelinearizationKeyProtocol is the structure storing the parameters and
// precomputations for the collective relinearization key generation protocol.
// The protocol is based on https://eprint.iacr.org/2021/1085.
type RelinearizationKeyProtocol struct {
	*rlwe.Encryptor
}

// RelinearizationKeyShare is a share in the [mhe.RelinearizationKeyProtocol].
type RelinearizationKeyShare struct {
	rlwe.GadgetCiphertext
}

// NewRelinearizationKeyProtocol creates a new [mhe.RelinearizationKeyProtocol] struct.
func NewRelinearizationKeyProtocol(params rlwe.ParameterProvider) *RelinearizationKeyProtocol {
	return &RelinearizationKeyProtocol{rlwe.NewEncryptor(params, nil)}
}

// ShallowCopy creates a shallow copy of the receiver in which all the read-only data-structures are
// shared with the receiver and the temporary buffers are reallocated. The receiver and the returned
// object can be used concurrently.
func (p *RelinearizationKeyProtocol) ShallowCopy() *RelinearizationKeyProtocol {
	return &RelinearizationKeyProtocol{p.Encryptor.ShallowCopy()}
}

// Gen generates a party's share in the RelinearizationKey Generation Protocol.
func (p RelinearizationKeyProtocol) Gen(sk *rlwe.SecretKey, pk *rlwe.PublicKey, share *RelinearizationKeyShare) (err error) {

	if err = p.WithKey(pk).EncryptZero(&share.GadgetCiphertext); err != nil {
		return
	}

	params := p.GetRLWEParameters()

	return rlwe.AddPlaintextToMatrix(params.RingQ(), params.RingP(), sk.Q, p.BuffQ[0], share.Vector[1], share.DigitDecomposition)
}

// Aggregate sets share3 to share1 + share2.
func (p RelinearizationKeyProtocol) Aggregate(share1, share2, share3 *RelinearizationKeyShare) (err error) {
	params := p.GetRLWEParameters()
	if err = share3.Vector[0].Aggregate(params.RingQ(), params.RingP(), &share1.Vector[0], &share2.Vector[0]); err != nil {
		return
	}
	return share3.Vector[1].Aggregate(params.RingQ(), params.RingP(), &share1.Vector[1], &share2.Vector[1])
}

// Finalize finalizes the protocol and populates the input computed collective RelinearizationKey.
func (p RelinearizationKeyProtocol) Finalize(share *RelinearizationKeyShare, evk *rlwe.RelinearizationKey) (err error) {
	evk.Copy(share.Vector)
	return
}

// Allocate allocates the share of the [mhe.RelinearizationKeyProtocol].
func (p RelinearizationKeyProtocol) Allocate(evkParams ...rlwe.EvaluationKeyParameters) *RelinearizationKeyShare {
	params := *p.GetRLWEParameters()
	LevelQ, LevelP, dd := rlwe.ResolveEvaluationKeyParameters(params, evkParams)
	return &RelinearizationKeyShare{GadgetCiphertext: *rlwe.NewGadgetCiphertext(params, 1, LevelQ, LevelP, dd)}
}
