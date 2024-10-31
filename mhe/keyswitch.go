package mhe

import (
	"fmt"

	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
)

// KeySwitchingProtocol is the structure storing the parameters and and precomputations for the collective key-switching protocol.
type KeySwitchingProtocol[T rlwe.SecretKey | rlwe.PublicKey] struct {
	*rlwe.Encryptor
	Sk *rlwe.SecretKey
}

// NewKeySwitchingProtocol creates a new KeySwitchingProtocol that will be used to perform a collective key-switching on a ciphertext encrypted under a collective public-key, whose
// secret-shares are distributed among j parties, re-encrypting the ciphertext under another public-key, whose secret-shares are also known to the
// parties.
func NewKeySwitchingProtocol[T rlwe.SecretKey | rlwe.PublicKey](params rlwe.ParameterProvider) *KeySwitchingProtocol[T] {
	return &KeySwitchingProtocol[T]{
		Encryptor: rlwe.NewEncryptor(params, nil),
	}
}

// ShallowCopy creates a shallow copy of KeySwitchingProtocol in which all the read-only data-structures are
// shared with the receiver and the temporary bufers are reallocated. The receiver and the returned
// KeySwitchingProtocol can be used concurrently.
func (p KeySwitchingProtocol[T]) ShallowCopy() *KeySwitchingProtocol[T] {
	return &KeySwitchingProtocol[T]{
		Encryptor: p.Encryptor.ShallowCopy(),
	}
}

// KeySwitchingShare is a type for the KeySwitch protocol shares.
type KeySwitchingShare struct {
	VectorShare
}

// Equal performs a deep equal between the receiver and the operand.
func (share KeySwitchingShare) Equal(other *KeySwitchingShare) bool {
	return share.VectorShare.Equal(&other.VectorShare)
}

func NewKeySwitchingShare(p rlwe.ParameterProvider, size, level int) *KeySwitchingShare {
	return &KeySwitchingShare{*NewVectorShare(p, level, -1, size)}
}

// Allocate allocates the share of the KeySwitchingProtocol.
func (p KeySwitchingProtocol[T]) Allocate(level int) *KeySwitchingShare {
	switch any(new(T)).(type) {
	case *rlwe.SecretKey:
		return NewKeySwitchingShare(p.GetRLWEParameters(), 1, level)
	default:
		return NewKeySwitchingShare(p.GetRLWEParameters(), 2, level)
	}
}

// Gen computes a party's public aggregatable transcrit (share) in the KeySwitchcol.
// ct is the rlwe.Ciphertext to keyswitch. Note that ct.Q[0] is not used by the function and can be nil/zero.
func (p KeySwitchingProtocol[T]) Gen(skIn *rlwe.SecretKey, keyOut *T, noise float64, ct *rlwe.Ciphertext, share *KeySwitchingShare) (err error) {

	ctKeySwitch := &rlwe.Ciphertext{}
	ctKeySwitch.Vector = &ring.Vector{}

	switch keyOut := any(keyOut).(type) {
	case *rlwe.SecretKey:

		if share.Size() != 1 {
			return fmt.Errorf("invalid share: should be of size 1 if keyOut is of type *rlwe.SecretKey, but is of size %d", share.Size())
		}

		ctKeySwitch.Q = []ring.RNSPoly{share.Q[0], ct.Q[1]}
		ctKeySwitch.MetaData = ct.MetaData

		if err = p.Encryptor.WithKey(keyOut).KeySwitch(skIn, noise, ctKeySwitch); err != nil {
			return
		}

	case *rlwe.PublicKey:

		if share.Size() != 2 {
			return fmt.Errorf("invalid share: should be of size 2 if keyOut is of type *rlwe.PublicKey, but is of size %d", share.Size())
		}

		ctKeySwitch.Q = []ring.RNSPoly{share.Q[0], share.Q[1]}
		ctKeySwitch.MetaData = ct.MetaData

		share.Q[1].Copy(&ct.Q[1])

		if err = p.Encryptor.WithKey(keyOut).KeySwitch(skIn, noise, ctKeySwitch); err != nil {
			return
		}
	}

	return
}

// Aggregate aggregates the public aggregatable transcripts: share3 = share1 + share2.
func (p KeySwitchingProtocol[T]) Aggregate(share1, share2, share3 *KeySwitchingShare) (err error) {
	if share1.Seed != share2.Seed {
		return fmt.Errorf("shares seed do not match")
	}
	share3.Seed = share1.Seed
	return share3.Vector.Aggregate(p.GetRLWEParameters().RingQ(), p.GetRLWEParameters().RingP(), &share1.Vector, &share2.Vector)
}

// FinalizeNew takes the public aggregated transcripts and peforms an oblivious re-encryption of in and returns the result in out.
func (p KeySwitchingProtocol[T]) FinalizeNew(in *rlwe.Ciphertext, share *KeySwitchingShare) (out *rlwe.Ciphertext, err error) {
	out = rlwe.NewCiphertext(p.GetRLWEParameters(), 1, min(in.Level(), share.Level()), -1)
	return out, p.Finalize(in, share, out)
}

// Finalize takes the public aggregated transcripts and peforms an oblivious re-encryption of in and returns the result in out.
func (p KeySwitchingProtocol[T]) Finalize(in *rlwe.Ciphertext, share *KeySwitchingShare, out *rlwe.Ciphertext) (err error) {

	level := min(min(in.Level(), out.Level()), share.Level())
	out.ResizeQ(level)
	*out.MetaData = *in.MetaData

	switch any(new(T)).(type) {
	case *rlwe.SecretKey:

		if share.Size() != 1 {
			return fmt.Errorf("invalid share: should be of size 1 if keyOut is of type *rlwe.SecretKey, but is of size %d", share.Size())
		}

		p.GetRLWEParameters().RingQ().AtLevel(level).Add(in.Q[0], share.Q[0], out.Q[0])

	case *rlwe.PublicKey:

		if share.Size() != 2 {
			return fmt.Errorf("invalid share: should be of size 2 if keyOut is of type *rlwe.PublicKey, but is of size %d", share.Size())
		}

		p.GetRLWEParameters().RingQ().AtLevel(level).Add(in.Q[0], share.Q[0], out.Q[0])
		out.Q[1].Copy(&share.Q[1])
	}

	return
}
