package mhe

import (
	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/sampling"
)

// PublicKeyProtocol is the structure storing the parameters and and precomputations for
// the collective encryption key generation protocol.
type PublicKeyProtocol struct {
	*rlwe.Encryptor
}

type PublicKeyShare struct {
	VectorShare
}

// NewPublicKeyProtocol creates a new PublicKeyProtocol instance
func NewPublicKeyProtocol(params rlwe.ParameterProvider) *PublicKeyProtocol {
	return &PublicKeyProtocol{rlwe.NewEncryptor(params, nil)}
}

// ShallowCopy creates a shallow copy of the receiver in which all the read-only data-structures are
// shared with the receiver and the temporary buffers are reallocated. The receiver and the returned
// struct can be used concurrently.
func (p PublicKeyProtocol) ShallowCopy() *PublicKeyProtocol {
	return &PublicKeyProtocol{p.Encryptor.ShallowCopy()}
}

// Allocate allocates the share of the PublicKeyGen protocol.
func (p PublicKeyProtocol) Allocate() (pkg *PublicKeyShare) {
	params := p.GetRLWEParameters()
	return &PublicKeyShare{VectorShare: *NewVectorShare(params, params.MaxLevelQ(), params.MaxLevelP(), 2)}
}

// Gen generates the party's public key share from its secret key as:
//
// a[seeded]*s_i + e_i
//
// for the receiver protocol. Has no effect is the share was already generated.
func (p PublicKeyProtocol) Gen(sk *rlwe.SecretKey, seed [32]byte, share *PublicKeyShare) (err error) {
	share.Seed = seed
	ct := &rlwe.Ciphertext{}
	ct.Vector = &share.Vector
	ct.MetaData = &rlwe.MetaData{IsNTT: true, IsMontgomery: true}
	return p.WithKey(sk).WithSeededPublicRandomness(seed).EncryptZero(ct)
}

// Aggregate evalutes share3 = share1 + share2
func (p PublicKeyProtocol) Aggregate(share1, share2, share3 *PublicKeyShare) (err error) {
	return share3.Aggregate(p.GetRLWEParameters(), &share1.VectorShare, &share2.VectorShare)
}

// Finalize return the current aggregation of the received shares as a bfv.PublicKey.
func (p PublicKeyProtocol) Finalize(share *PublicKeyShare, pubkey *rlwe.PublicKey) (err error) {
	params := p.GetRLWEParameters()
	pubkey.Q[0].Copy(&share.Q[0])
	point := ring.Point{Q: pubkey.Q[1]}
	if share.LevelP() > -1 {
		pubkey.P[0].Copy(&share.P[0])
		point.P = pubkey.P[1]
	}
	point.Randomize(params.RingQ(), params.RingP(), sampling.NewSource(share.Seed))
	return
}
