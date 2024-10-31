package mhe

import (
	"fmt"

	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/sampling"
)

// Thresholdizer is a type for generating secret-shares of ringqp.Poly types such that
// the resulting sharing has a t-out-of-N-threshold access-structure. It implements the
// `Thresholdize` operation as presented in "An Efficient Threshold Access-Structure
// for RLWE-Based Multiparty Homomorphic Encryption" (2022) by Mouchet, C., Bertrand, E.,
// and Hubaux, J. P. (https://eprint.iacr.org/2022/780).
//
// See the `mhe` package README.md.
type Thresholdizer struct {
	params rlwe.Parameters
}

// ShamirPublicPoint is a type for Shamir public point associated with a party identity within
// the t-out-of-N-threshold scheme.
//
// See Thresholdizer and Combiner types.
type ShamirPublicPoint uint64

// ShamirPolynomial represents a polynomial with ringqp.Poly coefficients. It is used by the
// Thresholdizer type to produce t-out-of-N-threshold shares of an ringqp.Poly.
//
// See [mhe.Thresholdizer].
type ShamirPolynomial struct {
	ring.Vector
}

// ShamirSecretShare represents a t-out-of-N-threshold secret-share.
//
// See [mhe.Thresholdizer] and [mhe.Combiner].
type ShamirSecretShare struct {
	ring.Point
}

// Equal performs a deep equal.
func (s ShamirSecretShare) Equal(other *ShamirSecretShare) bool {
	return s.Point.Equal(&other.Point)
}

// NewThresholdizer creates a new Thresholdizer instance from parameters.
func NewThresholdizer(params rlwe.ParameterProvider) *Thresholdizer {
	thr := &Thresholdizer{}
	thr.params = *params.GetRLWEParameters()
	return thr
}

// Gen generates a new secret ShamirPolynomial to be used in the Thresholdizer.GenShamirSecretShare method.
// It does so by sampling a random polynomial of degree threshold - 1 and with its constant term equal to secret.
func (thr Thresholdizer) Gen(threshold int, secret *rlwe.SecretKey) (*ShamirPolynomial, error) {
	if threshold < 1 {
		return nil, fmt.Errorf("threshold should be >= 1")
	}

	gen := *ring.NewVector(thr.params.N(), thr.params.MaxLevelQ(), thr.params.MaxLevelP(), threshold)
	gen.Randomize(thr.params.RingQ(), thr.params.RingP(), sampling.NewSource(sampling.NewSeed()))
	gen.Q[0].Copy(&secret.Q)

	if thr.params.MaxLevelP() > -1 {
		gen.P[0].Copy(&secret.P)
	}

	return &ShamirPolynomial{gen}, nil
}

// Allocate allocates a ShamirSecretShare struct.
func (thr Thresholdizer) Allocate() *ShamirSecretShare {
	return &ShamirSecretShare{*ring.NewPoint(thr.params.N(), thr.params.MaxLevelQ(), thr.params.MaxLevelP())}
}

// Aggregate aggregates two ShamirSecretShare and stores the result in outShare.
func (thr Thresholdizer) Aggregate(share1, share2, share3 *ShamirSecretShare) (err error) {
	return share3.Point.Aggregate(thr.params.RingQ(), thr.params.RingP(), &share1.Point, &share2.Point)
}

// Finalize generates a secret share for the given recipient, identified by its ShamirPublicPoint.
// The result is stored in ShareOut and should be sent to this party.
func (thr Thresholdizer) Finalize(recipient ShamirPublicPoint, secretPoly *ShamirPolynomial, shareOut *ShamirSecretShare) (err error) {
	rQ := thr.params.RingQ()
	rQ.EvalPolyScalar(secretPoly.Q, uint64(recipient), shareOut.Q)
	if rP := thr.params.RingP(); rP != nil {
		rP.EvalPolyScalar(secretPoly.P, uint64(recipient), shareOut.P)
	}
	return
}

// Combiner is a type for generating t-out-of-t additive shares from local t-out-of-N
// shares. It implements the `Combine` operation as presented in "An Efficient Threshold
// Access-Structure for RLWE-Based Multiparty Homomorphic Encryption" (2022) by Mouchet, C.,
// Bertrand, E., and Hubaux, J. P. (https://eprint.iacr.org/2022/780).
type Combiner struct {
	rQ             ring.RNSRing
	rP             ring.RNSRing
	threshold      int
	tmp1, tmp2     [2]ring.RNSScalar
	one            [2]ring.RNSScalar
	lagrangeCoeffs map[ShamirPublicPoint][2]ring.RNSScalar
}

// NewCombiner creates a new Combiner struct from the parameters and the set of ShamirPublicPoints. Note that the other
// parameter may contain the instantiator's own ShamirPublicPoint.
func NewCombiner(params rlwe.Parameters, own ShamirPublicPoint, others []ShamirPublicPoint, threshold int) *Combiner {
	cmb := &Combiner{}

	rQ := params.RingQ()
	rP := params.RingP()

	cmb.rQ = rQ
	cmb.rP = rP
	cmb.threshold = threshold

	cmb.tmp1[0] = make(ring.RNSScalar, params.MaxLevelQ()+1)
	cmb.tmp2[0] = make(ring.RNSScalar, params.MaxLevelQ()+1)
	cmb.one[0] = rQ.NewRNSScalarFromUInt64(1)
	for i, s := range rQ {
		cmb.one[0][i] = ring.MForm(cmb.one[0][i], s.Modulus, s.BRedConstant)
	}

	if rP != nil {
		cmb.tmp1[1] = make(ring.RNSScalar, params.MaxLevelP()+1)
		cmb.tmp2[1] = make(ring.RNSScalar, params.MaxLevelP()+1)
		cmb.one[1] = rP.NewRNSScalarFromUInt64(1)
		for i, s := range rP {
			cmb.one[1][i] = ring.MForm(cmb.one[1][i], s.Modulus, s.BRedConstant)
		}
	}

	// precomputes lagrange coefficient factors
	cmb.lagrangeCoeffs = make(map[ShamirPublicPoint][2]ring.RNSScalar)
	for _, spk := range others {
		if spk != own {
			var v [2]ring.RNSScalar
			v[0] = make(ring.RNSScalar, params.MaxLevelQ()+1)
			if rP != nil {
				v[1] = make(ring.RNSScalar, params.MaxLevelP()+1)
			}
			cmb.lagrangeCoeffs[spk] = v
			cmb.lagrangeCoeff(own, spk, cmb.lagrangeCoeffs[spk])
		}
	}

	return cmb
}

// Finalize generates a t-out-of-t additive share of the secret from a local aggregated share ownSecret and the set of active identities, identified
// by their ShamirPublicPoint. It stores the resulting additive share in skOut.
func (cmb Combiner) Finalize(activesPoints []ShamirPublicPoint, ownPoint ShamirPublicPoint, ownShare *ShamirSecretShare, skOut *rlwe.SecretKey) (err error) {

	if len(activesPoints) < cmb.threshold {
		return fmt.Errorf("not enough active players to combine threshold shares")
	}

	prod := cmb.tmp2
	copy(prod[0], cmb.one[0])
	copy(prod[1], cmb.one[1])

	rQ := cmb.rQ
	rP := cmb.rP

	for _, active := range activesPoints[:cmb.threshold] {
		//Lagrange Interpolation with the public threshold key of other active players
		if active != ownPoint {
			rQ.MulRNSScalar(prod[0], cmb.lagrangeCoeffs[active][0], prod[0])
			if rP != nil {
				rP.MulRNSScalar(prod[1], cmb.lagrangeCoeffs[active][1], prod[1])
			}
		}
	}

	rQ.MulRNSScalarMontgomery(ownShare.Q, prod[0], skOut.Q)
	if rP != nil {
		rP.MulRNSScalarMontgomery(ownShare.P, prod[1], skOut.P)
	}

	return
}

func (cmb Combiner) lagrangeCoeff(thisKey ShamirPublicPoint, thatKey ShamirPublicPoint, lagCoeff [2]ring.RNSScalar) {

	rQ := cmb.rQ
	rP := cmb.rP

	var this, that [2]ring.RNSScalar

	this[0] = rQ.NewRNSScalarFromUInt64(uint64(thisKey))
	that[0] = rQ.NewRNSScalarFromUInt64(uint64(thatKey))

	if rP != nil {
		this[1] = rP.NewRNSScalarFromUInt64(uint64(thisKey))
		that[1] = rP.NewRNSScalarFromUInt64(uint64(thatKey))
	}

	rQ.SubRNSScalar(that[0], this[0], lagCoeff[0])
	rQ.Inverse(lagCoeff[0])
	rQ.MulRNSScalar(lagCoeff[0], that[0], lagCoeff[0])
	if rP != nil {
		rP.SubRNSScalar(that[1], this[1], lagCoeff[1])
		rP.Inverse(lagCoeff[1])
		rP.MulRNSScalar(lagCoeff[1], that[1], lagCoeff[1])
	}
}
