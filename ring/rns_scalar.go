package ring

import (
	"math/big"
)

// RNSScalar represents a scalar value in the Ring (i.e., a degree-0 polynomial) in RNS form.
type RNSScalar []uint64

// NewRNSScalar creates a new Scalar value.
func (r RNSRing) NewRNSScalar() RNSScalar {
	return make(RNSScalar, r.ModuliChainLength())
}

// NewRNSScalarFromUInt64 creates a new Scalar initialized with value v.
func (r RNSRing) NewRNSScalarFromUInt64(v uint64) (rns RNSScalar) {
	rns = make(RNSScalar, r.ModuliChainLength())
	for i, s := range r {
		rns[i] = v % s.Modulus
	}
	return rns
}

// NewRNSScalarFromBigint creates a new Scalar initialized with value v.
func (r RNSRing) NewRNSScalarFromBigint(v *big.Int) (rns RNSScalar) {
	rns = make(RNSScalar, r.ModuliChainLength())
	tmp0 := new(big.Int)
	tmp1 := new(big.Int)
	for i, s := range r {
		rns[i] = tmp0.Mod(v, tmp1.SetUint64(s.Modulus)).Uint64()
	}
	return rns
}

// MFormRNSScalar switches an RNS scalar to the Montgomery domain.
// s2 = s1<<64 mod Q
func (r RNSRing) MFormRNSScalar(s1, s2 RNSScalar) {
	for i, s := range r {
		s2[i] = MForm(s1[i], s.Modulus, s.BRedConstant)
	}
}

// NegRNSScalar evaluates s2 = -s1.
func (r RNSRing) NegRNSScalar(s1, s2 RNSScalar) {
	for i, s := range r {
		s2[i] = s.Modulus - s1[i]
	}
}

// SubRNSScalar subtracts s2 to s1 and stores the result in sout.
func (r RNSRing) SubRNSScalar(s1, s2, sout RNSScalar) {
	for i, s := range r {
		if s2[i] > s1[i] {
			sout[i] = s1[i] + s.Modulus - s2[i]
		} else {
			sout[i] = s1[i] - s2[i]
		}
	}
}

// MulRNSScalar multiplies s1 and s2 and stores the result in sout.
// Multiplication is operated with Montgomery.
func (r RNSRing) MulRNSScalar(s1, s2, sout RNSScalar) {
	for i, s := range r {
		sout[i] = MRedLazy(s1[i], s2[i], s.Modulus, s.MRedConstant)
	}
}

// Inverse computes the modular inverse of a scalar a expressed in a CRT decomposition.
// The inversion is done in-place and assumes that a is in Montgomery form.
func (r RNSRing) Inverse(a RNSScalar) {
	for i, s := range r {
		a[i] = ModExpMontgomery(a[i], s.Modulus-2, s.Modulus, s.MRedConstant, s.BRedConstant)
	}
}
