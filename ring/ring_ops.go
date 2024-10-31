package ring

import (
	"math/big"

	"github.com/Pro7ech/lattigo/utils/bignum"
)

// Add evaluates p3 = p1 + p2 (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) Add(p1, p2, p3 []uint64) {
	AddVec(p1, p2, p3, r.Modulus)
}

// AddLazy evaluates p3 = p1 + p2.
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) AddLazy(p1, p2, p3 []uint64) {
	AddLazyVec(p1, p2, p3)
}

// Sub evaluates p3 = p1 - p2 (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) Sub(p1, p2, p3 []uint64) {
	SubVec(p1, p2, p3, r.Modulus)
}

// SubLazy evaluates p3 = p1 - p2.
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) SubLazy(p1, p2, p3 []uint64) {
	SubLazyVec(p1, p2, p3, r.Modulus)
}

// Neg evaluates p2 = -p1 (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) Neg(p1, p2 []uint64) {
	NegVec(p1, p2, r.Modulus)
}

// Reduce evaluates p2 = p1 (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) Reduce(p1, p2 []uint64) {
	BarrettReduceVec(p1, p2, r.Modulus, r.BRedConstant)
}

// ReduceLazy evaluates p2 = p1 (mod modulus) with p2 in range [0, 2*modulus-1].
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) ReduceLazy(p1, p2 []uint64) {
	BarrettReduceLazyVec(p1, p2, r.Modulus, r.BRedConstant)
}

// MulCoeffsLazy evaluates p3 = p1*p2.
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) MulCoeffsLazy(p1, p2, p3 []uint64) {
	MulVec(p1, p2, p3)
}

// MulCoeffsLazyThenAddLazy evaluates p3 = p3 + p1*p2.
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) MulCoeffsLazyThenAddLazy(p1, p2, p3 []uint64) {
	MulThenAddLazyVec(p1, p2, p3)
}

// MulCoeffsBarrett evaluates p3 = p1*p2 (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) MulCoeffsBarrett(p1, p2, p3 []uint64) {
	MulBarrettReduceVec(p1, p2, p3, r.Modulus, r.BRedConstant)
}

// MulCoeffsBarrettLazy evaluates p3 = p1*p2 (mod modulus) with p3 in [0, 2*modulus-1].
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) MulCoeffsBarrettLazy(p1, p2, p3 []uint64) {
	MulBarrettReduceLazyVec(p1, p2, p3, r.Modulus, r.BRedConstant)
}

// MulCoeffsBarrettThenAdd evaluates p3 = p3 + (p1*p2) (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) MulCoeffsBarrettThenAdd(p1, p2, p3 []uint64) {
	MulBarrettReduceThenAddVec(p1, p2, p3, r.Modulus, r.BRedConstant)
}

// MulCoeffsBarrettThenAddLazy evaluates p3 = p3 + p1*p2 (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) MulCoeffsBarrettThenAddLazy(p1, p2, p3 []uint64) {
	MulBarrettReduceThenAddLazyVec(p1, p2, p3, r.Modulus, r.BRedConstant)
}

// MulCoeffsMontgomery evaluates p3 = p1*p2 (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) MulCoeffsMontgomery(p1, p2, p3 []uint64) {
	MulMontgomeryReduceVec(p1, p2, p3, r.Modulus, r.MRedConstant)
}

// MulCoeffsMontgomeryLazy evaluates p3 = p1*p2 (mod modulus) with p3 in range [0, 2*modulus-1].
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) MulCoeffsMontgomeryLazy(p1, p2, p3 []uint64) {
	MulMontgomeryReduceLazyVec(p1, p2, p3, r.Modulus, r.MRedConstant)
}

// MulCoeffsMontgomeryThenAdd evaluates p3 = p3 + (p1*p2) (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) MulCoeffsMontgomeryThenAdd(p1, p2, p3 []uint64) {
	MulMontgomeryReduceThenAddVec(p1, p2, p3, r.Modulus, r.MRedConstant)
}

// MulCoeffsMontgomeryThenAddLazy evaluates p3 = p3 + (p1*p2 (mod modulus)).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) MulCoeffsMontgomeryThenAddLazy(p1, p2, p3 []uint64) {
	MulMontgomeryReduceThenAddLazyVec(p1, p2, p3, r.Modulus, r.MRedConstant)
}

// MulCoeffsMontgomeryLazyThenAddLazy evaluates p3 = p3 + p1*p2 (mod modulus) with p3 in range [0, 3modulus-2].
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) MulCoeffsMontgomeryLazyThenAddLazy(p1, p2, p3 []uint64) {
	MulMontgomeryReduceLazyThenAddLazyVec(p1, p2, p3, r.Modulus, r.MRedConstant)
}

// MulCoeffsMontgomeryThenSub evaluates p3 = p3 - p1*p2 (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) MulCoeffsMontgomeryThenSub(p1, p2, p3 []uint64) {
	MulMontgomeryReduceThenSubVec(p1, p2, p3, r.Modulus, r.MRedConstant)
}

// MulCoeffsMontgomeryThenSubLazy evaluates p3 = p3 - p1*p2 (mod modulus) with p3 in range [0, 2*modulus-2].
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) MulCoeffsMontgomeryThenSubLazy(p1, p2, p3 []uint64) {
	MulMontgomeryReduceThenSubLazyVec(p1, p2, p3, r.Modulus, r.MRedConstant)
}

// MulCoeffsMontgomeryLazyThenSubLazy evaluates p3 = p3 - p1*p2 (mod modulus) with p3 in range [0, 3*modulus-2].
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) MulCoeffsMontgomeryLazyThenSubLazy(p1, p2, p3 []uint64) {
	MulMontgomeryReduceLazyThenSubLazyVec(p1, p2, p3, r.Modulus, r.MRedConstant)
}

// MulCoeffsMontgomeryLazyThenNeg evaluates p3 = - p1*p2 (mod modulus) with p3 in range [0, 2*modulus-2].
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) MulCoeffsMontgomeryLazyThenNeg(p1, p2, p3 []uint64) {
	MulMontgomeryReduceLazyThenNegLazyVec(p1, p2, p3, r.Modulus, r.MRedConstant)
}

// AddLazyThenMulScalarMontgomery evaluates p3 = (p1+p2)*scalarMont (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) AddLazyThenMulScalarMontgomery(p1, p2 []uint64, scalarMont uint64, p3 []uint64) {
	AddThenMulScalarMontgomeryReduce(p1, p2, scalarMont, p3, r.Modulus, r.MRedConstant)
}

// AddScalarLazyThenMulScalarMontgomery evaluates p3 = (scalarMont0+p2)*scalarMont1 (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) AddScalarLazyThenMulScalarMontgomery(p1 []uint64, scalar0, scalarMont1 uint64, p2 []uint64) {
	AddScalarThenMulScalarMontgomeryReduceVec(p1, scalar0, scalarMont1, p2, r.Modulus, r.MRedConstant)
}

// AddScalar evaluates p2 = p1 + scalar (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) AddScalar(p1 []uint64, scalar uint64, p2 []uint64) {
	AddScalarVec(p1, scalar, p2, r.Modulus)
}

// AddScalarLazy evaluates p2 = p1 + scalar.
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) AddScalarLazy(p1 []uint64, scalar uint64, p2 []uint64) {
	AddScalarLazyVec(p1, scalar, p2)
}

// AddScalarLazyThenNegTwoModulusLazy evaluates p2 = 2*modulus - p1 + scalar.
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) AddScalarLazyThenNegTwoModulusLazy(p1 []uint64, scalar uint64, p2 []uint64) {
	AddScalarLazyThenNegateTwoModulusLazyVec(p1, scalar, p2, r.Modulus)
}

// SubScalar evaluates p2 = p1 - scalar (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) SubScalar(p1 []uint64, scalar uint64, p2 []uint64) {
	SubScalarVec(p1, scalar, p2, r.Modulus)
}

// SubScalarBigint evaluates p2 = p1 - scalar (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) SubScalarBigint(p1 []uint64, scalar *big.Int, p2 []uint64) {
	SubScalarVec(p1, new(big.Int).Mod(scalar, bignum.NewInt(r.Modulus)).Uint64(), p2, r.Modulus)
}

// MulScalar evaluates p2 = p1*scalar (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) MulScalar(p1 []uint64, scalar uint64, p2 []uint64) {
	MulScalarMontgomeryReduceVec(p1, MForm(scalar, r.Modulus, r.BRedConstant), p2, r.Modulus, r.MRedConstant)
}

// MulScalarMontgomery evaluates p2 = p1*scalarMont (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) MulScalarMontgomery(p1 []uint64, scalarMont uint64, p2 []uint64) {
	MulScalarMontgomeryReduceVec(p1, scalarMont, p2, r.Modulus, r.MRedConstant)
}

// MulScalarMontgomeryLazy evaluates p2 = p1*scalarMont (mod modulus) with p2 in range [0, 2*modulus-1].
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) MulScalarMontgomeryLazy(p1 []uint64, scalarMont uint64, p2 []uint64) {
	MulScalarMontgomeryReduceLazyVec(p1, scalarMont, p2, r.Modulus, r.MRedConstant)
}

// MulScalarMontgomeryThenAdd evaluates p2 = p2 + p1*scalarMont (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) MulScalarMontgomeryThenAdd(p1 []uint64, scalarMont uint64, p2 []uint64) {
	MulScalarMontgomeryReduceThenAddVec(p1, scalarMont, p2, r.Modulus, r.MRedConstant)
}

// MulScalarMontgomeryThenAddScalar evaluates p2 = scalar + p1*scalarMont (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) MulScalarMontgomeryThenAddScalar(p1 []uint64, scalar0, scalarMont1 uint64, p2 []uint64) {
	MulScalarMontgomeryReduceThenAddScalarVec(p1, scalar0, scalarMont1, p2, r.Modulus, r.MRedConstant)
}

// SubThenMulScalarMontgomeryTwoModulus evaluates p3 = (p1 + twomodulus - p2) * scalarMont (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) SubThenMulScalarMontgomeryTwoModulus(p1, p2 []uint64, scalarMont uint64, p3 []uint64) {
	SubToModulusThenMulScalarMontgomeryReduceVec(p1, p2, scalarMont, p3, r.Modulus, r.MRedConstant)
}

// MForm evaluates p2 = p1 * 2^64 (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) MForm(p1, p2 []uint64) {
	MFormVec(p1, p2, r.Modulus, r.BRedConstant)
}

// MFormLazy evaluates p2 = p1 * 2^64 (mod modulus) with p2 in the range [0, 2*modulus-1].
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) MFormLazy(p1, p2 []uint64) {
	MFormLazyVec(p1, p2, r.Modulus, r.BRedConstant)
}

// IMForm evaluates p2 = p1 * (2^64)^-1 (mod modulus).
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) IMForm(p1, p2 []uint64) {
	IMFormVec(p1, p2, r.Modulus, r.MRedConstant)
}

// CenterModU64 evaluates p2 = center(p1, w) % 2^{64}
// Iteration is done with respect to len(p1).
// All input must have a size which is a multiple of 8.
func (r Ring) CenterModU64(p1 []uint64, p2 []uint64) {
	CenterModU64Vec(p1, r.Modulus, p2)
}

func (r Ring) DecomposeUnsigned(j int, pw2 uint64, in, out []uint64) {
	DecomposeUnsigned(j, in, out, pw2, r.Modulus)
}

func (r Ring) DecomposeSigned(j int, pw2 uint64, in, carry, out []uint64) {
	DecomposeSigned(j, in, carry, out, pw2, r.Modulus)
}

func (r Ring) DecomposeSignedBalanced(j int, pw2 uint64, in, carry, out []uint64) {
	DecomposeSignedBalanced(j, in, carry, out, pw2, r.Modulus)
}
