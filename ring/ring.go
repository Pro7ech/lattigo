package ring

import (
	"fmt"
	"math/big"
	"math/bits"

	"github.com/Pro7ech/lattigo/utils"
	"github.com/Pro7ech/lattigo/utils/bignum"
	"github.com/Pro7ech/lattigo/utils/factorization"
)

// Ring is a struct storing precomputation
// for fast modular reduction and NTT for
// a given modulus.
type Ring struct {
	NumberTheoreticTransformer

	// Polynomial nb.Coefficients
	N int

	BaseModulus uint64

	BaseModulusPower int

	// BaseModulus^BaseModulusPower
	Modulus uint64

	// Unique factors of Modulus-1
	Factors []uint64

	// 2^bit_length(Modulus) - 1
	Mask uint64

	// Fast reduction constants
	BRedConstant [2]uint64 // Barrett Reduction
	MRedConstant uint64    // Montgomery Reduction

	*NTTTable // NTT related constants
}

// NewRing creates a new [Ring] with the standard NTT.
// NTT constants still need to be generated using .GenNTTConstants(NthRoot uint64).
func NewRing(N int, Modulus uint64, ModulusPower int) (s *Ring, err error) {
	return NewRingWithCustomNTT(N, Modulus, ModulusPower, NewNumberTheoreticTransformerStandard, 2*N)
}

// NewRingWithCustomNTT creates a new [Ring] with degree N and modulus Modulus with user-defined [NumberTheoreticTransformer] and primitive Nth root of unity.
// An error is returned with a nil *Ring in the case of non NTT-enabling parameters.
func NewRingWithCustomNTT(N int, Modulus uint64, ModulusPower int, ntt func(*Ring, int) NumberTheoreticTransformer, NthRoot int) (r *Ring, err error) {

	// Checks if N is a power of 2
	if N < MinimumRingDegreeForLoopUnrolledOperations || (N&(N-1)) != 0 && N != 0 {
		return nil, fmt.Errorf("invalid ring degree: must be a power of 2 greater than %d", MinimumRingDegreeForLoopUnrolledOperations)
	}

	if bits.Len64(Modulus)*ModulusPower > 62 {
		return nil, fmt.Errorf("invalid Modulus: Modulus^ModulusPower > 2^61")
	}

	r = &Ring{}

	r.N = N

	r.BaseModulus = Modulus

	r.Modulus = Modulus
	for i := 1; i < ModulusPower; i++ {
		r.Modulus *= Modulus
	}

	r.BaseModulusPower = ModulusPower

	r.Mask = (1 << uint64(bits.Len64(r.Modulus-1))) - 1

	// Computes the fast modular reduction constants for the Ring
	r.BRedConstant = GetBRedConstant(r.Modulus)

	// If qi is not a power of 2, we can compute the MRed (otherwise, it
	// would return an error as there is no valid Montgomery form mod a power of 2)
	if (r.Modulus&(r.Modulus-1)) != 0 && r.Modulus != 0 {
		r.MRedConstant = GetMRedConstant(r.Modulus)
	}

	r.NTTTable = new(NTTTable)
	r.NthRoot = uint64(NthRoot)

	r.NumberTheoreticTransformer = ntt(r, N)

	return
}

func (r Ring) LogN() int {
	return bits.Len64(uint64(r.N) - 1)
}

func (r Ring) NewPoly() Poly {
	return NewPoly(r.N)
}

// Stats returns base 2 logarithm of the standard deviation
// and the mean of the coefficients of the polynomial.
func (r Ring) Stats(poly Poly) [2]float64 {
	values := make([]big.Int, len(poly))
	for i := range values {
		values[i].SetUint64(poly[i])
	}
	return bignum.Stats(values, 128)
}

// Phi returns Phi(BaseModulus^BaseModulusPower)
func (r Ring) Phi() (phi uint64) {
	phi = r.BaseModulus - 1
	for i := 1; i < r.BaseModulusPower; i++ {
		phi *= r.BaseModulus
	}
	return
}

// Type returns the [Type] of [Ring] which might be either `Standard` or `ConjugateInvariant`.
func (r Ring) Type() Type {
	switch r.NumberTheoreticTransformer.(type) {
	case NumberTheoreticTransformerStandard:
		return Standard
	case NumberTheoreticTransformerConjugateInvariant:
		return ConjugateInvariant
	default:
		// Sanity check
		panic(fmt.Errorf("invalid NumberTheoreticTransformer type: %T", r.NumberTheoreticTransformer))
	}
}

// GenNTTTable generates the NTT tables for the target Ring.
// The fields `PrimitiveRoot` and `Factors` can be set manually to
// bypass the search for the primitive root (which requires to
// factor Modulus-1) and speedup the generation of the constants.
func (r *Ring) GenNTTTable() (err error) {

	if r.N == 0 || r.Modulus == 0 {
		return fmt.Errorf("invalid t parameters (missing)")
	}

	Modulus := r.Modulus
	NthRoot := r.NthRoot

	// Checks if each qi is prime and equal to 1 mod NthRoot
	if !IsPrime(r.BaseModulus) {
		return fmt.Errorf("invalid modulus: %d is not prime)", Modulus)
	}

	if Modulus&(NthRoot-1) != 1 {
		return fmt.Errorf("invalid modulus: %d != 1 mod NthRoot=%d)", Modulus, NthRoot)
	}

	// It is possible to manually set the primitive root along with the factors of q-1.
	// This is notably useful when marshalling the Ring, to avoid re-factoring q-1.
	// If both are set, then checks that that the root is indeed primitive.
	// Else, factorize q-1 and finds a primitive root.
	if r.PrimitiveRoot != 0 && r.Factors != nil {
		if err = CheckPrimitiveRoot(r.PrimitiveRoot, Modulus, r.Factors); err != nil {
			return
		}
	} else {

		if r.PrimitiveRoot, r.Factors, err = PrimitiveRoot(r.BaseModulus, r.Factors); err != nil {
			return
		}
	}

	logNthRoot := int(bits.Len64(NthRoot>>1) - 1)

	// BaseModulus^{k-1} * (BaseModulus - 1) - 1

	phi := r.Phi()

	// 1.1 Computes N^(-1) mod Q in Montgomery form
	r.NInv = MForm(ModExp(NthRoot>>1, phi-1, Modulus), Modulus, r.BRedConstant)

	// 1.2 Computes Psi and PsiInv in Montgomery form

	// Computes Psi and PsiInv in Montgomery form for BaseModulus
	Psi := ModExp(r.PrimitiveRoot, (r.BaseModulus-1)/NthRoot, r.BaseModulus)

	// Updates the primitive root mod P to mod P^k using Hensel lifting
	Psi = HenselLift(Psi, NthRoot, r.BaseModulus, r.BaseModulusPower)

	PsiMont := MForm(Psi, Modulus, r.BRedConstant)

	// Checks that Psi^{2N} = 1 mod BaseModulus^BaseModulusPower
	if IMForm(ModExpMontgomery(PsiMont, NthRoot, r.Modulus, r.MRedConstant, r.BRedConstant), r.Modulus, r.MRedConstant) != 1 {
		return fmt.Errorf("invalid 2Nth primtive root: psi^{2N} != 1 mod Modulus, something went wrong")
	}

	// Checks that Psi^{N} = -1 mod BaseModulus^BaseModulusPower
	if IMForm(ModExpMontgomery(PsiMont, NthRoot>>1, r.Modulus, r.MRedConstant, r.BRedConstant), r.Modulus, r.MRedConstant) != r.Modulus-1 {
		return fmt.Errorf("invalid 2Nth primtive root: psi^{2N} != 1 mod Modulus, something went wrong")
	}

	PsiInvMont := ModExpMontgomery(PsiMont, phi-1, Modulus, r.MRedConstant, r.BRedConstant)

	r.RootsForward = make([]uint64, NthRoot>>1)
	r.RootsBackward = make([]uint64, NthRoot>>1)

	r.RootsForward[0] = MForm(1, Modulus, r.BRedConstant)
	r.RootsBackward[0] = MForm(1, Modulus, r.BRedConstant)

	// Computes nttPsi[j] = nttPsi[j-1]*Psi and RootsBackward[j] = RootsBackward[j-1]*PsiInv
	for j := uint64(1); j < NthRoot>>1; j++ {

		indexReversePrev := utils.BitReverse64(j-1, logNthRoot)
		indexReverseNext := utils.BitReverse64(j, logNthRoot)

		r.RootsForward[indexReverseNext] = MRed(r.RootsForward[indexReversePrev], PsiMont, Modulus, r.MRedConstant)
		r.RootsBackward[indexReverseNext] = MRed(r.RootsBackward[indexReversePrev], PsiInvMont, Modulus, r.MRedConstant)
	}

	return
}

// PrimitiveRoot computes the smallest primitive root of the given prime q
// The unique factors of q-1 can be given to speed up the search for the root.
func PrimitiveRoot(q uint64, factors []uint64) (uint64, []uint64, error) {

	if factors != nil {
		if err := CheckFactors(q-1, factors); err != nil {
			return 0, factors, err
		}
	} else {

		factorsBig := factorization.GetFactors(new(big.Int).SetUint64(q - 1)) //Factor q-1, might be slow

		factors = make([]uint64, len(factorsBig))
		for i := range factors {
			factors[i] = factorsBig[i].Uint64()
		}
	}

	notFoundPrimitiveRoot := true

	var g uint64 = 2

	for notFoundPrimitiveRoot {
		g++
		for _, factor := range factors {
			// if for any factor of q-1, g^(q-1)/factor = 1 mod q, g is not a primitive root
			if ModExp(g, (q-1)/factor, q) == 1 {
				notFoundPrimitiveRoot = true
				break
			}
			notFoundPrimitiveRoot = false
		}
	}

	return g, factors, nil
}

// CheckFactors checks that the given list of factors contains
// all the unique primes of m.
func CheckFactors(m uint64, factors []uint64) (err error) {

	for _, factor := range factors {

		if !IsPrime(factor) {
			return fmt.Errorf("composite factor")
		}

		for m%factor == 0 {
			m /= factor
		}
	}

	if m != 1 {
		return fmt.Errorf("incomplete factor list")
	}

	return
}

// CheckPrimitiveRoot checks that g is a valid primitive root mod q,
// given the factors of q-1.
func CheckPrimitiveRoot(g, q uint64, factors []uint64) (err error) {

	if err = CheckFactors(q-1, factors); err != nil {
		return
	}

	for _, factor := range factors {
		if ModExp(g, (q-1)/factor, q) == 1 {
			return fmt.Errorf("invalid primitive root")
		}
	}

	return
}

// ringParametersLiteral is a struct to store the minimum information
// to uniquely identify a Ring and be able to reconstruct it efficiently.
// This struct's purpose is to faciliate marshalling of Rings.
type ringParametersLiteral struct {
	Type             uint8  // Standard or ConjugateInvariant
	LogN             uint8  // Log2 of the ring degree
	NthRoot          uint8  // N/NthRoot
	Modulus          uint64 // Modulus
	BaseModulus      uint64
	BaseModulusPower int
	Factors          []uint64 // Factors of Modulus-1
	PrimitiveRoot    uint64   // Primitive root used
}

// ParametersLiteral returns the RingParametersLiteral of the Ring.
func (r Ring) parametersLiteral() ringParametersLiteral {
	Factors := make([]uint64, len(r.Factors))
	copy(Factors, r.Factors)
	return ringParametersLiteral{
		Type:             uint8(r.Type()),
		LogN:             uint8(bits.Len64(uint64(r.N - 1))),
		NthRoot:          uint8(int(r.NthRoot) / r.N),
		Modulus:          r.Modulus,
		BaseModulus:      r.BaseModulus,
		BaseModulusPower: r.BaseModulusPower,
		Factors:          Factors,
		PrimitiveRoot:    r.PrimitiveRoot,
	}
}

func newRingFromParametersLiteral(p ringParametersLiteral) (r *Ring, err error) {

	r = new(Ring)

	r.N = 1 << int(p.LogN)

	r.NTTTable = new(NTTTable)
	r.NthRoot = uint64(r.N) * uint64(p.NthRoot)

	r.Modulus = p.Modulus
	r.BaseModulus = p.BaseModulus
	r.BaseModulusPower = p.BaseModulusPower

	r.Factors = make([]uint64, len(p.Factors))
	copy(r.Factors, p.Factors)

	r.PrimitiveRoot = p.PrimitiveRoot

	r.Mask = (1 << uint64(bits.Len64(r.Modulus-1))) - 1

	// Computes the fast modular reduction parameters for the Ring
	r.BRedConstant = GetBRedConstant(r.Modulus)

	// If qi is not a power of 2, we can compute the MRed (otherwise, it
	// would return an error as there is no valid Montgomery form mod a power of 2)
	if (r.Modulus&(r.Modulus-1)) != 0 && r.Modulus != 0 {
		r.MRedConstant = GetMRedConstant(r.Modulus)
	}

	switch Type(p.Type) {
	case Standard:

		r.NumberTheoreticTransformer = NewNumberTheoreticTransformerStandard(r, r.N)

		if int(r.NthRoot) < r.N<<1 {
			return nil, fmt.Errorf("invalid ring type: NthRoot must be at least 2N but is %dN", int(r.NthRoot)/r.N)
		}

	case ConjugateInvariant:

		r.NumberTheoreticTransformer = NewNumberTheoreticTransformerConjugateInvariant(r, r.N)

		if int(r.NthRoot) < r.N<<2 {
			return nil, fmt.Errorf("invalid ring type: NthRoot must be at least 4N but is %dN", int(r.NthRoot)/r.N)
		}

	default:
		return nil, fmt.Errorf("invalid ring type")
	}

	return r, r.GenNTTTable()
}

// SetCoefficientsBigint sets the coefficients of p1 from an array of Int variables.
func (r Ring) SetCoefficientsBigint(coeffs []big.Int, p1 []uint64) {
	QiBigint := new(big.Int)
	coeffTmp := new(big.Int)
	QiBigint.SetUint64(r.Modulus)
	for j := range coeffs {
		p1[j] = coeffTmp.Mod(&coeffs[j], QiBigint).Uint64()
	}
}
