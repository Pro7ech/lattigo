// Package ring implements RNS-accelerated modular arithmetic operations for polynomials, including:
// RNS basis extension; RNS rescaling; number theoretic transform (NTT); uniform, Gaussian and ternary sampling.
package ring

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"math/bits"

	"github.com/Pro7ech/lattigo/utils"
	"github.com/Pro7ech/lattigo/utils/bignum"
)

const (
	// GaloisGen is an integer of order N/2 modulo M that spans Z_M with the integer -1.
	// The j-th ring automorphism takes the root zeta to zeta^(5j).
	GaloisGen uint64 = 5

	// MinimumRingDegreeForLoopUnrolledOperations is the minimum ring degree required to
	// safely perform loop-unrolled operations
	MinimumRingDegreeForLoopUnrolledOperations = 8
)

// Type is the type of ring used by the cryptographic scheme
type Type int

// RingStandard and RingConjugateInvariant are two types of Rings.
const (
	Standard           = Type(0) // Z[X]/(X^N + 1) (Default)
	ConjugateInvariant = Type(1) // Z[X+X^-1]/(X^2N + 1)
)

// RNSRing is a struct regrouping a set o
type RNSRing []*Ring

// NewRNSRing creates a new [RNSRing] with degree N and coefficient moduli Moduli with Standard NTT. N must be a power of two larger than 8. Moduli should be
// a non-empty []uint64 with distinct prime elements. All moduli must also be equal to 1 modulo 2*N.
// An error is returned with a nil *Ring in the case of non NTT-enabling parameters.
func NewRNSRing(N int, Moduli []uint64) (r RNSRing, err error) {
	return NewRNSRingWithCustomNTT(N, Moduli, NewNumberTheoreticTransformerStandard, 2*N)
}

// NewRNSRingConjugateInvariant creates a new RNS Ring with degree N and coefficient moduli Moduli with Conjugate Invariant NTT. N must be a power of two larger than 8. Moduli should be
// a non-empty []uint64 with distinct prime elements. All moduli must also be equal to 1 modulo 4*N.
// An error is returned with a nil *Ring in the case of non NTT-enabling parameters.
func NewRNSRingConjugateInvariant(N int, Moduli []uint64) (r RNSRing, err error) {
	return NewRNSRingWithCustomNTT(N, Moduli, NewNumberTheoreticTransformerConjugateInvariant, 4*N)
}

// NewRNSRingFromType creates a new RNS Ring with degree N and coefficient moduli Moduli for which the type of NTT is determined by the ringType argument.
// If ringType==Standard, the ring is instantiated with standard NTT with the Nth root of unity 2*N. If ringType==ConjugateInvariant, the ring
// is instantiated with a ConjugateInvariant NTT with Nth root of unity 4*N. N must be a power of two larger than 8.
// Moduli should be a non-empty []uint64 with distinct prime elements. All moduli must also be equal to 1 modulo the root of unity.
// An error is returned with a nil *Ring in the case of non NTT-enabling parameters.
func NewRNSRingFromType(N int, Moduli []uint64, ringType Type) (r RNSRing, err error) {
	switch ringType {
	case Standard:
		return NewRNSRingWithCustomNTT(N, Moduli, NewNumberTheoreticTransformerStandard, 2*N)
	case ConjugateInvariant:
		return NewRNSRingWithCustomNTT(N, Moduli, NewNumberTheoreticTransformerConjugateInvariant, 4*N)
	default:
		return nil, fmt.Errorf("invalid ring type")
	}
}

// NewRNSRingWithCustomNTT creates a new RNS Ring with degree N and coefficient moduli Moduli with user-defined NTT transform and primitive Nth root of unity.
// ModuliChain should be a non-empty []uint64 with distinct prime elements.
// All moduli must also be equal to 1 modulo the root of unity.
// N must be a power of two larger than 8. An error is returned with a nil *Ring in the case of non NTT-enabling parameters.
func NewRNSRingWithCustomNTT(N int, ModuliChain []uint64, ntt func(*Ring, int) NumberTheoreticTransformer, NthRoot int) (r RNSRing, err error) {

	// Checks if N is a power of 2
	if N < MinimumRingDegreeForLoopUnrolledOperations || (N&(N-1)) != 0 && N != 0 {
		return nil, fmt.Errorf("invalid ring degree: must be a power of 2 greater than %d", MinimumRingDegreeForLoopUnrolledOperations)
	}

	if len(ModuliChain) == 0 {
		return nil, fmt.Errorf("invalid ModuliChain (must be a non-empty []uint64)")
	}

	if !utils.AllDistinct(ModuliChain) {
		return nil, fmt.Errorf("invalid ModuliChain (moduli are not distinct)")
	}

	r = make([]*Ring, len(ModuliChain))

	for i := range r {
		if r[i], err = NewRingWithCustomNTT(N, ModuliChain[i], 1, ntt, NthRoot); err != nil {
			return nil, err
		}
	}

	return r, r.GenNTTTables(nil, nil)
}

// NewRNSRingFromRings returns a new [Ring] instantiated with the provided Rings.
// All Rings must have the same ring degree.
func NewRNSRingFromRings(rings []*Ring) (r RNSRing, err error) {
	N := rings[0].N
	for i := range rings {
		if rings[i].N != N {
			return nil, fmt.Errorf("invalid Rings: all Rings must have the same ring degree")
		}
	}

	return RNSRing(rings), nil
}

// N returns the ring degree.
func (r RNSRing) N() int {
	return r[0].N
}

// LogN returns log2(ring degree).
func (r RNSRing) LogN() int {
	return bits.Len64(uint64(r.N() - 1))
}

// LogModuli returns the size of the extended modulus P in bits
func (r RNSRing) LogModuli() (logmod float64) {
	for _, qi := range r.ModuliChain() {
		logmod += math.Log2(float64(qi))
	}
	return
}

// NthRoot returns the multiplicative order of the primitive root.
func (r RNSRing) NthRoot() uint64 {
	return r[0].NthRoot
}

// ModuliChainLength returns the number of primes in the RNS basis of the ring.
func (r RNSRing) ModuliChainLength() int {
	return len(r)
}

// Level returns the level of the current ring.
func (r RNSRing) Level() int {
	return len(r) - 1
}

// AtLevel returns an instance of the target ring that operates at the target level.
// This instance is thread safe and can be use concurrently with the base ring.
func (r RNSRing) AtLevel(level int) RNSRing {

	// Sanity check
	if level < 0 {
		panic("level cannot be negative")
	}

	// Sanity check
	if level > r.MaxLevel() {
		panic("level cannot be larger than max level")
	}

	return r[:level+1]
}

// MaxLevel returns the maximum level allowed by the ring (#NbModuli -1).
func (r RNSRing) MaxLevel() int {
	return r.ModuliChainLength() - 1
}

// ModuliChain returns the list of primes in the modulus chain.
func (r RNSRing) ModuliChain() (moduli []uint64) {
	moduli = make([]uint64, len(r))
	for i := range r {
		moduli[i] = r[i].Modulus
	}

	return
}

// OverflowMargin returns the overflow margin of the ring.
func (r RNSRing) OverflowMargin() int {
	var maxQ uint64
	for _, s := range r {
		maxQ = max(maxQ, s.Modulus)
	}
	return int(math.Exp2(64) / float64(maxQ))
}

// MRedConstants returns the concatenation of the Montgomery constants
// of the target ring.
func (r RNSRing) MRedConstants() (MRC []uint64) {
	MRC = make([]uint64, len(r))
	for i := range r {
		MRC[i] = r[i].MRedConstant
	}

	return
}

// BRedConstants returns the concatenation of the Barrett constants
// of the target ring.
func (r RNSRing) BRedConstants() (BRC [][2]uint64) {
	BRC = make([][2]uint64, len(r))
	for i := range r {
		BRC[i] = r[i].BRedConstant
	}

	return
}

// NewRNSPoly creates a new [RNSPoly] with all coefficients set to 0.
func (r RNSRing) NewRNSPoly() RNSPoly {
	return NewRNSPoly(r.N(), len(r)-1)
}

// NewMonomialXi returns a polynomial X^{i}.
func (r RNSRing) NewMonomialXi(i int) (p RNSPoly) {

	p = r.NewRNSPoly()

	N := r.N()

	i &= (N << 1) - 1

	if i >= N {
		i -= N << 1
	}

	for k, s := range r {

		if i < 0 {
			p.At(k)[N+i] = s.Modulus - 1
		} else {
			p.At(k)[i] = 1
		}
	}

	return
}

// SetCoefficientsBigint sets the coefficients of p1 from an array of Int variables.
func (r RNSRing) SetCoefficientsBigint(coeffs []big.Int, p1 RNSPoly) {

	QiBigint := new(big.Int)
	coeffTmp := new(big.Int)
	for i, table := range r {

		QiBigint.SetUint64(table.Modulus)

		p1Coeffs := p1.At(i)

		for j := range coeffs {
			p1Coeffs[j] = coeffTmp.Mod(&coeffs[j], QiBigint).Uint64()
		}
	}
}

// PolyToString reconstructs p1 and returns the result in an array of string.
func (r RNSRing) PolyToString(p1 RNSPoly) []string {

	coeffsBigint := make([]big.Int, r.N())
	r.PolyToBigint(p1, 1, coeffsBigint)
	coeffsString := make([]string, len(coeffsBigint))

	for i := range coeffsBigint {
		coeffsString[i] = coeffsBigint[i].String()
	}

	return coeffsString
}

// PolyToBigint reconstructs p1 and returns the result in an array of Int.
// gap defines coefficients X^{i*gap} that will be reconstructed.
// For example, if gap = 1, then all coefficients are reconstructed, while
// if gap = 2 then only coefficients X^{2*i} are reconstructed.
func (r RNSRing) PolyToBigint(p1 RNSPoly, gap int, coeffsBigint []big.Int) {

	crtReconstruction := make([]*big.Int, r.Level()+1)

	QiB := new(big.Int)
	tmp := new(big.Int)
	modulusBigint := r.Modulus()

	for i, table := range r {
		QiB.SetUint64(table.Modulus)
		crtReconstruction[i] = new(big.Int).Quo(modulusBigint, QiB)
		tmp.ModInverse(crtReconstruction[i], QiB)
		tmp.Mod(tmp, QiB)
		crtReconstruction[i].Mul(crtReconstruction[i], tmp)
	}

	N := r.N()

	for i, j := 0, 0; j < N; i, j = i+1, j+gap {
		tmp.SetUint64(0)
		for k := 0; k < r.Level()+1; k++ {
			coeffsBigint[i].Add(&coeffsBigint[i], tmp.Mul(bignum.NewInt(p1.At(k)[j]), crtReconstruction[k]))
		}
		coeffsBigint[i].Mod(&coeffsBigint[i], modulusBigint)
	}
}

// PolyToBigintCentered reconstructs p1 and returns the result in an array of Int.
// Coefficients are centered around Q/2
// gap defines coefficients X^{i*gap} that will be reconstructed.
// For example, if gap = 1, then all coefficients are reconstructed, while
// if gap = 2 then only coefficients X^{2*i} are reconstructed.
func (r RNSRing) PolyToBigintCentered(p1 RNSPoly, gap int, values []big.Int) {
	PolyToBigintCentered(r, nil, p1, nil, gap, values)
}

// Equal checks if p1 = p2 in the given Ring.
func (r RNSRing) Equal(p1, p2 RNSPoly) bool {

	for i := 0; i < r.Level()+1; i++ {
		if len(p1.At(i)) != len(p2.At(i)) {
			return false
		}
	}

	r.Reduce(p1, p1)
	r.Reduce(p2, p2)

	return p1.Equal(&p2)
}

// Stats returns base 2 logarithm of the standard deviation
// and the mean of the coefficients of the polynomial.
func (r RNSRing) Stats(poly RNSPoly) [2]float64 {
	N := r.N()
	values := make([]big.Int, N)
	r.PolyToBigintCentered(poly, 1, values)
	return bignum.Stats(values, 128)
}

// String returns the string representation of the ring Type
func (rt Type) String() string {
	switch rt {
	case Standard:
		return "Standard"
	case ConjugateInvariant:
		return "ConjugateInvariant"
	default:
		return "Invalid"
	}
}

// UnmarshalJSON reads a JSON byte slice into the receiver Type
func (rt *Type) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	switch s {
	default:
		return fmt.Errorf("invalid ring type: %s", s)
	case "Standard":
		*rt = Standard
	case "ConjugateInvariant":
		*rt = ConjugateInvariant
	}

	return nil
}

// Type returns the [Type] of the first [Ring] which might be either `Standard` or `ConjugateInvariant`.
func (r RNSRing) Type() Type {
	return r[0].Type()
}

// MarshalJSON marshals the receiver [Type] into a JSON []byte
func (rt Type) MarshalJSON() ([]byte, error) {
	return json.Marshal(rt.String())
}

// ConjugateInvariant returns the conjugate invariant ring of the receiver RNSRing.
// If `r.Type()==ConjugateInvariant`, then the method returns the receiver.
// if `r.Type()==Standard`, then the method returns a ring with ring degree N/2.
// The returned Ring is a shallow copy of the receiver.
func (r RNSRing) ConjugateInvariant() (cr RNSRing, err error) {

	if r.Type() == ConjugateInvariant {
		return r, nil
	}

	cr = RNSRing(make([]*Ring, len(r)))

	factors := make([][]uint64, len(r))

	for i, s := range r {

		if cr[i], err = NewRingWithCustomNTT(s.N>>1, s.Modulus, 1, NewNumberTheoreticTransformerConjugateInvariant, int(s.NthRoot)); err != nil {
			return nil, err
		}

		factors[i] = s.Factors // Allocates factor for faster generation
	}

	return cr, cr.GenNTTTables(nil, factors)
}

// Standard returns the standard ring of the receiver RNSRing.
// If `r.Type()==Standard`, then the method returns the receiver.
// if `r.Type()==ConjugateInvariant`, then the method returns a ring with ring degree 2N.
// The returned Ring is a shallow copy of the receiver.
func (r RNSRing) Standard() (sr RNSRing, err error) {

	if r.Type() == Standard {
		return r, nil
	}

	sr = RNSRing(make([]*Ring, len(r)))

	factors := make([][]uint64, len(r))

	for i, s := range r {

		if sr[i], err = NewRingWithCustomNTT(s.N<<1, s.Modulus, 1, NewNumberTheoreticTransformerStandard, int(s.NthRoot)); err != nil {
			return nil, err
		}

		factors[i] = s.Factors // Allocates factor for faster generation
	}

	return sr, sr.GenNTTTables(nil, factors)
}

// Concat concatenates other to the receiver producing a new extended [RNSRing].
func (r RNSRing) Concat(other RNSRing) (rnew RNSRing) {
	return append(r, other...)
}

// AddModuli returns an instance of the receiver with an additional modulus.
func (r RNSRing) AddModuli(moduli []uint64) (rNew RNSRing, err error) {

	if !utils.AllDistinct(append(r.ModuliChain(), moduli...)) {
		return nil, fmt.Errorf("invalid ModuliChain (moduli are not distinct)")
	}

	// Computes bigQ for all levels
	rNew = r

	var ntt func(*Ring, int) NumberTheoreticTransformer

	switch r.Type() {
	case Standard:
		ntt = NewNumberTheoreticTransformerStandard
	case ConjugateInvariant:
		ntt = NewNumberTheoreticTransformerConjugateInvariant
	default:
		return nil, fmt.Errorf("invalid ring type")
	}

	for i := range moduli {

		var sNew *Ring
		if sNew, err = NewRingWithCustomNTT(r.N(), moduli[i], 1, ntt, int(r.NthRoot())); err != nil {
			return
		}

		if err = sNew.GenNTTTable(); err != nil {
			return nil, err
		}

		rNew = append(rNew, sNew)
	}

	return
}

// Modulus returns the full modulus.
// The internal level of the ring is taken into account.
func (r RNSRing) Modulus() (modulus *big.Int) {
	modulus = bignum.NewInt(r[0].Modulus)
	for _, s := range r[1:] {
		modulus.Mul(modulus, bignum.NewInt(s.Modulus))
	}
	return
}

// RescaleConstants returns the rescaling constants for a given level.
func (r RNSRing) RescaleConstants() (out []uint64) {

	qj := r[r.Level()].Modulus

	out = make([]uint64, r.Level())

	for i := 0; i < r.Level(); i++ {
		qi := r[i].Modulus
		out[i] = MForm(qi-ModExp(qj, qi-2, qi), qi, r[i].BRedConstant)
	}

	return
}

// GenNTTTables checks that N has been correctly initialized, and checks that each modulus is a prime congruent to 1 mod 2N (i.e. NTT-friendly).
// Then, it computes the variables required for the NTT. The purpose of ValidateParameters is to validate that the moduli allow the NTT, and to compute the
// NTT parameters.
func (r RNSRing) GenNTTTables(primitiveRoots []uint64, factors [][]uint64) (err error) {

	for i := range r {

		if primitiveRoots != nil && factors != nil {
			r[i].PrimitiveRoot = primitiveRoots[i]
			r[i].Factors = factors[i]
		}

		if err = r[i].GenNTTTable(); err != nil {
			return
		}
	}

	return nil
}

// rnsRingParametersLiteral is a struct to store the minimum information
// to uniquely identify a Ring and be able to reconstruct it efficiently.
// This struct's purpose is to facilitate the marshalling of Rings.
type rnsRingParametersLiteral []ringParametersLiteral

// parametersLiteral returns the RingParametersLiteral of the Ring.
func (r RNSRing) parametersLiteral() rnsRingParametersLiteral {
	p := make([]ringParametersLiteral, len(r))

	for i, s := range r {
		p[i] = s.parametersLiteral()
	}

	return rnsRingParametersLiteral(p)
}

// MarshalBinary encodes the object into a binary form on a newly allocated slice of bytes.
func (r RNSRing) MarshalBinary() (data []byte, err error) {
	return r.MarshalJSON()
}

// UnmarshalBinary decodes a slice of bytes generated by MarshalBinary or MarshalJSON on the object.
func (r *RNSRing) UnmarshalBinary(data []byte) (err error) {
	return r.UnmarshalJSON(data)
}

// MarshalJSON encodes the object into a binary form on a newly allocated slice of bytes with the json codec.
func (r RNSRing) MarshalJSON() (data []byte, err error) {
	return json.Marshal(r.parametersLiteral())
}

// UnmarshalJSON decodes a slice of bytes generated by MarshalJSON or MarshalBinary on the object.
func (r *RNSRing) UnmarshalJSON(data []byte) (err error) {

	p := rnsRingParametersLiteral{}

	if err = json.Unmarshal(data, &p); err != nil {
		return
	}

	var rr RNSRing
	if rr, err = newRNSRingFromparametersLiteral(p); err != nil {
		return
	}

	*r = rr

	return
}

func newRNSRingFromparametersLiteral(p rnsRingParametersLiteral) (r RNSRing, err error) {

	r = RNSRing(make([]*Ring, len(p)))

	for i := range r {

		if r[i], err = newRingFromParametersLiteral(p[i]); err != nil {
			return
		}

		if i > 0 {
			if r[i].N != r[i-1].N || r[i].NthRoot != r[i-1].NthRoot {
				return nil, fmt.Errorf("invalid Rings: all Rings must have the same ring degree and NthRoot")
			}
		}
	}

	return
}
