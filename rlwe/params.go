package rlwe

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"math/bits"
	"slices"

	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/utils/buffer"
	"github.com/google/go-cmp/cmp"
)

// MaxLogN is the log2 of the largest supported polynomial modulus degree.
const MaxLogN = 20

// MinLogN is the log2 of the smallest supported polynomial modulus degree (needed to ensure the NTT correctness).
const MinLogN = 4

// MaxModuliSize is the largest bit-length supported for the moduli in the RNS representation.
const MaxModuliSize = 60

// GaloisGen is an integer of order N=2^d modulo M=2N and that spans Z_M with the integer -1.
// The j-th ring automorphism takes the root zeta to zeta^(5j).
const GaloisGen uint64 = ring.GaloisGen

type ParameterProvider interface {
	GetRLWEParameters() *Parameters
}

// Parameters represents a set of generic RLWE parameters. Its fields are private and
// immutable. See [rlwe.ParametersLiteral] for user-specified parameters.
type Parameters struct {
	logN         int
	qi           []uint64
	pi           []uint64
	xe           Distribution
	xs           Distribution
	ringQ        ring.RNSRing
	ringP        ring.RNSRing
	ringType     ring.Type
	defaultScale Scale
	nttFlag      bool
}

// NewParameters returns a new set of generic RLWE parameters from the given ring degree logn, moduli q and p, and
// error distribution Xs (secret) and Xe (error). It returns the empty parameters Parameters{} and a non-nil error if the
// specified parameters are invalid.
func NewParameters(logn int, q, p []uint64, xs, xe DistributionLiteral, ringType ring.Type, defaultScale Scale, NTTFlag bool) (params Parameters, err error) {

	var lenP int
	if p != nil {
		lenP = len(p)
	}

	if err = checkSizeParams(logn, len(q), lenP); err != nil {
		return Parameters{}, err
	}

	params = Parameters{
		logN:         logn,
		qi:           make([]uint64, len(q)),
		pi:           make([]uint64, lenP),
		ringType:     ringType,
		defaultScale: defaultScale,
		nttFlag:      NTTFlag,
	}

	// pre-check that moduli chain is of valid size and that all factors are prime.
	// note: the Ring instantiation checks that the moduli are valid NTT-friendly primes.
	if err = CheckModuli(q, p); err != nil {
		return Parameters{}, err
	}

	copy(params.qi, q)

	if p != nil {
		copy(params.pi, p)
	}

	if err = params.initRings(); err != nil {
		return Parameters{}, fmt.Errorf("cannot NewParameters: %w", err)
	}

	switch xs := xs.(type) {
	case *ring.Ternary, *ring.DiscreteGaussian:
		params.xs = NewDistribution(xs.(ring.DistributionParameters), logn)
	default:
		return Parameters{}, fmt.Errorf("secret distribution type must be *ring.Ternary or *ring.DiscretGaussian but is %T", xs)
	}
	if err != nil {
		return Parameters{}, err
	}

	switch xe := xe.(type) {
	case *ring.Ternary, *ring.DiscreteGaussian:
		params.xe = NewDistribution(xe.(ring.DistributionParameters), logn)
	default:
		return Parameters{}, fmt.Errorf("error distribution type must be *ring.Ternary or *ring.DiscretGaussian but is %T", xe)
	}
	if err != nil {
		return Parameters{}, err
	}

	var warning error
	if params.XsHammingWeight() == 0 {
		warning = fmt.Errorf("warning secret standard HammingWeight is 0")
	}

	if params.xe.Std <= 0 {
		if warning != nil {
			warning = fmt.Errorf("%w; warning error standard deviation 0", warning)
		} else {
			warning = fmt.Errorf("warning error standard deviation 0")
		}
	}

	return params, warning
}

// NewParametersFromLiteral instantiate a set of generic RLWE parameters from an [rlwe.ParametersLiteral] specification.
// It returns the empty parameters Parameters{} and a non-nil error if the specified parameters are invalid.
//
// If the moduli chain is specified through the LogQ and LogP fields, the method generates a moduli chain matching
// the specified sizes (see `GenModuli`).
//
// If the secrets' density parameter (H) is left unset, its value is set to 2^(paramDef.LogN-1) to match
// the standard ternary distribution.
//
// If the error variance is left unset, its value is set to `DefaultError`.
//
// If the RingType is left unset, the default value is ring.Standard.
func NewParametersFromLiteral(paramDef ParametersLiteral) (params Parameters, err error) {

	LogN := paramDef.LogN

	LogNthRoot := paramDef.LogNthRoot
	switch paramDef.RingType {
	case ring.Standard:
		LogNthRoot = max(LogNthRoot, LogN+1)
	case ring.ConjugateInvariant:
		LogNthRoot = max(LogNthRoot, LogN+2)
	default:
		return Parameters{}, fmt.Errorf("invalid field ring.Type: must be ring.Standard or ring.ConjugateInvariant but is %T", paramDef.RingType)
	}

	Q, P := paramDef.Q, paramDef.P
	LogQ, LogP := paramDef.LogQ, paramDef.LogP

	if (len(LogQ) > 0 && len(Q) > 0) || (len(LogQ)+len(Q) == 0) {
		return Parameters{}, fmt.Errorf("invalid field LogQ and/or Q: exactly one of them should be left empty")
	}

	if len(LogP) > 0 && len(P) > 0 {
		return Parameters{}, fmt.Errorf("invalid field LogP and/or P: at most one of them must be non empty")
	}

	primes := map[uint64]bool{}

	for _, qi := range append(Q, P...) {
		if _, ok := primes[qi]; !ok {
			primes[qi] = true
		} else {
			return Parameters{}, fmt.Errorf("invalid field Q or P: moduli should all be distinct")
		}
	}

	var Xs ring.DistributionParameters
	if Xs = paramDef.Xs; Xs == nil {
		Xs = &DefaultXs
	}

	var Xe ring.DistributionParameters
	if Xe = paramDef.Xe; Xe == nil {
		// prevents the zero value of ParameterLiteral to result in a noise-less parameter instance.
		// Users should use the NewParameters method to explicitely create noiseless instances.
		Xe = &DefaultXe
	}

	var DefaultScale Scale
	if DefaultScale = paramDef.DefaultScale; DefaultScale.Cmp(Scale{}) == 0 {
		DefaultScale = NewScale(1)
	}

	if QBis, PBis, err := GenModuli(LogN, LogNthRoot, LogQ, LogP, primes); err != nil {
		return Parameters{}, fmt.Errorf("GenModuli: %w", err)
	} else {
		return NewParameters(
			LogN,
			append(Q, QBis...),
			append(P, PBis...),
			Xs,
			Xe,
			paramDef.RingType,
			DefaultScale,
			paramDef.NTTFlag)
	}
}

// NewCustomParameters enables the construction of custom [rlwe.Parameters] by passing each private field individually.
func NewCustomParameters(LogN int, qi, pi []uint64, xe, xs Distribution, ringQ, ringP ring.RNSRing, ringType ring.Type, defaultScale Scale, nttFlag bool) Parameters {
	return Parameters{
		logN:         LogN,
		qi:           qi,
		pi:           pi,
		xe:           xe,
		xs:           xs,
		ringQ:        ringQ,
		ringP:        ringP,
		ringType:     ringType,
		defaultScale: defaultScale,
		nttFlag:      nttFlag,
	}
}

// StandardParameters returns a RLWE parameter set that corresponds to the
// standard dual of a conjugate invariant parameter set. If the receiver is already
// a standard set, then the method returns the receiver.
func (p Parameters) StandardParameters() (pci Parameters, err error) {

	switch p.ringType {
	case ring.Standard:
		return p, nil
	case ring.ConjugateInvariant:
		pci = p
		pci.logN = p.logN + 1
		pci.ringType = ring.Standard
		err = pci.initRings()
	default:
		err = fmt.Errorf("invalid ring type")
	}

	return
}

// ParametersLiteral returns the ParametersLiteral of the target Parameters.
func (p Parameters) ParametersLiteral() ParametersLiteral {

	Q := make([]uint64, len(p.qi))
	copy(Q, p.qi)

	P := make([]uint64, len(p.pi))
	copy(P, p.pi)

	return ParametersLiteral{
		LogN:         p.logN,
		Q:            Q,
		P:            P,
		Xe:           p.xe.DistributionParameters,
		Xs:           p.xs.DistributionParameters,
		RingType:     p.ringType,
		DefaultScale: p.defaultScale,
		NTTFlag:      p.nttFlag,
	}
}

// GetRLWEParameters returns a pointer to the underlying RLWE parameters.
func (p Parameters) GetRLWEParameters() *Parameters {
	return &p
}

// NewScale creates a new scale using the stored default scale as template.
func (p Parameters) NewScale(scale interface{}) Scale {
	newScale := NewScale(scale)
	newScale.Mod = p.defaultScale.Mod
	return newScale
}

// N returns the ring degree
func (p Parameters) N() int {
	return 1 << p.logN
}

// LogN returns the log of the degree of the polynomial ring
func (p Parameters) LogN() int {
	return p.logN
}

// NthRoot returns the NthRoot of the ring.
func (p Parameters) NthRoot() int {
	if p.RingQ() != nil {
		return int(p.RingQ().NthRoot())
	}

	return 0
}

// LogNthRoot returns the log2(NthRoot) of the ring.
func (p Parameters) LogNthRoot() int {
	return bits.Len64(uint64(p.NthRoot() - 1))
}

// DefaultScale returns the default scaling factor of the plaintext, if any.
func (p Parameters) DefaultScale() Scale {
	return p.defaultScale
}

// RingQ returns a pointer to ringQ.
func (p Parameters) RingQ() ring.RNSRing {
	return p.ringQ
}

// RingQAtLevel returns a pointer to ringQ at the given level.
func (p Parameters) RingQAtLevel(LevelQ int) (rQ ring.RNSRing) {
	return p.RingQ().AtLevel(LevelQ)
}

// RingP returns a pointer to ringP.
func (p Parameters) RingP() ring.RNSRing {
	return p.ringP
}

// CoalescedRingP returns the coalesced ringP, i.e. ringQ[#Q - coalescing * #P:] + ringP.
// See https://eprint.iacr.org/2023/1328.
func (p Parameters) CoalescedRingP(coalescing int) ring.RNSRing {
	if coalescing == 0 {
		return p.ringP
	}
	PCount := p.PCount()
	QCount := PCount * (p.QCount() / PCount)
	cPCount := (coalescing + 1) * PCount
	cQCount := (PCount + QCount) - cPCount
	r, err := ring.NewRNSRingFromRings(append(p.ringQ[cQCount:QCount], p.ringP...))
	if err != nil {
		panic(err)
	}
	return r
}

// MaxCoalescing returns the maximum coalscing factor (0 being no coalescing).
// See https://eprint.iacr.org/2023/1328.
func (p Parameters) MaxCoalescing() (maxCoalescing int) {
	maxCoalescing = 0
	LogN := p.LogN()
	LevelQ := p.MaxLevelQ()
	LevelP := p.MaxLevelP()
	for i := 0; i < p.MaxLevelQ(); i++ {
		maxCoalescing = max(maxCoalescing, optimalCoalescingFactor(LogN, i, LevelQ, LevelP))
	}
	return
}

// RingPAtLevel returns a pointer to ringP at the given level.
func (p Parameters) RingPAtLevel(LevelP int) (rP ring.RNSRing) {
	if rP = p.RingP(); rP != nil && LevelP > -1 {
		return rP.AtLevel(LevelP)
	}
	return nil
}

// NTTFlag returns a boolean indicating if elements are stored by default in the NTT domain.
func (p Parameters) NTTFlag() bool {
	return p.nttFlag
}

// Xs returns the Distribution of the secret
func (p Parameters) Xs() ring.DistributionParameters {
	return p.xs.DistributionParameters
}

// XsHammingWeight returns the expected Hamming weight of the secret.
func (p Parameters) XsHammingWeight() int {
	switch xs := p.xs.DistributionParameters.(type) {
	case *ring.Ternary:
		if xs.H != 0 {
			return xs.H
		} else {
			return int(math.Ceil(float64(p.N()) * xs.P))
		}
	case *ring.DiscreteGaussian:
		return int(math.Ceil(float64(p.N()) * float64(xs.Sigma) * math.Sqrt(2.0/math.Pi)))
	default:
		panic(fmt.Sprintf("invalid error distribution: must be *ring.DiscretGaussian or *ring.Ternary but is %T", xs))
	}
}

// Xe returns Distribution of the error
func (p Parameters) Xe() ring.DistributionParameters {
	return p.xe.DistributionParameters
}

// NoiseBound returns truncation bound for the error distribution.
func (p Parameters) NoiseBound() float64 {
	return p.xe.AbsBound
}

// NoiseFreshPK returns the standard deviation
// of a fresh encryption with the public key.
func (p Parameters) NoiseFreshPK() (std float64) {

	H := float64(p.XsHammingWeight() + 1)

	// (1/12 + H*1/12)
	// = (H+1)/12
	if p.RingP() != nil {
		std = (H + 1) / 12.0
	} else {
		// sqrt(N*e^2*sk^2 + e^2 + N*e^2*sk^2)
		// = sqrt(e^2*H + e^2 + e^2*H)
		// = sqrt(2e^2(H+1))
		std = 2 * p.xe.Std * p.xe.Std * (H + 1)
	}

	if p.RingType() == ring.ConjugateInvariant {
		std *= 2
	}

	return math.Sqrt(std)
}

// NoiseFreshSK returns the standard deviation
// of a fresh encryption with the secret key.
func (p Parameters) NoiseFreshSK() (std float64) {
	return p.xe.Std
}

// RingType returns the type of the underlying ring.
func (p Parameters) RingType() ring.Type {
	return p.ringType
}

// MaxLevel returns the maximum level of a ciphertext.
func (p Parameters) MaxLevel() int {
	return p.MaxLevelQ()
}

// MaxLevelQ returns the maximum level of the modulus Q.
func (p Parameters) MaxLevelQ() int {
	return p.QCount() - 1
}

// MaxLevelP returns the maximum level of the modulus P.
func (p Parameters) MaxLevelP() int {
	return p.PCount() - 1
}

// Q returns a new slice with the factors of the ciphertext modulus q
func (p Parameters) Q() []uint64 {
	qi := make([]uint64, len(p.qi))
	copy(qi, p.qi)
	return qi
}

// QCount returns the number of factors of the ciphertext modulus Q
func (p Parameters) QCount() int {
	return len(p.qi)
}

// QBigInt return the ciphertext-space modulus Q in big.Integer, reconstructed, representation.
func (p Parameters) QBigInt() *big.Int {
	q := big.NewInt(1)
	for _, qi := range p.qi {
		q.Mul(q, new(big.Int).SetUint64(qi))
	}
	return q
}

// P returns a new slice with the factors of the ciphertext modulus extension P
func (p Parameters) P() []uint64 {
	pi := make([]uint64, len(p.pi))
	copy(pi, p.pi)
	return pi
}

// PCount returns the number of factors of the ciphertext modulus extension P
func (p Parameters) PCount() int {
	return len(p.pi)
}

// PBigInt return the ciphertext-space extension modulus P in big.Integer, reconstructed, representation.
func (p Parameters) PBigInt() *big.Int {
	pInt := big.NewInt(1)
	for _, pi := range p.pi {
		pInt.Mul(pInt, new(big.Int).SetUint64(pi))
	}
	return pInt
}

// QP return the extended ciphertext-space modulus QP in RNS representation.
func (p Parameters) QP() []uint64 {
	qp := make([]uint64, len(p.qi)+len(p.pi))
	copy(qp, p.qi)
	copy(qp[len(p.qi):], p.pi)
	return qp
}

// QPCount returns the number of factors of the ciphertext modulus + the modulus extension P
func (p Parameters) QPCount() int {
	return len(p.qi) + len(p.pi)
}

// QPBigInt return the extended ciphertext-space modulus QP in big.Integer, reconstructed, representation.
func (p Parameters) QPBigInt() *big.Int {
	pqInt := p.QBigInt()
	pqInt.Mul(pqInt, p.PBigInt())
	return pqInt
}

// LogQ returns the size of the extended modulus Q in bits
func (p Parameters) LogQ() (logq float64) {
	return p.ringQ.LogModuli()
}

// LogQi returns round(log2) of each primes of the modulus Q.
func (p Parameters) LogQi() (logqi []int) {
	qi := p.Q()
	logqi = make([]int, len(qi))
	for i := range qi {
		logqi[i] = int(math.Round(math.Log2(float64(qi[i]))))
	}
	return
}

// LogP returns the size of the extended modulus P in bits
func (p Parameters) LogP() (logp float64) {
	if p.ringP == nil {
		return 0
	}
	return p.ringP.LogModuli()
}

// LogPi returns the round(log2) of each primes of the modulus P.
func (p Parameters) LogPi() (logpi []int) {
	pi := p.P()
	logpi = make([]int, len(pi))
	for i := range pi {
		logpi[i] = int(math.Round(math.Log2(float64(pi[i]))))
	}
	return
}

// LogQP returns the size of the extended modulus QP in bits
func (p Parameters) LogQP() (logqp float64) {
	return p.LogQ() + p.LogP()
}

// MaxBit returns max(max(bitLen(Q[:levelQ+1])), max(bitLen(P[:levelP+1])).
func (p Parameters) MaxBit(levelQ, levelP int) (c int) {
	for _, qi := range p.Q()[:levelQ+1] {
		c = max(c, bits.Len64(qi))
	}

	if p.PCount() != 0 {
		for _, pi := range p.P()[:levelP+1] {
			c = max(c, bits.Len64(pi))
		}
	}

	return
}

// QiOverflowMargin returns floor(2^64 / max(Qi)), i.e. the number of times elements of Z_max{Qi} can
// be added together before overflowing 2^64.
func (p Parameters) QiOverflowMargin(level int) int {

	if level+1 > len(p.qi) {
		panic("invalid level: cannot be greater than len(params.MaxLevelQ())+1")
	}

	return int(math.Exp2(64) / float64(slices.Max(p.qi[:level+1])))
}

// PiOverflowMargin returns floor(2^64 / max(Pi)), i.e. the number of times elements of Z_max{Pi} can
// be added together before overflowing 2^64.
func (p Parameters) PiOverflowMargin(level int) int {

	if len(p.pi) == 0 {
		panic("invalid call: method is not supported if modulus P is empty")
	}

	if level+1 > len(p.pi) {
		panic("invalid level: cannot be greater than params.MaxLevelP()")
	}

	return int(math.Exp2(64) / float64(slices.Max(p.pi[:level+1])))
}

// DecompositionMatrixDimensions returns the shape of the RNS + Digit decomposition matrix.
// Shape is returned as rows = len(dims) and len(cols[i]) = dims[i].
func (p Parameters) DecompositionMatrixDimensions(levelQ, levelP int, dd DigitDecomposition) (dims []int) {

	if levelP == -1 {
		dims = make([]int, levelQ+1)
	} else {
		dims = make([]int, (levelQ+levelP+1)/(levelP+1))
	}

	if dd.Type == 0 || levelP > 0 {
		for i := range dims {
			dims[i] = 1
		}
	} else {
		for i := range dims {
			dims[i] = (bits.Len64(p.qi[i]) + dd.Log2Basis) / dd.Log2Basis
		}
	}
	return
}

// GaloisElements takes a list of integers k and returns the list [GaloisGen^{k[i]} mod NthRoot, ...].
func (p Parameters) GaloisElements(k []int) (galEls []uint64) {
	galEls = make([]uint64, len(k))
	for i, ki := range k {
		galEls[i] = p.GaloisElement(ki)
	}
	return
}

// GaloisElement takes an integer k and returns GaloisGen^{k} mod NthRoot.
func (p Parameters) GaloisElement(k int) uint64 {
	return ring.ModExp(GaloisGen, uint64(k)&(p.ringQ.NthRoot()-1), p.ringQ.NthRoot())
}

// ModInvGaloisElement takes a Galois element of the form GaloisGen^{k} mod NthRoot
// and returns GaloisGen^{-k} mod NthRoot.
func (p Parameters) ModInvGaloisElement(galEl uint64) uint64 {
	return ring.ModExp(galEl, p.ringQ.NthRoot()-1, p.ringQ.NthRoot())
}

// GaloisElementOrderTwoOrthogonalSubgroup returns GaloisGen^{-1} mod NthRoot
func (p Parameters) GaloisElementOrderTwoOrthogonalSubgroup() uint64 {
	if p.ringType == ring.ConjugateInvariant {
		panic("Cannot generate GaloisElementInverse if ringType is ConjugateInvariant")
	}
	return p.ringQ.NthRoot() - 1
}

// SolveDiscreteLogGaloisElement takes a Galois element of the form GaloisGen^{k} mod NthRoot and returns k.
func (p Parameters) SolveDiscreteLogGaloisElement(galEl uint64) (k int) {

	N := p.ringQ.NthRoot()

	var kuint uint64

	x := N >> 3

	for {

		if ring.ModExpPow2(GaloisGen, kuint, N) != ring.ModExpPow2(galEl, x, N) {
			kuint |= N >> 3
		}

		if x == 1 {
			return int(kuint)
		}

		x >>= 1
		kuint >>= 1
	}
}

// Equal checks two Parameter structs for equality.
func (p Parameters) Equal(other *Parameters) (res bool) {
	res = p.logN == other.logN
	res = res && p.xs.DistributionParameters.Equal(other.xs.DistributionParameters)
	res = res && p.xe.DistributionParameters.Equal(other.xe.DistributionParameters)
	res = res && cmp.Equal(p.qi, other.qi)
	res = res && cmp.Equal(p.pi, other.pi)
	res = res && (p.ringType == other.ringType)
	res = res && (p.defaultScale.Equal(other.defaultScale))
	res = res && (p.nttFlag == other.nttFlag)
	return
}

// BinarySize returns the serialized size of the object in bytes.
func (p Parameters) BinarySize() int {
	return p.ParametersLiteral().BinarySize()
}

// WriteTo writes the object on an io.Writer. It implements the io.WriterTo
// interface, and will write exactly object.BinarySize() bytes on w.
//
// Unless w implements the buffer.Writer interface (see lattigo/utils/buffer/writer.go),
// it will be wrapped into a bufio.Writer. Since this requires allocations, it
// is preferable to pass a buffer.Writer directly:
//
//   - When writing multiple times to a io.Writer, it is preferable to first wrap the
//     io.Writer in a pre-allocated bufio.Writer.
//   - When writing to a pre-allocated var b []byte, it is preferable to pass
//     buffer.NewBuffer(b) as w (see lattigo/utils/buffer/buffer.go).
func (p Parameters) WriteTo(w io.Writer) (n int64, err error) {
	return p.ParametersLiteral().WriteTo(w)
}

// ReadFrom reads on the object from an io.Writer. It implements the
// io.ReaderFrom interface.
//
// Unless r implements the buffer.Reader interface (see see lattigo/utils/buffer/reader.go),
// it will be wrapped into a bufio.Reader. Since this requires allocation, it
// is preferable to pass a buffer.Reader directly:
//
//   - When reading multiple values from a io.Reader, it is preferable to first
//     first wrap io.Reader in a pre-allocated bufio.Reader.
//   - When reading from a var b []byte, it is preferable to pass a buffer.NewBuffer(b)
//     as w (see lattigo/utils/buffer/buffer.go).
func (p *Parameters) ReadFrom(r io.Reader) (n int64, err error) {
	var paramsLit ParametersLiteral
	if n, err = paramsLit.ReadFrom(r); err != nil {
		return
	}
	*p, err = NewParametersFromLiteral(paramsLit)
	return
}

// MarshalBinary encodes the object into a binary form on a newly allocated slice of bytes.
func (p Parameters) MarshalBinary() (data []byte, err error) {
	buf := buffer.NewBufferSize(p.BinarySize())
	_, err = p.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary decodes a slice of bytes generated by
// MarshalBinary or WriteTo on the object.
func (p *Parameters) UnmarshalBinary(data []byte) (err error) {
	_, err = p.ReadFrom(buffer.NewBuffer(data))
	return
}

// MarshalJSON returns a JSON representation of this parameter set. See `Marshal` from the `encoding/json` package.
func (p Parameters) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.ParametersLiteral())
}

// UnmarshalJSON reads a JSON representation of a parameter set into the receiver Parameter. See `Unmarshal` from the `encoding/json` package.
func (p *Parameters) UnmarshalJSON(data []byte) (err error) {
	var params ParametersLiteral
	if err = json.Unmarshal(data, &params); err != nil {
		return err
	}
	*p, err = NewParametersFromLiteral(params)
	return
}

// CheckModuli checks that the provided q and p correspond to a valid moduli chain.
func CheckModuli(q, p []uint64) error {

	for i, qi := range q {
		if uint64(bits.Len64(qi)-1) > MaxModuliSize+1 {
			return fmt.Errorf("a Qi bit-size (i=%d) is larger than %d", i, MaxModuliSize)
		}
	}

	for i, qi := range q {
		if !ring.IsPrime(qi) {
			return fmt.Errorf("a Qi (i=%d) is not a prime", i)
		}
	}

	if p != nil {

		for i, pi := range p {
			if uint64(bits.Len64(pi)-1) > MaxModuliSize+2 {
				return fmt.Errorf("a Pi bit-size (i=%d) is larger than %d", i, MaxModuliSize)
			}
		}

		for i, pi := range p {
			if !ring.IsPrime(pi) {
				return fmt.Errorf("a Pi (i=%d) is not a prime", i)
			}
		}
	}

	return nil
}

// UnpackLevelParams is an internal function for unpacking level values
// passed as variadic function parameters.
func (p Parameters) UnpackLevelParams(args []int) (levelQ, levelP int) {
	switch len(args) {
	case 0:
		return p.MaxLevelQ(), p.MaxLevelP()
	case 1:
		return args[0], p.MaxLevelP()
	default:
		return args[0], args[1]
	}
}

func checkSizeParams(logN int, lenQ, lenP int) error {
	if logN > MaxLogN {
		return fmt.Errorf("logN=%d is larger than MaxLogN=%d", logN, MaxLogN)
	}
	if logN < MinLogN {
		return fmt.Errorf("logN=%d is smaller than MinLogN=%d", logN, MinLogN)
	}
	return nil
}

func checkModuliLogSize(logQ, logP []int) error {

	for i, qi := range logQ {
		if qi <= 0 || qi > MaxModuliSize {
			return fmt.Errorf("logQ[%d]=%d is not in ]0, %d]", i, qi, MaxModuliSize)
		}
	}

	for i, pi := range logP {
		if pi <= 0 || pi > MaxModuliSize+1 {
			return fmt.Errorf("logP[%d]=%d is not in ]0,%d]", i, pi, MaxModuliSize+1)
		}
	}

	return nil
}

// GenModuli generates a valid moduli chain from the provided moduli sizes.
func GenModuli(LogN, LogNthRoot int, logQ, logP []int, have map[uint64]bool) (q, p []uint64, err error) {

	if err = checkSizeParams(LogN, len(logQ), len(logP)); err != nil {
		return
	}

	if err = checkModuliLogSize(logQ, logP); err != nil {
		return
	}

	// Extracts all the different primes bit size and maps their number
	primesbitlen := make(map[int]int)
	for _, qi := range logQ {
		primesbitlen[qi]++
	}

	for _, pj := range logP {
		primesbitlen[pj]++
	}

	// For each bit-size, finds that many primes
	var prime uint64
	primes := make(map[int][]uint64)
	for bitsize, value := range primesbitlen {

		g := ring.NewNTTFriendlyPrimesGenerator(uint64(bitsize), uint64(1<<LogNthRoot))

		if bitsize == 61 {

			for i := 0; i < value; i++ {

				if prime, err = g.NextDownstreamPrime(); err != nil {
					return q, p, fmt.Errorf("failed to generate %d primes of bit-size=61 for LogNthRoot=%d: %w", value, LogNthRoot, err)
				}

				for have[prime] {
					if prime, err = g.NextDownstreamPrime(); err != nil {
						return q, p, fmt.Errorf("failed to generate %d primes of bit-size=61 for LogNthRoot=%d: %w", value, LogNthRoot, err)
					}
				}

				primes[bitsize] = append(primes[bitsize], prime)
			}

		} else {

			for i := 0; i < value; i++ {

				if prime, err = g.NextAlternatingPrime(); err != nil {
					return q, p, fmt.Errorf("cannot GenModuli: failed to generate %d primes of bit-size=%d for LogNthRoot=%d: %w", value, bitsize, LogNthRoot, err)
				}

				for have[prime] {
					if prime, err = g.NextAlternatingPrime(); err != nil {
						return q, p, fmt.Errorf("cannot GenModuli: failed to generate %d primes of bit-size=%d for LogNthRoot=%d: %w", value, bitsize, LogNthRoot, err)
					}
				}

				primes[bitsize] = append(primes[bitsize], prime)
			}
		}
	}

	// Assigns the primes to the moduli chain
	for _, qi := range logQ {
		q = append(q, primes[qi][0])
		primes[qi] = primes[qi][1:]
	}

	// Assigns the primes to the special primes list for the extended ring
	for _, pj := range logP {
		p = append(p, primes[pj][0])
		primes[pj] = primes[pj][1:]
	}

	return
}

func (p *Parameters) initRings() (err error) {
	if p.ringQ, err = ring.NewRNSRingFromType(1<<p.logN, p.qi, p.ringType); err != nil {
		return fmt.Errorf("initRings/ringQ: %w", err)
	}
	if len(p.pi) != 0 {
		if p.ringP, err = ring.NewRNSRingFromType(1<<p.logN, p.pi, p.ringType); err != nil {
			return fmt.Errorf("initRings/ringP: %w", err)
		}
	}
	return
}
