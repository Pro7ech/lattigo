package hefloat

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"

	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/bignum"
	"github.com/Pro7ech/lattigo/utils/buffer"
)

// PrecisionMode is a variable that defines how many primes (one
// per machine word) are required to store initial message values.
// This also sets how many primes are consumed per rescaling.
//
// There are currently two modes supported:
// - PREC64 (one 64 bit word)
// - PREC128 (two 64 bit words)
//
// PREC64 is the default mode and supports reference plaintext scaling
// factors of up to 2^{64}, while PREC128 scaling factors of up to 2^{128}.
//
// The PrecisionMode is chosen automatically based on the provided initial
// `LogDefaultScale` value provided by the user.
type PrecisionMode int

const (
	NTTFlag = true
	PREC64  = PrecisionMode(0)
	PREC128 = PrecisionMode(1)
)

// Parameters represents a parameter set for the CKKS cryptosystem. Its fields are private and
// immutable. See ParametersLiteral for user-specified parameters.
type Parameters struct {
	rlwe.Parameters
	precisionMode PrecisionMode
}

// NewParametersFromLiteral instantiate a set of CKKS parameters from a ParametersLiteral specification.
// It returns the empty parameters Parameters{} and a non-nil error if the specified parameters are invalid.
//
// If the `LogSlots` field is left unset, its value is set to `LogN-1` for the Standard ring and to `LogN` for
// the conjugate-invariant ring.
//
// See `rlwe.NewParametersFromLiteral` for default values of the other optional fields.
func NewParametersFromLiteral(pl ParametersLiteral) (Parameters, error) {
	rlweParams, err := rlwe.NewParametersFromLiteral(pl.GetRLWEParametersLiteral())
	if err != nil {
		return Parameters{}, fmt.Errorf("cannot NewParametersFromLiteral: %w", err)
	}

	var precisionMode PrecisionMode
	if pl.LogDefaultScale <= 64 {
		precisionMode = PREC64
	} else if pl.LogDefaultScale <= 128 {
		precisionMode = PREC128
	} else {
		return Parameters{}, fmt.Errorf("cannot NewParametersFromLiteral: LogDefaultScale=%d > 128 or < 0", pl.LogDefaultScale)
	}

	return Parameters{rlweParams, precisionMode}, nil
}

// StandardParameters returns the CKKS parameters corresponding to the receiver
// parameter set. If the receiver is already a standard parameter set
// (i.e., RingType==Standard), then the method returns the receiver.
func (p Parameters) StandardParameters() (pckks Parameters, err error) {
	if p.RingType() == ring.Standard {
		return p, nil
	}
	pckks = p
	pckks.Parameters, err = pckks.Parameters.StandardParameters()
	pckks.precisionMode = p.precisionMode
	return
}

// ParametersLiteral returns the ParametersLiteral of the target Parameters.
func (p Parameters) ParametersLiteral() (pLit ParametersLiteral) {
	return ParametersLiteral{
		LogN:            p.LogN(),
		LogNthRoot:      p.LogNthRoot(),
		Q:               p.Q(),
		P:               p.P(),
		Xe:              p.Xe(),
		Xs:              p.Xs(),
		RingType:        p.RingType(),
		LogDefaultScale: p.LogDefaultScale(),
	}
}

// GetRLWEParameters returns a pointer to the underlying RLWE parameters.
func (p Parameters) GetRLWEParameters() *rlwe.Parameters {
	return &p.Parameters
}

// MaxLevel returns the maximum ciphertext level
func (p Parameters) MaxLevel() int {
	return p.QCount() - 1
}

// MaxDimensions returns the maximum dimension of the matrix that can be SIMD packed in a single plaintext polynomial.
func (p Parameters) MaxDimensions() ring.Dimensions {
	switch p.RingType() {
	case ring.Standard:
		return ring.Dimensions{Rows: 1, Cols: p.N() >> 1}
	case ring.ConjugateInvariant:
		return ring.Dimensions{Rows: 1, Cols: p.N()}
	default:
		// Sanity check
		panic("cannot MaxDimensions: invalid ring type")
	}
}

// LogMaxDimensions returns the log2 of maximum dimension of the matrix that can be SIMD packed in a single plaintext polynomial.
func (p Parameters) LogMaxDimensions() ring.Dimensions {
	switch p.RingType() {
	case ring.Standard:
		return ring.Dimensions{Rows: 0, Cols: p.LogN() - 1}
	case ring.ConjugateInvariant:
		return ring.Dimensions{Rows: 0, Cols: p.LogN()}
	default:
		// Sanity check
		panic("cannot LogMaxDimensions: invalid ring type")
	}
}

// MaxSlots returns the total number of entries (`slots`) that a plaintext can store.
// This value is obtained by multiplying all dimensions from MaxDimensions.
func (p Parameters) MaxSlots() int {
	dims := p.MaxDimensions()
	return dims.Rows * dims.Cols
}

// LogMaxSlots returns the total number of entries (`slots`) that a plaintext can store.
// This value is obtained by summing all log dimensions from LogDimensions.
func (p Parameters) LogMaxSlots() int {
	dims := p.LogMaxDimensions()
	return dims.Rows + dims.Cols
}

// LogDefaultScale returns the log2 of the default plaintext
// scaling factor (rounded to the nearest integer).
func (p Parameters) LogDefaultScale() int {
	return int(math.Round(math.Log2(p.DefaultScale().Float64())))
}

// EncodingPrecision returns the encoding precision in bits of the plaintext values which
// is max(53, log2(DefaultScale)).
func (p Parameters) EncodingPrecision() (prec uint) {
	if log2scale := math.Log2(p.DefaultScale().Float64()); log2scale <= 53 {
		prec = 53
	} else {
		prec = uint(log2scale)
	}

	return
}

// PrecisionMode returns the precision mode of the parameters.
// This value can be ckks.PREC64 or ckks.PREC128.
func (p Parameters) PrecisionMode() PrecisionMode {
	return p.precisionMode
}

// LevelsConsumedPerRescaling returns the number of levels (i.e. primes)
// consumed per rescaling. This value is 1 if the precision mode is PREC64
// and is 2 if the precision mode is PREC128.
func (p Parameters) LevelsConsumedPerRescaling() int {
	switch p.precisionMode {
	case PREC128:
		return 2
	default:
		return 1
	}
}

// GetScalingFactor returns a scaling factor b such that Rescale(a * b) = c
func (p Parameters) GetScalingFactor(a, c rlwe.Scale, level int) (b rlwe.Scale) {
	b = c
	Q := p.Q()
	for i := range p.LevelsConsumedPerRescaling() {
		b = b.Mul(rlwe.NewScale(Q[level-i]))
	}
	b = b.Div(a)
	return
}

// MaxDepth returns the maximum depth enabled by the parameters,
// which is obtained as p.MaxLevel() / p.LevelsConsumedPerRescaling().
func (p Parameters) MaxDepth() int {
	return p.MaxLevel() / p.LevelsConsumedPerRescaling()
}

// LogQLvl returns the size of the modulus Q in bits at a specific level
func (p Parameters) LogQLvl(level int) int {
	tmp := p.QLvl(level)
	return tmp.BitLen()
}

// QLvl returns the product of the moduli at the given level as a big.Int
func (p Parameters) QLvl(level int) *big.Int {
	tmp := bignum.NewInt(1)
	for _, qi := range p.Q()[:level+1] {
		tmp.Mul(tmp, bignum.NewInt(qi))
	}
	return tmp
}

// GaloisElementForRotation returns the Galois element for generating the
// automorphism phi(k): X -> X^{5^k mod 2N} mod (X^{N} + 1), which acts as a
// cyclic rotation by k position to the left on batched plaintexts.
//
// Example:
// Recall that batched plaintexts are 2xN/2 matrices of the form [m, conjugate(m)]
// (the conjugate is implicitely ingored) thus given the following plaintext matrix:
//
// [a, b, c, d][conj(a), conj(b), conj(c), conj(d)]
//
// a rotation by k=3 will change the plaintext to:
//
// [d, a, b, c][conj(d), conj(a), conj(b), conj(c)]
//
// Providing a negative k will change direction of the cyclic rotation to the right.
//
// Note that when using the ConjugateInvariant variant of the scheme, the conjugate is
// dropped and the matrix becomes an 1xN matrix.
func (p Parameters) GaloisElementForRotation(k int) uint64 {
	return p.Parameters.GaloisElement(k)
}

// GaloisElementForComplexConjugation returns the Galois element for generating the
// automorphism X -> X^{-1 mod NthRoot} mod (X^{N} + 1). This automorphism
// acts as a swapping the rows of the plaintext algebra when the plaintext
// is batched.
//
// Example:
// Recall that batched plaintexts are 2xN/2 matrices of the form [m, conjugate(m)]
// (the conjugate is implicitely ingored) thus given the following plaintext matrix:
//
// [a, b, c, d][conj(a), conj(b), conj(c), conj(d)]
//
// the complex conjugation will return the following plaintext matrix:
//
// [conj(a), conj(b), conj(c), conj(d)][a, b, c, d]
//
// Note that when using the ConjugateInvariant variant of the scheme, the conjugate is
// dropped and this operation is not defined.
func (p Parameters) GaloisElementForComplexConjugation() uint64 {
	return p.Parameters.GaloisElementOrderTwoOrthogonalSubgroup()
}

// GaloisElementsForInnerSum returns the list of Galois elements necessary to apply the method
// `InnerSum` operation with parameters `batch` and `n`.
func (p Parameters) GaloisElementsForInnerSum(batch, n int) []uint64 {
	return rlwe.GaloisElementsForInnerSum(p, batch, n)
}

// GaloisElementsForReplicate returns the list of Galois elements necessary to perform the
// `Replicate` operation with parameters `batch` and `n`.
func (p Parameters) GaloisElementsForReplicate(batch, n int) []uint64 {
	return rlwe.GaloisElementsForReplicate(p, batch, n)
}

// GaloisElementsForTrace returns the list of Galois elements requored for the for the `Trace` operation.
// Trace maps X -> sum((-1)^i * X^{i*n+1}) for 2^{LogN} <= i < N.
func (p Parameters) GaloisElementsForTrace(logN int) []uint64 {
	return rlwe.GaloisElementsForTrace(p, logN)
}

// Equal compares two sets of parameters for equality.
func (p Parameters) Equal(other *Parameters) bool {
	return p.Parameters.Equal(&other.Parameters) && p.precisionMode == other.precisionMode
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

// UnmarshalJSON reads a JSON representation of a parameter set into the receiver Parameter. See `Unmarshal` from the `encoding/json` package.
func (p *Parameters) UnmarshalJSON(data []byte) (err error) {
	var params ParametersLiteral
	if err = json.Unmarshal(data, &params); err != nil {
		return
	}
	*p, err = NewParametersFromLiteral(params)
	return
}
