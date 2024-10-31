package heint

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/bits"
	"slices"

	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/buffer"
)

const (
	NTTFlag = true
)

// Parameters represents a parameter set for the BGV cryptosystem. Its fields are private and
// immutable. See ParametersLiteral for user-specified parameters.
type Parameters struct {
	rlwe.Parameters
	RQMul ring.RNSRing
	RT    *ring.Ring
}

// NewParameters instantiate a set of BGV parameters from the generic RLWE parameters and the BGV-specific ones.
// It returns the empty parameters Parameters{} and a non-nil error if the specified parameters are invalid.
// See the ParametersLiteral type for more details on the BGV parameters.
func NewParameters(rlweParams rlwe.Parameters, T uint64, K int) (p Parameters, err error) {

	if !rlweParams.NTTFlag() {
		return Parameters{}, fmt.Errorf("provided RLWE parameters are invalid for BGV scheme (NTTFlag must be true)")
	}

	if T == 0 || K == 0 {
		return Parameters{}, fmt.Errorf("invalid parameters: T = 0 or K == 0")
	}

	if bits.Len64(T)*int(K) > 61 {
		return Parameters{}, fmt.Errorf("invalid parameters: T^K > 2^{62}-1")
	}

	if slices.Contains(rlweParams.Q(), T) {
		return Parameters{}, fmt.Errorf("insecure parameters: T|Q")
	}

	if rlweParams.Equal(&rlwe.Parameters{}) {
		return Parameters{}, fmt.Errorf("provided RLWE parameters are invalid")
	}

	if T > rlweParams.Q()[0] {
		return Parameters{}, fmt.Errorf("t=%d is larger than Q[0]=%d", T, rlweParams.Q()[0])
	}

	var RQMul ring.RNSRing
	nbQiMul := int(math.Ceil(float64(rlweParams.RingQ().Modulus().BitLen()+rlweParams.LogN()) / 61.0))
	g := ring.NewNTTFriendlyPrimesGenerator(61, uint64(rlweParams.NthRoot()))
	primes, err := g.NextDownstreamPrimes(nbQiMul)
	if err != nil {
		return Parameters{}, err
	}
	if RQMul, err = ring.NewRNSRing(rlweParams.N(), primes); err != nil {
		return Parameters{}, err
	}

	// Find the largest cyclotomic order enabled by T
	var order uint64
	for order = uint64(1 << bits.Len64(T)); T&(order-1) != 1 && order != 0; order >>= 1 {
	}

	if order < 16 {
		return Parameters{}, fmt.Errorf("provided plaintext modulus T has cyclotomic order < 16 (ring degree of minimum 8 is required by the backend)")
	}

	var RT *ring.Ring
	if RT, err = ring.NewRing(min(rlweParams.N(), int(order>>1)), T, K); err != nil {
		return Parameters{}, fmt.Errorf("provided plaintext modulus T is invalid: %w", err)
	}

	if err = RT.GenNTTTable(); err != nil {
		return Parameters{}, err
	}

	return Parameters{
		Parameters: rlweParams,
		RQMul:      RQMul,
		RT:         RT,
	}, nil
}

// NewParametersFromLiteral instantiate a set of BGV parameters from a ParametersLiteral specification.
// It returns the empty parameters Parameters{} and a non-nil error if the specified parameters are invalid.
//
// See `rlwe.NewParametersFromLiteral` for default values of the optional fields and other details on the BGV
// parameters.
func NewParametersFromLiteral(pl ParametersLiteral) (Parameters, error) {
	rlweParams, err := rlwe.NewParametersFromLiteral(pl.GetRLWEParametersLiteral())
	if err != nil {
		return Parameters{}, err
	}
	return NewParameters(rlweParams, pl.T, pl.R)
}

// ParametersLiteral returns the ParametersLiteral of the target Parameters.
func (p Parameters) ParametersLiteral() ParametersLiteral {
	return ParametersLiteral{
		LogN:       p.LogN(),
		LogNthRoot: p.LogNthRoot(),
		Q:          p.Q(),
		P:          p.P(),
		Xe:         p.Xe(),
		Xs:         p.Xs(),
		T:          p.BasePlaintextModulus(),
		R:          p.BasePlaintextModulusPower(),
	}
}

// GetRLWEParameters returns a pointer to the underlying RLWE parameters.
func (p Parameters) GetRLWEParameters() *rlwe.Parameters {
	return &p.Parameters
}

// MaxDimensions returns the maximum dimension of the matrix that can be SIMD packed in a single plaintext polynomial.
func (p Parameters) MaxDimensions() ring.Dimensions {
	switch p.RingType() {
	case ring.Standard:
		return ring.Dimensions{Rows: 2, Cols: p.RT.N >> 1}
	case ring.ConjugateInvariant:
		return ring.Dimensions{Rows: 1, Cols: p.RT.N}
	default:
		panic("cannot MaxDimensions: invalid ring type")
	}
}

// LogMaxDimensions returns the log2 of maximum dimension of the matrix that can be SIMD packed in a single plaintext polynomial.
func (p Parameters) LogMaxDimensions() ring.Dimensions {
	switch p.RingType() {
	case ring.Standard:
		return ring.Dimensions{Rows: 1, Cols: p.RT.LogN() - 1}
	case ring.ConjugateInvariant:
		return ring.Dimensions{Rows: 0, Cols: p.RT.LogN()}
	default:
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

// BasePlaintextModulus returns the base plaintext modulus.
func (p Parameters) BasePlaintextModulus() uint64 {
	return p.RT.BaseModulus
}

// PlaintextModulus returns {BasePlaintextModulus}^{BasePlaintextModulusPower}.
func (p Parameters) PlaintextModulus() uint64 {
	return p.RT.Modulus
}

// BasePlaintextModulusPower returns the plaintext modulus power K.
func (p Parameters) BasePlaintextModulusPower() int {
	return p.RT.BaseModulusPower
}

// LogBasePlaintextModulus returns log2(BasePlaintextModulus).
func (p Parameters) LogBasePlaintextModulus() float64 {
	return math.Log2(float64(p.BasePlaintextModulus()))
}

// LogPlaintextModulus returns log2(PlaintextModulus).
func (p Parameters) LogPlaintextModulus() float64 {
	return math.Log2(float64(p.PlaintextModulus()))
}

// GaloisElementForColRotation returns the Galois element for generating the
// automorphism phi(k): X -> X^{5^k mod 2N} mod (X^{N} + 1), which acts as a
// column-wise cyclic rotation by k position to the left on batched plaintexts.
//
// Example:
// Recall that batched plaintexts are 2xN/2 matrices, thus given the following
// plaintext matrix:
//
// [a, b, c, d][e, f, g, h]
//
// a rotation by k=3 will change the plaintext to:
//
// [d, a, b, d][h, e, f, g]
//
// Providing a negative k will change direction of the cyclic rotation do the right.
func (p Parameters) GaloisElementForColRotation(k int) uint64 {
	return p.Parameters.GaloisElement(k)
}

// GaloisElementForRowRotation returns the Galois element for generating the
// automorphism X -> X^{-1 mod NthRoot} mod (X^{N} + 1). This automorphism
// acts as a swapping the rows of the plaintext algebra when the plaintext
// is batched.
//
// Example:
// Recall that batched plaintexts are 2xN/2 matrices, thus given the following
// plaintext matrix:
//
// [a, b, c, d][e, f, g, h]
//
// a row rotation will change the plaintext to:
//
// [e, f, g, h][a, b, c, d]
func (p Parameters) GaloisElementForRowRotation() uint64 {
	return p.Parameters.GaloisElementOrderTwoOrthogonalSubgroup()
}

// GaloisElementsForInnerSum returns the list of Galois elements necessary to apply the method
// `InnerSum` operation with parameters `batch` and `n`.
func (p Parameters) GaloisElementsForInnerSum(batch, n int) (galEls []uint64) {
	galEls = rlwe.GaloisElementsForInnerSum(p, batch, n)
	if n > p.N()>>1 {
		galEls = append(galEls, p.GaloisElementForRowRotation())
	}
	return
}

// GaloisElementsForReplicate returns the list of Galois elements necessary to perform the
// `Replicate` operation with parameters `batch` and `n`.
func (p Parameters) GaloisElementsForReplicate(batch, n int) (galEls []uint64) {
	galEls = rlwe.GaloisElementsForReplicate(p, batch, n)
	if n > p.N()>>1 {
		galEls = append(galEls, p.GaloisElementForRowRotation())
	}
	return
}

// GaloisElementsForTrace returns the list of Galois elements requored for the for the `Trace` operation.
// Trace maps X -> sum((-1)^i * X^{i*n+1}) for 2^{LogN} <= i < N.
func (p Parameters) GaloisElementsForTrace(logN int) []uint64 {
	return rlwe.GaloisElementsForTrace(p, logN)
}

// Equal compares two sets of parameters for equality.
func (p Parameters) Equal(other *Parameters) bool {
	return p.Parameters.Equal(&other.Parameters) && (p.PlaintextModulus() == other.PlaintextModulus())
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
