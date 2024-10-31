// Package rgsw implements an RLWE-based GSW encryption and external product RLWE x RGSW -> RLWE.
// RSGW ciphertexts are tuples of two rlwe.GadgetCiphertext encrypting (`m(X)`, s*m(X)).
package rgsw

import (
	"bufio"
	"fmt"
	"io"

	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/buffer"
	"github.com/Pro7ech/lattigo/utils/structs"
)

// Ciphertext is a generic type for RGSW ciphertext.
type Ciphertext struct {
	rlwe.DigitDecomposition
	Matrix structs.Matrix[ring.Matrix]
}

// NewCiphertext allocates a new RGSW ciphertext in the NTT domain.
func NewCiphertext(params rlwe.ParameterProvider, LevelQ, LevelP int, DD rlwe.DigitDecomposition) (ct *Ciphertext) {
	ct = new(Ciphertext)
	ct.FromBuffer(params, LevelQ, LevelP, DD, make([]uint64, ct.BufferSize(params, LevelQ, LevelP, DD)))
	return
}

// BufferSize returns the minimum buffer size
// to instantiate the receiver through [FromBuffer].
func (ct *Ciphertext) BufferSize(params rlwe.ParameterProvider, LevelQ, LevelP int, DD rlwe.DigitDecomposition) int {
	if LevelP > 0 {
		DD = rlwe.DigitDecomposition{}
	}
	p := params.GetRLWEParameters()
	dims := p.DecompositionMatrixDimensions(LevelQ, LevelP, DD)
	return 4 * new(ring.Matrix).BufferSize(p.N(), LevelQ, LevelP, dims)
}

// FromBuffer assigns new backing array to the receiver.
// Method panics if len(buf) is too small.
// Minimum backing array size can be obtained with [BufferSize].
func (ct *Ciphertext) FromBuffer(params rlwe.ParameterProvider, LevelQ, LevelP int, DD rlwe.DigitDecomposition, buf []uint64) {

	if size := ct.BufferSize(params, LevelQ, LevelP, DD); len(buf) < size {
		panic(fmt.Errorf("invalid buffer size: len(buf)=%d < %d ", len(buf), size))
	}

	p := params.GetRLWEParameters()

	dims := p.DecompositionMatrixDimensions(LevelQ, LevelP, DD)

	size := new(ring.Matrix).BufferSize(p.N(), LevelQ, LevelP, dims)

	ct.Matrix = [][]ring.Matrix{{ring.Matrix{}, ring.Matrix{}}, {ring.Matrix{}, ring.Matrix{}}}

	var ptr int
	for i := range 2 {
		for j := range 2 {
			ct.Matrix[i][j].FromBuffer(p.N(), LevelQ, LevelP, dims, buf[ptr:])
			ptr += size
		}
	}

	ct.DigitDecomposition = DD
}

// FromGadgetCiphertext populates the receiver from an [rlwe.GadgetCiphertext] and an [rgsw.Evaluator]
// instantiated with an [rlwe.RelinearizationKey].
//
// The receiver [rgsw.Ciphertext] is constructed as follow:
//
// inputs:
// - gct = [-as + w*m + e, a]
// - rlk = [-bs + ws^2 + e, b]
//
// output:
// - rgsw: [[-as + w*m + e, a], [<a, rlk[0]>, <a, rlk[1]> + -as + w*m + e]]
//
// The first component of the [rgsw.Ciphertext] shares the backing array of the input [rlwe.GadgetCiphertext].
//
// The method will panic if the input [rlwe.GadgetCiphertext].LevelP() isn't -1.
func (ct *Ciphertext) FromGadgetCiphertext(eval *Evaluator, gct *rlwe.GadgetCiphertext) (err error) {

	if gct.LevelP() != -1 {
		return fmt.Errorf("invalid argument: gct.LevelP() should be -1 but is %d", gct.LevelP())
	}

	dims := gct.Dims()

	ct.Matrix = [][]ring.Matrix{
		{gct.Vector[0], gct.Vector[1]},
		{ring.Matrix{}, ring.Matrix{}},
	}

	p := eval.GetRLWEParameters()

	LevelQ := gct.LevelQ()
	LevelP := gct.LevelP()

	rQ := p.RingQAtLevel(LevelQ)

	size := new(ring.Matrix).BufferSize(p.N(), LevelQ, LevelP, dims)

	buf := make([]uint64, 2*size)

	var ptr int
	ct.Matrix[1][0].FromBuffer(p.N(), LevelQ, LevelP, dims, buf[ptr:])
	ptr += size
	ct.Matrix[1][1].FromBuffer(p.N(), LevelQ, LevelP, dims, buf[ptr:])
	ptr += size

	var rlk *rlwe.RelinearizationKey
	if rlk, err = eval.CheckAndGetRelinearizationKey(); err != nil {
		return fmt.Errorf("eval.CheckAndGetRelinearizationKey: %w", err)
	}

	p0 := eval.BuffQ[1]

	for i := range dims {
		for j := range dims[i] {

			cij0 := ct.At(0).At(i, j)
			cij1 := ct.At(1).At(i, j)

			rQ.IMForm(cij0.Q[1], p0)

			// [a] * [-bs + ws^2 + e, b]
			eval.GadgetProduct(LevelQ, p0, true, &rlk.GadgetCiphertext, cij1)

			rQ.MForm(cij1.Q[0], cij1.Q[0])
			rQ.MForm(cij1.Q[1], cij1.Q[1])

			// [-bs + as^2 + e, b] + [0, -as + wm + e]
			rQ.Add(cij1.Q[1], cij0.Q[0], cij1.Q[1])
		}
	}

	ct.DigitDecomposition = gct.DigitDecomposition

	return
}

// LevelQ returns the level of the modulus Q of the target.
func (ct Ciphertext) LevelQ() int {
	return ct.Matrix[0][0].LevelQ()
}

// LevelP returns the level of the modulus P of the target.
func (ct Ciphertext) LevelP() int {
	return ct.Matrix[0][0].LevelP()
}

func (ct Ciphertext) At(i int) *rlwe.GadgetCiphertext {
	return &rlwe.GadgetCiphertext{
		DigitDecomposition: ct.DigitDecomposition,
		Vector:             ct.Matrix[i],
	}
}

// BinarySize returns the serialized size of the object in bytes.
func (ct Ciphertext) BinarySize() int {
	return 2 + ct.Matrix.BinarySize()
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
func (ct Ciphertext) WriteTo(w io.Writer) (n int64, err error) {
	switch w := w.(type) {
	case buffer.Writer:

		var inc int64

		if inc, err = buffer.WriteAsUint8[rlwe.DigitDecompositionType](w, ct.Type); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.WriteAsUint8[int](w, ct.Log2Basis); err != nil {
			return n + inc, err
		}

		n += inc

		inc, err = ct.Matrix.WriteTo(w)

		return n + inc, err

	default:
		return ct.WriteTo(bufio.NewWriter(w))
	}
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
func (ct *Ciphertext) ReadFrom(r io.Reader) (n int64, err error) {
	switch r := r.(type) {
	case buffer.Reader:

		var inc int64

		if inc, err = buffer.ReadAsUint8[rlwe.DigitDecompositionType](r, &ct.Type); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.ReadAsUint8[int](r, &ct.Log2Basis); err != nil {
			return n + inc, err
		}

		n += inc

		inc, err = ct.Matrix.ReadFrom(r)

		return n + inc, err

	default:
		return ct.ReadFrom(bufio.NewReader(r))
	}
}

// MarshalBinary encodes the object into a binary form on a newly allocated slice of bytes.
func (ct Ciphertext) MarshalBinary() (p []byte, err error) {
	buf := buffer.NewBufferSize(ct.BinarySize())
	_, err = ct.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary decodes a slice of bytes generated by
// MarshalBinary or WriteTo on the object.
func (ct *Ciphertext) UnmarshalBinary(p []byte) (err error) {
	_, err = ct.ReadFrom(buffer.NewBuffer(p))
	return
}

// Plaintext stores an RGSW plaintext value.
type Plaintext rlwe.GadgetPlaintext

// NewPlaintext creates a new RGSW plaintext from value, which can be either uint64, int64 or *ring.Poly.
// Plaintext is returned in the NTT and Montgomery domain.
func NewPlaintext(params rlwe.Parameters, value interface{}, LevelQ, LevelP int, dd rlwe.DigitDecomposition) (*Plaintext, error) {
	gct, err := rlwe.NewGadgetPlaintext(params, value, LevelQ, LevelP, dd)
	return &Plaintext{Value: gct.Value}, err
}
