package rlwe

import (
	"bufio"
	"fmt"
	"io"

	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/utils/buffer"
	"github.com/Pro7ech/lattigo/utils/sampling"
)

type PlaintextWrapper interface {
	AsPlaintext() *Plaintext
}

// Plaintext is a common base type for RLWE plaintexts.
type Plaintext struct {
	*MetaData
	*ring.Point
}

// NewPlaintext creates a new Plaintext.
func NewPlaintext(params ParameterProvider, LevelQ, LevelP int) (pt *Plaintext) {
	pt = new(Plaintext)
	pt.FromBuffer(params, LevelQ, LevelP, make([]uint64, pt.BufferSize(params, LevelQ, LevelP)))
	pt.MetaData = &MetaData{IsNTT: params.GetRLWEParameters().NTTFlag()}
	return
}

// BufferSize returns the minimum buffer size
// to instantiate the receiver through [FromBuffer].
func (pt *Plaintext) BufferSize(params ParameterProvider, LevelQ, LevelP int) int {
	p := params.GetRLWEParameters()
	return pt.Point.BufferSize(p.N(), LevelQ, LevelP)
}

// FromBuffer assigns new backing array to the receiver.
// Method panics if len(buf) is too small.
// Minimum backing array size can be obtained with [BufferSize].
func (pt *Plaintext) FromBuffer(params ParameterProvider, LevelQ, LevelP int, buf []uint64) {

	if size := pt.BufferSize(params, LevelQ, LevelP); len(buf) < size {
		panic(fmt.Errorf("invalid buffer size: len(buf)=%d < %d", len(buf), size))
	}

	p := params.GetRLWEParameters()

	if pt.Point == nil {
		pt.Point = &ring.Point{}
	}

	pt.Point.FromBuffer(p.N(), LevelQ, LevelP, buf)
}

// NewPlaintextAtLevelFromPoly constructs a new Plaintext at a specific level
// where the message is set to the passed poly. No checks are performed on poly and
// the returned Plaintext will share its backing array of coefficients.
// Returned plaintext's MetaData is allocated but empty.
func NewPlaintextAtLevelFromPoly(LevelQ, LevelP int, pQ, pP ring.RNSPoly) (pt *Plaintext, err error) {
	p, err := ring.NewPointAtLevelFromPoly(LevelQ, LevelP, pQ, pP)
	if err != nil {
		return nil, err
	}
	return &Plaintext{Point: p, MetaData: &MetaData{}}, nil
}

// Degree returns the degree of the receiver.
func (pt Plaintext) Degree() int {
	return 0
}

func (pt Plaintext) Clone() (ptCpy *Plaintext) {
	return &Plaintext{Point: pt.Point.Clone(), MetaData: pt.MetaData.Clone()}
}

// AsPoint wraps the receiver into an [rlwe.Point].
func (pt *Plaintext) AsPoint() *ring.Point {
	return pt.Point
}

// AsCiphertext wraps the receiver into an [rlwe.Ciphertext].
func (pt *Plaintext) AsCiphertext() *Ciphertext {
	return &Ciphertext{Vector: pt.Point.AsVector(), MetaData: pt.MetaData}
}

// AsPlaintext wraps the receiver into an [rlwe.Plaintext].
func (pt *Plaintext) AsPlaintext() *Plaintext {
	return pt
}

// Randomize populates the receiver with uniform random coefficients.
func (pt *Plaintext) Randomize(params ParameterProvider, source *sampling.Source) {
	p := params.GetRLWEParameters()
	pt.Point.Randomize(p.RingQAtLevel(pt.LevelQ()), p.RingPAtLevel(pt.LevelP()), source)
}

// BinarySize returns the serialized size of the object in bytes.
func (pt Plaintext) BinarySize() (size int) {
	size++
	if pt.MetaData != nil {
		size += pt.MetaData.BinarySize()
	}
	return size + pt.Point.BinarySize()
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
func (pt Plaintext) WriteTo(w io.Writer) (n int64, err error) {
	switch w := w.(type) {
	case buffer.Writer:

		var inc int64

		if pt.MetaData != nil {

			if inc, err = buffer.WriteUint8(w, 1); err != nil {
				return n + inc, err
			}

			n += inc

			if inc, err = pt.MetaData.WriteTo(w); err != nil {
				return n + inc, err
			}

			n += inc

		} else {
			if inc, err = buffer.WriteUint8(w, 0); err != nil {
				return n + inc, err
			}

			n += inc
		}

		if inc, err = pt.Point.WriteTo(w); err != nil {
			return n + inc, err
		}

		return n + inc, err
	default:
		return pt.WriteTo(bufio.NewWriter(w))
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
func (pt *Plaintext) ReadFrom(r io.Reader) (n int64, err error) {
	switch r := r.(type) {
	case buffer.Reader:

		var inc int64

		var hasMetaData uint8

		if inc, err = buffer.ReadUint8(r, &hasMetaData); err != nil {
			return n + inc, err
		}

		n += inc

		if hasMetaData == 1 {

			if pt.MetaData == nil {
				pt.MetaData = &MetaData{}
			}

			if inc, err = pt.MetaData.ReadFrom(r); err != nil {
				return n + inc, err
			}

			n += inc
		}

		if pt.Point == nil {
			pt.Point = &ring.Point{}
		}

		if inc, err = pt.Point.ReadFrom(r); err != nil {
			return n + inc, err
		}

		return n + inc, err

	default:
		return pt.ReadFrom(bufio.NewReader(r))
	}
}

// MarshalBinary encodes the object into a binary form on a newly allocated slice of bytes.
func (pt Plaintext) MarshalBinary() (data []byte, err error) {
	buf := buffer.NewBufferSize(pt.BinarySize())
	_, err = pt.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary decodes a slice of bytes generated by
// MarshalBinary or WriteTo on the object.
func (pt *Plaintext) UnmarshalBinary(p []byte) (err error) {
	_, err = pt.ReadFrom(buffer.NewBuffer(p))
	return
}
