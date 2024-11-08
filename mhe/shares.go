package mhe

import (
	"bufio"
	"fmt"
	"io"

	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/buffer"
)

// VectorShare is a struct storing the PublicKeyGen protocol's share.
type VectorShare struct {
	Seed [32]byte
	ring.Vector
}

func NewVectorShare(params rlwe.ParameterProvider, LevelQ, LevelP, size int) *VectorShare {
	p := params.GetRLWEParameters()
	return &VectorShare{Vector: *ring.NewVector(p.N(), LevelQ, LevelP, size)}
}

func (share VectorShare) Aggregate(params rlwe.ParameterProvider, share1, share2 *VectorShare) (err error) {

	if share1.Seed != share2.Seed {
		return fmt.Errorf("shares seed do not match")
	}
	p := params.GetRLWEParameters()
	return share.Vector.Aggregate(p.RingQ(), p.RingP(), &share1.Vector, &share2.Vector)
}

// Equal performs a deep equal between the receiver and the operand.
func (share VectorShare) Equal(other *VectorShare) bool {
	return share.Seed == other.Seed && share.Vector.Equal(&other.Vector)
}

// BinarySize returns the serialized size of the object in bytes.
func (share VectorShare) BinarySize() (size int) {
	return 32 + share.Vector.BinarySize()
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
func (share VectorShare) WriteTo(w io.Writer) (n int64, err error) {
	switch w := w.(type) {
	case buffer.Writer:

		var inc int64

		if inc, err = buffer.Write(w, share.Seed[:]); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = share.Vector.WriteTo(w); err != nil {
			return
		}

		return n + inc, w.Flush()
	default:
		return share.WriteTo(bufio.NewWriter(w))
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
func (share *VectorShare) ReadFrom(r io.Reader) (n int64, err error) {
	switch r := r.(type) {
	case buffer.Reader:

		var inc int64

		if inc, err = buffer.Read(r, share.Seed[:]); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = share.Vector.ReadFrom(r); err != nil {
			return n + inc, err
		}

		return n + inc, nil
	default:
		return share.ReadFrom(bufio.NewReader(r))
	}
}

// MarshalBinary encodes the object into a binary form on a newly allocated slice of bytes.
func (share VectorShare) MarshalBinary() (p []byte, err error) {
	buf := buffer.NewBufferSize(share.BinarySize())
	_, err = share.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary decodes a slice of bytes generated by
// MarshalBinary or WriteTo on the object.
func (share *VectorShare) UnmarshalBinary(p []byte) (err error) {
	_, err = share.ReadFrom(buffer.NewBuffer(p))
	return
}