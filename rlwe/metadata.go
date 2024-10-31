package rlwe

import (
	"bufio"
	"io"

	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/utils/buffer"
	"github.com/google/go-cmp/cmp"
)

// MetaData is a struct storing metadata.
type MetaData struct {
	// Scale is the scaling factor of the plaintext.
	Scale Scale

	// LogDimensions is the Log2 of the 2D plaintext matrix dimensions.
	LogDimensions ring.Dimensions

	// IsBatched is a flag indicating if the underlying plaintext is encoded
	// in such a way that product in R[X]/(X^N+1) acts as a point-wise multiplication
	// in the plaintext space.
	IsBatched bool

	// IsNTT is a flag indicating if the ciphertext is in the NTT domain.
	IsNTT bool

	// IsMontgomery is a flag indicating if the ciphertext is in the Montgomery domain.
	IsMontgomery bool
}

// Clone returns a copy of the target.
func (m *MetaData) Clone() *MetaData {
	if m == nil {
		return nil
	}
	mClone := *m
	return &mClone
}

func (m *MetaData) Equal(other *MetaData) (res bool) {

	if m == nil && other == nil {
		return true
	}

	if (m != nil && other == nil) || (m == nil && other != nil) {
		return false
	}

	res = cmp.Equal(&m.Scale, &other.Scale)
	res = res && m.IsBatched == other.IsBatched
	res = res && m.LogDimensions == other.LogDimensions
	res = res && m.IsNTT == other.IsNTT
	res = res && m.IsMontgomery == other.IsMontgomery

	return
}

// Slots returns the total number of slots that the plaintext holds.
func (m MetaData) Slots() int {
	return 1 << m.LogSlots()
}

// LogSlots returns the log2 of the total number of slots that the plaintext holds.
func (m MetaData) LogSlots() int {
	return m.LogDimensions.Cols + m.LogDimensions.Rows
}

// LogScale returns log2(scale).
func (m MetaData) LogScale() float64 {
	return m.Scale.Log2()
}

// BinarySize returns the size in bytes that the object once marshalled into a binary form.
func (m MetaData) BinarySize() int {
	return m.Scale.BinarySize() + 5
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
func (m MetaData) WriteTo(w io.Writer) (n int64, err error) {
	switch w := w.(type) {
	case buffer.Writer:

		var inc int64

		if inc, err = m.Scale.WriteTo(w); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.WriteAsUint8[int](w, m.LogDimensions.Rows); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.WriteAsUint8[int](w, m.LogDimensions.Cols); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.WriteAsUint8[bool](w, m.IsBatched); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.WriteAsUint8[bool](w, m.IsNTT); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.WriteAsUint8[bool](w, m.IsMontgomery); err != nil {
			return n + inc, err
		}

		n += inc

		return n, w.Flush()
	default:
		return m.WriteTo(bufio.NewWriter(w))
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
func (m *MetaData) ReadFrom(r io.Reader) (n int64, err error) {
	switch r := r.(type) {
	case buffer.Reader:

		var inc int64

		if inc, err = m.Scale.ReadFrom(r); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.ReadAsUint8[int](r, &m.LogDimensions.Rows); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.ReadAsUint8[int](r, &m.LogDimensions.Cols); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.ReadAsUint8[bool](r, &m.IsBatched); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.ReadAsUint8[bool](r, &m.IsNTT); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.ReadAsUint8[bool](r, &m.IsMontgomery); err != nil {
			return n + inc, err
		}

		n += inc

		return n, nil
	default:
		return m.ReadFrom(bufio.NewReader(r))
	}
}

// MarshalBinary encodes the object into a binary form on a newly allocated slice of bytes.
func (m MetaData) MarshalBinary() (p []byte, err error) {
	buf := buffer.NewBufferSize(m.BinarySize())
	_, err = m.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary decodes a slice of bytes generated by
// MarshalBinary or WriteTo on the object.
func (m *MetaData) UnmarshalBinary(p []byte) (err error) {
	_, err = m.ReadFrom(buffer.NewBuffer(p))
	return
}
