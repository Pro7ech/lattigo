package rlwe

import (
	"bufio"
	"fmt"
	"io"

	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/utils/buffer"
	"github.com/Pro7ech/lattigo/utils/sampling"
)

type CiphertextWrapper interface {
	AsCiphertext() *Ciphertext
}

// Ciphertext is wrapper around an [rlwe.Vector].
type Ciphertext struct {
	*MetaData
	*ring.Vector
}

// NewCiphertext returns a new Ciphertext with zero values.
// The field [rlwe.Metadata] is initialized with the IsNTT flag set to parameters
// default NTT domain (see [rlwe.Parameters]).
func NewCiphertext(params ParameterProvider, Degree, LevelQ, LevelP int) (ct *Ciphertext) {
	ct = new(Ciphertext)
	ct.FromBuffer(params, Degree, LevelQ, LevelP, make([]uint64, ct.BufferSize(params, Degree, LevelQ, LevelP)))
	ct.MetaData = &MetaData{IsNTT: params.GetRLWEParameters().NTTFlag()}
	return
}

// BufferSize returns the minimum buffer size
// to instantiate the receiver through [FromBuffer].
func (ct *Ciphertext) BufferSize(params ParameterProvider, Degree, LevelQ, LevelP int) int {
	p := params.GetRLWEParameters()
	return ct.Vector.BufferSize(p.N(), LevelQ, LevelP, Degree+1)
}

// FromBuffer assigns new backing array to the receiver.
// Method panics if len(buf) is too small.
// Minimum backing array size can be obtained with [BufferSize].
func (ct *Ciphertext) FromBuffer(params ParameterProvider, Degree, LevelQ, LevelP int, buf []uint64) {

	if size := ct.BufferSize(params, Degree, LevelQ, LevelP); len(buf) < size {
		panic(fmt.Errorf("invalid buffer size: len(buf)=%d < %d", len(buf), size))
	}

	p := params.GetRLWEParameters()

	if ct.Vector == nil {
		ct.Vector = &ring.Vector{}
	}

	ct.Vector.FromBuffer(p.N(), LevelQ, LevelP, Degree+1, buf)
}

// NewCiphertextAtLevelFromPoly returns an instance of a Ciphertext at a specific level
// where the message is set to the passed poly. No checks are performed on poly and
// the returned Ciphertext will share its backing array of coefficients.
// Returned Ciphertext's MetaData is allocated but empty.
func NewCiphertextAtLevelFromPoly(LevelQ, LevelP int, pQ, pP []ring.RNSPoly) (*Ciphertext, error) {
	v, err := ring.NewVectorAtLevelFromPoly(LevelQ, LevelP, pQ, pP)
	if err != nil {
		return nil, fmt.Errorf("NewVectorAtLevelFromPoly: %w", err)
	}
	return &Ciphertext{Vector: v, MetaData: &MetaData{}}, nil
}

// AsVector wraps the receiver into an [rlwe.Vector].
func (ct *Ciphertext) AsVector() *ring.Vector {
	return ct.Vector
}

// AsPlaintext wraps the receiver into an [rlwe.Plaintext].
func (ct *Ciphertext) AsPlaintext() *Plaintext {
	return &Plaintext{Point: ct.AsPoint(), MetaData: ct.MetaData}
}

// AsCiphertext wraps the receiver into an [rlwe.Ciphertext].
func (ct *Ciphertext) AsCiphertext() *Ciphertext {
	return ct
}

// ConcatPtoQ returns an instance of the receiver where the modulus Q
// is increased to Q[:] + P[:n] and the modulus P reduced to P[n:].
// n must be a positive integer 0 <= n <= ct.LevelP()+1.
func (ct *Ciphertext) ConcatPtoQ(n int) *Ciphertext {
	return &Ciphertext{Vector: ct.Vector.ConcatPtoQ(n), MetaData: ct.MetaData}
}

// ConcatQtoP returns an instance of the receiver where the modulus Q
// is reduced to Q[:n] and the modulus P increased to Q[n:] + P[:].
// n must be a positive integer 0 <= n < ct.LevelQ()+1.
func (ct *Ciphertext) ConcatQtoP(n int) *Ciphertext {
	return &Ciphertext{Vector: ct.Vector.ConcatQtoP(n), MetaData: ct.MetaData}
}

// Degree returns the degree of the receiver.
func (ct *Ciphertext) Degree() int {
	return ct.Size() - 1
}

// ResizeDegree resize the degree of the receiver to the given degree.
func (ct *Ciphertext) ResizeDegree(degree int) {
	ct.ResizeSize(degree + 1)
}

// Clone returns a deep copy of the receiver.
func (ct *Ciphertext) Clone() *Ciphertext {
	return &Ciphertext{Vector: ct.Vector.Clone(), MetaData: ct.MetaData.Clone()}
}

// Copy copies the input element and its parameters on the receiver.
func (ct *Ciphertext) Copy(other *Ciphertext) {
	ct.Vector.Copy(other.Vector)
	*ct.MetaData = *other.MetaData
}

// Equal performs a deep equal.
func (ct *Ciphertext) Equal(other *Ciphertext) bool {
	return ct.Vector.Equal(other.Vector)
}

// GetSmallestLargest returns the provided element that has the smallest degree as a first
// returned value and the largest degree as second return value. If the degree match, the
// order is the same as for the input.
func GetSmallestLargest(el0, el1 *Ciphertext) (smallest, largest *Ciphertext, sameDegree bool) {
	switch {
	case el0.Degree() > el1.Degree():
		return el1, el0, false
	case el0.Degree() < el1.Degree():
		return el0, el1, false
	}
	return el0, el1, true
}

func (ct *Ciphertext) SwitchRingDegree(rQ, rP ring.RNSRing, buff []uint64, ctOut *Ciphertext) {

	if ct.IsNTT {

		rQ = rQ.AtLevel(min(ct.LevelQ(), ctOut.LevelQ()))
		for i := 0; i < min(ct.Size(), ctOut.Size()); i++ {
			rQ.SwitchRingDegreeNTT(ct.Q[i], buff, ctOut.Q[i])
		}

		if LevelP := min(ct.LevelP(), ctOut.LevelP()); rP != nil && LevelP > -1 {
			rP = rP.AtLevel(LevelP)
			for i := 0; i < min(ct.Size(), ctOut.Size()); i++ {
				rP.SwitchRingDegreeNTT(ct.P[i], buff, ctOut.P[i])
			}
		}

		ctOut.IsNTT = true

	} else {

		rQ = rQ.AtLevel(min(ct.LevelQ(), ctOut.LevelQ()))
		for i := 0; i < min(ct.Size(), ctOut.Size()); i++ {
			rQ.SwitchRingDegree(ct.Q[i], ctOut.Q[i])
		}

		if LevelP := min(ct.LevelP(), ctOut.LevelP()); rP != nil && LevelP > -1 {
			rP = rP.AtLevel(LevelP)
			for i := 0; i < min(ct.Size(), ctOut.Size()); i++ {
				rP.SwitchRingDegree(ct.P[i], ctOut.P[i])
			}
		}

		ctOut.IsNTT = false
	}
}

// Randomize populates the receiver with uniform random coefficients.
func (ct *Ciphertext) Randomize(params ParameterProvider, source *sampling.Source) {
	p := params.GetRLWEParameters()
	ct.Vector.Randomize(p.RingQAtLevel(ct.LevelQ()), p.RingPAtLevel(ct.LevelP()), source)
}

// BinarySize returns the serialized size of the object in bytes.
func (ct *Ciphertext) BinarySize() (size int) {
	size++
	if ct.MetaData != nil {
		size += ct.MetaData.BinarySize()
	}
	return size + ct.Vector.BinarySize()
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
func (ct *Ciphertext) WriteTo(w io.Writer) (n int64, err error) {
	switch w := w.(type) {
	case buffer.Writer:

		var inc int64

		if ct.MetaData != nil {

			if inc, err = buffer.WriteUint8(w, 1); err != nil {
				return n + inc, err
			}

			n += inc

			if inc, err = ct.MetaData.WriteTo(w); err != nil {
				return n + inc, err
			}

			n += inc

		} else {
			if inc, err = buffer.WriteUint8(w, 0); err != nil {
				return n + inc, err
			}

			n += inc
		}

		if inc, err = ct.Vector.WriteTo(w); err != nil {
			return n + inc, err
		}

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

		var hasMetaData uint8

		if inc, err = buffer.ReadUint8(r, &hasMetaData); err != nil {
			return n + inc, err
		}

		n += inc

		if hasMetaData == 1 {

			if ct.MetaData == nil {
				ct.MetaData = &MetaData{}
			}

			if inc, err = ct.MetaData.ReadFrom(r); err != nil {
				return n + inc, err
			}

			n += inc
		}

		if ct.Vector == nil {
			ct.Vector = &ring.Vector{}
		}

		if inc, err = ct.Vector.ReadFrom(r); err != nil {
			return n + inc, err
		}

		return n + inc, err

	default:
		return ct.ReadFrom(bufio.NewReader(r))
	}
}

// MarshalBinary encodes the object into a binary form on a newly allocated slice of bytes.
func (ct *Ciphertext) MarshalBinary() (data []byte, err error) {
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
