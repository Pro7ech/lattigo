package ring

import (
	"fmt"
	"io"
	"math/bits"

	"github.com/Pro7ech/lattigo/utils"
	"github.com/Pro7ech/lattigo/utils/structs"
)

// RNSPoly is the structure that contains the coefficients of an RNS polynomial.
// Coefficients are stored as a matrix backed by an 1D array.
type RNSPoly []Poly

// BufferSize returns the minimum buffer size
// to instantiate the receiver through [FromBuffer].
func (p *RNSPoly) BufferSize(N, Level int) int {
	return N * (Level + 1)
}

// FromBuffer assigns new backing array to the receiver.
func (p *RNSPoly) FromBuffer(N, Level int, buf []uint64) {

	if len(buf) < p.BufferSize(N, Level) {
		panic(fmt.Errorf("invalid buffer size: N=%d x (Level+1)=%d < len(p)=%d", N, Level+1, len(buf)))
	}

	*p = make([]Poly, Level+1)
	for i := range Level + 1 {
		(*p)[i] = buf[i*N : (i+1)*N]
	}
}

// NewRNSPoly creates a new polynomial with N coefficients set to zero and Level+1 moduli.
func NewRNSPoly(N, Level int) (p RNSPoly) {
	p.FromBuffer(N, Level, make([]uint64, p.BufferSize(N, Level)))
	return
}

// At returns the i-th row of the receiver.
func (p RNSPoly) At(i int) Poly {
	if i > p.Level() {
		panic(fmt.Errorf("i > p.Level()"))
	}
	return p[i]
}

// Resize resizes the level of the target polynomial to the provided level.
// If the provided level is larger than the current level, then allocates zero
// coefficients, otherwise dereferences the coefficients above the provided level.
func (p *RNSPoly) Resize(level int) {
	N := p.N()
	if p.Level() > level {
		*p = (*p)[:level+1]
	} else if level > p.Level() {
		prevLevel := p.Level()
		*p = append(*p, make([]Poly, level-prevLevel)...)
		for i := prevLevel + 1; i < level+1; i++ {
			(*p)[i] = NewPoly(N)
		}
	}
}

// N returns the number of coefficients of the polynomial, which equals the degree of the Ring cyclotomic polynomial.
func (p RNSPoly) N() int {
	if len(p) == 0 {
		return 0
	}
	return p.At(0).N()
}

// LogN returns the base two logarithm of the number of coefficients of the polynomial.
func (p RNSPoly) LogN() int {
	return bits.Len64(uint64(p.N()) - 1)
}

// Level returns the current number of moduli minus 1.
func (p RNSPoly) Level() int {
	return len(p) - 1
}

// Zero sets all coefficients of the target polynomial to 0.
func (p RNSPoly) Zero() {
	for i := range p {
		ZeroVec(p.At(i))
	}
}

// Ones sets all coefficients of the target polynomial to 1.
func (p RNSPoly) Ones() {
	for i := range p {
		OneVec(p.At(i))
	}
}

func (p RNSPoly) Equal(other *RNSPoly) bool {
	return structs.Vector[Poly](p).Equal(structs.Vector[Poly](*other))
}

func (p RNSPoly) Clone() *RNSPoly {
	pCpy := RNSPoly(structs.Vector[Poly](p).Clone())
	return &pCpy
}

// Copy copies the coefficients of p1 on the target polynomial.
// This method does nothing if the underlying arrays are the same.
// This method will resize the target polynomial to the level of
// the input polynomial.
func (p *RNSPoly) Copy(p1 *RNSPoly) {
	p.Resize(p1.Level())
	p.CopyLvl(p1.Level(), p1)
}

// CopyLvl copies the coefficients of p1 on the target polynomial.
// This method does nothing if the underlying arrays are the same.
// Expects the degree of both polynomials to be identical.
func (p *RNSPoly) CopyLvl(level int, p1 *RNSPoly) {
	for i := 0; i < level+1; i++ {
		if !utils.Alias1D(p.At(i), p1.At(i)) {
			copy(p.At(i), p1.At(i))
		}
	}
}

// SwitchRingDegree changes the ring degree of p0 to the one of p1.
// Maps Y^{N/n} -> X^{N} or X^{N} -> Y^{N/n}.
// Inputs are expected to not be in the NTT domain.
func (r RNSRing) SwitchRingDegree(p0, p1 RNSPoly) {

	NIn, NOut := p0.N(), p1.N()

	gapIn, gapOut := NOut/NIn, 1
	if NIn > NOut {
		gapIn, gapOut = 1, NIn/NOut
	}

	for j := range r {
		tmp0, tmp1 := p1.At(j), p0.At(j)
		for w0, w1 := 0, 0; w0 < NOut; w0, w1 = w0+gapIn, w1+gapOut {
			tmp0[w0] = tmp1[w1]
		}
	}
}

// SwitchRingDegreeNTT changes the ring degree of p0 to the one of p1.
// Maps Y^{N/n} -> X^{N} or X^{N} -> Y^{N/n}.
// Inputs are expected to be in the NTT domain.
func (r RNSRing) SwitchRingDegreeNTT(p0 RNSPoly, buff []uint64, p1 RNSPoly) {

	NIn, NOut := p0.N(), p1.N()

	if NIn > NOut {

		gap := NIn / NOut

		for j, s := range r {

			tmpIn, tmpOut := p0.At(j), p1.At(j)

			s.INTT(tmpIn, buff)

			for w0, w1 := 0, 0; w0 < NOut; w0, w1 = w0+1, w1+gap {
				tmpOut[w0] = buff[w1]
			}

			switch r.Type() {
			case Standard:
				NTTStandard(tmpOut, tmpOut, NOut, s.Modulus, s.MRedConstant, s.BRedConstant, s.RootsForward)
			case ConjugateInvariant:
				NTTConjugateInvariant(tmpOut, tmpOut, NOut, s.Modulus, s.MRedConstant, s.BRedConstant, s.RootsForward)
			}
		}

	} else {
		gap := NOut / NIn

		for j := range p0 {
			tmpIn := p0.At(j)
			tmpOut := p1.At(j)
			for i := range p0.At(0) {
				c := tmpIn[i]
				for w := 0; w < gap; w++ {
					tmpOut[i*gap+w] = c
				}
			}
		}
	}
}

// BinarySize returns the serialized size of the object in bytes.
func (p RNSPoly) BinarySize() (size int) {
	return structs.Vector[Poly](p).BinarySize()
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
func (p RNSPoly) WriteTo(w io.Writer) (n int64, err error) {
	return structs.Vector[Poly](p).WriteTo(w)
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
func (p *RNSPoly) ReadFrom(r io.Reader) (n int64, err error) {
	v := structs.Vector[Poly](*p)
	if n, err = v.ReadFrom(r); err != nil {
		return
	}
	*p = []Poly(v)
	return
}

// MarshalBinary encodes the object into a binary form on a newly allocated slice of bytes.
func (p RNSPoly) MarshalBinary() (data []byte, err error) {
	return structs.Vector[Poly](p).MarshalBinary()
}

// UnmarshalBinary decodes a slice of bytes generated by
// MarshalBinary or WriteTo on the object.
func (p *RNSPoly) UnmarshalBinary(data []byte) (err error) {
	v := structs.Vector[Poly](*p)
	if err = v.UnmarshalBinary(data); err != nil {
		return
	}
	*p = []Poly(v)
	return
}
