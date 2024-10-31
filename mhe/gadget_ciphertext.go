package mhe

import (
	"bufio"
	"fmt"
	"io"
	"slices"

	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/buffer"
	"github.com/Pro7ech/lattigo/utils/sampling"
)

// GadgetCiphertextProtocol is the structure storing the parameters for the collective EvaluationKey generation.
type GadgetCiphertextProtocol struct {
	*rlwe.KeyGenerator
}

// ShallowCopy creates a shallow copy of the receiver in which all the read-only data-structures are
// shared with the receiver and the temporary buffers are reallocated. The receiver and the returned
// object can be used concurrently.
func (p GadgetCiphertextProtocol) ShallowCopy() *GadgetCiphertextProtocol {
	return &GadgetCiphertextProtocol{KeyGenerator: p.KeyGenerator.ShallowCopy()}
}

// NewGadgetCiphertextProtocol instantiates a new [mhe.GadgetCiphertextProtocol].
func NewGadgetCiphertextProtocol(params rlwe.ParameterProvider) (p *GadgetCiphertextProtocol) {
	return &GadgetCiphertextProtocol{KeyGenerator: rlwe.NewKeyGenerator(params)}
}

// Allocate allocates a party's share in the [mhe.GadgetCiphertextProtocol].
func (p GadgetCiphertextProtocol) Allocate(LevelQ, LevelP int, DD rlwe.DigitDecomposition) *GadgetCiphertextShare {
	return &GadgetCiphertextShare{GadgetCiphertext: *rlwe.NewGadgetCiphertext(p.GetRLWEParameters(), 0, LevelQ, LevelP, DD)}
}

// Gen generates a party's share in the [mhe.GadgetCiphertextProtocol].
func (p GadgetCiphertextProtocol) Gen(sk *rlwe.SecretKey, pt *rlwe.Plaintext, seed [32]byte, share *GadgetCiphertextShare) (err error) {
	share.Seed = seed
	return p.WithKey(sk).WithSeededPublicRandomness(seed).Encrypt(pt, &share.GadgetCiphertext)
}

// Aggregate sets share3 to share1 + share2.
func (p GadgetCiphertextProtocol) Aggregate(share1, share2, share3 *GadgetCiphertextShare) (err error) {
	return share3.Aggregate(p.GetRLWEParameters(), share1, share2)
}

// Finalize finalizes the protocol and populates the input computed collective [rlwe.GadgetCiphertext].
func (p GadgetCiphertextProtocol) Finalize(share *GadgetCiphertextShare, ct *rlwe.GadgetCiphertext) (err error) {
	return share.Get(p.GetRLWEParameters(), ct)
}

type GadgetCiphertextShare struct {
	Seed [32]byte
	rlwe.GadgetCiphertext
}

// Equal performs a deep equal between the receiver and the operand.
func (share GadgetCiphertextShare) Equal(other *GadgetCiphertextShare) bool {
	return share.Seed == other.Seed && share.GadgetCiphertext.Equal(&other.GadgetCiphertext)
}

// Aggregate sets the receiver to a + b.
func (share *GadgetCiphertextShare) Aggregate(params rlwe.ParameterProvider, a, b *GadgetCiphertextShare) (err error) {

	if a.Seed != b.Seed {
		return fmt.Errorf("shares seed do not match")
	}

	if a.DigitDecomposition != b.DigitDecomposition {
		return fmt.Errorf("shares digit decomposition do not match")
	}

	share.Seed = a.Seed
	share.DigitDecomposition = a.DigitDecomposition

	p := params.GetRLWEParameters()

	return share.Vector[0].Aggregate(p.RingQ(), p.RingP(), &a.Vector[0], &b.Vector[0])
}

// Get copies the data of the receiver on a pre-allocated [rlwe.GadgetCiphertext].
func (share GadgetCiphertextShare) Get(params rlwe.ParameterProvider, gct *rlwe.GadgetCiphertext) (err error) {

	if gct.LevelQ() != share.LevelQ() {
		return fmt.Errorf("share LevelQ do not match")
	}

	if gct.LevelP() != share.LevelP() {
		return fmt.Errorf("share LevelP do not match")
	}

	if !slices.Equal(gct.Dims(), share.Dims()) {
		return fmt.Errorf("share dimensions do not match")
	}

	gct.Vector[0].Copy(&share.Vector[0])
	p := params.GetRLWEParameters()
	gct.Vector[1].Randomize(p.RingQ(), p.RingP(), sampling.NewSource(share.Seed))
	gct.DigitDecomposition = share.DigitDecomposition

	return
}

// AsGadgetCiphertext wraps the receiver into an [rlwe.GadgetCiphertext].
func (share GadgetCiphertextShare) AsGadgetCiphertext(params rlwe.ParameterProvider) (gct *rlwe.GadgetCiphertext) {
	gct = &rlwe.GadgetCiphertext{
		DigitDecomposition: share.DigitDecomposition,
		Vector:             make([]ring.Matrix, 2),
	}

	gct.Vector[0] = share.Vector[0]
	p := params.GetRLWEParameters()
	gct.Vector[1] = *ring.NewMatrix(p.N(), gct.Vector[0].LevelQ(), gct.Vector[0].LevelP(), gct.Vector[0].Dims())
	gct.Vector[1].Randomize(p.RingQ(), p.RingP(), sampling.NewSource(share.Seed))

	return
}

// GetNew copies the data of the receiver on a new [rlwe.GadgetCiphertext].
func (share GadgetCiphertextShare) GetNew(params rlwe.ParameterProvider) (gct *rlwe.GadgetCiphertext) {
	gct = &rlwe.GadgetCiphertext{
		DigitDecomposition: share.DigitDecomposition,
		Vector:             make([]ring.Matrix, 2),
	}

	gct.Vector[0] = *share.Vector[0].Clone()
	p := params.GetRLWEParameters()
	gct.Vector[1] = *ring.NewMatrix(p.N(), gct.Vector[0].LevelQ(), gct.Vector[0].LevelP(), gct.Vector[0].Dims())
	gct.Vector[1].Randomize(p.RingQ(), p.RingP(), sampling.NewSource(share.Seed))

	return
}

// BinarySize returns the serialized size of the object in bytes.
func (share GadgetCiphertextShare) BinarySize() (dataLen int) {
	return 32 + share.GadgetCiphertext.BinarySize()
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
func (share GadgetCiphertextShare) WriteTo(w io.Writer) (n int64, err error) {

	switch w := w.(type) {
	case buffer.Writer:

		var inc int64

		if inc, err = buffer.Write(w, share.Seed[:]); err != nil {
			return n + inc, err
		}

		n += inc

		inc, err = share.GadgetCiphertext.WriteTo(w)

		return n + inc, err

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
func (share *GadgetCiphertextShare) ReadFrom(r io.Reader) (n int64, err error) {
	switch r := r.(type) {
	case buffer.Reader:

		var inc int64

		if inc, err = buffer.Read(r, share.Seed[:]); err != nil {
			return n + inc, err
		}

		n += inc

		inc, err = share.GadgetCiphertext.ReadFrom(r)

		return n + inc, err

	default:
		return share.ReadFrom(bufio.NewReader(r))
	}
}

// MarshalBinary encodes the object into a binary form on a newly allocated slice of bytes.
func (share GadgetCiphertextShare) MarshalBinary() (data []byte, err error) {
	buf := buffer.NewBufferSize(share.BinarySize())
	_, err = share.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary decodes a slice of bytes generated by
// MarshalBinary or WriteTo on the object.
func (share *GadgetCiphertextShare) UnmarshalBinary(p []byte) (err error) {
	_, err = share.ReadFrom(buffer.NewBuffer(p))
	return
}
