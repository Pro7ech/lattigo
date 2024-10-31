package mhe

import (
	"bufio"
	"fmt"
	"io"

	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/buffer"
)

// GaloisKeyProtocol is the structure storing the parameters for the collective GaloisKeys generation.
type GaloisKeyProtocol struct {
	EvaluationKeyProtocol
}

// ShallowCopy creates a shallow copy of GaloisKeyProtocol in which all the read-only data-structures are
// shared with the receiver and the temporary buffers are reallocated. The receiver and the returned
// GaloisKeyProtocol can be used concurrently.
func (p GaloisKeyProtocol) ShallowCopy() *GaloisKeyProtocol {
	return &GaloisKeyProtocol{EvaluationKeyProtocol: *p.EvaluationKeyProtocol.ShallowCopy()}
}

// NewGaloisKeyProtocol creates a GaloisKeyProtocol instance.
func NewGaloisKeyProtocol(params rlwe.ParameterProvider) (p *GaloisKeyProtocol) {
	return &GaloisKeyProtocol{EvaluationKeyProtocol: *NewEvaluationKeyProtocol(params)}
}

// Allocate allocates a party's share in the GaloisKey Generation.
func (p GaloisKeyProtocol) Allocate(evkParams ...rlwe.EvaluationKeyParameters) (pShare *GaloisKeyShare) {
	return &GaloisKeyShare{EvaluationKeyShare: *p.EvaluationKeyProtocol.Allocate(evkParams...)}
}

// Gen generates a party's share in the GaloisKey Generation.
func (p GaloisKeyProtocol) Gen(sk *rlwe.SecretKey, galEl uint64, seed [32]byte, share *GaloisKeyShare) (err error) {

	LevelQ := share.LevelQ()
	LevelP := share.LevelP()

	params := p.GetRLWEParameters()

	skOut := &rlwe.SecretKey{}
	skOut.Point = p.Point
	skOut.IsNTT = true
	skOut.IsMontgomery = true

	rQ := params.RingQ().AtLevel(LevelQ)

	galElInv := params.ModInvGaloisElement(galEl)

	share.GaloisElement = galEl

	rQ.AutomorphismNTT(sk.Q, galElInv, skOut.Q)

	if rP := params.RingP(); rP != nil && LevelP > -1 {
		//skOut.P = p.BuffP[3]
		rP.AtLevel(LevelP).AutomorphismNTT(sk.P, galElInv, skOut.P)
	}

	return p.EvaluationKeyProtocol.Gen(sk, skOut, seed, &share.EvaluationKeyShare)

}

// Aggregate computes share3 = share1 + share2.
func (p GaloisKeyProtocol) Aggregate(share1, share2, share3 *GaloisKeyShare) (err error) {

	if share1.GaloisElement != share2.GaloisElement {
		return fmt.Errorf("share Galois elements do not match")
	}

	share3.GaloisElement = share1.GaloisElement

	return p.EvaluationKeyProtocol.Aggregate(&share1.EvaluationKeyShare, &share2.EvaluationKeyShare, &share3.EvaluationKeyShare)
}

// FinalizeNew finalizes the GaloisKey Generation and returns a new [rlwe.GaloisKey].
func (p GaloisKeyProtocol) FinalizeNew(share *GaloisKeyShare) (gk *rlwe.GaloisKey) {
	gk = new(rlwe.GaloisKey)
	gk.EvaluationKey = *p.EvaluationKeyProtocol.FinalizeNew(&share.EvaluationKeyShare)
	gk.GaloisElement = share.GaloisElement
	gk.NthRoot = uint64(p.GetRLWEParameters().NthRoot())
	return
}

// Finalize finalizes the GaloisKey Generation and populates the input [rlwe.GaloisKey].
func (p GaloisKeyProtocol) Finalize(share *GaloisKeyShare, gk *rlwe.GaloisKey) (err error) {
	if err = p.EvaluationKeyProtocol.Finalize(&share.EvaluationKeyShare, &gk.EvaluationKey); err != nil {
		return
	}
	gk.GaloisElement = share.GaloisElement
	gk.NthRoot = uint64(p.GetRLWEParameters().NthRoot())
	return
}

// GaloisKeyShare is represent a Party's share in the GaloisKey Generation protocol.
type GaloisKeyShare struct {
	GaloisElement uint64
	EvaluationKeyShare
}

// Equal performs a deep equal between the receiver and the operand.
func (share GaloisKeyShare) Equal(other *GaloisKeyShare) bool {
	return share.GaloisElement == other.GaloisElement && share.EvaluationKeyShare.Equal(&other.EvaluationKeyShare)
}

// BinarySize returns the serialized size of the object in bytes.
func (share GaloisKeyShare) BinarySize() int {
	return 8 + share.EvaluationKeyShare.BinarySize()
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
func (share GaloisKeyShare) WriteTo(w io.Writer) (n int64, err error) {
	switch w := w.(type) {
	case buffer.Writer:
		var inc int64

		if inc, err = buffer.WriteUint64(w, share.GaloisElement); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = share.EvaluationKeyShare.WriteTo(w); err != nil {
			return n + inc, err
		}

		n += inc

		return n, err

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
func (share *GaloisKeyShare) ReadFrom(r io.Reader) (n int64, err error) {
	switch r := r.(type) {
	case buffer.Reader:

		var inc int64
		if inc, err = buffer.ReadUint64(r, &share.GaloisElement); err != nil {
			return n + inc, err
		}
		n += inc

		if inc, err = share.EvaluationKeyShare.ReadFrom(r); err != nil {
			return n + inc, err
		}

		return n + inc, nil
	default:
		return share.ReadFrom(bufio.NewReader(r))
	}
}

// MarshalBinary encodes the object into a binary form on a newly allocated slice of bytes.
func (share GaloisKeyShare) MarshalBinary() (p []byte, err error) {
	buf := buffer.NewBufferSize(share.BinarySize())
	_, err = share.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary decodes a slice of bytes generated by
// MarshalBinary or WriteTo on the object.
func (share *GaloisKeyShare) UnmarshalBinary(p []byte) (err error) {
	_, err = share.ReadFrom(buffer.NewBuffer(p))
	return
}
