package mhe

import (
	"bufio"
	"fmt"
	"io"

	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/buffer"
)

// CircularCiphertextProtocol is a non-interactive public aggregatable
// transcripts (PAT) protocol by which a set of parties, each holding
// a secret sk_{i} and a message m_{i}, can collectively  generate in
// a single round the encryption RLWE_{sk}(m*sk) where sk = sum sk_{i}
// and m = sum m_{i}.
// An RLWE is an [rlwe.Ciphertext].
type CircularCiphertextProtocol struct {
	GadgetCiphertextProtocol
	eval *rlwe.Evaluator
	buff *rlwe.Plaintext
}

// NewCircularCiphertextProtocol creates an [mhe.CircularCiphertextProtocol] instance.
func NewCircularCiphertextProtocol(params rlwe.ParameterProvider) *CircularCiphertextProtocol {
	p := *params.GetRLWEParameters()
	return &CircularCiphertextProtocol{
		GadgetCiphertextProtocol: *NewGadgetCiphertextProtocol(params),
		eval:                     rlwe.NewEvaluator(params, nil),
		buff:                     rlwe.NewPlaintext(p, p.MaxLevelQ(), p.MaxLevelP()),
	}
}

// ShallowCopy creates a shallow copy of the receiver in which all the read-only data-structures are
// shared with the receiver and the temporary buffers are reallocated. The receiver and the returned
// object can be used concurrently.
func (p CircularCiphertextProtocol) ShallowCopy() *CircularCiphertextProtocol {
	return &CircularCiphertextProtocol{
		GadgetCiphertextProtocol: *p.GadgetCiphertextProtocol.ShallowCopy(),
		eval:                     p.eval.ShallowCopy(),
		buff:                     p.buff.Clone(),
	}
}

// GenEphemeralSecret generates the ephemeral secret and its associated public share.
// This ephemeral secret can be reused across multiple calls of the main protocol.
func (p CircularCiphertextProtocol) GenEphemeralSecret(sk *rlwe.SecretKey, seed [32]byte, DDGRLWE rlwe.DigitDecomposition) (u *rlwe.SecretKey, share *GadgetCiphertextShare, err error) {

	params := p.GetRLWEParameters()

	share = &GadgetCiphertextShare{
		Seed:             seed,
		GadgetCiphertext: *rlwe.NewGadgetCiphertext(params, 0, params.MaxLevelQ(), params.MaxLevelP(), DDGRLWE),
	}

	// u
	u = rlwe.NewKeyGenerator(params).GenSecretKeyNew()

	// GRLWE_{bi,s}(-u) mod [QP][P']
	rQ := p.GetRLWEParameters().RingQ()
	rQ.AtLevel(share.LevelQ()).Neg(u.ConcatPtoQ(u.LevelP()+1).Q, p.buff.Q)
	rQ.Reduce(p.buff.Q, p.buff.Q)
	p.buff.MetaData = &u.MetaData
	return u, share, p.GadgetCiphertextProtocol.Gen(sk, p.buff, seed, share)
}

// Gen populates the [mhe.CircularCiphertextShare] with the public aggregatable transcript (PAT).
func (p CircularCiphertextProtocol) Gen(sk, u *rlwe.SecretKey, pt *rlwe.Plaintext, seed [32]byte, share *CircularCiphertextShare) (err error) {

	// RLWE_{a,u}(m)
	if err = p.WithKey(u).WithSeededPublicRandomness(seed).Encrypt(pt, &share.RLWE1); err != nil {
		return
	}

	// RLWE_{a,s}(0)
	if err = p.WithKey(sk).WithSeededPublicRandomness(seed).EncryptZero(&share.RLWE2); err != nil {
		return
	}

	share.Seed = seed

	return nil
}

// Aggregate aggregates the public aggregatable transcripts: share3 = share1 + share2.
func (p CircularCiphertextProtocol) Aggregate(share1, share2, share3 *CircularCiphertextShare) (err error) {

	if share1.Seed != share2.Seed {
		return fmt.Errorf("share1.Seed != share2.Seed")
	}

	share3.Seed = share1.Seed

	rQ := p.GetRLWEParameters().RingQ().AtLevel(share1.RLWE1.LevelQ())

	// RLWE_{u_{0}}(m_{0}) + RLWE_{u_{1}}(m_{1})
	rQ.Add(share1.RLWE1.Q[0], share2.RLWE1.Q[0], share3.RLWE1.Q[0])

	// RLWE_{s_{0}}(0) + RLWE_{s_{1}}(0)
	rQ.Add(share1.RLWE2.Q[0], share2.RLWE2.Q[0], share3.RLWE2.Q[0])

	return
}

// Finalize takes the public aggregated transcripts (share and ctu) and populates ctMS with RLWE_{s}(ms).
func (p CircularCiphertextProtocol) Finalize(share *CircularCiphertextShare, ctU *rlwe.GadgetCiphertext, ctMS *rlwe.Ciphertext) (err error) {
	// RLWE_{s}(0) x GRLWE_{s}(-u) + (0, RLWE_{u}(m)[0])
	return p.finalize(&share.RLWE1, &share.RLWE2, ctU, ctMS)
}

func (p CircularCiphertextProtocol) finalize(RLWE1, RLWE2 *rlwe.Ciphertext, ctU *rlwe.GadgetCiphertext, ctMS *rlwe.Ciphertext) (err error) {
	// RLWE_{s}(0) x GRLWE_{s}(-u) + (0, RLWE_{u}(m)[0])
	LevelQ := ctU.LevelQ()
	p.eval.GadgetProduct(LevelQ, RLWE2.Q[0], RLWE2.IsNTT, ctU, ctMS)
	p.GetRLWEParameters().RingQ().AtLevel(LevelQ).Add(ctMS.Q[1], RLWE1.Q[0], ctMS.Q[1])
	return
}

// CircularCiphertextShare is represent a Party's share in the [mhe.CircularCiphertextProtocol].
type CircularCiphertextShare struct {
	Seed  [32]byte
	RLWE1 rlwe.Ciphertext // RLWE_{u}(m)[SeedRLWE]
	RLWE2 rlwe.Ciphertext // RLWE_{s}(0)[SeedRLWE]
}

// Allocate allocates a party's share in the [mhe.CircularCiphertextProtocol].
func (p CircularCiphertextProtocol) Allocate() *CircularCiphertextShare {
	params := *p.GetRLWEParameters()
	return &CircularCiphertextShare{
		RLWE1: *rlwe.NewCiphertext(params, 0, params.MaxLevelQ(), -1),
		RLWE2: *rlwe.NewCiphertext(params, 0, params.MaxLevelQ(), -1),
	}
}

// Equal performs a deep equal between the receiver and the operand.
func (share CircularCiphertextShare) Equal(other *CircularCiphertextShare) bool {
	return share.Seed == other.Seed && share.RLWE1.Equal(&other.RLWE1) && share.RLWE2.Equal(&other.RLWE2)
}

// BinarySize returns the serialized size of the object in bytes.
func (share CircularCiphertextShare) BinarySize() int {
	return 32 + share.RLWE1.BinarySize() + share.RLWE2.BinarySize()
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
func (share CircularCiphertextShare) WriteTo(w io.Writer) (n int64, err error) {
	switch w := w.(type) {
	case buffer.Writer:
		var inc int64

		if inc, err = buffer.Write(w, share.Seed[:]); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = share.RLWE1.WriteTo(w); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = share.RLWE2.WriteTo(w); err != nil {
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
func (share *CircularCiphertextShare) ReadFrom(r io.Reader) (n int64, err error) {
	switch r := r.(type) {
	case buffer.Reader:

		var inc int64

		if inc, err = buffer.Read(r, share.Seed[:]); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = share.RLWE1.ReadFrom(r); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = share.RLWE2.ReadFrom(r); err != nil {
			return n + inc, err
		}

		n += inc

		return n, err

	default:
		return share.ReadFrom(bufio.NewReader(r))
	}
}

// MarshalBinary encodes the object into a binary form on a newly allocated slice of bytes.
func (share CircularCiphertextShare) MarshalBinary() (p []byte, err error) {
	buf := buffer.NewBufferSize(share.BinarySize())
	_, err = share.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary decodes a slice of bytes generated by
// MarshalBinary or WriteTo on the object.
func (share *CircularCiphertextShare) UnmarshalBinary(p []byte) (err error) {
	_, err = share.ReadFrom(buffer.NewBuffer(p))
	return
}
