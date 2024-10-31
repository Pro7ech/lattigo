package mhe

import (
	"bufio"
	"fmt"
	"io"
	"slices"

	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/buffer"
)

// CircularGadgetCiphertextProtocol is a non-interactive public aggregatable
// transcripts (PAT) protocol by which a set of parties, each holding a secret
// sk_{i} and a message m_{i}, can collectively  generate in a single round the
// encryption GRLWE_{sk}(m*sk)  where sk = sum sk_{i} and m = sum m_{i}.
// An GRLWE is an [rlwe.GadgetCiphertext].
type CircularGadgetCiphertextProtocol struct {
	params rlwe.Parameters
	CircularCiphertextProtocol
}

// NewCircularGadgetCiphertextProtocol creates an [mhe.CircularGadgetCiphertextProtocol] instance.
func NewCircularGadgetCiphertextProtocol(params rlwe.ParameterProvider, LogP int) *CircularGadgetCiphertextProtocol {

	p := *params.GetRLWEParameters()

	paramsConcatQPLit := rlwe.ParametersLiteral{
		LogN:     p.LogN(),
		Q:        slices.Concat(p.Q(), p.P()),
		NTTFlag:  p.NTTFlag(),
		RingType: p.RingType(),
	}

	if LogP > 0 {
		paramsConcatQPLit.LogP = []int{LogP}
	}

	var paramsConcatQP rlwe.Parameters
	var err error
	if paramsConcatQP, err = rlwe.NewParametersFromLiteral(paramsConcatQPLit); err != nil {
		panic(err)
	}

	return &CircularGadgetCiphertextProtocol{
		params:                     p,
		CircularCiphertextProtocol: *NewCircularCiphertextProtocol(paramsConcatQP),
	}
}

// ShallowCopy creates a shallow copy of the receiver in which all the read-only data-structures are
// shared with the receiver and the temporary buffers are reallocated. The receiver and the returned
// object can be used concurrently.
func (p CircularGadgetCiphertextProtocol) ShallowCopy() *CircularGadgetCiphertextProtocol {
	return &CircularGadgetCiphertextProtocol{
		params:                     p.params,
		CircularCiphertextProtocol: *p.CircularCiphertextProtocol.ShallowCopy(),
	}
}

// GenEphemeralSecret generates the ephemeral secret and its associated public share.
// This ephemeral secret can be reused across multiple calls of the main protocol.
func (p CircularGadgetCiphertextProtocol) GenEphemeralSecret(sk *rlwe.SecretKey, seed [32]byte, DDGRLWE rlwe.DigitDecomposition) (u *rlwe.SecretKey, share *GadgetCiphertextShare, err error) {

	params := p.GetRLWEParameters()

	share = &GadgetCiphertextShare{
		Seed:             seed,
		GadgetCiphertext: *rlwe.NewGadgetCiphertext(params, 0, params.MaxLevelQ(), params.MaxLevelP(), DDGRLWE),
	}

	// u
	u = rlwe.NewKeyGenerator(p.params).GenSecretKeyNew()

	// GRLWE_{bi,s}(-u) mod [QP][P']
	rQ := p.GetRLWEParameters().RingQ()
	rQ.AtLevel(share.LevelQ()).Neg(u.ConcatPtoQ(u.LevelP()+1).Q, p.buff.Q)
	rQ.Reduce(p.buff.Q, p.buff.Q)
	p.buff.MetaData = &u.MetaData

	return u, share, p.GadgetCiphertextProtocol.Gen(p.getExtendedKey(sk), p.buff, seed, share)
}

// Gen populates the [mhe.CircularGadgetCiphertextShare] with the public aggregatable transcript (PAT).
func (p CircularGadgetCiphertextProtocol) Gen(sk, u *rlwe.SecretKey, pt *rlwe.Plaintext, seed [32]byte, share *CircularGadgetCiphertextShare) (err error) {

	enc := rlwe.NewEncryptor(p.params, nil)

	// GRLWE_{ai,u}(m) mod [Q][P]
	if err = enc.WithKey(u).WithSeededPublicRandomness(seed).Encrypt(pt, &share.GRLWE1); err != nil {
		return
	}

	// GRLWE_{ai,s}(0) mod [Q][P]
	if err = enc.WithKey(sk).WithSeededPublicRandomness(seed).EncryptZero(&share.GRLWE2); err != nil {
		return
	}

	share.Seed = seed

	return
}

func (p CircularGadgetCiphertextProtocol) getExtendedKey(skQP *rlwe.SecretKey) (skQPP *rlwe.SecretKey) {

	rQ := p.CircularCiphertextProtocol.GetRLWEParameters().RingQ()
	rP := p.CircularCiphertextProtocol.GetRLWEParameters().RingP()

	skQPP = &rlwe.SecretKey{}
	skQPP.Q = skQP.Point.ConcatPtoQ(skQP.LevelP() + 1).Q

	if rP != nil {
		skQPP.P = rP.NewRNSPoly()
		rQ.INTT(skQPP.Q, skQPP.Q)
		rQ.IMForm(skQPP.Q, skQPP.Q)
		ring.ExtendBasisSmallNorm(rQ[0].Modulus, rP.ModuliChain(), skQPP.Q, skQPP.P)
		rQ.NTT(skQPP.Q, skQPP.Q)
		rQ.MForm(skQPP.Q, skQPP.Q)
		rP.NTT(skQPP.P, skQPP.P)
		rP.MForm(skQPP.P, skQPP.P)
	}

	return
}

// Aggregate aggregates the public aggregatable transcripts: share3 = share1 + share2.
func (p CircularGadgetCiphertextProtocol) Aggregate(share1, share2, share3 *CircularGadgetCiphertextShare) (err error) {

	if share1.Seed != share2.Seed {
		return fmt.Errorf("shares seed do not match")
	}

	if err = share3.GRLWE1.Vector[0].Aggregate(p.params.RingQ(), p.params.RingP(), &share2.GRLWE1.Vector[0], &share1.GRLWE1.Vector[0]); err != nil {
		return
	}

	return share3.GRLWE2.Vector[0].Aggregate(p.params.RingQ(), p.params.RingP(), &share2.GRLWE2.Vector[0], &share1.GRLWE2.Vector[0])
}

// FinalizeNew takes the public aggregated transcripts (share and ctu) returns ctMS with GRLWE_{s}(ms).
func (p CircularGadgetCiphertextProtocol) FinalizeNew(share *CircularGadgetCiphertextShare, ctu *rlwe.GadgetCiphertext) (ctMS *rlwe.GadgetCiphertext, err error) {
	params := p.params
	ctMS = rlwe.NewGadgetCiphertext(params, 1, params.MaxLevelQ(), params.MaxLevelP(), share.GRLWE1.DigitDecomposition)
	return ctMS, p.Finalize(share, ctu, ctMS)
}

// Finalize takes the public aggregated transcripts (share and ctu) and populates ctMS with GRLWE_{s}(ms).
func (p CircularGadgetCiphertextProtocol) Finalize(share *CircularGadgetCiphertextShare, ctu *rlwe.GadgetCiphertext, ctMS *rlwe.GadgetCiphertext) (err error) {

	dims := share.GRLWE1.Dims()

	LevelP := share.GRLWE1.LevelP()

	rQ := p.CircularCiphertextProtocol.GetRLWEParameters().RingQ()

	for i := range dims {
		for j := range dims[i] {

			RLWE1 := share.GRLWE1.At(i, j).ConcatPtoQ(LevelP + 1) // [QP] <- [Q][P]
			RLWE2 := share.GRLWE2.At(i, j).ConcatPtoQ(LevelP + 1) // [QP] <- [Q][P]
			RLWEOut := ctMS.At(i, j).ConcatPtoQ(LevelP + 1)       // [QP] <- [Q][P]

			// Default domain of GRLWE ciphertexts is NTT and Montgomery domains.
			// Bug RNS/Digit decomposition are incompatible with Montgomery domain.
			rQ.IMForm(RLWE1.Q[0], RLWE1.Q[0])
			rQ.IMForm(RLWE2.Q[0], RLWE2.Q[0])

			// RLWE_{s}(0)_[QP] x GRLWE_{s}(-u)_[QP][P'] + (0, RLWE_{u}(m)[0])_[QP]
			if err = p.finalize(RLWE1, RLWE2, ctu, RLWEOut); err != nil {
				return
			}

			rQ.MForm(RLWEOut.Q[0], RLWEOut.Q[0])
			rQ.MForm(RLWEOut.Q[1], RLWEOut.Q[1])
		}
	}

	return
}

// Allocate allocates a party's share in the [mhe.CircularCiphertextProtocol].
func (p CircularGadgetCiphertextProtocol) Allocate(dd rlwe.DigitDecomposition) *CircularGadgetCiphertextShare {
	return &CircularGadgetCiphertextShare{
		GRLWE1: *rlwe.NewGadgetCiphertext(p.params, 0, p.params.MaxLevelQ(), p.params.MaxLevelP(), dd),
		GRLWE2: *rlwe.NewGadgetCiphertext(p.params, 0, p.params.MaxLevelQ(), p.params.MaxLevelP(), dd),
	}
}

// CircularGadgetCiphertextShare is represent a Party's share in the [mhe.CircularGadgetCiphertextProtocol].
type CircularGadgetCiphertextShare struct {
	Seed   [32]byte
	GRLWE1 rlwe.GadgetCiphertext // GRLWE_{a, u}(m) [QP]
	GRLWE2 rlwe.GadgetCiphertext // GRLWE_{a, s}(0) [QP]
}

// Equal performs a deep equal between the receiver and the operand.
func (share CircularGadgetCiphertextShare) Equal(other *CircularGadgetCiphertextShare) bool {
	return share.Seed == other.Seed && share.GRLWE1.Equal(&other.GRLWE1) && share.GRLWE2.Equal(&other.GRLWE2)
}

// BinarySize returns the serialized size of the object in bytes.
func (share CircularGadgetCiphertextShare) BinarySize() int {
	return 32 + share.GRLWE1.BinarySize() + share.GRLWE2.BinarySize()
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
func (share CircularGadgetCiphertextShare) WriteTo(w io.Writer) (n int64, err error) {
	switch w := w.(type) {
	case buffer.Writer:
		var inc int64

		if inc, err = buffer.Write(w, share.Seed[:]); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = share.GRLWE1.WriteTo(w); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = share.GRLWE2.WriteTo(w); err != nil {
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
func (share *CircularGadgetCiphertextShare) ReadFrom(r io.Reader) (n int64, err error) {
	switch r := r.(type) {
	case buffer.Reader:

		var inc int64

		if inc, err = buffer.Read(r, share.Seed[:]); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = share.GRLWE1.ReadFrom(r); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = share.GRLWE2.ReadFrom(r); err != nil {
			return n + inc, err
		}

		n += inc

		return n, err

	default:
		return share.ReadFrom(bufio.NewReader(r))
	}
}

// MarshalBinary encodes the object into a binary form on a newly allocated slice of bytes.
func (share CircularGadgetCiphertextShare) MarshalBinary() (p []byte, err error) {
	buf := buffer.NewBufferSize(share.BinarySize())
	_, err = share.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary decodes a slice of bytes generated by
// MarshalBinary or WriteTo on the object.
func (share *CircularGadgetCiphertextShare) UnmarshalBinary(p []byte) (err error) {
	_, err = share.ReadFrom(buffer.NewBuffer(p))
	return
}
