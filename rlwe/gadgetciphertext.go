package rlwe

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"math/big"
	"slices"

	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/utils/buffer"
	"github.com/Pro7ech/lattigo/utils/structs"
	"github.com/google/go-cmp/cmp"
)

// GadgetCiphertext is a struct for storing an encrypted
// plaintext times the gadget power matrix.
type GadgetCiphertext struct {
	*CompressionInfos
	DigitDecomposition
	structs.Vector[ring.Matrix]
	CoalescingFactor   int
	CoalescingConstant ring.RNSScalar
}

// NewGadgetCiphertext returns a new Ciphertext key with pre-allocated zero-value.
// Ciphertext is always in the NTT domain.
// A GadgetCiphertext is created by default at degree 1 with the the maximum LevelQ and LevelP and with no base 2 decomposition.
// Give the optional GadgetCiphertextParameters struct to create a GadgetCiphertext with at a specific degree, LevelQ, LevelP and/or base 2 decomposition.
func NewGadgetCiphertext(params ParameterProvider, Degree, LevelQ, LevelP int, DD DigitDecomposition) (ct *GadgetCiphertext) {
	ct = new(GadgetCiphertext)
	ct.FromBuffer(params, Degree, LevelQ, LevelP, DD, make([]uint64, ct.BufferSize(params, Degree, LevelQ, LevelP, DD)))
	return
}

// BufferSize returns the minimum buffer size
// to instantiate the receiver through [FromBuffer].
func (ct *GadgetCiphertext) BufferSize(params ParameterProvider, Degree, LevelQ, LevelP int, DD DigitDecomposition) (size int) {
	if LevelP > 0 {
		DD = DigitDecomposition{}
	}
	p := params.GetRLWEParameters()
	dims := p.DecompositionMatrixDimensions(LevelQ, LevelP, DD)
	return new(ring.Matrix).BufferSize(p.N(), LevelQ, LevelP, dims) * (Degree + 1)
}

// FromBuffer assigns new backing array to the receiver.
// Method panics if len(buf) is too small.
// Minimum backing array size can be obtained with [BufferSize].
func (ct *GadgetCiphertext) FromBuffer(params ParameterProvider, Degree, LevelQ, LevelP int, DD DigitDecomposition, buf []uint64) {

	if size := ct.BufferSize(params, Degree, LevelQ, LevelP, DD); len(buf) < size {
		panic(fmt.Errorf("invalid buffer size: len(buf)=%d < %d ", len(buf), size))
	}

	p := params.GetRLWEParameters()

	if LevelP > 0 {
		DD = DigitDecomposition{}
	}

	dims := p.DecompositionMatrixDimensions(LevelQ, LevelP, DD)

	var ptr int
	ct.Vector = make([]ring.Matrix, Degree+1)
	for i := range Degree + 1 {
		ct.Vector[i].FromBuffer(p.N(), LevelQ, LevelP, dims, buf[ptr:])
		ptr += ct.Vector[i].BufferSize(p.N(), LevelQ, LevelP, dims)
	}

	ct.DigitDecomposition = DD
}

// LogN returns the base 2 logarithm of the ring dimension of the receiver.
func (ct *GadgetCiphertext) LogN() int {
	return ct.Vector[0].LogN()
}

// Degree returns the degree of the receiver.
func (ct *GadgetCiphertext) Degree() int {
	return len(ct.Vector) - 1
}

// LevelQ returns the level of the modulus Q of the receiver.
func (ct *GadgetCiphertext) LevelQ() int {
	return ct.Vector[0].LevelQ()
}

// LevelP returns the level of the modulus P of the receiver.
func (ct *GadgetCiphertext) LevelP() int {
	return ct.Vector[0].LevelP()
}

// DropGadget returns an instance of the recceiver where n rows of
// the RNS gadget matrix are dropped.
// The method will panic if n > ct.Dims().
func (ct *GadgetCiphertext) DropGadget(n int) *GadgetCiphertext {
	dims := len(ct.Dims())
	if n > dims {
		panic(fmt.Errorf("cannot DropGadget: n > ct.Dims()"))
	}
	return &GadgetCiphertext{
		DigitDecomposition: ct.DigitDecomposition,
		Vector: structs.Vector[ring.Matrix]{
			ring.Matrix{Q: ct.Vector[0].Q[:dims-n], P: ct.Vector[0].P[:dims-n]},
			ring.Matrix{Q: ct.Vector[1].Q[:dims-n], P: ct.Vector[1].P[:dims-n]},
		},
	}
}

// ConcatPtoQ returns an instance of the receiver where the modulus Q
// is increased to Q[:] + P[:n] and the modulus P reduced to P[n:].
// n must be a positive integer 0 <= n <= ct.LevelP()+1.
func (ct *GadgetCiphertext) ConcatPtoQ(n int) *GadgetCiphertext {
	return &GadgetCiphertext{
		DigitDecomposition: ct.DigitDecomposition,
		Vector:             structs.Vector[ring.Matrix]{*ct.Vector[0].ConcatPtoQ(n), *ct.Vector[1].ConcatPtoQ(n)},
	}
}

// ConcatQtoP returns an instance of the receiver where the modulus Q
// is reduced to Q[:n] and the modulus P increased to Q[n:] + P[:].
// n must be a positive integer 0 <= n < ct.LevelQ()+1.
func (ct *GadgetCiphertext) ConcatQtoP(n int) *GadgetCiphertext {
	return &GadgetCiphertext{
		DigitDecomposition: ct.DigitDecomposition,
		Vector:             structs.Vector[ring.Matrix]{*ct.Vector[0].ConcatQtoP(n), *ct.Vector[1].ConcatQtoP(n)},
	}
}

// At returns the [rlwe.Ciphertext] at position [i][j] in the receiver.
func (ct *GadgetCiphertext) At(i, j int) (el *Ciphertext) {
	el = &Ciphertext{}
	el.Vector = &ring.Vector{}
	el.MetaData = &MetaData{}
	el.IsNTT = true
	el.IsMontgomery = true

	if ct.Degree() == 0 {
		el.Q = []ring.RNSPoly{ct.Vector[0].Q[i][j]}

		if ct.LevelP() > -1 {
			el.P = []ring.RNSPoly{ct.Vector[0].P[i][j]}
		}
	} else {
		el.Q = []ring.RNSPoly{ct.Vector[0].Q[i][j], ct.Vector[1].Q[i][j]}

		if ct.LevelP() > -1 {
			el.P = []ring.RNSPoly{ct.Vector[0].P[i][j], ct.Vector[1].P[i][j]}
		}
	}

	return
}

// Dims returns the dimension of the receiver.
func (ct *GadgetCiphertext) Dims() (dims []int) {
	return ct.Vector[0].Dims()
}

// Equal checks two Ciphertexts for equality.
func (ct *GadgetCiphertext) Equal(other *GadgetCiphertext) bool {
	return (ct.DigitDecomposition == other.DigitDecomposition) && cmp.Equal(ct.Vector, other.Vector)
}

// Clone creates a deep copy of the receiver Ciphertext and returns it.
func (ct *GadgetCiphertext) Clone() (ctCopy *GadgetCiphertext) {
	return &GadgetCiphertext{DigitDecomposition: ct.DigitDecomposition, Vector: ct.Vector.Clone()}
}

// OptimalCoalescingFactor finds the optimal coalescing parameter for the given parameters.
func (ct *GadgetCiphertext) OptimalCoalescingFactor(LevelQ int) (coalescing int) {

	if ct.DigitDecomposition.Type != 0 || ct.LevelP() == -1 {
		return
	}

	return optimalCoalescingFactor(ct.LogN(), LevelQ, ct.LevelQ(), ct.LevelP())
}

func optimalCoalescingFactor(LogN, LevelQ, cLevelQ, cLevelP int) (coalescing int) {

	// Heuristically, we find the optimal coalescing parameters by
	// estimating the cost of coalescing + gadget product.
	QCount := LevelQ + 1
	cQCount := cLevelQ + 1
	cPCount := cLevelP + 1

	var alpha int // number of P
	var beta int  // ceil((LevelQ+1)/alpha)
	var k int
	var cost int = math.MaxInt

	for {

		alpha = (k + 1) * cPCount
		beta = (QCount + alpha - 1) / alpha

		if QCount > cQCount-cQCount%cPCount-alpha {
			break
		}

		// Omits the N factor
		totalCost := k * ((QCount + cPCount - 1) / cPCount) * (QCount + cPCount)                          // Coalescing cost
		totalCost += QCount*(LogN*(3+beta)+beta*(alpha+2)+2*alpha+6) + alpha*(2*LogN+2+3*beta) - 4*QCount // https://eprint.iacr.org/2020/1203 appendix C.1

		if totalCost < cost {
			coalescing = k
			cost = totalCost
		}

		k++
	}

	return
}

// Coalesce coalesces the receiver on the buffer.
// Assumes GadgetP divides GadgetP.
func (ct *GadgetCiphertext) Coalesce(params ParameterProvider, LevelQ, coalescing int, buf []uint64) (coalesced *GadgetCiphertext) {

	// We think in counts, not levels, for simplicity.
	LevelP := ct.LevelP()

	if ct.LevelP() == -1 {
		panic(fmt.Errorf("cannot Coalesce if #P=0"))
	}

	// Adjust GadgetQCount to be a multiple of GadgetPCount.
	GadgetQCount := ct.LevelQ() + 1
	GadgetQCount -= GadgetQCount % (LevelP + 1)

	p := params.GetRLWEParameters()

	rQ := p.RingQ()
	rP := p.RingP()

	cQCount := coalescing * (LevelP + 1)
	cPCount := cQCount + LevelP + 1

	dims := len(p.DecompositionMatrixDimensions(LevelQ, cPCount-1, DigitDecomposition{}))

	coalesced = new(GadgetCiphertext)
	coalesced.FromBuffer(params, 1, LevelQ+cQCount, LevelP, ct.DigitDecomposition, buf)

	for i := range dims {

		start := i * (coalescing + 1)
		end := min((i+1)*(coalescing+1), (GadgetQCount/(LevelP+1))-coalescing)

		for k := 0; k < LevelQ+1; k++ {
			copy(coalesced.Vector[0].Q[i][0][k], ct.Vector[0].Q[start][0][k])
			copy(coalesced.Vector[1].Q[i][0][k], ct.Vector[1].Q[start][0][k])
		}

		for k0, k1 := LevelQ+1, GadgetQCount-cQCount; k1 < GadgetQCount; k0, k1 = k0+1, k1+1 {
			copy(coalesced.Vector[0].Q[i][0][k0], ct.Vector[0].Q[start][0][k1])
			copy(coalesced.Vector[1].Q[i][0][k0], ct.Vector[1].Q[start][0][k1])
		}

		for k := 0; k < LevelP+1; k++ {
			copy(coalesced.Vector[0].P[i][0][k], ct.Vector[0].P[start][0][k])
			copy(coalesced.Vector[1].P[i][0][k], ct.Vector[1].P[start][0][k])
		}

		for j := start + 1; j < end; j++ {

			for k := 0; k < LevelQ+1; k++ {
				rQ[k].Add(coalesced.Vector[0].Q[i][0][k], ct.Vector[0].Q[j][0][k], coalesced.Vector[0].Q[i][0][k])
				rQ[k].Add(coalesced.Vector[1].Q[i][0][k], ct.Vector[1].Q[j][0][k], coalesced.Vector[1].Q[i][0][k])
			}

			for k0, k1 := LevelQ+1, GadgetQCount-cQCount; k1 < GadgetQCount; k0, k1 = k0+1, k1+1 {
				rQ[k1].Add(coalesced.Vector[0].Q[i][0][k0], ct.Vector[0].Q[j][0][k1], coalesced.Vector[0].Q[i][0][k0])
				rQ[k1].Add(coalesced.Vector[1].Q[i][0][k0], ct.Vector[1].Q[j][0][k1], coalesced.Vector[1].Q[i][0][k0])
			}

			for k := 0; k < LevelP+1; k++ {
				rP[k].Add(coalesced.Vector[0].P[i][0][k], ct.Vector[0].P[j][0][k], coalesced.Vector[0].P[i][0][k])
				rP[k].Add(coalesced.Vector[1].P[i][0][k], ct.Vector[1].P[j][0][k], coalesced.Vector[1].P[i][0][k])
			}
		}
	}

	coalesced = coalesced.DropGadget(len(coalesced.Dims()) - dims).ConcatQtoP(coalescing * (LevelP + 1))

	c := big.NewInt(int64(p.qi[GadgetQCount-cQCount]))
	for _, qi := range p.qi[GadgetQCount-cQCount+1 : GadgetQCount] {
		c.Mul(c, big.NewInt(int64(qi)))
	}

	coalesced.CoalescingConstant = rQ.AtLevel(LevelQ).NewRNSScalarFromBigint(c)
	rQ.AtLevel(LevelQ).MFormRNSScalar(coalesced.CoalescingConstant, coalesced.CoalescingConstant)

	coalesced.CoalescingFactor = coalescing

	return
}

// BinarySize returns the serialized size of the object in bytes.
func (ct *GadgetCiphertext) BinarySize() (dataLen int) {
	return 2 + ct.Vector.BinarySize()
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
func (ct *GadgetCiphertext) WriteTo(w io.Writer) (n int64, err error) {

	switch w := w.(type) {
	case buffer.Writer:

		var inc int64

		if inc, err = buffer.WriteAsUint8[DigitDecompositionType](w, ct.Type); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.WriteAsUint8[int](w, ct.Log2Basis); err != nil {
			return n + inc, err
		}

		n += inc

		inc, err = ct.Vector.WriteTo(w)

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
func (ct *GadgetCiphertext) ReadFrom(r io.Reader) (n int64, err error) {
	switch r := r.(type) {
	case buffer.Reader:

		var inc int64

		if inc, err = buffer.ReadAsUint8[DigitDecompositionType](r, &ct.Type); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.ReadAsUint8[int](r, &ct.Log2Basis); err != nil {
			return n + inc, err
		}

		n += inc

		inc, err = ct.Vector.ReadFrom(r)

		return n + inc, err

	default:
		return ct.ReadFrom(bufio.NewReader(r))
	}
}

// MarshalBinary encodes the object into a binary form on a newly allocated slice of bytes.
func (ct *GadgetCiphertext) MarshalBinary() (data []byte, err error) {
	buf := buffer.NewBufferSize(ct.BinarySize())
	_, err = ct.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary decodes a slice of bytes generated by
// MarshalBinary or WriteTo on the object.
func (ct *GadgetCiphertext) UnmarshalBinary(p []byte) (err error) {
	_, err = ct.ReadFrom(buffer.NewBuffer(p))
	return
}

// AddPlaintextToMatrix takes a plaintext polynomial and adds the plaintext times the gadget decomposition
// matrix to the matrix ct.
func AddPlaintextToMatrix(rQ, rP ring.RNSRing, pt, buff ring.RNSPoly, ct ring.Matrix, dd DigitDecomposition) (err error) {

	LevelQ := ct.LevelQ()
	LevelP := ct.LevelP()

	rQ = rQ.AtLevel(LevelQ)

	if LevelP != -1 {
		rQ.MulScalarBigint(pt, rP.AtLevel(LevelP).Modulus(), buff) // P * pt
	} else {
		LevelP = 0
		buff.CopyLvl(LevelQ, &pt) // 1 * pt
	}

	dims := ct.Dims()

	N := rQ.N()

	var index int
	for j := range slices.Max(dims) {

		for i := range dims {

			if j < dims[i] {

				// e + (m * P * w^2j) * (q_star * q_tild) mod QP
				//
				// q_prod = prod(q[i*#Pi+j])
				// q_star = Q/qprod
				// q_tild = q_star^-1 mod q_prod
				//
				// Therefore : (pt * P * w^2j) * (q_star * q_tild) = pt*P*w^2j mod q[i*#Pi+j], else 0
				for k := 0; k < LevelP+1; k++ {

					index = i*(LevelP+1) + k

					// Handle cases where #pj does not divide #qi
					if index >= LevelQ+1 {
						break
					}

					qi := rQ[index].Modulus
					p0tmp := buff.At(index)

					p1tmp := ct.Q[i][j].At(index)
					for w := 0; w < N; w++ {
						p1tmp[w] = ring.CRed(p1tmp[w]+p0tmp[w], qi)
					}
				}
			}
		}

		// w^2j
		rQ.MulScalar(buff, 1<<dd.Log2Basis, buff)
	}

	return
}

// GadgetPlaintext stores a plaintext value times the gadget vector.
type GadgetPlaintext struct {
	Value structs.Vector[ring.RNSPoly]
}

// NewGadgetPlaintext creates a new gadget plaintext from value, which can be either uint64, int64 or *ring.RNSPoly.
// Plaintext is returned in the NTT and Montgomery domain.
func NewGadgetPlaintext(p Parameters, value interface{}, LevelQ, LevelP int, dd DigitDecomposition) (pt *GadgetPlaintext, err error) {

	ringQ := p.RingQ().AtLevel(LevelQ)

	BaseTwoDecompositionVectorSize := slices.Max(p.DecompositionMatrixDimensions(LevelQ, LevelP, dd))

	pt = new(GadgetPlaintext)
	pt.Value = make([]ring.RNSPoly, BaseTwoDecompositionVectorSize)

	switch el := value.(type) {
	case uint64:
		pt.Value[0] = ringQ.NewRNSPoly()
		for i := 0; i < LevelQ+1; i++ {
			pt.Value[0].At(i)[0] = el
		}
	case int64:
		pt.Value[0] = ringQ.NewRNSPoly()
		if el < 0 {
			for i := 0; i < LevelQ+1; i++ {
				pt.Value[0].At(i)[0] = ringQ[i].Modulus - uint64(-el)
			}
		} else {
			for i := 0; i < LevelQ+1; i++ {
				pt.Value[0].At(i)[0] = uint64(el)
			}
		}
	case ring.RNSPoly:
		pt.Value[0] = *el.Clone()
	default:
		return nil, fmt.Errorf("cannot NewGadgetPlaintext: unsupported type, must be either int64, uint64 or ring.RNSPoly but is %T", el)
	}

	if LevelP > -1 {
		ringQ.MulScalarBigint(pt.Value[0], p.RingP().AtLevel(LevelP).Modulus(), pt.Value[0])
	}

	ringQ.NTT(pt.Value[0], pt.Value[0])
	ringQ.MForm(pt.Value[0], pt.Value[0])

	for i := 1; i < len(pt.Value); i++ {

		pt.Value[i] = *pt.Value[0].Clone()

		for j := 0; j < i; j++ {
			ringQ.MulScalar(pt.Value[i], 1<<dd.Log2Basis, pt.Value[i])
		}
	}

	return
}
