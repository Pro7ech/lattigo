package heint

import (
	"fmt"
	"math/big"

	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils"
)

type Integer interface {
	int64 | uint64
}

// IntegerSlice is an empty interface whose goal is to
// indicate that the expected input should be []Integer.
// See Integer for information on the type constraint.
type IntegerSlice interface {
}

// GaloisGen is an integer of order N=2^d modulo M=2N and that spans Z_M with the integer -1.
// The j-th ring automorphism takes the root zeta to zeta^(5j).
const GaloisGen uint64 = ring.GaloisGen

// Encoder is a structure that stores the parameters to encode values on a plaintext in a SIMD (Single-Instruction Multiple-Data) fashion.
type Encoder struct {
	parameters Parameters

	indexMatrix []uint64

	bufQ ring.RNSPoly
	bufT []uint64
	bufB []big.Int

	paramsQP []ring.ModUpConstants
	qHalf    []*big.Int

	tInvModQ []*big.Int
}

// NewEncoder creates a new Encoder from the provided parameters.
func NewEncoder(parameters Parameters) *Encoder {

	rQ := parameters.RingQ()
	rT := parameters.RT

	paramsQP := make([]ring.ModUpConstants, rQ.ModuliChainLength())

	qHalf := make([]*big.Int, rQ.ModuliChainLength())

	moduli := rQ.ModuliChain()
	T := rT.Modulus
	tInvModQ := make([]*big.Int, rQ.ModuliChainLength())
	TBig := new(big.Int).SetUint64(T)

	tInvModQ[0] = new(big.Int).ModInverse(TBig, rQ.AtLevel(0).Modulus())

	for i := 1; i < len(moduli); i++ {
		Q := rQ.AtLevel(i).Modulus()
		paramsQP[i] = rQ.AtLevel(i).ModUpConstants(ring.RNSRing([]*ring.Ring{rT}))
		qHalf[i] = new(big.Int).Set(Q)
		qHalf[i].Rsh(qHalf[i], 1)
		tInvModQ[i] = new(big.Int).ModInverse(TBig, Q)
	}

	var bufB []big.Int
	if parameters.LogMaxDimensions().Cols < parameters.LogN()-1 {
		bufB = make([]big.Int, parameters.MaxSlots())
	}

	return &Encoder{
		parameters:  parameters,
		indexMatrix: permuteMatrix(parameters.LogMaxSlots()),
		bufQ:        rQ.NewRNSPoly(),
		bufT:        make([]uint64, rT.N),
		bufB:        bufB,
		paramsQP:    paramsQP,
		qHalf:       qHalf,
		tInvModQ:    tInvModQ,
	}
}

func permuteMatrix(logN int) (perm []uint64) {

	var N, pow, pos uint64 = uint64(1 << logN), 1, 0

	mask := 2*N - 1

	perm = make([]uint64, N)

	halfN := int(N >> 1)

	for i, j := 0, halfN; i < halfN; i, j = i+1, j+1 {

		pos = utils.BitReverse64(pow>>1, logN) // = (pow-1)/2

		perm[i] = pos
		perm[j] = N - pos - 1

		pow *= GaloisGen
		pow &= mask
	}

	return perm
}

// GetRLWEParameters returns the underlying rlwe.Parameters of the target object.
func (ecd Encoder) GetRLWEParameters() *rlwe.Parameters {
	return &ecd.parameters.Parameters
}

// Encode encodes an IntegerSlice of size at most N, where N is the smallest value satisfying PlaintextModulus = 1 mod 2N,
// on a pre-allocated plaintext.
func (ecd Encoder) Encode(values IntegerSlice, pt *rlwe.Plaintext) (err error) {

	if pt.IsBatched {
		return ecd.embed(values, true, pt.MetaData, pt.Q)
	} else {

		rT := ecd.parameters.RT
		N := ecd.parameters.N()
		T := rT.Modulus
		BRC := rT.BRedConstant

		ptT := ecd.bufQ.At(0)

		var valLen int
		switch values := values.(type) {
		case []uint64:

			if len(values) > N {
				return fmt.Errorf("cannot Encode (IsBatched = false): len(values)=%d > N=%d", len(values), N)
			}

			copy(ptT, values)
			valLen = len(values)
		case []int64:

			if len(values) > N {
				return fmt.Errorf("cannot Encode (IsBatched = false): len(values)=%d > N=%d", len(values), N)
			}

			var sign, abs uint64
			for i, c := range values {
				sign = uint64(c) >> 63
				abs = ring.BRedAdd(uint64(c*((int64(sign)^1)-int64(sign))), T, BRC)
				ptT[i] = sign*(T-abs) | (sign^1)*abs
			}

			valLen = len(values)
		}

		for i := valLen; i < N; i++ {
			ptT[i] = 0
		}

		rT.MulScalar(ptT, pt.Scale.Uint64(), ptT)
		ecd.RingT2Q(pt.Level(), true, ptT, pt.Q)

		if pt.IsNTT {
			ecd.parameters.RingQ().AtLevel(pt.Level()).NTT(pt.Q, pt.Q)
		}

		return
	}
}

// EncodeRingT encodes an IntegerSlice at the given scale on a polynomial pT with coefficients modulo the plaintext modulus.
func (ecd Encoder) EncodeRingT(values IntegerSlice, scale rlwe.Scale, pT []uint64) (err error) {
	perm := ecd.indexMatrix

	rT := ecd.parameters.RT

	slots := len(pT)

	var valLen int
	switch values := values.(type) {
	case []uint64:

		if len(values) > slots {
			return fmt.Errorf("cannot Encode (IsBatched = true): len(values)=%d > slots=%d", len(values), slots)
		}

		for i, c := range values {
			pT[perm[i]] = c
		}

		rT.Reduce(pT, pT)

		valLen = len(values)

	case []int64:

		if len(values) > slots {
			return fmt.Errorf("cannot Encode (IsBatched = true): len(values)=%d > slots=%d", len(values), slots)
		}

		T := rT.Modulus
		BRC := rT.BRedConstant

		var sign, abs uint64
		for i, c := range values {
			sign = uint64(c) >> 63
			abs = ring.BRedAdd(uint64(c*((int64(sign)^1)-int64(sign))), T, BRC)
			pT[perm[i]] = sign*(T-abs) | (sign^1)*abs
		}

		valLen = len(values)
	default:
		return fmt.Errorf("values.(type) must be either []uint64 or []int64 but is %T", values)
	}

	// Zeroes the non-mapped coefficients
	N := len(ecd.indexMatrix)
	for i := valLen; i < N; i++ {
		pT[perm[i]] = 0
	}

	// INTT on the Y = X^{N/n}
	rT.INTT(pT, pT)
	rT.MulScalar(pT, scale.Uint64(), pT)

	return nil
}

// Embed is a generic method to encode an IntegerSlice on ring.Point or ring.RNSPoly.
// Accepted polyOut.(type) are a ring.Point and ring.RNSPoly.
func (ecd Encoder) Embed(values interface{}, metadata *rlwe.MetaData, polyOut interface{}) (err error) {
	return ecd.embed(values, false, metadata, polyOut)
}

// embed is a generic method to encode an IntegerSlice on ring.Point or *ring.RNSPoly.
// If scaleUp is true, then the values will to be multiplied by PlaintextModulus^{-1} mod Q after being encoded on the polynomial.
// Encoding is done according to the metadata.
// Accepted polyOut.(type) are a ring.Point and *ring.RNSPoly
func (ecd Encoder) embed(values IntegerSlice, scaleUp bool, metadata *rlwe.MetaData, polyOut interface{}) (err error) {
	pT := ecd.bufT

	if err = ecd.EncodeRingT(values, metadata.Scale, pT); err != nil {
		return
	}

	// Maps Y = X^{N/n} -> X and quantizes.
	switch p := polyOut.(type) {
	case ring.Point:

		levelQ := p.Q.Level()

		ecd.RingT2Q(levelQ, scaleUp, pT, p.Q)

		rQ := ecd.parameters.RingQ().AtLevel(levelQ)

		if metadata.IsNTT {
			rQ.NTT(p.Q, p.Q)
		}

		if metadata.IsMontgomery {
			rQ.MForm(p.Q, p.Q)
		}

		if p.P.Level() > -1 {

			levelP := p.P.Level()

			ecd.RingT2Q(levelP, scaleUp, pT, p.P)

			ringP := ecd.parameters.RingP().AtLevel(levelP)

			if metadata.IsNTT {
				ringP.NTT(p.P, p.P)
			}

			if metadata.IsMontgomery {
				ringP.MForm(p.P, p.P)
			}
		}

	case ring.RNSPoly:

		level := p.Level()

		ecd.RingT2Q(level, scaleUp, pT, p)

		rQ := ecd.parameters.RingQ().AtLevel(level)

		if metadata.IsNTT {
			rQ.NTT(p, p)
		}

		if metadata.IsMontgomery {
			rQ.MForm(p, p)
		}

	default:
		return fmt.Errorf("cannot embed: invalid polyOut.(Type) must be ring.Point or *ring.RNSPoly")
	}

	return
}

// DecodeRingT decodes a polynomial pT with coefficients modulo the plaintext modulus on an InterSlice at the given scale.
func (ecd Encoder) DecodeRingT(pT []uint64, scale rlwe.Scale, values IntegerSlice) (err error) {

	rT := ecd.parameters.RT
	rT.MulScalar(pT, ring.ModExp(scale.Uint64(), rT.Phi()-1, rT.Modulus), ecd.bufT)
	pT = ecd.bufT
	rT.NTT(pT, pT)

	switch values := values.(type) {
	case []uint64:
		for i := range values {
			values[i] = pT[ecd.indexMatrix[i]]
		}
	case []int64:
		modulus := int64(ecd.parameters.PlaintextModulus())
		modulusHalf := modulus >> 1
		var value int64
		for i := range values {
			if value = int64(pT[ecd.indexMatrix[i]]); value >= modulusHalf {
				values[i] = value - modulus
			} else {
				values[i] = value
			}
		}
	default:
		return fmt.Errorf("cannot DecodeRingT: values must be either []uint64 or []int64 but is %T", values)
	}

	return
}

// RingT2Q takes pT in base PlaintextModulus and writes it in base Q[level] on pQ.
// If scaleUp is true, multiplies the values of pQ by PlaintextModulus^{-1} mod Q[level].
func (ecd Encoder) RingT2Q(level int, scaleUp bool, pT []uint64, pQ ring.RNSPoly) {

	N := pQ.N()
	n := len(pT)

	gap := N / n

	for i := 0; i < level+1; i++ {

		coeffs := pQ.At(i)

		copy(coeffs, pT)

		if gap > 1 {

			for j := n; j < N; j++ {
				coeffs[j] = 0
			}

			for j := n - 1; j > 0; j-- {
				coeffs[j*gap] = coeffs[j]
				coeffs[j] = 0
			}
		}
	}

	if scaleUp {
		ecd.parameters.RingQ().AtLevel(level).MulScalarBigint(pQ, ecd.tInvModQ[level], pQ)
	}
}

// RingQ2T takes pQ in base Q[level] and writes it in base PlaintextModulus on pT.
// If scaleUp is true, the values of pQ are multiplied by PlaintextModulus mod Q[level]
// before being converted into the base PlaintextModulus.
func (ecd Encoder) RingQ2T(level int, scaleDown bool, pQ ring.RNSPoly, pT []uint64) {

	rQ := ecd.parameters.RingQ().AtLevel(level)
	rT := ecd.parameters.RT

	var poly ring.RNSPoly
	if scaleDown {
		rQ.MulScalar(pQ, ecd.parameters.PlaintextModulus(), ecd.bufQ)
		poly = ecd.bufQ
	} else {
		poly = pQ
	}

	gap := pQ.N() / len(pT)

	if level > 0 {

		if gap == 1 {
			rQ.AddScalarBigint(poly, ecd.qHalf[level], ecd.bufQ)
			ring.ReconstructModP(ecd.bufQ[:level+1], pT, rQ, rT, ecd.paramsQP[level])
			rT.SubScalarBigint(pT, ecd.qHalf[level], pT)
		} else {
			rQ.PolyToBigintCentered(poly, gap, ecd.bufB)
			rT.SetCoefficientsBigint(ecd.bufB, pT)
		}

	} else {

		if gap == 1 {
			rQ.AddScalar(poly, rQ[0].Modulus>>1, ecd.bufQ)
			rT.Reduce(ecd.bufQ.At(0), pT)
		} else {

			n := len(pT)

			pQCoeffs := poly.At(0)
			bufQCoeffs := ecd.bufQ.At(0)

			for i := 0; i < n; i++ {
				bufQCoeffs[i] = pQCoeffs[i*gap]
			}

			rQ[0].AddScalar(bufQCoeffs[:n], rQ[0].Modulus>>1, bufQCoeffs[:n])
			rT.Reduce(bufQCoeffs[:n], pT)
		}

		rT.SubScalar(pT, ring.BRedAdd(rQ[0].Modulus>>1, rT.Modulus, rT.BRedConstant), pT)
	}
}

// Decode decodes a plaintext on an IntegerSlice mod PlaintextModulus of size at most N, where N is the smallest value satisfying PlaintextModulus = 1 mod 2N.
func (ecd Encoder) Decode(pt *rlwe.Plaintext, values IntegerSlice) (err error) {

	if pt.IsBatched {

		pT := ecd.bufT

		if pt.IsNTT {
			ecd.parameters.RingQ().AtLevel(pt.Level()).INTT(pt.Q, ecd.bufQ)
			ecd.RingQ2T(pt.Level(), true, ecd.bufQ, pT)
		} else {
			ecd.RingQ2T(pt.Level(), true, pt.Q, pT)
		}

		return ecd.DecodeRingT(pT, pt.Scale, values)
	} else {

		pT := ecd.bufQ.At(0)

		if pt.IsNTT {
			ecd.parameters.RingQ().AtLevel(pt.Level()).INTT(pt.Q, ecd.bufQ)
			ecd.RingQ2T(pt.Level(), true, ecd.bufQ, pT)
		} else {
			ecd.RingQ2T(pt.Level(), true, pt.Q, pT)
		}

		rT := ecd.parameters.RT
		rT.MulScalar(pT, ring.ModExp(pt.Scale.Uint64(), rT.Phi()-1, rT.Modulus), pT)

		switch values := values.(type) {
		case []uint64:
			copy(values, pT)
		case []int64:

			rT := ecd.parameters.RT
			N := ecd.parameters.N()
			modulus := int64(rT.Modulus)
			modulusHalf := modulus >> 1

			var value int64
			for i := 0; i < N; i++ {
				if value = int64(pT[i]); value >= modulusHalf {
					values[i] = value - modulus
				} else {
					values[i] = value
				}
			}

		default:
			return fmt.Errorf("cannot Decode: values must be either []uint64 or []int64 but is %T", values)
		}

		return
	}
}

// ShallowCopy returns a lightweight copy of the target object
// that can be used concurrently with the original object.
func (ecd Encoder) ShallowCopy() *Encoder {

	var bufB []big.Int
	if ecd.parameters.LogMaxDimensions().Cols < ecd.parameters.LogN()-1 {
		bufB = make([]big.Int, ecd.parameters.MaxSlots())
	}

	return &Encoder{
		parameters:  ecd.parameters,
		indexMatrix: ecd.indexMatrix,
		bufQ:        ecd.parameters.RingQ().NewRNSPoly(),
		bufT:        make([]uint64, ecd.parameters.RT.N),
		bufB:        bufB,
		paramsQP:    ecd.paramsQP,
		qHalf:       ecd.qHalf,
		tInvModQ:    ecd.tInvModQ,
	}
}
