package rlwe

import (
	"fmt"
	"math/big"

	"github.com/Pro7ech/lattigo/ring"
)

// Trace maps X -> sum((-1)^i * X^{i*n+1}) for n <= i < N
// Monomial X^k vanishes if k is not divisible by (N/n), otherwise it is multiplied by (N/n).
// Ciphertext is pre-multiplied by (N/n)^-1 to remove the (N/n) factor.
// Examples of full Trace for [0 + 1X + 2X^2 + 3X^3 + 4X^4 + 5X^5 + 6X^6 + 7X^7]
//
// 1.
//
//	  [1 + 2X + 3X^2 + 4X^3 + 5X^4 + 6X^5 + 7X^6 + 8X^7]
//	+ [1 - 6X - 3X^2 + 8X^3 + 5X^4 + 2X^5 - 7X^6 - 4X^7]  {X-> X^(i * 5^1)}
//	= [2 - 4X + 0X^2 +12X^3 +10X^4 + 8X^5 - 0X^6 + 4X^7]
//
// 2.
//
//	  [2 - 4X + 0X^2 +12X^3 +10X^4 + 8X^5 - 0X^6 + 4X^7]
//	+ [2 + 4X + 0X^2 -12X^3 +10X^4 - 8X^5 + 0X^6 - 4X^7]  {X-> X^(i * 5^2)}
//	= [4 + 0X + 0X^2 - 0X^3 +20X^4 + 0X^5 + 0X^6 - 0X^7]
//
// 3.
//
//	  [4 + 0X + 0X^2 - 0X^3 +20X^4 + 0X^5 + 0X^6 - 0X^7]
//	+ [4 + 0X + 0X^2 - 0X^3 -20X^4 + 0X^5 + 0X^6 - 0X^7]  {X-> X^(i * -1)}
//	= [8 + 0X + 0X^2 - 0X^3 + 0X^4 + 0X^5 + 0X^6 - 0X^7]
//
// The method will return an error if the input and output ciphertexts degree is not one.
func (eval Evaluator) Trace(ctIn *Ciphertext, logN int, opOut *Ciphertext) (err error) {

	if ctIn.Degree() != 1 || opOut.Degree() != 1 {
		return fmt.Errorf("ctIn.Degree() != 1 or opOut.Degree() != 1")
	}

	params := eval.GetRLWEParameters()

	level := min(ctIn.Level(), opOut.Level())

	opOut.ResizeQ(level)

	*opOut.MetaData = *ctIn.MetaData

	gap := 1 << (params.LogN() - logN - 1)

	if logN == 0 {
		gap <<= 1
	}

	if gap > 1 {

		rQ := params.RingQ().AtLevel(level)

		if rQ.Type() == ring.ConjugateInvariant {
			gap >>= 1 // We skip the last step that applies phi(5^{-1})
		}

		NInv := new(big.Int).SetUint64(uint64(gap))
		NInv.ModInverse(NInv, rQ.Modulus())

		// pre-multiplication by (N/n)^-1
		rQ.MulScalarBigint(ctIn.Q[0], NInv, opOut.Q[0])
		rQ.MulScalarBigint(ctIn.Q[1], NInv, opOut.Q[1])

		if !ctIn.IsNTT {
			rQ.NTT(opOut.Q[0], opOut.Q[0])
			rQ.NTT(opOut.Q[1], opOut.Q[1])
			opOut.IsNTT = true
		}

		buff, err := NewCiphertextAtLevelFromPoly(level, -1, []ring.RNSPoly{eval.BuffQ[3], eval.BuffQ[4]}, nil)

		// Sanity check, this error should not happen unless the
		// evaluator's buffer thave been improperly tempered with.
		if err != nil {
			panic(err)
		}

		buff.MetaData = &MetaData{}
		buff.IsNTT = true

		for i := logN; i < params.LogN()-1; i++ {

			if err = eval.Automorphism(opOut, params.GaloisElement(1<<i), buff); err != nil {
				return err
			}

			rQ.Add(opOut.Q[0], buff.Q[0], opOut.Q[0])
			rQ.Add(opOut.Q[1], buff.Q[1], opOut.Q[1])
		}

		if logN == 0 && rQ.Type() == ring.Standard {

			if err = eval.Automorphism(opOut, rQ.NthRoot()-1, buff); err != nil {
				return err
			}

			rQ.Add(opOut.Q[0], buff.Q[0], opOut.Q[0])
			rQ.Add(opOut.Q[1], buff.Q[1], opOut.Q[1])
		}

		if !ctIn.IsNTT {
			rQ.INTT(opOut.Q[0], opOut.Q[0])
			rQ.INTT(opOut.Q[1], opOut.Q[1])
			opOut.IsNTT = false
		}

	} else {
		if ctIn != opOut {
			opOut.Copy(ctIn)
		}
	}

	return
}

// GaloisElementsForTrace returns the list of Galois elements requored for the for the `Trace` operation.
// Trace maps X -> sum((-1)^i * X^{i*n+1}) for 2^{LogN} <= i < N.
func GaloisElementsForTrace(params ParameterProvider, logN int) (galEls []uint64) {

	p := params.GetRLWEParameters()

	galEls = []uint64{}
	for i, j := logN, 0; i < p.LogN()-1; i, j = i+1, j+1 {
		galEls = append(galEls, p.GaloisElement(1<<i))
	}

	if logN == 0 {
		switch p.RingType() {
		case ring.Standard:
			galEls = append(galEls, p.GaloisElementOrderTwoOrthogonalSubgroup())
		case ring.ConjugateInvariant:
			panic("cannot GaloisElementsForTrace: Galois element GaloisGen^-1 is undefined in ConjugateInvariant Ring")
		default:
			panic("cannot GaloisElementsForTrace: invalid ring type")
		}
	}

	return
}

// InnerSum applies an optimized inner sum on the Element (log2(n) + HW(n) rotations with double hoisting).
// The operation assumes that `ctIn` encrypts Slots/`batchSize` sub-vectors of size `batchSize` and will add them together (in parallel) in groups of `n`.
// It outputs in opOut a Element for which the "leftmost" sub-vector of each group is equal to the sum of the group.
//
// The inner sum is computed in a tree fashion. Example for batchSize=2 & n=4 (garbage slots are marked by 'x'):
//
// 1) [{a, b}, {c, d}, {e, f}, {g, h}, {a, b}, {c, d}, {e, f}, {g, h}]
//
//  2. [{a, b}, {c, d}, {e, f}, {g, h}, {a, b}, {c, d}, {e, f}, {g, h}]
//     +
//     [{c, d}, {e, f}, {g, h}, {x, x}, {c, d}, {e, f}, {g, h}, {x, x}] (rotate batchSize * 2^{0})
//     =
//     [{a+c, b+d}, {x, x}, {e+g, f+h}, {x, x}, {a+c, b+d}, {x, x}, {e+g, f+h}, {x, x}]
//
//  3. [{a+c, b+d}, {x, x}, {e+g, f+h}, {x, x}, {a+c, b+d}, {x, x}, {e+g, f+h}, {x, x}] (rotate batchSize * 2^{1})
//     +
//     [{e+g, f+h}, {x, x}, {x, x}, {x, x}, {e+g, f+h}, {x, x}, {x, x}, {x, x}] =
//     =
//     [{a+c+e+g, b+d+f+h}, {x, x}, {x, x}, {x, x}, {a+c+e+g, b+d+f+h}, {x, x}, {x, x}, {x, x}]
func (eval Evaluator) InnerSum(ctIn *Ciphertext, batchSize, n int, buf HoistingBuffer, opOut *Ciphertext) (err error) {

	params := eval.GetRLWEParameters()

	LevelQ := ctIn.Level()
	LevelP := params.PCount() - 1

	rQ := params.RingQAtLevel(LevelQ)
	rP := params.RingPAtLevel(LevelP)

	opOut.ResizeQ(LevelQ)
	*opOut.MetaData = *ctIn.MetaData

	ctNTT, err := NewCiphertextAtLevelFromPoly(LevelQ, -1, eval.BuffCt.Q[:2], nil)

	// Sanity check, this error should not happen unless the
	// evaluator's buffer thave been improperly tempered with.
	if err != nil {
		panic(err)
	}

	ctNTT.MetaData = &MetaData{}
	ctNTT.IsNTT = true

	if !ctIn.IsNTT {
		rQ.NTT(ctIn.Q[0], ctNTT.Q[0])
		rQ.NTT(ctIn.Q[1], ctNTT.Q[1])
	} else {
		ctNTT.Q[0].CopyLvl(LevelQ, &ctIn.Q[0])
		ctNTT.Q[1].CopyLvl(LevelQ, &ctIn.Q[1])
	}

	if n == 1 {
		if ctIn != opOut {
			opOut.Q[0].CopyLvl(LevelQ, &ctIn.Q[0])
			opOut.Q[1].CopyLvl(LevelQ, &ctIn.Q[1])
		}
	} else {

		// BuffQP[0:2] are used by AutomorphismHoistedLazy

		// Accumulator mod QP (i.e. opOut Mod QP)
		accQP := &Ciphertext{}
		accQP.Vector = &ring.Vector{}
		accQP.Q = []ring.RNSPoly{eval.BuffQ[2], eval.BuffQ[3]}
		accQP.P = []ring.RNSPoly{eval.BuffP[2], eval.BuffP[3]}
		accQP.MetaData = ctNTT.MetaData

		// Buffer mod QP (i.e. to store the result of lazy gadget products)
		cQP := &Ciphertext{}
		cQP.Vector = &ring.Vector{}
		cQP.Q = []ring.RNSPoly{eval.BuffQ[4], eval.BuffQ[5]}
		cQP.P = []ring.RNSPoly{eval.BuffP[4], eval.BuffP[5]}
		cQP.MetaData = ctNTT.MetaData

		// Buffer mod Q (i.e. to store the result of gadget products)
		cQ, err := NewCiphertextAtLevelFromPoly(LevelQ, -1, []ring.RNSPoly{cQP.Q[0], cQP.Q[1]}, nil)

		// Sanity check, this error should not happen unless the
		// evaluator's buffer thave been improperly tempered with.
		if err != nil {
			panic(err)
		}

		cQ.MetaData = ctNTT.MetaData

		state := false
		copy := true
		// Binary reading of the input n
		for i, j := 0, n; j > 0; i, j = i+1, j>>1 {

			// Starts by decomposing the input Ciphertext
			eval.FillHoistingBuffer(LevelQ, LevelP, ctNTT.Q[1], true, buf)

			// If the binary reading scans a 1 (j is odd)
			if j&1 == 1 {

				k := n - (n & ((2 << i) - 1))
				k *= batchSize

				// If the rotation is not zero
				if k != 0 {

					rot := params.GaloisElement(k)

					// opOutQP = opOutQP + Rotate(ctNTT, k)
					if copy {
						if err = eval.AutomorphismHoistedLazy(LevelQ, ctNTT, buf, rot, accQP); err != nil {
							return err
						}
						copy = false
					} else {
						if err = eval.AutomorphismHoistedLazy(LevelQ, ctNTT, buf, rot, cQP); err != nil {
							return err
						}

						rQ.Add(accQP.Q[0], cQP.Q[0], accQP.Q[0])
						rQ.Add(accQP.Q[1], cQP.Q[1], accQP.Q[1])

						if rP != nil {
							rP.Add(accQP.P[0], cQP.P[0], accQP.P[0])
							rP.Add(accQP.P[1], cQP.P[1], accQP.P[1])
						}
					}

					// j is even
				} else {

					state = true

					// if n is not a power of two, then at least one j was odd, and thus the buffer opOutQP is not empty
					if n&(n-1) != 0 {

						// opOut = opOutQP/P + ctNTT
						rQ.ModDownNTT(rP, accQP.Q[0], accQP.P[0], eval.BuffQ[0], eval.BuffP[0], opOut.Q[0]) // Division by P
						rQ.ModDownNTT(rP, accQP.Q[1], accQP.P[1], eval.BuffQ[0], eval.BuffP[0], opOut.Q[1]) // Division by P

						rQ.Add(opOut.Q[0], ctNTT.Q[0], opOut.Q[0])
						rQ.Add(opOut.Q[1], ctNTT.Q[1], opOut.Q[1])

					} else {
						opOut.Q[0].CopyLvl(LevelQ, &ctNTT.Q[0])
						opOut.Q[1].CopyLvl(LevelQ, &ctNTT.Q[1])
					}
				}
			}

			if !state {

				rot := params.GaloisElement((1 << i) * batchSize)

				// ctNTT = ctNTT + Rotate(ctNTT, 2^i)
				if err = eval.AutomorphismHoisted(ctNTT, buf, rot, cQ); err != nil {
					return err
				}
				rQ.Add(ctNTT.Q[0], cQ.Q[0], ctNTT.Q[0])
				rQ.Add(ctNTT.Q[1], cQ.Q[1], ctNTT.Q[1])
			}
		}
	}

	if !ctIn.IsNTT {
		rQ.INTT(opOut.Q[0], opOut.Q[0])
		rQ.INTT(opOut.Q[1], opOut.Q[1])
	}

	return
}

// InnerFunction applies an user defined function on the Ciphertext with a tree-like combination requiring log2(n) + HW(n) rotations.
//
// InnerFunction with f = eval.Add(a, b, c) is equivalent to InnerSum (although slightly slower).
//
// The operation assumes that `ctIn` encrypts Slots/`batchSize` sub-vectors of size `batchSize` and will add them together (in parallel) in groups of `n`.
// It outputs in opOut a Ciphertext for which the "leftmost" sub-vector of each group is equal to the pair-wise recursive evaluation of function over the group.
//
// The inner function is computed in a tree fashion. Example for batchSize=2 & n=4 (garbage slots are marked by 'x'):
//
// 1) [{a, b}, {c, d}, {e, f}, {g, h}, {a, b}, {c, d}, {e, f}, {g, h}]
//
//  2. [{a, b}, {c, d}, {e, f}, {g, h}, {a, b}, {c, d}, {e, f}, {g, h}]
//     f
//     [{c, d}, {e, f}, {g, h}, {x, x}, {c, d}, {e, f}, {g, h}, {x, x}] (rotate batchSize * 2^{0})
//     =
//     [{f(a, c), f(b, d)}, {f(c, e), f(d, f)}, {f(e, g), f(f, h)}, {x, x}, {f(a, c), f(b, d)}, {f(c, e), f(d, f)}, {f(e, g), f(f, h)}, {x, x}]
//
//  3. [{f(a, c), f(b, d)}, {x, x}, {f(e, g), f(f, h)}, {x, x}, {f(a, c), f(b, d)}, {x, x}, {f(e, g), f(f, h)}, {x, x}] (rotate batchSize * 2^{1})
//     +
//     [{f(e, g), f(f, h)}, {x, x}, {x, x}, {x, x}, {f(e, g), f(f, h)}, {x, x}, {x, x}, {x, x}] =
//     =
//     [{f(f(a,c),f(e,g)), f(f(b, d), f(f, h))}, {x, x}, {x, x}, {x, x}, {f(f(a,c),f(e,g)), f(f(b, d), f(f, h))}, {x, x}, {x, x}, {x, x}]
func (eval Evaluator) InnerFunction(ctIn []Ciphertext, batchSize, n int, f func(a, b, c []Ciphertext) (err error), opOut []Ciphertext) (err error) {

	if len(ctIn) != len(opOut) {
		return fmt.Errorf("invalid inputs: len(ctIn) != len(opOut)")
	}

	for i := range ctIn {
		if ctIn[i].Level() != ctIn[0].Level() || !ctIn[i].Scale.Equal(ctIn[0].Scale) {
			return fmt.Errorf("invalid inputs: all ctIn must have the same level and scale")
		}

		if opOut[i].Level() != opOut[0].Level() || !opOut[i].Scale.Equal(opOut[0].Scale) {
			return fmt.Errorf("invalid inputs: all opOut must have the same level and scale")
		}
	}

	params := eval.GetRLWEParameters()

	levelQ := min(ctIn[0].Level(), opOut[0].Level())

	ringQ := params.RingQ().AtLevel(levelQ)

	for i := range opOut {
		opOut[i].ResizeQ(levelQ)
		*opOut[i].MetaData = *ctIn[i].MetaData
	}

	P0 := make([]ring.RNSPoly, len(ctIn))
	P1 := make([]ring.RNSPoly, len(ctIn))
	P2 := make([]ring.RNSPoly, len(ctIn))
	P3 := make([]ring.RNSPoly, len(ctIn))

	for i := range ctIn {
		P0[i] = params.RingQ().NewRNSPoly()
		P1[i] = params.RingQ().NewRNSPoly()
		P2[i] = params.RingQ().NewRNSPoly()
		P3[i] = params.RingQ().NewRNSPoly()
	}

	ctNTT := make([]Ciphertext, len(ctIn))

	for i := range ctNTT {

		ctNTT[i] = *NewCiphertext(params, 1, levelQ, -1)

		*ctNTT[i].MetaData = *ctIn[i].MetaData
		ctNTT[i].IsNTT = true

		if !ctIn[i].IsNTT {
			ringQ.NTT(ctIn[i].Q[0], ctNTT[i].Q[0])
			ringQ.NTT(ctIn[i].Q[1], ctNTT[i].Q[1])
		} else {
			ctNTT[i].Copy(&ctIn[i])
		}
	}

	if n == 1 {
		for i := range opOut {
			opOut[i].Copy(&ctIn[i])
		}
	} else {

		accQ := make([]Ciphertext, len(ctIn))

		for i := range accQ {
			// Accumulator mod Q
			ct, err := NewCiphertextAtLevelFromPoly(levelQ, -1, []ring.RNSPoly{P0[i], P1[i]}, nil)

			// Sanity check, this error should not happen unless the
			// evaluator's buffer thave been improperly tempered with.
			if err != nil {
				panic(err)
			}

			*ct.MetaData = *ctNTT[i].MetaData
			accQ[i] = *ct
		}

		cQ := make([]Ciphertext, len(ctIn))

		for i := range cQ {

			// Buffer mod Q
			ct, err := NewCiphertextAtLevelFromPoly(levelQ, -1, []ring.RNSPoly{P2[i], P3[i]}, nil)

			// Sanity check, this error should not happen unless the
			// evaluator's buffer thave been improperly tempered with.
			if err != nil {
				panic(err)
			}

			*ct.MetaData = *ctNTT[i].MetaData

			cQ[i] = *ct
		}

		state := false
		copy := true
		// Binary reading of the input n
		for i, j := 0, n; j > 0; i, j = i+1, j>>1 {

			// If the binary reading scans a 1 (j is odd)
			if j&1 == 1 {

				k := n - (n & ((2 << i) - 1))
				k *= batchSize

				// If the rotation is not zero
				if k != 0 {

					rot := params.GaloisElement(k)

					// opOutQ = f(opOutQ, Rotate(ctNTT, k), opOutQ)
					if copy {
						for i := range ctIn {
							if err = eval.Automorphism(&ctNTT[i], rot, &accQ[i]); err != nil {
								return err
							}
						}
						copy = false
					} else {
						for i := range ctIn {
							if err = eval.Automorphism(&ctNTT[i], rot, &cQ[i]); err != nil {
								return err
							}
						}

						if err = f(accQ, cQ, accQ); err != nil {
							return err
						}
					}

					// j is even
				} else {

					state = true

					// if n is not a power of two, then at least one j was odd, and thus the buffer opOutQ is not empty
					if n&(n-1) != 0 {

						for i := range ctIn {
							opOut[i].Copy(&accQ[i])
						}

						if err = f(opOut, ctNTT, opOut); err != nil {
							return err
						}

					} else {
						for i := range ctIn {
							opOut[i].Copy(&ctNTT[i])
						}
					}
				}
			}

			if !state {

				galEl := params.GaloisElement((1 << i) * batchSize)

				for i := range ctIn {
					// ctNTT = f(ctNTT, Rotate(ctNTT, 2^i), ctNTT)
					if err = eval.Automorphism(&ctNTT[i], galEl, &cQ[i]); err != nil {
						return err
					}
				}

				if err = f(ctNTT, cQ, ctNTT); err != nil {
					return err
				}
			}
		}
	}

	for i := range ctIn {
		if !ctIn[i].IsNTT {
			ringQ.INTT(opOut[i].Q[0], opOut[i].Q[0])
			ringQ.INTT(opOut[i].Q[1], opOut[i].Q[1])
		}
	}

	return
}

// GaloisElementsForInnerSum returns the list of Galois elements necessary to apply the method
// `InnerSum` operation with parameters `batch` and `n`.
func GaloisElementsForInnerSum(params ParameterProvider, batch, n int) (galEls []uint64) {

	rotIndex := make(map[int]bool)

	var k int
	for i := 1; i < n; i <<= 1 {

		k = i
		k *= batch
		rotIndex[k] = true

		k = n - (n & ((i << 1) - 1))
		k *= batch
		rotIndex[k] = true
	}

	rotations := make([]int, len(rotIndex))
	var i int
	for j := range rotIndex {
		rotations[i] = j
		i++
	}

	return params.GetRLWEParameters().GaloisElements(rotations)
}

// Replicate applies an optimized replication on the Ciphertext (log2(n) + HW(n) rotations with double hoisting).
// It acts as the inverse of a inner sum (summing elements from left to right).
// The replication is parameterized by the size of the sub-vectors to replicate "batchSize" and
// the number of times 'n' they need to be replicated.
// To ensure correctness, a gap of zero values of size batchSize * (n-1) must exist between
// two consecutive sub-vectors to replicate.
// This method is faster than Replicate when the number of rotations is large and it uses log2(n) + HW(n) instead of 'n'.
func (eval Evaluator) Replicate(ctIn *Ciphertext, batchSize, n int, buf HoistingBuffer, opOut *Ciphertext) (err error) {
	return eval.InnerSum(ctIn, -batchSize, n, buf, opOut)
}

// GaloisElementsForReplicate returns the list of Galois elements necessary to perform the
// `Replicate` operation with parameters `batch` and `n`.
func GaloisElementsForReplicate(params ParameterProvider, batch, n int) (galEls []uint64) {
	return GaloisElementsForInnerSum(params, -batch, n)
}
