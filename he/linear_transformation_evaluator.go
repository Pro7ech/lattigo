package he

import (
	"fmt"
	"maps"
	"slices"

	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
)

// EvaluatorForLinearTransformation defines a set of common and scheme agnostic method necessary to instantiate an LinearTransformationEvaluator.
type EvaluatorForLinearTransformation interface {
	rlwe.ParameterProvider
	Rescale(op1, op2 *rlwe.Ciphertext) (err error)
	GetBuffQ() [6]ring.RNSPoly
	GetBuffP() [6]ring.RNSPoly
	GetBuffCt() *rlwe.Ciphertext
	NewHoistingBuffer(LevelQ, LevelP int) rlwe.HoistingBuffer
	FillHoistingBuffer(LevelQ, LevelP int, c1 ring.RNSPoly, isNTT bool, buf rlwe.HoistingBuffer)
	CheckAndGetGaloisKey(galEl uint64) (evk *rlwe.GaloisKey, err error)
	GadgetProductLazy(LevelQ int, overwrite bool, cx ring.RNSPoly, cxIsNTT bool, gadgetCt *rlwe.GadgetCiphertext, ct *rlwe.Ciphertext) (err error)
	GadgetProductHoistedLazy(LevelQ int, overwrite bool, buf rlwe.HoistingBuffer, gadgetCt *rlwe.GadgetCiphertext, ct *rlwe.Ciphertext) (err error)
	AutomorphismHoistedLazy(LevelQ int, ctIn *rlwe.Ciphertext, buf rlwe.HoistingBuffer, galEl uint64, ctQP *rlwe.Ciphertext) (err error)
	ModDownNTT(LevelQ, LevelP int, p1Q, p1P, p2Q ring.RNSPoly)
	AutomorphismIndex(uint64) []uint64
}

type EvaluatorForDiagonalMatrix interface {
	FillHoistingBuffer(LevelQ, LevelP int, c1 ring.RNSPoly, isNTT bool, buf rlwe.HoistingBuffer)
	GetPreRotatedCiphertextForDiagonalMatrixMultiplication(LevelQ, LevelP int, ctIn *rlwe.Ciphertext, buf rlwe.HoistingBuffer, rots []int, ctPreRot map[int]*rlwe.Ciphertext) (err error)
	MultiplyByDiagMatrix(ctIn *rlwe.Ciphertext, matrix *LinearTransformation, buf rlwe.HoistingBuffer, opOut *rlwe.Ciphertext) (err error)
	MultiplyByDiagMatrixBSGS(ctIn *rlwe.Ciphertext, matrix *LinearTransformation, ctInPreRot map[int]*rlwe.Ciphertext, opOut *rlwe.Ciphertext) (err error)
}

type LinearTransformationEvaluator struct {
	EvaluatorForLinearTransformation
	EvaluatorForDiagonalMatrix
}

// NewLinearTransformationEvaluator instantiates a new LinearTransformationEvaluator from a circuit.EvaluatorForLinearTransformation.
// The default hefloat.Evaluator is compliant to the EvaluatorForLinearTransformation interface.
// This method is allocation free.
func NewLinearTransformationEvaluator(eval EvaluatorForLinearTransformation) (linTransEval *LinearTransformationEvaluator) {
	return &LinearTransformationEvaluator{
		EvaluatorForLinearTransformation: eval,
		EvaluatorForDiagonalMatrix:       &defaultDiagonalMatrixEvaluator{eval},
	}
}

// defaultDiagonalMatrixEvaluator is a struct implementing the interface EvaluatorForDiagonalMatrix.
type defaultDiagonalMatrixEvaluator struct {
	EvaluatorForLinearTransformation
}

// GetPreRotatedCiphertextForDiagonalMatrixMultiplication populates ctPreRot with the pre-rotated ciphertext for the rotations rots and deletes rotated ciphertexts that are not in rots.
func (eval defaultDiagonalMatrixEvaluator) GetPreRotatedCiphertextForDiagonalMatrixMultiplication(LevelQ, LevelP int, ctIn *rlwe.Ciphertext, buf rlwe.HoistingBuffer, rots []int, ctPreRot map[int]*rlwe.Ciphertext) (err error) {
	return GetPreRotatedCiphertextForDiagonalMatrixMultiplication(LevelQ, LevelP, eval, ctIn, buf, rots, ctPreRot)
}

// MultiplyByDiagMatrix multiplies the Ciphertext "ctIn" by the plaintext matrix "matrix" and returns the result on the Ciphertext
// "opOut". Memory buffers for the decomposed ciphertext [rlwe.HoistingBuffer] must be provided.
// The naive approach is used (single hoisting and no baby-step giant-step), which is faster than MultiplyByDiagMatrixBSGS
// for matrix of only a few non-zero diagonals but uses more keys.
func (eval defaultDiagonalMatrixEvaluator) MultiplyByDiagMatrix(ctIn *rlwe.Ciphertext, matrix *LinearTransformation, buf rlwe.HoistingBuffer, opOut *rlwe.Ciphertext) (err error) {
	return MultiplyByDiagMatrix(eval.EvaluatorForLinearTransformation, ctIn, matrix, buf, opOut)
}

// MultiplyByDiagMatrixBSGS multiplies the Ciphertext "ctIn" by the plaintext matrix "matrix" and returns the result on the Ciphertext "opOut".
// ctInPreRotated can be obtained with GetPreRotatedCiphertextForDiagonalMatrixMultiplication.
// The BSGS approach is used (double hoisting with baby-step giant-step), which is faster than MultiplyByDiagMatrix
// for matrix with more than a few non-zero diagonals and uses significantly less keys.
func (eval defaultDiagonalMatrixEvaluator) MultiplyByDiagMatrixBSGS(ctIn *rlwe.Ciphertext, matrix *LinearTransformation, ctPreRot map[int]*rlwe.Ciphertext, opOut *rlwe.Ciphertext) (err error) {
	return MultiplyByDiagMatrixBSGS(eval.EvaluatorForLinearTransformation, ctIn, matrix, ctPreRot, opOut)
}

// EvaluateNew takes as input a ciphertext ctIn and a linear transformation M and evaluate and returns opOut: M(ctIn).
func (eval LinearTransformationEvaluator) EvaluateNew(ctIn *rlwe.Ciphertext, linearTransformation *LinearTransformation, buf rlwe.HoistingBuffer) (opOut *rlwe.Ciphertext, err error) {
	ops, err := eval.EvaluateManyNew(ctIn, []*LinearTransformation{linearTransformation}, buf)
	if err != nil {
		return nil, err
	}
	return ops[0], nil
}

// Evaluate takes as input a ciphertext ctIn, a linear transformation M and evaluates opOut: M(ctIn).
func (eval LinearTransformationEvaluator) Evaluate(ctIn *rlwe.Ciphertext, linearTransformation *LinearTransformation, buf rlwe.HoistingBuffer, opOut *rlwe.Ciphertext) (err error) {
	return EvaluateLinearTransformationsMany(eval.EvaluatorForLinearTransformation, eval.EvaluatorForDiagonalMatrix, ctIn, []*LinearTransformation{linearTransformation}, buf, []*rlwe.Ciphertext{opOut})
}

// EvaluateManyNew takes as input a ciphertext ctIn and a list of linear transformations [M0, M1, M2, ...] and returns opOut:[M0(ctIn), M1(ctIn), M2(ctInt), ...].
func (eval LinearTransformationEvaluator) EvaluateManyNew(ctIn *rlwe.Ciphertext, linearTransformations []*LinearTransformation, buf rlwe.HoistingBuffer) (opOut []*rlwe.Ciphertext, err error) {
	params := eval.GetRLWEParameters()
	opOut = make([]*rlwe.Ciphertext, len(linearTransformations))
	for i := range opOut {
		opOut[i] = rlwe.NewCiphertext(params, 1, linearTransformations[i].LevelQ, -1)
	}
	return opOut, eval.EvaluateMany(ctIn, linearTransformations, buf, opOut)
}

// EvaluateMany takes as input a ciphertext ctIn, a list of linear transformations [M0, M1, M2, ...] and a list of pre-allocated receiver opOut
// and evaluates opOut: [M0(ctIn), M1(ctIn), M2(ctIn), ...]
func (eval LinearTransformationEvaluator) EvaluateMany(ctIn *rlwe.Ciphertext, linearTransformations []*LinearTransformation, buf rlwe.HoistingBuffer, opOut []*rlwe.Ciphertext) (err error) {
	return EvaluateLinearTransformationsMany(eval.EvaluatorForLinearTransformation, eval.EvaluatorForDiagonalMatrix, ctIn, linearTransformations, buf, opOut)
}

// EvaluateSequentialNew takes as input a ciphertext ctIn and a list of linear transformations [M0, M1, M2, ...] and returns opOut:...M2(M1(M0(ctIn))
func (eval LinearTransformationEvaluator) EvaluateSequentialNew(ctIn *rlwe.Ciphertext, linearTransformations []*LinearTransformation, buf rlwe.HoistingBuffer) (opOut *rlwe.Ciphertext, err error) {
	opOut = rlwe.NewCiphertext(eval.GetRLWEParameters(), 1, linearTransformations[0].LevelQ, -1)
	return opOut, eval.EvaluateSequential(ctIn, linearTransformations, buf, opOut)
}

// EvaluateSequential takes as input a ciphertext ctIn and a list of linear transformations [M0, M1, M2, ...] and returns opOut:...M2(M1(M0(ctIn))
func (eval LinearTransformationEvaluator) EvaluateSequential(ctIn *rlwe.Ciphertext, linearTransformations []*LinearTransformation, buf rlwe.HoistingBuffer, opOut *rlwe.Ciphertext) (err error) {
	return EvaluateLinearTranformationSequential(eval.EvaluatorForLinearTransformation, eval.EvaluatorForDiagonalMatrix, ctIn, linearTransformations, buf, opOut)
}

// EvaluateLinearTransformationsMany takes as input a ciphertext ctIn, a list of linear transformations [M0, M1, M2, ...] and a list of pre-allocated receiver opOut
// and evaluates opOut: [M0(ctIn), M1(ctIn), M2(ctIn), ...]
func EvaluateLinearTransformationsMany(evalLT EvaluatorForLinearTransformation, evalDiag EvaluatorForDiagonalMatrix, ctIn *rlwe.Ciphertext, linearTransformations []*LinearTransformation, buf rlwe.HoistingBuffer, opOut []*rlwe.Ciphertext) (err error) {

	if len(opOut) < len(linearTransformations) {
		return fmt.Errorf("output *rlwe.Ciphertext slice is too small")
	}

	for i := range linearTransformations {
		if opOut[i] == nil {
			return fmt.Errorf("output slice contains unallocated ciphertext")
		}
	}

	var LevelQ int
	LevelP := linearTransformations[0].LevelP
	for _, lt := range linearTransformations {
		LevelQ = max(LevelQ, lt.LevelQ)
		if LevelP != lt.LevelP {
			return fmt.Errorf("all [he.LinearTransformation]s must have the same LevelP")
		}
	}
	LevelQ = min(LevelQ, ctIn.Level())

	evalDiag.FillHoistingBuffer(LevelQ, LevelP, ctIn.Q[1], ctIn.IsNTT, buf)

	ctPreRot := map[int]*rlwe.Ciphertext{}

	for _, lt := range linearTransformations {
		if lt.GiantStep == 0 {
			return fmt.Errorf("invalid [he.LinearTransformation]: GiantStep = 0")
		} else if lt.GiantStep != -1 {
			_, _, rotN2 := lt.BSGSIndex()
			if err = evalDiag.GetPreRotatedCiphertextForDiagonalMatrixMultiplication(LevelQ, LevelP, ctIn, buf, rotN2, ctPreRot); err != nil {
				return fmt.Errorf("evalDiag.GetPreRotatedCiphertextForDiagonalMatrixMultiplication: %w", err)
			}
		}
	}

	for i, lt := range linearTransformations {
		if lt.GiantStep == -1 {
			if err = evalDiag.MultiplyByDiagMatrix(ctIn, lt, buf, opOut[i]); err != nil {
				return fmt.Errorf("evalDiag.MultiplyByDiagMatrix: %w", err)
			}
		} else {
			if err = evalDiag.MultiplyByDiagMatrixBSGS(ctIn, lt, ctPreRot, opOut[i]); err != nil {
				return fmt.Errorf("evalDiag.MultiplyByDiagMatrixBSGS: %w", err)
			}
		}
	}

	return
}

// GetPreRotatedCiphertextForDiagonalMatrixMultiplication populates ctPreRot with the pre-rotated ciphertext for the rotations rots.
func GetPreRotatedCiphertextForDiagonalMatrixMultiplication(LevelQ, LevelP int, eval EvaluatorForLinearTransformation, ctIn *rlwe.Ciphertext, buf rlwe.HoistingBuffer, rots []int, ctPreRot map[int]*rlwe.Ciphertext) (err error) {

	params := eval.GetRLWEParameters()

	// Computes the rotation only for the ones that are not already present.
	for _, i := range rots {
		if _, ok := ctPreRot[i]; i != 0 && !ok {
			ctPreRot[i] = rlwe.NewCiphertext(params, 1, LevelQ, LevelP)
			if err = eval.AutomorphismHoistedLazy(LevelQ, ctIn, buf, params.GaloisElement(i), ctPreRot[i]); err != nil {
				return
			}
		}
	}

	return
}

// EvaluateLinearTranformationSequential takes as input a ciphertext ctIn and a list of linear transformations [M0, M1, M2, ...] and evaluates opOut:...M2(M1(M0(ctIn))
func EvaluateLinearTranformationSequential(evalLT EvaluatorForLinearTransformation, evalDiag EvaluatorForDiagonalMatrix, ctIn *rlwe.Ciphertext, linearTransformations []*LinearTransformation, buf rlwe.HoistingBuffer, opOut *rlwe.Ciphertext) (err error) {

	if err = EvaluateLinearTransformationsMany(evalLT, evalDiag, ctIn, linearTransformations[:1], buf, []*rlwe.Ciphertext{opOut}); err != nil {
		return fmt.Errorf("EvaluateLinearTransformationsMany: %w", err)
	}

	for i := 1; i < len(linearTransformations); i++ {

		if err = evalLT.Rescale(opOut, opOut); err != nil {
			return fmt.Errorf("evalLT.Rescale: %w", err)
		}

		if err = EvaluateLinearTransformationsMany(evalLT, evalDiag, opOut, linearTransformations[i:i+1], buf, []*rlwe.Ciphertext{opOut}); err != nil {
			return fmt.Errorf("EvaluateLinearTransformationsMany: %w", err)
		}
	}

	return
}

// MultiplyByDiagMatrix multiplies the Ciphertext "ctIn" by the plaintext matrix "matrix" and returns the result on the Ciphertext
// "opOut". Memory buffers for the decomposed ciphertext BuffDecompQP, BuffDecompQP must be provided, those are list of poly of ringQ and ringP
// respectively, each of size params.Beta().
// The naive approach is used (single hoisting and no baby-step giant-step), which is faster than MultiplyByDiagMatrixBSGS
// for matrix of only a few non-zero diagonals but uses more keys.
func MultiplyByDiagMatrix(eval EvaluatorForLinearTransformation, ctIn *rlwe.Ciphertext, matrix *LinearTransformation, buf rlwe.HoistingBuffer, opOut *rlwe.Ciphertext) (err error) {

	BuffQ := eval.GetBuffQ()
	BuffP := eval.GetBuffP()
	BuffCt := eval.GetBuffCt()

	*opOut.MetaData = *ctIn.MetaData
	opOut.Scale = opOut.Scale.Mul(matrix.Scale)

	params := eval.GetRLWEParameters()

	LevelQ := min(opOut.Level(), min(ctIn.Level(), matrix.LevelQ))
	LevelP := matrix.LevelP

	rQ := params.RingQAtLevel(LevelQ)
	rP := params.RingPAtLevel(LevelP)

	opOut.ResizeQ(LevelQ)

	QiOverF := params.QiOverflowMargin(LevelQ)
	PiOverF := params.PiOverflowMargin(LevelP)

	c0OutQP := ring.Point{Q: opOut.Q[0], P: BuffQ[5]}
	c1OutQP := ring.Point{Q: opOut.Q[1], P: BuffP[5]}

	ct0TimesP := BuffQ[0] // ct0 * P mod Q
	tmp0QP := ring.Point{Q: BuffQ[1], P: BuffP[1]}
	tmp1QP := ring.Point{Q: BuffQ[2], P: BuffP[2]}

	cQP := &rlwe.Ciphertext{}
	cQP.Vector = &ring.Vector{}
	cQP.Q = BuffQ[3:5]
	cQP.P = BuffP[3:5]
	cQP.MetaData = &rlwe.MetaData{}
	cQP.MetaData.IsNTT = true

	BuffCt.Q[0].CopyLvl(LevelQ, &ctIn.Q[0])
	BuffCt.Q[1].CopyLvl(LevelQ, &ctIn.Q[1])

	ctInTmp0, ctInTmp1 := BuffCt.Q[0], BuffCt.Q[1]

	rQ.MulScalarBigint(ctInTmp0, rP.Modulus(), ct0TimesP) // P*c0

	slots := 1 << matrix.LogDimensions.Cols

	keys := slices.Collect(maps.Keys(matrix.Vec))
	slices.Sort(keys)

	var state bool
	if keys[0] == 0 {
		state = true
		keys = keys[1:]
	}

	for i, k := range keys {

		k &= (slots - 1)

		galEl := params.GaloisElement(k)

		var evk *rlwe.GaloisKey
		var err error
		if evk, err = eval.CheckAndGetGaloisKey(galEl); err != nil {
			return fmt.Errorf("eval.CheckAndGetGaloisKey: %w", err)
		}

		if evk.LevelP() != LevelP {
			return fmt.Errorf("LinearTransformation.LevelP = %d != GaloiKey[%d].LevelP() = %d: ensure that the LevelP of the linear transformation is the same as the LevelP of the GaloisKeys", LevelP, galEl, evk.LevelP())
		}

		index := eval.AutomorphismIndex(galEl)

		if err = eval.GadgetProductHoistedLazy(LevelQ, true, buf, &evk.GadgetCiphertext, cQP); err != nil {
			return fmt.Errorf("eval.GadgetProductHoistedLazy: %w", err)
		}

		rQ.Add(cQP.Q[0], ct0TimesP, cQP.Q[0])

		rQ.AutomorphismNTTWithIndex(cQP.Q[0], index, tmp0QP.Q)
		rQ.AutomorphismNTTWithIndex(cQP.Q[1], index, tmp1QP.Q)
		rP.AutomorphismNTTWithIndex(cQP.P[0], index, tmp0QP.P)
		rP.AutomorphismNTTWithIndex(cQP.P[1], index, tmp1QP.P)

		pt := matrix.Vec[k]

		if i == 0 {
			// keyswitch(c1_Q) = (d0_QP, d1_QP)
			rQ.MulCoeffsMontgomery(pt.Q, tmp0QP.Q, c0OutQP.Q)
			rQ.MulCoeffsMontgomery(pt.Q, tmp1QP.Q, c1OutQP.Q)
			rP.MulCoeffsMontgomery(pt.P, tmp0QP.P, c0OutQP.P)
			rP.MulCoeffsMontgomery(pt.P, tmp1QP.P, c1OutQP.P)
		} else {
			// keyswitch(c1_Q) = (d0_QP, d1_QP)
			rQ.MulCoeffsMontgomeryThenAdd(pt.Q, tmp0QP.Q, c0OutQP.Q)
			rQ.MulCoeffsMontgomeryThenAdd(pt.Q, tmp1QP.Q, c1OutQP.Q)
			rP.MulCoeffsMontgomeryThenAdd(pt.P, tmp0QP.P, c0OutQP.P)
			rP.MulCoeffsMontgomeryThenAdd(pt.P, tmp1QP.P, c1OutQP.P)
		}

		if i%QiOverF == QiOverF-1 {
			rQ.Reduce(c0OutQP.Q, c0OutQP.Q)
			rQ.Reduce(c1OutQP.Q, c1OutQP.Q)
		}

		if i%PiOverF == PiOverF-1 {
			rP.Reduce(c0OutQP.P, c0OutQP.P)
			rP.Reduce(c1OutQP.P, c1OutQP.P)
		}
	}

	if len(keys)%QiOverF == 0 {
		rQ.Reduce(c0OutQP.Q, c0OutQP.Q)
		rQ.Reduce(c1OutQP.Q, c1OutQP.Q)
	}

	if len(keys)%PiOverF == 0 {
		rP.Reduce(c0OutQP.P, c0OutQP.P)
		rP.Reduce(c1OutQP.P, c1OutQP.P)
	}

	eval.ModDownNTT(LevelQ, LevelP, c0OutQP.Q, c0OutQP.P, c0OutQP.Q) // sum(phi(c0 * P + d0_QP))/P
	eval.ModDownNTT(LevelQ, LevelP, c1OutQP.Q, c1OutQP.P, c1OutQP.Q) // sum(phi(d1_QP))/P

	if state { // Rotation by zero
		rQ.MulCoeffsMontgomeryThenAdd(matrix.Vec[0].Q, ctInTmp0, c0OutQP.Q) // opOut += c0_Q * plaintext
		rQ.MulCoeffsMontgomeryThenAdd(matrix.Vec[0].Q, ctInTmp1, c1OutQP.Q) // opOut += c1_Q * plaintext
	}

	return
}

// MultiplyByDiagMatrixBSGS multiplies the Ciphertext "ctIn" by the plaintext matrix "matrix" and returns the result on the Ciphertext "opOut".
// ctInPreRotated can be obtained with GetPreRotatedCiphertextForDiagonalMatrixMultiplication.
// The BSGS approach is used (double hoisting with baby-step giant-step), which is faster than MultiplyByDiagMatrix
// for matrix with more than a few non-zero diagonals and uses significantly less keys.
func MultiplyByDiagMatrixBSGS(eval EvaluatorForLinearTransformation, ctIn *rlwe.Ciphertext, matrix *LinearTransformation, ctInPreRot map[int]*rlwe.Ciphertext, opOut *rlwe.Ciphertext) (err error) {

	params := eval.GetRLWEParameters()

	BuffQ := eval.GetBuffQ()
	BuffP := eval.GetBuffP()

	BuffCt := eval.GetBuffCt()

	*opOut.MetaData = *ctIn.MetaData
	opOut.Scale = opOut.Scale.Mul(matrix.Scale)

	LevelQ := min(opOut.Level(), min(ctIn.Level(), matrix.LevelQ))
	LevelP := matrix.LevelP

	rQ := params.RingQAtLevel(LevelQ)
	rP := params.RingPAtLevel(LevelP)

	opOut.ResizeQ(LevelQ)

	QiOverF := params.QiOverflowMargin(LevelQ) >> 1
	PiOverF := params.PiOverflowMargin(LevelP) >> 1

	// Computes the N2 rotations indexes of the non-zero rows of the diagonalized DFT matrix for the baby-step giant-step algorithm
	index, _, _ := matrix.BSGSIndex()

	BuffCt.Q[0].CopyLvl(LevelQ, &ctIn.Q[0])
	BuffCt.Q[1].CopyLvl(LevelQ, &ctIn.Q[1])

	ctInTmp0, ctInTmp1 := BuffCt.Q[0], BuffCt.Q[1]

	// Accumulator inner loop
	tmp0QP := ring.Point{Q: BuffQ[1], P: BuffP[1]}
	tmp1QP := ring.Point{Q: BuffQ[2], P: BuffP[2]}

	// Accumulator outer loop
	cQP := &rlwe.Ciphertext{}
	cQP.Vector = &ring.Vector{}
	cQP.Q = BuffQ[3:5]
	cQP.P = BuffP[3:5]
	cQP.MetaData = &rlwe.MetaData{}
	cQP.MetaData.IsNTT = true

	// Result in QP
	c0OutQP := ring.Point{Q: opOut.Q[0], P: BuffQ[5]}
	c1OutQP := ring.Point{Q: opOut.Q[1], P: BuffP[5]}

	P := rP.Modulus()

	rQ.MulScalarBigint(ctInTmp0, P, ctInTmp0) // P*c0
	rQ.MulScalarBigint(ctInTmp1, P, ctInTmp1) // P*c1

	keys := slices.Collect(maps.Keys(index))
	slices.Sort(keys)

	// OUTER LOOP
	var cnt0 int
	for _, j := range keys {

		// INNER LOOP
		var cnt1 int
		for _, i := range index[j] {

			pt := matrix.Vec[j+i]
			ct := ctInPreRot[i]

			if i == 0 {
				if cnt1 == 0 {
					rQ.MulCoeffsMontgomeryLazy(pt.Q, ctInTmp0, tmp0QP.Q)
					rQ.MulCoeffsMontgomeryLazy(pt.Q, ctInTmp1, tmp1QP.Q)
					tmp0QP.P.Zero()
					tmp1QP.P.Zero()
				} else {
					rQ.MulCoeffsMontgomeryLazyThenAddLazy(pt.Q, ctInTmp0, tmp0QP.Q)
					rQ.MulCoeffsMontgomeryLazyThenAddLazy(pt.Q, ctInTmp1, tmp1QP.Q)
				}
			} else {
				if cnt1 == 0 {
					rQ.MulCoeffsMontgomeryLazy(pt.Q, ct.Q[0], tmp0QP.Q)
					rQ.MulCoeffsMontgomeryLazy(pt.Q, ct.Q[1], tmp1QP.Q)
					rP.MulCoeffsMontgomeryLazy(pt.P, ct.P[0], tmp0QP.P)
					rP.MulCoeffsMontgomeryLazy(pt.P, ct.P[1], tmp1QP.P)
				} else {
					rQ.MulCoeffsMontgomeryLazyThenAddLazy(pt.Q, ct.Q[0], tmp0QP.Q)
					rQ.MulCoeffsMontgomeryLazyThenAddLazy(pt.Q, ct.Q[1], tmp1QP.Q)
					rP.MulCoeffsMontgomeryLazyThenAddLazy(pt.P, ct.P[0], tmp0QP.P)
					rP.MulCoeffsMontgomeryLazyThenAddLazy(pt.P, ct.P[1], tmp1QP.P)
				}
			}

			if cnt1%QiOverF == QiOverF-1 {
				rQ.Reduce(tmp0QP.Q, tmp0QP.Q)
				rQ.Reduce(tmp1QP.Q, tmp1QP.Q)
			}

			if cnt1%PiOverF == PiOverF-1 {
				rP.Reduce(tmp0QP.P, tmp0QP.P)
				rP.Reduce(tmp1QP.P, tmp1QP.P)
			}

			cnt1++
		}

		if cnt1%QiOverF != 0 {
			rQ.Reduce(tmp0QP.Q, tmp0QP.Q)
			rQ.Reduce(tmp1QP.Q, tmp1QP.Q)
		}

		if cnt1%PiOverF != 0 {
			rP.Reduce(tmp0QP.P, tmp0QP.P)
			rP.Reduce(tmp1QP.P, tmp1QP.P)
		}

		// If j != 0, then rotates ((tmp0QP.Q, tmp0QP.P), (tmp1QP.Q, tmp1QP.P)) by N1*j and adds the result on ((cQP.Value[0].Q, cQP.Value[0].P), (cQP.Value[1].Q, cQP.Value[1].P))
		if j != 0 {

			// Hoisting of the ModDown of sum(sum(phi(d1) * plaintext))
			eval.ModDownNTT(LevelQ, LevelP, tmp1QP.Q, tmp1QP.P, tmp1QP.Q) // c1 * plaintext + sum(phi(d1) * plaintext) + phi(c1) * plaintext mod Q

			galEl := params.GaloisElement(j)

			var evk *rlwe.GaloisKey
			var err error
			if evk, err = eval.CheckAndGetGaloisKey(galEl); err != nil {
				return fmt.Errorf("CheckAndGetGaloisKey: %w", err)
			}

			if evk.LevelP() != LevelP {
				return fmt.Errorf("LinearTransformation.LevelP = %d != GaloiKey[%d].LevelP() = %d: ensure that the LevelP of the linear transformation is the same as the LevelP of the GaloisKeys", LevelP, galEl, evk.LevelP())
			}

			rotIndex := eval.AutomorphismIndex(galEl)
			// EvaluationKey(P*phi(tmpRes_1)) = (d0, d1) in base QP
			if err = eval.GadgetProductLazy(LevelQ, true, tmp1QP.Q, true, &evk.GadgetCiphertext, cQP); err != nil {
				return fmt.Errorf("eval.GadgetProductLazy: %w", err)
			}

			rQ.Add(cQP.Q[0], tmp0QP.Q, cQP.Q[0])
			rP.Add(cQP.P[0], tmp0QP.P, cQP.P[0])

			// Outer loop rotations
			if cnt0 == 0 {
				rQ.AutomorphismNTTWithIndex(cQP.Q[0], rotIndex, c0OutQP.Q)
				rQ.AutomorphismNTTWithIndex(cQP.Q[1], rotIndex, c1OutQP.Q)
				rP.AutomorphismNTTWithIndex(cQP.P[0], rotIndex, c0OutQP.P)
				rP.AutomorphismNTTWithIndex(cQP.P[1], rotIndex, c1OutQP.P)
			} else {
				rQ.AutomorphismNTTWithIndexThenAddLazy(cQP.Q[0], rotIndex, c0OutQP.Q)
				rQ.AutomorphismNTTWithIndexThenAddLazy(cQP.Q[1], rotIndex, c1OutQP.Q)
				rP.AutomorphismNTTWithIndexThenAddLazy(cQP.P[0], rotIndex, c0OutQP.P)
				rP.AutomorphismNTTWithIndexThenAddLazy(cQP.P[1], rotIndex, c1OutQP.P)
			}

			// Else directly adds on ((cQP.Value[0].Q, cQP.Value[0].P), (cQP.Value[1].Q, cQP.Value[1].P))
		} else {
			if cnt0 == 0 {
				c0OutQP.Q.CopyLvl(LevelQ, &tmp0QP.Q)
				c0OutQP.P.CopyLvl(LevelP, &tmp0QP.P)
				c1OutQP.Q.CopyLvl(LevelQ, &tmp1QP.Q)
				c1OutQP.P.CopyLvl(LevelP, &tmp1QP.P)
			} else {
				rQ.AddLazy(c0OutQP.Q, tmp0QP.Q, c0OutQP.Q)
				rQ.AddLazy(c1OutQP.Q, tmp1QP.Q, c1OutQP.Q)
				rP.AddLazy(c0OutQP.P, tmp0QP.P, c0OutQP.P)
				rP.AddLazy(c1OutQP.P, tmp1QP.P, c1OutQP.P)
			}
		}

		if cnt0%QiOverF == QiOverF-1 {
			rQ.Reduce(opOut.Q[0], opOut.Q[0])
			rQ.Reduce(opOut.Q[1], opOut.Q[1])
		}

		if cnt0%PiOverF == PiOverF-1 {
			rP.Reduce(c0OutQP.P, c0OutQP.P)
			rP.Reduce(c1OutQP.P, c1OutQP.P)
		}

		cnt0++
	}

	if cnt0%QiOverF != 0 {
		rQ.Reduce(opOut.Q[0], opOut.Q[0])
		rQ.Reduce(opOut.Q[1], opOut.Q[1])
	}

	if cnt0%PiOverF != 0 {
		rP.Reduce(c0OutQP.P, c0OutQP.P)
		rP.Reduce(c1OutQP.P, c1OutQP.P)
	}

	eval.ModDownNTT(LevelQ, LevelP, opOut.Q[0], c0OutQP.P, opOut.Q[0]) // sum(phi(c0 * P + d0_QP))/P
	eval.ModDownNTT(LevelQ, LevelP, opOut.Q[1], c1OutQP.P, opOut.Q[1]) // sum(phi(d1_QP))/P

	return
}
