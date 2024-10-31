package heint

import (
	"fmt"
	"math"
	"math/big"

	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils"
)

// Evaluator is a struct that holds the necessary elements to perform the homomorphic operations between ciphertexts and/or plaintexts.
// It also holds a memory buffer used to store intermediate computations.
type Evaluator struct {
	*evaluatorBase
	*evaluatorBuffers
	*rlwe.Evaluator
	*Encoder
}

type evaluatorBase struct {
	tMontgomery   ring.RNSScalar
	levelQMul     []int      // optimal #QiMul depending on #Qi (variable level)
	pHalf         []*big.Int // all prod(QiMul) / 2 depending on #Qi
	buffModUpQMul ring.RNSPoly
}

func (eval evaluatorBase) ShallowCopy() *evaluatorBase {
	return &evaluatorBase{
		tMontgomery:   eval.tMontgomery,
		levelQMul:     eval.levelQMul,
		pHalf:         eval.pHalf,
		buffModUpQMul: *eval.buffModUpQMul.Clone(),
	}
}

func newEvaluatorPrecomp(parameters Parameters) *evaluatorBase {
	rQ := parameters.RingQ()
	rQMul := parameters.RQMul
	t := parameters.PlaintextModulus()

	levelQMul := make([]int, rQ.ModuliChainLength())
	Q := new(big.Int).SetUint64(1)
	for i := range levelQMul {
		Q.Mul(Q, new(big.Int).SetUint64(rQ[i].Modulus))
		levelQMul[i] = int(math.Ceil(float64(Q.BitLen()+parameters.LogN())/61.0)) - 1
	}

	pHalf := make([]*big.Int, rQMul.ModuliChainLength())

	QMul := new(big.Int).SetUint64(1)
	for i := range pHalf {
		QMul.Mul(QMul, new(big.Int).SetUint64(rQMul[i].Modulus))
		pHalf[i] = new(big.Int).Rsh(QMul, 1)
	}

	// t * 2^{64} mod Q
	tMontgomery := rQ.NewRNSScalarFromBigint(new(big.Int).Lsh(new(big.Int).SetUint64(t), 64))
	rQ.MFormRNSScalar(tMontgomery, tMontgomery)

	return &evaluatorBase{
		tMontgomery:   tMontgomery,
		levelQMul:     levelQMul,
		pHalf:         pHalf,
		buffModUpQMul: rQMul.NewRNSPoly(),
	}
}

type evaluatorBuffers struct {
	buffQMul [7]ring.RNSPoly
}

func newEvaluatorBuffer(params Parameters) *evaluatorBuffers {

	rQMul := params.RQMul

	buffQMul := [7]ring.RNSPoly{
		rQMul.NewRNSPoly(),
		rQMul.NewRNSPoly(),
		rQMul.NewRNSPoly(),
		rQMul.NewRNSPoly(),
		rQMul.NewRNSPoly(),
		rQMul.NewRNSPoly(),
		rQMul.NewRNSPoly(),
	}

	return &evaluatorBuffers{
		buffQMul: buffQMul,
	}
}

// NewEvaluator creates a new Evaluator, that can be used to do homomorphic
// operations on ciphertexts and/or plaintexts. It stores a memory buffer
// and ciphertexts that will be used for intermediate values.
func NewEvaluator(parameters Parameters, evk rlwe.EvaluationKeySet) *Evaluator {
	ev := new(Evaluator)
	ev.evaluatorBase = newEvaluatorPrecomp(parameters)
	ev.evaluatorBuffers = newEvaluatorBuffer(parameters)
	ev.Evaluator = rlwe.NewEvaluator(parameters.Parameters, evk)
	ev.Encoder = NewEncoder(parameters)

	return ev
}

// GetParameters returns a pointer to the underlying bgv.Parameters.
func (eval Evaluator) GetParameters() *Parameters {
	return &eval.Encoder.parameters
}

// ShallowCopy creates a shallow copy of this Evaluator in which the read-only data-structures are
// shared with the receiver.
func (eval Evaluator) ShallowCopy() *Evaluator {
	return &Evaluator{
		evaluatorBase:    eval.evaluatorBase.ShallowCopy(),
		Evaluator:        eval.Evaluator.ShallowCopy(),
		evaluatorBuffers: newEvaluatorBuffer(*eval.GetParameters()),
		Encoder:          eval.Encoder.ShallowCopy(),
	}
}

// WithKey creates a shallow copy of this Evaluator in which the read-only data-structures are
// shared with the receiver but the EvaluationKey is evaluationKey.
func (eval Evaluator) WithKey(evk rlwe.EvaluationKeySet) *Evaluator {
	return &Evaluator{
		evaluatorBase:    eval.evaluatorBase,
		Evaluator:        eval.Evaluator.WithKey(evk),
		evaluatorBuffers: eval.evaluatorBuffers,
		Encoder:          eval.Encoder,
	}
}

// LevelsConsumedPerRescaling returns the number of level consumed by a rescaling.
func (eval Evaluator) LevelsConsumedPerRescaling() int {
	return 1
}

// Add adds op1 to op0 and returns the result in op2.
// The following types are accepted for op1:
//   - rlwe.Element
//   - *big.Int, uint64, int64, int
//   - []uint64 or []int64 (of size at most N where N is the smallest integer satisfying PlaintextModulus = 1 mod 2N)
//
// If op1 is an rlwe.Element and the scales of op0, op1 and op2 do not match, then a scale matching operation will
// be automatically carried out to ensure that addition is performed between operands of the same scale.
// This scale matching operation will increase the noise by a small factor.
// For this reason it is preferable to ensure that all operands are already at the same scale when calling this method.
func (eval Evaluator) Add(op0 *rlwe.Ciphertext, op1 rlwe.Operand, op2 *rlwe.Ciphertext) (err error) {
	return eval.addition(op0, op1, op2, true)
}

// AddNew adds op1 to op0 and returns the result on a new *rlwe.Ciphertext op2.
// The following types are accepted for op1:
//   - [rlwe.Element]
//   - *big.Int, uint64, int64, int
//   - []uint64 or []int64 (of size at most N where N is the smallest integer satisfying PlaintextModulus = 1 mod 2N)
//
// If op1 is an rlwe.Element and the scales of op0 and op1 not match, then a scale matching operation will
// be automatically carried out to ensure that addition is performed between operands of the same scale.
// This scale matching operation will increase the noise by a small factor.
// For this reason it is preferable to ensure that all operands are already at the same scale when calling this method.
func (eval Evaluator) AddNew(op0 *rlwe.Ciphertext, op1 rlwe.Operand) (op2 *rlwe.Ciphertext, err error) {

	switch op1 := op1.(type) {
	case rlwe.Element:
		op2 = eval.newCiphertextBinary(op0, op1)
	default:
		op2 = NewCiphertext(eval.parameters, op0.Degree(), op0.Level())
	}

	return op2, eval.Add(op0, op1, op2)
}

// Sub subtracts op1 to op0 and returns the result in op2.
// The following types are accepted for op1:
//   - [rlwe.Element]
//   - *big.Int, uint64, int64, int
//   - []uint64 or []int64 (of size at most N where N is the smallest integer satisfying PlaintextModulus = 1 mod 2N)
//
// If op1 is an rlwe.Element and the scales of op0, op1 and op2 do not match, then a scale matching operation will
// be automatically carried out to ensure that the subtraction is performed between operands of the same scale.
// This scale matching operation will increase the noise by a small factor.
// For this reason it is preferable to ensure that all operands are already at the same scale when calling this method.
func (eval Evaluator) Sub(op0 *rlwe.Ciphertext, op1 rlwe.Operand, op2 *rlwe.Ciphertext) (err error) {
	return eval.addition(op0, op1, op2, false)
}

// SubNew subtracts op1 to op0 and returns the result in a new *rlwe.Ciphertext op2.
// The following types are accepted for op1:
//   - [rlwe.Element]
//   - *big.Int, uint64, int64, int
//   - []uint64 or []int64 (of size at most N where N is the smallest integer satisfying PlaintextModulus = 1 mod 2N)
//
// If op1 is an rlwe.Element and the scales of op0, op1 and op2 do not match, then a scale matching operation will
// be automatically carried out to ensure that the subtraction is performed between operands of the same scale.
// This scale matching operation will increase the noise by a small factor.
// For this reason it is preferable to ensure that all operands are already at the same scale when calling this method.
func (eval Evaluator) SubNew(op0 *rlwe.Ciphertext, op1 rlwe.Operand) (op2 *rlwe.Ciphertext, err error) {
	switch op1 := op1.(type) {
	case rlwe.Element:
		op2 = eval.newCiphertextBinary(op0, op1)
	default:
		op2 = NewCiphertext(eval.parameters, op0.Degree(), op0.Level())
	}

	return op2, eval.Sub(op0, op1, op2)
}

func (eval Evaluator) addition(op0 *rlwe.Ciphertext, op1 rlwe.Operand, op2 *rlwe.Ciphertext, positive bool) (err error) {

	rQ := eval.parameters.RingQ()

	switch op1 := op1.(type) {
	case rlwe.Element:

		el1 := op1.AsCiphertext()

		degree, level, err := eval.InitOutputBinaryOp(op0, el1, op0.Degree()+op1.Degree(), op2)
		if err != nil {
			return fmt.Errorf("cannot Add: %w", err)
		}

		op2.ResizeQ(level)
		op2.ResizeDegree(degree)

		if positive {
			if op0.Scale.Cmp(el1.Scale) == 0 {
				eval.evaluateInPlace(level, op0, el1, op2, rQ.AtLevel(level).Add)
			} else {
				eval.matchScaleThenEvaluateInPlace(level, op0, el1, op2, rQ.AtLevel(level).MulScalarThenAdd)
			}
		} else {
			if op0.Scale.Cmp(el1.Scale) == 0 {
				eval.evaluateInPlace(level, op0, el1, op2, rQ.AtLevel(level).Sub)
			} else {
				eval.matchScaleThenEvaluateInPlace(level, op0, el1, op2, rQ.AtLevel(level).MulScalarThenSub)
			}
		}

	case *big.Int:

		_, level, err := eval.InitOutputUnaryOp(op0, op2)
		if err != nil {
			return fmt.Errorf("cannot Add: %w", err)
		}

		op2.ResizeQ(level)
		op2.ResizeDegree(op0.Degree())

		TBig := new(big.Int).SetUint64(eval.parameters.RT.Modulus)

		// Sets op1 to the scale of op0
		op1.Mul(op1, new(big.Int).SetUint64(op0.Scale.Uint64()))
		op1.Mod(op1, TBig)

		// If op1 > T/2 -> op1 -= T
		if op1.Cmp(new(big.Int).Rsh(TBig, 1)) == 1 {
			op1.Sub(op1, TBig)
		}

		// Scales op0 by T^{-1} mod Q
		op1.Mul(op1, eval.tInvModQ[level])

		if positive {
			rQ.AtLevel(level).AddScalarBigint(op0.Q[0], op1, op2.Q[0])
		} else {
			rQ.AtLevel(level).SubScalarBigint(op0.Q[0], op1, op2.Q[0])
		}

		if op0.Vector != op2.Vector {
			for i := 1; i < op0.Degree()+1; i++ {
				op2.Q[i].CopyLvl(level, &op0.Q[i])
			}
		}

	case uint64:
		return eval.addition(op0, new(big.Int).SetUint64(op1), op2, positive)
	case int64:
		return eval.addition(op0, new(big.Int).SetInt64(op1), op2, positive)
	case int:
		return eval.addition(op0, new(big.Int).SetInt64(int64(op1)), op2, positive)
	case []uint64, []int64:

		_, level, err := eval.InitOutputUnaryOp(op0, op2)
		if err != nil {
			return fmt.Errorf("cannot Add: %w", err)
		}

		op2.ResizeQ(level)
		op2.ResizeDegree(op0.Degree())

		// Instantiates new plaintext from buffer
		pt, err := rlwe.NewPlaintextAtLevelFromPoly(level, -1, eval.BuffQ[0], ring.RNSPoly{})

		// This error should not happen, unless the evaluator's buffer were
		// improperly tempered with. If it does happen, there is no way to
		// recover from it.
		if err != nil {
			panic(err)
		}

		pt.MetaData = op0.MetaData // Sets the metadata, notably matches scalses

		// Encodes the vector on the plaintext
		if err = eval.Encoder.Encode(op1, pt); err != nil {
			return err
		}

		// Generic in place evaluation
		if positive {
			eval.evaluateInPlace(level, op0, pt.AsCiphertext(), op2, eval.parameters.RingQ().AtLevel(level).Add)
		} else {
			eval.evaluateInPlace(level, op0, pt.AsCiphertext(), op2, eval.parameters.RingQ().AtLevel(level).Sub)
		}
	default:
		return fmt.Errorf("invalid op1.(Type), expected rlwe.Element, []uint64, []int64, *big.Int, uint64, int64 or int, but got %T", op1)
	}

	return
}

func (eval Evaluator) evaluateInPlace(level int, el0, el1, elOut *rlwe.Ciphertext, evaluate func(ring.RNSPoly, ring.RNSPoly, ring.RNSPoly)) {

	smallest, largest, _ := rlwe.GetSmallestLargest(el0, el1)

	for i := 0; i < smallest.Degree()+1; i++ {
		evaluate(el0.Q[i], el1.Q[i], elOut.Q[i])
	}

	// If the inputs degrees differ, it copies the remaining degree on the receiver.
	if largest.Vector != nil && largest.Vector != elOut.Vector { // checks to avoid unnecessary work.
		for i := smallest.Degree() + 1; i < largest.Degree()+1; i++ {
			elOut.Q[i].CopyLvl(level, &largest.Q[i])
		}
	}

	elOut.Scale = el0.Scale
}

func (eval Evaluator) matchScaleThenEvaluateInPlace(level int, el0, el1, elOut *rlwe.Ciphertext, evaluate func(ring.RNSPoly, uint64, ring.RNSPoly)) {

	r0, r1, _ := eval.matchScalesBinary(el0.Scale.Uint64(), el1.Scale.Uint64())

	for i := range el0.Q {
		eval.parameters.RingQ().AtLevel(level).MulScalar(el0.Q[i], r0, elOut.Q[i])
	}

	for i := el0.Degree() + 1; i < elOut.Degree()+1; i++ {
		elOut.Q[i].Zero()
	}

	for i := range el1.Q {
		evaluate(el1.Q[i], r1, elOut.Q[i])
	}

	elOut.Scale = el0.Scale.Mul(eval.parameters.NewScale(r0))
}

func (eval Evaluator) newCiphertextBinary(op0, op1 rlwe.Element) (op2 *rlwe.Ciphertext) {
	return NewCiphertext(*eval.GetParameters(), max(op0.Degree(), op1.Degree()), min(op0.Level(), op1.Level()))
}

// DropLevel reduces the level of op0 by levels.
// No rescaling is applied during this procedure.
func (eval Evaluator) DropLevel(op0 *rlwe.Ciphertext, levels int) {
	op0.ResizeQ(op0.Level() - levels)
}

// Mul multiplies op0 with op1 without relinearization and using standard tensoring (BGV/CKKS-style), and returns the result in op2.
// This tensoring increases the noise by a multiplicative factor of the plaintext and noise norms of the operands and will usually
// require to be followed by a rescaling operation to avoid an exponential growth of the noise from subsequent multiplications.
// The procedure will return an error if either op0 or op1 are have a degree higher than 1.
// The procedure will return an error if op2.Degree != op0.Degree + op1.Degree.
//
// The following types are accepted for op1:
//   - [rlwe.Element]
//   - *big.Int, uint64, int64, int
//   - []uint64 or []int64 (of size at most N where N is the smallest integer satisfying PlaintextModulus = 1 mod 2N)
//
// If op1 is an [rlwe.Element]:
//   - the level of op2 will be updated to min(op0.Level(), op1.Level())
//   - the scale of op2 will be updated to op0.Scale * op1.Scale
func (eval Evaluator) Mul(op0 *rlwe.Ciphertext, op1 rlwe.Operand, op2 *rlwe.Ciphertext) (err error) {

	switch op1 := op1.(type) {
	case rlwe.Element:

		el := op1.AsCiphertext()

		_, level, err := eval.InitOutputBinaryOp(op0, el, 2, op2)
		if err != nil {
			return fmt.Errorf("cannot Mul: %w", err)
		}

		op2.ResizeQ(level)

		if err = eval.tensorStandard(op0, el, false, op2); err != nil {
			return fmt.Errorf("cannot Mul: %w", err)
		}

	case *big.Int:

		_, level, err := eval.InitOutputUnaryOp(op0, op2)
		if err != nil {
			return fmt.Errorf("cannot Mul: %w", err)
		}

		op2.ResizeQ(level)
		op2.ResizeDegree(op0.Degree())

		rQ := eval.parameters.RingQ().AtLevel(level)

		TBig := new(big.Int).SetUint64(eval.parameters.RT.Modulus)

		op1.Mod(op1, TBig)

		// If op1 > T/2 then subtract T to minimize the noise
		if op1.Cmp(new(big.Int).Rsh(TBig, 1)) == 1 {
			op1.Sub(op1, TBig)
		}

		for i := 0; i < op0.Degree()+1; i++ {
			rQ.MulScalarBigint(op0.Q[i], op1, op2.Q[i])
		}

	case uint64:
		return eval.Mul(op0, new(big.Int).SetUint64(op1), op2)
	case int:
		return eval.Mul(op0, new(big.Int).SetInt64(int64(op1)), op2)
	case int64:
		return eval.Mul(op0, new(big.Int).SetInt64(op1), op2)
	case []uint64, []int64:

		_, level, err := eval.InitOutputUnaryOp(op0, op2)
		if err != nil {
			return fmt.Errorf("cannot Mul: %w", err)
		}

		op2.ResizeQ(level)
		op2.ResizeDegree(op0.Degree())

		// Instantiates new plaintext from buffer
		pt, err := rlwe.NewPlaintextAtLevelFromPoly(level, -1, eval.BuffQ[0], ring.RNSPoly{})

		// This error should not happen, unless the evaluator's buffer were
		// improperly tempered with. If it does happen, there is no way to
		// recover from it.
		if err != nil {
			panic(err)
		}

		pt.MetaData = op0.MetaData.Clone() // Sets the metadata, notably matches scales
		pt.Scale = rlwe.NewScale(1)

		// Encodes the vector on the plaintext
		if err := eval.Encoder.Encode(op1, pt); err != nil {
			return err
		}

		if err = eval.tensorStandard(op0, pt.AsCiphertext(), false, op2); err != nil {
			return fmt.Errorf("cannot Mul: %w", err)
		}
	default:
		return fmt.Errorf("invalid op1.(Type), expected rlwe.Element, []uint64, []int64, *big.Int, uint64, int64 or int, but got %T", op1)
	}

	return
}

// MulNew multiplies op0 with op1 without relinearization and using standard tensoring (BGV/CKKS-style), and returns the result in a new *rlwe.Ciphertext op2.
// This tensoring increases the noise by a multiplicative factor of the plaintext and noise norms of the operands and will usually
// require to be followed by a rescaling operation to avoid an exponential growth of the noise from subsequent multiplications.
// The procedure will return an error if either op0 or op1 are have a degree higher than 1.
//
// The following types are accepted for op1:
//   - [rlwe.Element]
//   - *big.Int, uint64, int64, int
//   - []uint64 or []int64 (of size at most N where N is the smallest integer satisfying PlaintextModulus = 1 mod 2N)
//
// If op1 is an [rlwe.Element]:
//   - the degree of op2 will be op0.Degree() + op1.Degree()
//   - the level of op2 will be to min(op0.Level(), op1.Level())
//   - the scale of op2 will be to op0.Scale * op1.Scale
func (eval Evaluator) MulNew(op0 *rlwe.Ciphertext, op1 rlwe.Operand) (op2 *rlwe.Ciphertext, err error) {
	switch op1 := op1.(type) {
	case rlwe.Element:
		op2 = NewCiphertext(eval.parameters, op0.Degree()+op1.Degree(), min(op0.Level(), op1.Level()))
	default:
		op2 = NewCiphertext(eval.parameters, op0.Degree(), op0.Level())
	}

	return op2, eval.Mul(op0, op1, op2)
}

// MulRelin multiplies op0 with op1 with relinearization and using standard tensoring (BGV/CKKS-style), and returns the result in op2.
// This tensoring increases the noise by a multiplicative factor of the plaintext and noise norms of the operands and will usually
// require to be followed by a rescaling operation to avoid an exponential growth of the noise from subsequent multiplications.
// The procedure will return an error if either op0.Degree or op1.Degree > 1.
// The procedure will return an error if op2.Degree != op0.Degree + op1.Degree.
// The procedure will return an error if the evaluator was not created with an relinearization key.
//
// The following types are accepted for op1:
//   - [rlwe.Element]
//   - *big.Int, uint64, int64, int
//   - []uint64 or []int64 (of size at most N where N is the smallest integer satisfying PlaintextModulus = 1 mod 2N)
//
// If op1 is an [rlwe.Element]:
//   - the level of op2 will be updated to min(op0.Level(), op1.Level())
//   - the scale of op2 will be updated to op0.Scale * op1.Scale
func (eval Evaluator) MulRelin(op0 *rlwe.Ciphertext, op1 rlwe.Operand, op2 *rlwe.Ciphertext) (err error) {
	switch op1 := op1.(type) {
	case rlwe.Element:

		el := op1.AsCiphertext()

		_, level, err := eval.InitOutputBinaryOp(op0, el, 2, op2)
		if err != nil {
			return fmt.Errorf("cannot MulRelin: %w", err)
		}

		op2.ResizeQ(level)

		if err = eval.tensorStandard(op0, el, true, op2); err != nil {
			return fmt.Errorf("cannot MulRelin: %w", err)
		}

	default:
		if err = eval.Mul(op0, op1, op2); err != nil {
			return fmt.Errorf("cannot MulRelin: %w", err)
		}
	}

	return
}

// MulRelinNew multiplies op0 with op1 with relinearization and and using standard tensoring (BGV/CKKS-style), returns the result in a new *rlwe.Ciphertext op2.
// This tensoring increases the noise by a multiplicative factor of the plaintext and noise norms of the operands and will usually
// require to be followed by a rescaling operation to avoid an exponential growth of the noise from subsequent multiplications.
// The procedure will return an error if either op0.Degree or op1.Degree > 1.
// The procedure will return an error if the evaluator was not created with an relinearization key.
//
// The following types are accepted for op1:
//   - [rlwe.Element]
//   - *big.Int, uint64, int64, int
//   - []uint64 or []int64 (of size at most N where N is the smallest integer satisfying PlaintextModulus = 1 mod 2N)
//
// If op1 is an [rlwe.Element]:
//   - the level of op2 will be to min(op0.Level(), op1.Level())
//   - the scale of op2 will be to op0.Scale * op1.Scale
func (eval Evaluator) MulRelinNew(op0 *rlwe.Ciphertext, op1 rlwe.Operand) (op2 *rlwe.Ciphertext, err error) {
	switch op1 := op1.(type) {
	case rlwe.Element:
		op2 = NewCiphertext(eval.parameters, 1, min(op0.Level(), op1.Level()))
	default:
		op2 = NewCiphertext(eval.parameters, 1, op0.Level())
	}

	return op2, eval.MulRelin(op0, op1, op2)
}

func (eval Evaluator) tensorStandardDegreeTwo(LevelQ int, op0, op1, op2 *rlwe.Ciphertext, c2 ring.RNSPoly) {

	rQ := eval.parameters.RingQ().AtLevel(LevelQ)

	c00 := eval.BuffQ[0]
	c01 := eval.BuffQ[1]

	// Avoid overwriting if the second input is the output
	if op1.Vector == op2.Vector {
		op0, op1 = op1, op0
	}

	c0 := op2.Q[0]
	c1 := op2.Q[1]

	// Multiply by T * 2^{64} * 2^{64} -> result multipled by T and switched in the Montgomery domain
	rQ.MulRNSScalarMontgomery(op0.Q[0], eval.tMontgomery, c00)
	rQ.MulRNSScalarMontgomery(op0.Q[1], eval.tMontgomery, c01)

	if op0.Vector == op1.Vector { // squaring case
		rQ.MulCoeffsMontgomery(c00, op1.Q[0], c0) // c0 = c[0]*c[0]
		rQ.MulCoeffsMontgomery(c01, op1.Q[1], c2) // c2 = c[1]*c[1]
		rQ.MulCoeffsMontgomery(c00, op1.Q[1], c1) // c1 = 2*c[0]*c[1]
		rQ.Add(c1, c1, c1)
	} else { // regular case
		rQ.MulCoeffsMontgomery(c00, op1.Q[0], c0) // c0 = c0[0]*c0[0]
		rQ.MulCoeffsMontgomery(c01, op1.Q[1], c2) // c2 = c0[1]*c1[1]
		rQ.MulCoeffsMontgomery(c00, op1.Q[1], c1)
		rQ.MulCoeffsMontgomeryThenAdd(c01, op1.Q[0], c1) // c1 = c0[0]*c1[1] + c0[1]*c1[0]
	}
}

func (eval Evaluator) tensorStandard(op0, op1 *rlwe.Ciphertext, relin bool, op2 *rlwe.Ciphertext) (err error) {

	level := op2.Level()

	op2.Scale = op0.Scale.Mul(op1.Scale)

	rQ := eval.parameters.RingQ().AtLevel(level)

	// Case Ciphertext (x) Ciphertext
	if op0.Degree() == 1 && op1.Degree() == 1 {

		if !relin {
			op2.ResizeDegree(2)
			eval.tensorStandardDegreeTwo(level, op0, op1, op2, op2.Q[2])
		} else {
			op2.ResizeDegree(1)
			eval.tensorStandardDegreeTwo(level, op0, op1, op2, eval.BuffQ[2])

			if err = eval.RelinearizeInplace(op2, eval.BuffQ[2]); err != nil {
				return fmt.Errorf("eval.RelinearizeInplace: %w", err)
			}
		}

		// Case Plaintext (x) Ciphertext or Ciphertext (x) Plaintext
	} else {

		if op0.Degree() < op1.Degree() {
			op0, op1 = op1, op0
		}

		c00 := eval.BuffQ[0]
		// Multiply by T * 2^{64} * 2^{64} -> result multipled by T and switched in the Montgomery domain
		rQ.MulRNSScalarMontgomery(op1.Q[0], eval.tMontgomery, c00)

		if relin && op0.Degree() == 2 {

			if op0 != op2 {
				op2.ResizeDegree(1)
			}

			rQ.MulCoeffsMontgomery(op0.Q[0], c00, op2.Q[0])
			rQ.MulCoeffsMontgomery(op0.Q[1], c00, op2.Q[1])
			rQ.MulCoeffsMontgomery(op0.Q[2], c00, eval.BuffQ[2])

			if err = eval.RelinearizeInplace(op2, eval.BuffQ[2]); err != nil {
				return fmt.Errorf("eval.RelinearizeInplace: %w", err)
			}

		} else {

			if op0 != op2 {
				op2.ResizeDegree(op0.Degree())
			}

			for i := range op0.Q {
				rQ.MulCoeffsMontgomery(op0.Q[i], c00, op2.Q[i])
			}
		}
	}

	return
}

// MulScaleInvariant multiplies op0 with op1 without relinearization and using scale invariant tensoring (BFV-style), and returns the result in op2.
// This tensoring increases the noise by a constant factor regardless of the current noise, thus no rescaling is required with subsequent multiplications if they are
// performed with the invariant tensoring procedure. Rescaling can still be useful to reduce the size of the ciphertext, once the noise is higher than the prime
// that will be used for the rescaling or to ensure that the noise is minimal before using the regular tensoring.
// The procedure will return an error if either op0.Degree or op1.Degree > 1.
// The procedure will return an error if the evaluator was not created with an relinearization key.
//
// The following types are accepted for op1:
//   - [rlwe.Element]
//   - *big.Int, uint64, int64, int
//   - []uint64 or []int64 (of size at most N where N is the smallest integer satisfying PlaintextModulus = 1 mod 2N)
//
// If op1 is an [rlwe.Element]:
//   - the level of op2 will be updated to min(op0.Level(), op1.Level())
//   - the scale of op2 will be to op0.Scale * op1.Scale * (-Q mod T)^{-1} mod T
func (eval Evaluator) MulScaleInvariant(op0 *rlwe.Ciphertext, op1 rlwe.Operand, op2 *rlwe.Ciphertext) (err error) {
	switch op1 := op1.(type) {
	case rlwe.Element:

		el := op1.AsCiphertext()

		_, level, err := eval.InitOutputBinaryOp(op0, el, 2, op2)
		if err != nil {
			return fmt.Errorf("cannot MulInvariant: %w", err)
		}

		op2.ResizeQ(level)

		if el.Degree() == 0 || op0.Degree() == 0 {

			if err = eval.tensorStandard(op0, el, false, op2); err != nil {
				return fmt.Errorf("cannot MulInvariant: %w", err)
			}

		} else {

			if err = eval.tensorScaleInvariant(op0, el, false, op2); err != nil {
				return fmt.Errorf("cannot MulInvariant: %w", err)
			}
		}
	case []uint64, []int64:

		_, level, err := eval.InitOutputUnaryOp(op0, op2)
		if err != nil {
			return fmt.Errorf("cannot MulInvariant: %w", err)
		}

		op2.ResizeQ(level)
		op2.ResizeDegree(op0.Degree())

		// Instantiates new plaintext from buffer
		pt, err := rlwe.NewPlaintextAtLevelFromPoly(level, -1, eval.BuffQ[0], ring.RNSPoly{})

		// This error should not happen, unless the evaluator's buffer were
		// improperly tempered with. If it does happen, there is no way to
		// recover from it.
		if err != nil {
			panic(err)
		}
		pt.MetaData = op0.MetaData.Clone() // Sets the metadata, notably matches scales
		pt.Scale = rlwe.NewScale(1)

		// Encodes the vector on the plaintext
		if err := eval.Encoder.Encode(op1, pt); err != nil {
			return err
		}

		if err = eval.tensorStandard(op0, pt.AsCiphertext(), false, op2); err != nil {
			return fmt.Errorf("cannot MulInvariant: %w", err)
		}

	default:
		if err = eval.Mul(op0, op1, op2); err != nil {
			return fmt.Errorf("cannot MulInvariant: %w", err)
		}
	}
	return
}

// MulScaleInvariantNew multiplies op0 with op1 without relinearization and using scale invariant tensoring (BFV-style), and returns the result in a new *rlwe.Ciphertext op2.
// This tensoring increases the noise by a constant factor regardless of the current noise, thus no rescaling is required with subsequent multiplications if they are
// performed with the invariant tensoring procedure. Rescaling can still be useful to reduce the size of the ciphertext, once the noise is higher than the prime
// that will be used for the rescaling or to ensure that the noise is minimal before using the regular tensoring.
// The procedure will return an error if either op0.Degree or op1.Degree > 1.
// The procedure will return an error if the evaluator was not created with an relinearization key.
//
// The following types are accepted for op1:
//   - [rlwe.Element]
//   - *big.Int, uint64, int64, int
//   - []uint64 or []int64 (of size at most N where N is the smallest integer satisfying PlaintextModulus = 1 mod 2N)
//
// If op1 is an [rlwe.Element]:
//   - the level of op2 will be to min(op0.Level(), op1.Level())
//   - the scale of op2 will be to op0.Scale * op1.Scale * (-Q mod PlaintextModulus)^{-1} mod PlaintextModulus
func (eval Evaluator) MulScaleInvariantNew(op0 *rlwe.Ciphertext, op1 rlwe.Operand) (op2 *rlwe.Ciphertext, err error) {
	switch op1 := op1.(type) {
	case rlwe.Element:
		op2 = NewCiphertext(eval.parameters, op0.Degree()+op1.Degree(), min(op0.Level(), op1.Level()))
	default:
		op2 = NewCiphertext(eval.parameters, op0.Degree(), op0.Level())
	}
	return op2, eval.MulScaleInvariant(op0, op1, op2)
}

// MulRelinScaleInvariant multiplies op0 with op1 with relinearization and using scale invariant tensoring (BFV-style), and returns the result in op2.
// This tensoring increases the noise by a constant factor regardless of the current noise, thus no rescaling is required with subsequent multiplications if they are
// performed with the invariant tensoring procedure. Rescaling can still be useful to reduce the size of the ciphertext, once the noise is higher than the prime
// that will be used for the rescaling or to ensure that the noise is minimal before using the regular tensoring.
// The procedure will return an error if either op0.Degree or op1.Degree > 1.
// The procedure will return an error if the evaluator was not created with an relinearization key.
//
// The following types are accepted for op1:
//   - [rlwe.Element]
//   - *big.Int, uint64, int64, int
//   - []uint64 or []int64 (of size at most N where N is the smallest integer satisfying PlaintextModulus = 1 mod 2N)
//
// If op1 is an [rlwe.Element]:
//   - the level of op2 will be updated to min(op0.Level(), op1.Level())
//   - the scale of op2 will be to op0.Scale * op1.Scale * (-Q mod PlaintextModulus)^{-1} mod PlaintextModulus
func (eval Evaluator) MulRelinScaleInvariant(op0 *rlwe.Ciphertext, op1 rlwe.Operand, op2 *rlwe.Ciphertext) (err error) {
	switch op1 := op1.(type) {
	case rlwe.Element:

		el := op1.AsCiphertext()

		_, level, err := eval.InitOutputBinaryOp(op0, el, 2, op2)
		if err != nil {
			return fmt.Errorf("cannot MulRelinInvariant: %w", err)
		}

		op2.ResizeQ(level)

		if el.Degree() == 0 {

			if err = eval.tensorStandard(op0, el, true, op2); err != nil {
				return fmt.Errorf("cannot MulRelinInvariant: %w", err)
			}

		} else {

			if err = eval.tensorScaleInvariant(op0, el, true, op2); err != nil {
				return fmt.Errorf("cannot MulRelinInvariant: %w", err)
			}
		}

	case []uint64, []int64:

		_, level, err := eval.InitOutputUnaryOp(op0, op2)

		if err != nil {
			return fmt.Errorf("cannot MulRelinInvariant: %w", err)
		}

		op2.ResizeQ(level)
		op2.ResizeDegree(op0.Degree())

		// Instantiates new plaintext from buffer
		pt, err := rlwe.NewPlaintextAtLevelFromPoly(level, -1, eval.BuffQ[0], ring.RNSPoly{})

		// This error should not happen, unless the evaluator's buffer were
		// improperly tempered with. If it does happen, there is no way to
		// recover from it.
		if err != nil {
			panic(err)
		}

		pt.MetaData = op0.MetaData.Clone() // Sets the metadata, notably matches scales
		pt.Scale = rlwe.NewScale(1)

		// Encodes the vector on the plaintext
		if err := eval.Encoder.Encode(op1, pt); err != nil {
			return fmt.Errorf("cannot MulRelinInvariant: %w", err)
		}

		if err = eval.tensorStandard(op0, pt.AsCiphertext(), true, op2); err != nil {
			return fmt.Errorf("cannot MulRelinInvariant: %w", err)
		}

	case uint64, int64, int, *big.Int:
		if err = eval.Mul(op0, op1, op2); err != nil {
			return fmt.Errorf("cannot MulRelinInvariant: %w", err)
		}
	default:
		return fmt.Errorf("cannot MulRelinInvariant: invalid op1.(Type), expected rlwe.Element, []uint64, []int64, uint64, int64 or int, but got %T", op1)
	}
	return
}

// MulRelinScaleInvariantNew multiplies op0 with op1 with relinearization and using scale invariant tensoring (BFV-style), and returns the result in a new *rlwe.Ciphertext op2.
// This tensoring increases the noise by a constant factor regardless of the current noise, thus no rescaling is required with subsequent multiplications if they are
// performed with the invariant tensoring procedure. Rescaling can still be useful to reduce the size of the ciphertext, once the noise is higher than the prime
// that will be used for the rescaling or to ensure that the noise is minimal before using the regular tensoring.
// The procedure will return an error if either op0.Degree or op1.Degree > 1.
// The procedure will return an error if the evaluator was not created with an relinearization key.
//
// The following types are accepted for op1:
//   - [rlwe.Element]
//   - *big.Int, uint64, int64, int
//   - []uint64 or []int64 (of size at most N where N is the smallest integer satisfying PlaintextModulus = 1 mod 2N)
//
// If op1 is an [rlwe.Element]:
//   - the level of op2 will be to min(op0.Level(), op1.Level())
//   - the scale of op2 will be to op0.Scale * op1.Scale * (-Q mod PlaintextModulus)^{-1} mod PlaintextModulus
func (eval Evaluator) MulRelinScaleInvariantNew(op0 *rlwe.Ciphertext, op1 rlwe.Operand) (op2 *rlwe.Ciphertext, err error) {
	switch op1 := op1.(type) {
	case rlwe.Element:
		op2 = NewCiphertext(eval.parameters, 1, min(op0.Level(), op1.Level()))
	default:
		op2 = NewCiphertext(eval.parameters, op0.Degree(), op0.Level())
	}

	if err = eval.MulRelinScaleInvariant(op0, op1, op2); err != nil {
		return nil, fmt.Errorf("cannot MulRelinInvariantNew: %w", err)
	}
	return
}

// tensorScaleInvariant computes (op0 x op1) * (t/Q) and stores the result in op2.
func (eval Evaluator) tensorScaleInvariant(op0, op1 *rlwe.Ciphertext, relin bool, op2 *rlwe.Ciphertext) (err error) {

	level := min(min(op0.Level(), op1.Level()), op2.Level())

	levelQMul := eval.levelQMul[level]

	// Avoid overwriting if the second input is the output
	var tmp0Q0, tmp1Q0 *rlwe.Ciphertext
	if op1.Vector == op2.Vector {
		tmp0Q0, tmp1Q0 = op1, op0
	} else {
		tmp0Q0, tmp1Q0 = op0, op1
	}

	tmp0Q1 := &rlwe.Ciphertext{}
	tmp0Q1.Vector = &ring.Vector{}
	tmp0Q1.Q = eval.buffQMul[0:3]

	tmp1Q1 := &rlwe.Ciphertext{}
	tmp1Q1.Vector = &ring.Vector{}
	tmp1Q1.Q = eval.buffQMul[3:5]

	tmp2Q1 := tmp0Q1

	eval.modUpAndNTT(level, levelQMul, tmp0Q0, tmp0Q1)

	if tmp0Q0.Vector != tmp1Q0.Vector {
		eval.modUpAndNTT(level, levelQMul, tmp1Q0, tmp1Q1)
	}

	var c2 ring.RNSPoly
	if !relin {
		op2.ResizeQ(level)
		op2.ResizeDegree(2)
		c2 = op2.Q[2]
	} else {
		op2.ResizeQ(level)
		op2.ResizeDegree(1)
		c2 = eval.BuffQ[2]
	}

	tmp2Q0, err := rlwe.NewCiphertextAtLevelFromPoly(level, -1, []ring.RNSPoly{op2.Q[0], op2.Q[1], c2}, nil)
	if err != nil {
		panic(err)
	}

	eval.tensorLowDeg(level, levelQMul, tmp0Q0, tmp1Q0, tmp2Q0, tmp0Q1, tmp1Q1, tmp2Q1)

	eval.quantize(level, levelQMul, tmp2Q0.Q[0], tmp2Q1.Q[0])
	eval.quantize(level, levelQMul, tmp2Q0.Q[1], tmp2Q1.Q[1])
	eval.quantize(level, levelQMul, tmp2Q0.Q[2], tmp2Q1.Q[2])

	if relin {
		if err = eval.RelinearizeInplace(op2, c2); err != nil {
			return fmt.Errorf("eval.RelinearizeInplace: %w", err)
		}
	}

	op2.Scale = UpdateScaleInvariant(eval.parameters, op0.Scale, tmp1Q0.Scale, level)

	return
}

// UpdateScaleInvariant returns c = a * b / (-Q[level] mod PlaintextModulus), where a, b are the input scale,
// level the level at which the operation is carried out and and c is the new scale after performing the
// invariant tensoring (BFV-style).
func UpdateScaleInvariant(params Parameters, a, b rlwe.Scale, level int) (c rlwe.Scale) {
	c = a.Mul(b)
	qModTNeg := new(big.Int).Mod(params.RingQ().AtLevel(level).Modulus(), new(big.Int).SetUint64(params.PlaintextModulus())).Uint64()
	qModTNeg = params.PlaintextModulus() - qModTNeg
	c = c.Div(params.NewScale(qModTNeg))
	return
}

func (eval Evaluator) modUpAndNTT(level, levelQMul int, ctQ0, ctQ1 *rlwe.Ciphertext) {
	rQ, rQMul := eval.parameters.RingQ().AtLevel(level), eval.parameters.RQMul.AtLevel(levelQMul)
	for i := range ctQ0.Q {
		rQ.INTT(ctQ0.Q[i], eval.BuffQ[0])
		rQ.ModUp(rQMul, eval.BuffQ[0], eval.buffModUpQMul, ctQ1.Q[i])
		rQMul.NTTLazy(ctQ1.Q[i], ctQ1.Q[i])
	}
}

func (eval Evaluator) tensorLowDeg(level, levelQMul int, op0Q0, op1Q0, op2Q0, op0Q1, op1Q1, op2Q1 *rlwe.Ciphertext) {

	rQ, rQMul := eval.parameters.RingQ().AtLevel(level), eval.parameters.RQMul.AtLevel(levelQMul)

	c00 := eval.BuffQ[0]
	c01 := eval.BuffQ[1]

	rQ.MForm(op0Q0.Q[0], c00)
	rQ.MForm(op0Q0.Q[1], c01)

	c00M := eval.buffQMul[5]
	c01M := eval.buffQMul[6]

	rQMul.MForm(op0Q1.Q[0], c00M)
	rQMul.MForm(op0Q1.Q[1], c01M)

	// Squaring case
	if op0Q0.Vector == op1Q0.Vector {
		rQ.MulCoeffsMontgomery(c00, op0Q0.Q[0], op2Q0.Q[0]) // c0 = c0[0]*c0[0]
		rQ.MulCoeffsMontgomery(c01, op0Q0.Q[1], op2Q0.Q[2]) // c2 = c0[1]*c0[1]
		rQ.MulCoeffsMontgomery(c00, op0Q0.Q[1], op2Q0.Q[1]) // c1 = 2*c0[0]*c0[1]
		rQ.AddLazy(op2Q0.Q[1], op2Q0.Q[1], op2Q0.Q[1])

		rQMul.MulCoeffsMontgomery(c00M, op0Q1.Q[0], op2Q1.Q[0])
		rQMul.MulCoeffsMontgomery(c01M, op0Q1.Q[1], op2Q1.Q[2])
		rQMul.MulCoeffsMontgomery(c00M, op0Q1.Q[1], op2Q1.Q[1])
		rQMul.AddLazy(op2Q1.Q[1], op2Q1.Q[1], op2Q1.Q[1])

		// Normal case
	} else {
		rQ.MulCoeffsMontgomery(c00, op1Q0.Q[0], op2Q0.Q[0]) // c0 = c0[0]*c1[0]
		rQ.MulCoeffsMontgomery(c01, op1Q0.Q[1], op2Q0.Q[2]) // c2 = c0[1]*c1[1]
		rQ.MulCoeffsMontgomery(c00, op1Q0.Q[1], op2Q0.Q[1]) // c1 = c0[0]*c1[1] + c0[1]*c1[0]
		rQ.MulCoeffsMontgomeryThenAddLazy(c01, op1Q0.Q[0], op2Q0.Q[1])

		rQMul.MulCoeffsMontgomery(c00M, op1Q1.Q[0], op2Q1.Q[0])
		rQMul.MulCoeffsMontgomery(c01M, op1Q1.Q[1], op2Q1.Q[2])
		rQMul.MulCoeffsMontgomery(c00M, op1Q1.Q[1], op2Q1.Q[1])
		rQMul.MulCoeffsMontgomeryThenAddLazy(c01M, op1Q1.Q[0], op2Q1.Q[1])
	}
}

func (eval Evaluator) quantize(level, levelQMul int, c2Q1, c2Q2 ring.RNSPoly) {

	rQ, rQMul := eval.parameters.RingQ().AtLevel(level), eval.parameters.RQMul.AtLevel(levelQMul)

	// Applies the inverse NTT to the ciphertext, scales down the ciphertext
	// by t/q and reduces its basis from QP to Q

	rQ.INTTLazy(c2Q1, c2Q1)
	rQMul.INTTLazy(c2Q2, c2Q2)

	// Extends the basis Q of ct(x) to the basis P and Divides (ct(x)Q -> P) by Q
	rQMul.ModDown(rQ, c2Q2, c2Q1, eval.BuffModDownQ, eval.buffModUpQMul, c2Q2)

	// Centers ct(x)P by (P-1)/2 and extends ct(x)P to the basis Q
	rQMul.ModUp(rQ, c2Q2, eval.buffModUpQMul, c2Q1)

	// (ct(x)/Q)*T, doing so only requires that Q*P > Q*Q, faster but adds error ~|T|
	rQ.MulScalar(c2Q1, eval.parameters.PlaintextModulus(), c2Q1)

	rQ.NTT(c2Q1, c2Q1)
}

// MulThenAdd multiplies op0 with op1 using standard tensoring and without relinearization, and adds the result on op2.
// The procedure will return an error if either op0.Degree() or op1.Degree() > 1.
// The procedure will return an error if either op0 == op2 or op1 == op2.
//
// The following types are accepted for op1:
//   - [rlwe.Element]
//   - *big.Int, uint64, int64, int
//   - []uint64 or []int64 (of size at most N where N is the smallest integer satisfying PlaintextModulus = 1 mod 2N)
//
// If op1 is an [rlwe.Element] and op2.Scale != op1.Scale * op0.Scale, then a scale matching operation will
// be automatically carried out to ensure that addition is performed between operands of the same scale.
// This scale matching operation will increase the noise by a small factor.
// For this reason it is preferable to ensure that op2.Scale == op1.Scale * op0.Scale when calling this method.
func (eval Evaluator) MulThenAdd(op0 *rlwe.Ciphertext, op1 rlwe.Operand, op2 *rlwe.Ciphertext) (err error) {

	switch op1 := op1.(type) {
	case rlwe.Element:

		el := op1.AsCiphertext()

		_, level, err := eval.InitOutputBinaryOp(op0, el, 2, op2)
		if err != nil {
			return fmt.Errorf("cannot MulThenAdd: %w", err)
		}

		if op0.Vector == op2.Vector || el.Vector == op2.Vector {
			return fmt.Errorf("cannot MulThenAdd: op2 must be different from op0 and op1")
		}

		op2.ResizeQ(level)

		if err = eval.mulRelinThenAdd(op0, el, false, op2); err != nil {
			return fmt.Errorf("cannot MulThenAdd: %w", err)
		}

	case *big.Int:

		_, level, err := eval.InitOutputUnaryOp(op0, op2)

		if err != nil {
			return fmt.Errorf("cannot MulThenAdd: %w", err)
		}

		op2.ResizeQ(op2.Level())

		rQ := eval.parameters.RingQ().AtLevel(level)

		s := eval.parameters.RT

		// op1 *= (op1.Scale / op2.Scale)
		if op0.Scale.Cmp(op2.Scale) != 0 {
			ratio := ring.ModExp(op0.Scale.Uint64(), s.Phi()-1, s.Modulus)
			ratio = ring.BRed(ratio, op2.Scale.Uint64(), s.Modulus, s.BRedConstant)
			op1.Mul(op1, new(big.Int).SetUint64(ratio))
		}

		TBig := new(big.Int).SetUint64(s.Modulus)

		op1.Mod(op1, TBig)

		// If op1 > T/2 then subtract T to minimize the noise
		if op1.Cmp(new(big.Int).Rsh(TBig, 1)) == 1 {
			op1.Sub(op1, TBig)
		}

		for i := 0; i < op0.Degree()+1; i++ {
			rQ.MulScalarBigintThenAdd(op0.Q[i], op1, op2.Q[i])
		}

	case int:
		return eval.MulThenAdd(op0, new(big.Int).SetInt64(int64(op1)), op2)
	case int64:
		return eval.MulThenAdd(op0, new(big.Int).SetInt64(op1), op2)
	case uint64:
		return eval.MulThenAdd(op0, new(big.Int).SetUint64(op1), op2)
	case []uint64, []int64:

		_, level, err := eval.InitOutputUnaryOp(op0, op2)

		if err != nil {
			return fmt.Errorf("cannot MulThenAdd: %w", err)
		}

		op2.ResizeQ(op2.Level())

		// Instantiates new plaintext from buffer
		pt, err := rlwe.NewPlaintextAtLevelFromPoly(level, -1, eval.BuffQ[0], ring.RNSPoly{})

		// This error should not happen, unless the evaluator's buffer were
		// improperly tempered with. If it does happen, there is no way to
		// recover from it.
		if err != nil {
			panic(err)
		}
		pt.MetaData = op0.MetaData.Clone() // Sets the metadata, notably matches scales

		// op1 *= (op1.Scale / op2.Scale)
		if op0.Scale.Cmp(op2.Scale) != 0 {
			s := eval.parameters.RT
			ratio := ring.ModExp(op0.Scale.Uint64(), s.Phi()-1, s.Modulus)
			pt.Scale = rlwe.NewScale(ring.BRed(ratio, op2.Scale.Uint64(), s.Modulus, s.BRedConstant))
		} else {
			pt.Scale = rlwe.NewScale(1)
		}

		// Encodes the vector on the plaintext
		if err := eval.Encoder.Encode(op1, pt); err != nil {
			return fmt.Errorf("cannot MulThenAdd: %w", err)
		}

		if err = eval.MulThenAdd(op0, pt, op2); err != nil {
			return fmt.Errorf("cannot MulThenAdd: %w", err)
		}

	default:
		return fmt.Errorf("cannot MulThenAdd: invalid op1.(Type), expected rlwe.Element, []uint64, []int64, *big.Int, uint64, int64 or int, but got %T", op1)
	}

	return
}

// MulRelinThenAdd multiplies op0 with op1 using standard tensoring and with relinearization, and adds the result on op2.
// The procedure will return an error if either op0.Degree() or op1.Degree() > 1.
// The procedure will return an error if either op0 == op2 or op1 == op2.
//
// The following types are accepted for op1:
//   - [rlwe.Element]
//   - *big.Int, uint64, int64, int
//   - []uint64 or []int64 (of size at most N where N is the smallest integer satisfying PlaintextModulus = 1 mod 2N)
//
// If op1 is an [rlwe.Element] and op2.Scale != op1.Scale * op0.Scale, then a scale matching operation will
// be automatically carried out to ensure that addition is performed between operands of the same scale.
// This scale matching operation will increase the noise by a small factor.
// For this reason it is preferable to ensure that op2.Scale == op1.Scale * op0.Scale when calling this method.
func (eval Evaluator) MulRelinThenAdd(op0 *rlwe.Ciphertext, op1 rlwe.Operand, op2 *rlwe.Ciphertext) (err error) {
	switch op1 := op1.(type) {
	case rlwe.Element:
		if op1.Degree() == 0 {
			return eval.MulThenAdd(op0, op1, op2)
		} else {

			el := op1.AsCiphertext()

			_, level, err := eval.InitOutputBinaryOp(op0, el, 2, op2)
			if err != nil {
				return fmt.Errorf("cannot MulThenAdd: %w", err)
			}

			if op0.Vector == op2.Vector || el.Vector == op2.Vector {
				return fmt.Errorf("cannot MulThenAdd: op2 must be different from op0 and op1")
			}

			op2.ResizeQ(level)

			return eval.mulRelinThenAdd(op0, el, true, op2)
		}
	default:
		return eval.MulThenAdd(op0, op1, op2)
	}
}

func (eval Evaluator) mulRelinThenAdd(op0, op1 *rlwe.Ciphertext, relin bool, op2 *rlwe.Ciphertext) (err error) {

	level := op2.Level()

	rQ := eval.parameters.RingQ().AtLevel(level)
	sT := eval.parameters.RT

	var c00, c01, c0, c1, c2 ring.RNSPoly

	// Case Ciphertext (x) Ciphertext
	if op0.Degree() == 1 && op1.Degree() == 1 {

		c00 = eval.BuffQ[0]
		c01 = eval.BuffQ[1]

		c0 = op2.Q[0]
		c1 = op2.Q[1]

		if !relin {
			op2.ResizeQ(level)
			op2.ResizeDegree(2)
			c2 = op2.Q[2]
		} else {
			op2.ResizeQ(level)
			op2.ResizeDegree(max(1, op2.Degree()))
			c2 = eval.BuffQ[2]
		}

		tmp0, tmp1 := op0, op1

		// If op0.Scale * op1.Scale != op2.Scale then
		// updates op1.Scale and op2.Scale
		var r0 uint64 = 1
		if targetScale := ring.BRed(op0.Scale.Uint64(), op1.Scale.Uint64(), sT.Modulus, sT.BRedConstant); op2.Scale.Cmp(eval.parameters.NewScale(targetScale)) != 0 {
			var r1 uint64
			r0, r1, _ = eval.matchScalesBinary(targetScale, op2.Scale.Uint64())

			for i := range op2.Q {
				rQ.MulScalar(op2.Q[i], r1, op2.Q[i])
			}

			op2.Scale = op2.Scale.Mul(eval.parameters.NewScale(r1))
		}

		// Multiply by T * 2^{64} * 2^{64} -> result multipled by T and switched in the Montgomery domain
		rQ.MulRNSScalarMontgomery(tmp0.Q[0], eval.tMontgomery, c00)
		rQ.MulRNSScalarMontgomery(tmp0.Q[1], eval.tMontgomery, c01)

		// Scales the input to the output scale
		if r0 != 1 {
			rQ.MulScalar(c00, r0, c00)
			rQ.MulScalar(c01, r0, c01)
		}

		rQ.MulCoeffsMontgomeryThenAdd(c00, tmp1.Q[0], c0) // c0 += c[0]*c[0]
		rQ.MulCoeffsMontgomeryThenAdd(c00, tmp1.Q[1], c1) // c1 += c[0]*c[1]
		rQ.MulCoeffsMontgomeryThenAdd(c01, tmp1.Q[0], c1) // c1 += c[1]*c[0]

		if relin {
			rQ.MulCoeffsMontgomery(c01, tmp1.Q[1], c2) // c2 += c[1]*c[1]
			if err := eval.RelinearizeInplace(op2, c2); err != nil {
				return fmt.Errorf("eval.RelinearizeInplace: %w", err)
			}
		} else {
			rQ.MulCoeffsMontgomeryThenAdd(c01, tmp1.Q[1], c2) // c2 += c[1]*c[1]
		}

		// Case Plaintext (x) Ciphertext or Ciphertext (x) Plaintext
	} else {

		op2.ResizeQ(level)
		op2.ResizeDegree(max(op0.Degree(), op2.Degree()))

		c00 := eval.BuffQ[0]

		// Multiply by T * 2^{64} * 2^{64} -> result multipled by T and switched in the Montgomery domain
		rQ.MulRNSScalarMontgomery(op1.Q[0], eval.tMontgomery, c00)

		// If op0.Scale * op1.Scale != op2.Scale then
		// updates op1.Scale and op2.Scale
		var r0 = uint64(1)
		if targetScale := ring.BRed(op0.Scale.Uint64(), op1.Scale.Uint64(), sT.Modulus, sT.BRedConstant); op2.Scale.Cmp(eval.parameters.NewScale(targetScale)) != 0 {
			var r1 uint64
			r0, r1, _ = eval.matchScalesBinary(targetScale, op2.Scale.Uint64())

			for i := range op2.Q {
				rQ.MulScalar(op2.Q[i], r1, op2.Q[i])
			}

			op2.Scale = op2.Scale.Mul(eval.parameters.NewScale(r1))
		}

		if r0 != 1 {
			rQ.MulScalar(c00, r0, c00)
		}

		for i := range op0.Q {
			rQ.MulCoeffsMontgomeryThenAdd(op0.Q[i], c00, op2.Q[i])
		}
	}

	return
}

// Rescale divides (rounded) op0 by the last prime of the moduli chain and returns the result on op2.
// This procedure divides the noise by the last prime of the moduli chain while preserving
// the MSB-plaintext bits.
// The procedure will return an error if:
//   - op0.Level() == 0 (the input ciphertext is already at the last prime)
//   - op2.Level() < op0.Level() - 1 (not enough space to store the result)
//
// The scale of op2 will be updated to op0.Scale * qi^{-1} mod PlaintextModulus where qi is the prime consumed by
// the rescaling operation.
func (eval Evaluator) Rescale(op0, op2 *rlwe.Ciphertext) (err error) {

	if op0.MetaData == nil || op2.MetaData == nil {
		return fmt.Errorf("cannot Rescale: op0.MetaData or op2.MetaData is nil")
	}

	if op0.Level() == 0 {
		return fmt.Errorf("cannot rescale: op0 already at level 0")
	}

	if op2.Level() < op0.Level()-1 {
		return fmt.Errorf("cannot rescale: op2.Level() < op0.Level()-1")
	}

	level := op0.Level()
	rQ := eval.parameters.RingQ().AtLevel(level)

	for i := range op2.Q {
		rQ.DivRoundByLastModulusNTT(op0.Q[i], eval.BuffQ[0], op2.Q[i])
	}

	op2.ResizeQ(level - 1)

	*op2.MetaData = *op0.MetaData
	op2.Scale = op0.Scale.Div(eval.parameters.NewScale(rQ[level].Modulus))
	return
}

// RelinearizeNew applies the relinearization procedure on op0 and returns the result in a new op1.
func (eval Evaluator) RelinearizeNew(op0 *rlwe.Ciphertext) (op1 *rlwe.Ciphertext, err error) {
	op1 = NewCiphertext(eval.parameters, 1, op0.Level())
	return op1, eval.Relinearize(op0, op1)
}

// ApplyEvaluationKeyNew re-encrypts op0 under a different key and returns the result in a new op1.
// It requires a EvaluationKey, which is computed from the key under which the Ciphertext is currently encrypted,
// and the key under which the Ciphertext will be re-encrypted.
// The procedure will return an error if either op0.Degree() or op1.Degree() != 1.
func (eval Evaluator) ApplyEvaluationKeyNew(op0 *rlwe.Ciphertext, evk *rlwe.EvaluationKey) (op1 *rlwe.Ciphertext, err error) {
	op1 = NewCiphertext(eval.parameters, op0.Degree(), op0.Level())
	return op1, eval.ApplyEvaluationKey(op0, evk, op1)
}

// RotateColumnsNew rotates the columns of op0 by k positions to the left, and returns the result in a newly created element.
// The procedure will return an error if the corresponding Galois key has not been generated and attributed to the evaluator.
// The procedure will return an error if op0.Degree() != 1.
func (eval Evaluator) RotateColumnsNew(op0 *rlwe.Ciphertext, k int) (op1 *rlwe.Ciphertext, err error) {
	op1 = NewCiphertext(eval.parameters, op0.Degree(), op0.Level())
	return op1, eval.RotateColumns(op0, k, op1)
}

// RotateColumns rotates the columns of op0 by k positions to the left and returns the result in op1.
// The procedure will return an error if the corresponding Galois key has not been generated and attributed to the evaluator.
// The procedure will return an error if either op0.Degree() or op1.Degree() != 1.
func (eval Evaluator) RotateColumns(op0 *rlwe.Ciphertext, k int, op1 *rlwe.Ciphertext) (err error) {
	return eval.Automorphism(op0, eval.parameters.GaloisElement(k), op1)
}

// RotateRowsNew swaps the rows of op0 and returns the result in a new op1.
// The procedure will return an error if the corresponding Galois key has not been generated and attributed to the evaluator.
// The procedure will return an error if op0.Degree() != 1.
func (eval Evaluator) RotateRowsNew(op0 *rlwe.Ciphertext) (op1 *rlwe.Ciphertext, err error) {
	op1 = NewCiphertext(eval.parameters, op0.Degree(), op0.Level())
	return op1, eval.RotateRows(op0, op1)
}

// RotateRows swaps the rows of op0 and returns the result in op1.
// The procedure will return an error if the corresponding Galois key has not been generated and attributed to the evaluator.
// The procedure will return an error if either op0.Degree() or op1.Degree() != 1.
func (eval Evaluator) RotateRows(op0, op1 *rlwe.Ciphertext) (err error) {
	return eval.Automorphism(op0, eval.parameters.GaloisElementForRowRotation(), op1)
}

// RotateHoistedLazyNew applies a series of rotations on the same ciphertext and returns each different rotation in a map indexed by the rotation.
// Results are not rescaled by P.
func (eval Evaluator) RotateHoistedLazyNew(level int, rotations []int, op0 *rlwe.Ciphertext, buf rlwe.HoistingBuffer) (op1 map[int]*rlwe.Ciphertext, err error) {
	op1 = make(map[int]*rlwe.Ciphertext)
	for _, i := range rotations {
		if i != 0 {
			op1[i] = rlwe.NewCiphertext(eval.parameters, 1, level, eval.parameters.MaxLevelP())
			if err = eval.AutomorphismHoistedLazy(level, op0, buf, eval.parameters.GaloisElement(i), op1[i]); err != nil {
				return
			}
		}
	}

	return
}

// MatchScalesAndLevel updates the both input ciphertexts to ensures that their scale matches.
// To do so it computes t0 * a = op1 * b such that:
//   - op0.Scale * a = op1.Scale: make the scales match.
//   - gcd(a, PlaintextModulus) == gcd(b, PlaintextModulus) == 1: ensure that the new scale is not a zero divisor if PlaintextModulus is not prime.
//   - |a+b| is minimal: minimize the added noise by the procedure.
func (eval Evaluator) MatchScalesAndLevel(op0, op1 *rlwe.Ciphertext) {

	r0, r1, _ := eval.matchScalesBinary(op0.Scale.Uint64(), op1.Scale.Uint64())

	level := min(op0.Level(), op1.Level())

	rQ := eval.parameters.RingQ().AtLevel(level)

	for _, el := range op0.Q {
		rQ.MulScalar(el, r0, el)
	}

	op0.ResizeQ(level)
	op0.Scale = op0.Scale.Mul(eval.parameters.NewScale(r0))

	for _, el := range op1.Q {
		rQ.MulScalar(el, r1, el)
	}

	op1.ResizeQ(level)
	op1.Scale = op1.Scale.Mul(eval.parameters.NewScale(r1))
}

func (eval Evaluator) GetRLWEParameters() *rlwe.Parameters {
	return eval.Evaluator.GetRLWEParameters()
}

func (eval Evaluator) matchScalesBinary(scale0, scale1 uint64) (r0, r1, e uint64) {

	rT := eval.parameters.RT

	t := rT.Modulus
	tHalf := t >> 1
	BRedConstant := rT.BRedConstant

	// This should never happen and if it were to happen,
	// there is no way to recovernfrom it.
	if utils.GCD(scale0, t) != 1 {
		panic("cannot matchScalesBinary: invalid ciphertext scale: gcd(scale, t) != 1")
	}

	var a = t
	var b uint64 = 0
	var A = ring.BRed(ring.ModExp(scale0, rT.Phi()-1, t), scale1, t, BRedConstant)
	var B uint64 = 1

	r0, r1 = A, B

	e = center(A, tHalf, t) + 1

	for A != 0 {

		q := a / A
		a, A = A, a%A
		b, B = B, ring.CRed(t+b-ring.BRed(B, q, t, BRedConstant), t)

		if A != 0 && utils.GCD(A, t) == 1 {
			tmp := center(A, tHalf, t) + center(B, tHalf, t)
			if tmp < e {
				e = tmp
				r0, r1 = A, B
			}
		}
	}

	return
}

func center(x, thalf, t uint64) uint64 {
	if x >= thalf {
		return t - x
	}
	return x
}
