package hefloat

import (
	"fmt"
	"math/big"

	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/bignum"
)

// Evaluator is a struct that holds the necessary elements to execute the homomorphic operations between Ciphertexts and/or Plaintexts.
// It also holds a memory buffer used to store intermediate computations.
type Evaluator struct {
	*Encoder
	*rlwe.Evaluator
}

// NewEvaluator creates a new Evaluator, that can be used to do homomorphic
// operations on the Ciphertexts and/or Plaintexts. It stores a memory buffer
// and Ciphertexts that will be used for intermediate values.
func NewEvaluator(params Parameters, evk rlwe.EvaluationKeySet) *Evaluator {
	return &Evaluator{
		Encoder:   NewEncoder(params),
		Evaluator: rlwe.NewEvaluator(params, evk),
	}
}

// GetRLWEParameters returns a pointer to the underlying rlwe.Parameters.
func (eval *Evaluator) GetRLWEParameters() *rlwe.Parameters {
	return &eval.Encoder.parameters.Parameters
}

// LevelsConsumedPerRescaling returns the number of level consumed by a rescaling.
func (eval *Evaluator) LevelsConsumedPerRescaling() int {
	return eval.Parameters().LevelsConsumedPerRescaling()
}

// MatchScalesForMul updates the scale of either op0 or op1 if op0.Level() > op1.Level() or op1.Level() > op0.Level()
// respectively, such taht Rescale(Mul(op0, op1)).Scale = targetScale.
// If op0.Level() == op1.Scale() nothing is done.
func (eval *Evaluator) MatchScalesForMul(op0, op1 *rlwe.Ciphertext, targetScale rlwe.Scale) (err error) {
	if op0.Level() > op1.Level() {
		if err = eval.SetScale(op0, eval.Parameters().GetScalingFactor(op1.Scale, targetScale, op1.Level())); err != nil {
			return
		}
	} else if op1.Level() > op0.Level() {
		if err = eval.SetScale(op1, eval.Parameters().GetScalingFactor(op0.Scale, targetScale, op0.Level())); err != nil {
			return
		}
	}
	return
}

// Add adds op1 to op0 and returns the result in opOut.
// The following types are accepted for op1:
//   - rlwe.Element
//   - [he.Float], [he.Complex] or [he.Integer]
//   - []complex128, []float64, []big.Float or []bignum.Complex of size at most params.MaxSlots()
//
// Passing an invalid type will return an error.
func (eval *Evaluator) Add(op0 *rlwe.Ciphertext, op1 rlwe.Operand, opOut *rlwe.Ciphertext) (err error) {
	return eval.addition(op0, op1, opOut, true)
}

// AddNew adds op1 to op0 and returns the result in a newly created element opOut.
// The following types are accepted for op1:
//   - rlwe.Element
//   - [he.Complex], [he.Float], [he.Int]
//   - []complex128, []float64, []big.Float or []bignum.Complex of size at most params.MaxSlots()
//
// Passing an invalid type will return an error.
func (eval *Evaluator) AddNew(op0 *rlwe.Ciphertext, op1 rlwe.Operand) (opOut *rlwe.Ciphertext, err error) {
	opOut = NewCiphertext(eval.Parameters(), op0.Degree(), op0.Level())
	return opOut, eval.Add(op0, op1, opOut)
}

// Sub subtracts op1 from op0 and returns the result in opOut.
// The following types are accepted for op1:
//   - rlwe.Element
//   - [he.Complex], [he.Float], [he.Int]
//   - []complex128, []float64, []big.Float or []bignum.Complex of size at most params.MaxSlots()
//
// Passing an invalid type will return an error.
func (eval *Evaluator) Sub(op0 *rlwe.Ciphertext, op1 rlwe.Operand, opOut *rlwe.Ciphertext) (err error) {
	return eval.addition(op0, op1, opOut, false)
}

// SubNew subtracts op1 from op0 and returns the result in a newly created element opOut.
// The following types are accepted for op1:
//   - rlwe.Element
//   - [he.Complex], [he.Float], [he.Int]
//   - []complex128, []float64, []big.Float or []bignum.Complex of size at most params.MaxSlots()
//
// Passing an invalid type will return an error.
func (eval *Evaluator) SubNew(op0 *rlwe.Ciphertext, op1 rlwe.Operand) (opOut *rlwe.Ciphertext, err error) {
	opOut = NewCiphertext(eval.Parameters(), op0.Degree(), op0.Level())
	return opOut, eval.Sub(op0, op1, opOut)
}

func (eval *Evaluator) addition(op0 *rlwe.Ciphertext, op1 rlwe.Operand, opOut *rlwe.Ciphertext, positive bool) (err error) {

	switch op1 := op1.(type) {
	case rlwe.Element:

		// Checks operand validity and retrieves minimum level
		degree, level, err := eval.InitOutputBinaryOp(op0, op1.AsCiphertext(), op0.Degree()+op1.Degree(), opOut)
		if err != nil {
			return fmt.Errorf("eval.InitOutputBinaryOp: %w", err)
		}

		opOut.ResizeQ(level)
		opOut.ResizeDegree(degree)

		// Generic inplace evaluation
		if positive {
			eval.evaluateInPlace(level, op0, op1.AsCiphertext(), opOut, eval.Parameters().RingQ().AtLevel(level).Add)
		} else {
			eval.evaluateInPlace(level, op0, op1.AsCiphertext(), opOut, eval.Parameters().RingQ().AtLevel(level).Sub)
		}

	case complex128, float64, int, int64, uint, uint64, big.Int, big.Float, bignum.Complex, *big.Int, *big.Float, *bignum.Complex:

		_, level, err := eval.InitOutputUnaryOp(op0, opOut)
		if err != nil {
			return fmt.Errorf("eval.InitOutputUnaryOp: %w", err)
		}

		opOut.ResizeQ(level)
		opOut.ResizeDegree(op0.Degree())

		// Convertes the scalar to a complex RNS scalar
		RNSReal, RNSImag := bigComplexToRNSScalar(eval.Parameters().RingQ().AtLevel(level), &op0.Scale.Value, bignum.ToComplex(op1, eval.Parameters().EncodingPrecision()))

		// Generic inplace evaluation
		if positive {
			eval.evaluateWithScalar(level, op0.Q[:1], RNSReal, RNSImag, opOut.Q[:1], eval.Parameters().RingQ().AtLevel(level).AddDoubleRNSScalar)
		} else {
			eval.evaluateWithScalar(level, op0.Q[:1], RNSReal, RNSImag, opOut.Q[:1], eval.Parameters().RingQ().AtLevel(level).SubDoubleRNSScalar)
		}

		if op0.Vector != opOut.Vector {
			for i := 1; i < len(opOut.Q); i++ {
				opOut.Q[i].CopyLvl(level, &op0.Q[i]) // Resize step ensures identical size
			}
		}

	case []complex128, []float64, []big.Float, []bignum.Complex:

		_, level, err := eval.InitOutputUnaryOp(op0, opOut)
		if err != nil {
			return fmt.Errorf("eval.InitOutputUnaryOp: %w", err)
		}

		opOut.ResizeQ(level)
		opOut.ResizeDegree(op0.Degree())

		// Instantiates new plaintext from buffer
		pt, err := rlwe.NewPlaintextAtLevelFromPoly(level, -1, eval.BuffQ[0], ring.RNSPoly{})

		// Sanity check, this error should not happen unless the evaluator's buffers
		// were improperly tempered with.
		if err != nil {
			panic(err)
		}

		pt.MetaData = op0.MetaData // Sets the metadata, notably matches scales

		// Encodes the vector on the plaintext
		if err := eval.Encode(op1, pt); err != nil {
			return fmt.Errorf("eval.Encode: %w", err)
		}

		// Generic in place evaluation
		if positive {
			eval.evaluateInPlace(level, op0, pt.AsCiphertext(), opOut, eval.Parameters().RingQ().AtLevel(level).Add)
		} else {
			eval.evaluateInPlace(level, op0, pt.AsCiphertext(), opOut, eval.Parameters().RingQ().AtLevel(level).Sub)
		}
	default:
		return fmt.Errorf("invalid op1.(type): must be rlwe.Element, he.Float, he.Complex or he.Integer, []complex128, []float64, []big.Float or []bignum.Complex, but is %T", op1)
	}

	return
}

func (eval *Evaluator) evaluateInPlace(level int, c0, c1, opOut *rlwe.Ciphertext, evaluate func(ring.RNSPoly, ring.RNSPoly, ring.RNSPoly)) {

	var tmp0, tmp1 *rlwe.Ciphertext

	maxDegree := max(c0.Degree(), c1.Degree())
	minDegree := min(c0.Degree(), c1.Degree())

	c0Scale := c0.Scale
	c1Scale := c1.Scale

	cmp := c0.Scale.Cmp(c1.Scale)

	var err error

	// Checks whether or not the receiver element is the same as one of the input elements
	// and acts accordingly to avoid unnecessary element creation or element overwriting,
	// and scales properly the element before the evaluation.
	if opOut.Vector == c0.Vector {

		if cmp == 1 {

			ratioFlo := c0Scale.Div(c1Scale).Value

			ratioInt, _ := ratioFlo.Int(nil)

			if ratioInt.Cmp(new(big.Int).SetUint64(0)) == 1 {

				tmp1, err = rlwe.NewCiphertextAtLevelFromPoly(level, -1, eval.BuffCt.Q[:c1.Degree()+1], []ring.RNSPoly{})

				// Sanity check, this error should not happen unless the evaluator's buffers
				// were improperly tempered with.
				if err != nil {
					panic(err)
				}
				*tmp1.MetaData = *opOut.MetaData

				if err = eval.Mul(c1, ratioInt, tmp1); err != nil {
					return
				}
			}

		} else if cmp == -1 {

			ratioFlo := c1Scale.Div(c0Scale).Value

			ratioInt, _ := ratioFlo.Int(nil)

			if ratioInt.Cmp(new(big.Int).SetUint64(0)) == 1 {

				if err = eval.Mul(c0, ratioInt, c0); err != nil {
					return
				}

				opOut.Scale = c1.Scale

				tmp1 = c1
			}

		} else {
			tmp1 = c1
		}

		tmp0 = c0

	} else if opOut.Vector == c1.Vector {

		if cmp == 1 {

			ratioFlo := c0Scale.Div(c1Scale).Value

			ratioInt, _ := ratioFlo.Int(nil)

			if ratioInt.Cmp(new(big.Int).SetUint64(0)) == 1 {
				if err = eval.Mul(c1, ratioInt, opOut); err != nil {
					return
				}

				opOut.Scale = c0.Scale

				tmp0 = c0
			}

		} else if cmp == -1 {

			ratioFlo := c1Scale.Div(c0Scale).Value

			ratioInt, _ := ratioFlo.Int(nil)

			if ratioInt.Cmp(new(big.Int).SetUint64(0)) == 1 {
				// Will avoid resizing on the output
				tmp0, err = rlwe.NewCiphertextAtLevelFromPoly(level, -1, eval.BuffCt.Q[:c0.Degree()+1], []ring.RNSPoly{})

				// Sanity check, this error should not happen unless the evaluator's buffers
				// were improperly tempered with.
				if err != nil {
					panic(err)
				}
				*tmp0.MetaData = *opOut.MetaData

				if err = eval.Mul(c0, ratioInt, tmp0); err != nil {
					return
				}
			}

		} else {
			tmp0 = c0
		}

		tmp1 = c1

	} else {

		if cmp == 1 {

			ratioFlo := c0Scale.Div(c1Scale).Value

			ratioInt, _ := ratioFlo.Int(nil)

			if ratioInt.Cmp(new(big.Int).SetUint64(0)) == 1 {
				// Will avoid resizing on the output
				tmp1, err = rlwe.NewCiphertextAtLevelFromPoly(level, -1, eval.BuffCt.Q[:c1.Degree()+1], []ring.RNSPoly{})

				// Sanity check, this error should not happen unless the evaluator's buffers
				// were improperly tempered with.
				if err != nil {
					panic(err)
				}
				*tmp1.MetaData = *opOut.MetaData

				if err = eval.Mul(c1, ratioInt, tmp1); err != nil {
					return
				}

				tmp0 = c0
			}

		} else if cmp == -1 {

			ratioFlo := c1Scale.Div(c0Scale).Value

			ratioInt, _ := ratioFlo.Int(nil)

			if ratioInt.Cmp(new(big.Int).SetUint64(0)) == 1 {

				tmp0, err = rlwe.NewCiphertextAtLevelFromPoly(level, -1, eval.BuffCt.Q[:c0.Degree()+1], []ring.RNSPoly{})

				// Sanity check, this error should not happen unless the evaluator's buffers
				// were improperly tempered with.
				if err != nil {
					panic(err)
				}
				*tmp0.MetaData = *opOut.MetaData

				if err = eval.Mul(c0, ratioInt, tmp0); err != nil {
					return
				}

				tmp1 = c1

			}

		} else {
			tmp0 = c0
			tmp1 = c1
		}
	}

	for i := 0; i < minDegree+1; i++ {
		evaluate(tmp0.Q[i], tmp1.Q[i], opOut.Q[i])
	}

	opOut.Scale = c0.Scale.Max(c1.Scale)

	// If the inputs degrees differ, it copies the remaining degree on the receiver.
	// Also checks that the receiver is not one of the inputs to avoid unnecessary work.

	if c0.Degree() > c1.Degree() && tmp0.Vector != opOut.Vector {
		for i := minDegree + 1; i < maxDegree+1; i++ {
			opOut.Q[i].CopyLvl(level, &tmp0.Q[i])
		}
	} else if c1.Degree() > c0.Degree() && tmp1.Vector != opOut.Vector {
		for i := minDegree + 1; i < maxDegree+1; i++ {
			opOut.Q[i].CopyLvl(level, &tmp1.Q[i])
		}
	}
}

func (eval *Evaluator) evaluateWithScalar(level int, p0 []ring.RNSPoly, RNSReal, RNSImag ring.RNSScalar, p1 []ring.RNSPoly, evaluate func(ring.RNSPoly, ring.RNSScalar, ring.RNSScalar, ring.RNSPoly)) {

	// Component wise operation with the following vector:
	// [a + b*psi_qi^2, ....., a + b*psi_qi^2, a - b*psi_qi^2, ...., a - b*psi_qi^2] mod Qi
	// [{                  N/2                }{                N/2               }]
	// Which is equivalent outside of the NTT domain to evaluating a to the first coefficient of op0 and b to the N/2-th coefficient of op0.
	for i, s := range eval.Parameters().RingQ().AtLevel(level) {
		RNSImag[i] = ring.MRed(RNSImag[i], s.RootsForward[1], s.Modulus, s.MRedConstant)
		RNSReal[i], RNSImag[i] = ring.CRed(RNSReal[i]+RNSImag[i], s.Modulus), ring.CRed(RNSReal[i]+s.Modulus-RNSImag[i], s.Modulus)
	}

	for i := range p0 {
		evaluate(p0[i], RNSReal, RNSImag, p1[i])
	}
}

// ScaleUpNew multiplies op0 by scale and sets its scale to its previous scale times scale returns the result in opOut.
func (eval *Evaluator) ScaleUpNew(op0 *rlwe.Ciphertext, scale rlwe.Scale) (opOut *rlwe.Ciphertext, err error) {
	opOut = NewCiphertext(eval.Parameters(), op0.Degree(), op0.Level())
	return opOut, eval.ScaleUp(op0, scale, opOut)
}

// ScaleUp multiplies op0 by scale and sets its scale to its previous scale times scale returns the result in opOut.
func (eval *Evaluator) ScaleUp(op0 *rlwe.Ciphertext, scale rlwe.Scale, opOut *rlwe.Ciphertext) (err error) {

	if err = eval.Mul(op0, scale.Uint64(), opOut); err != nil {
		return fmt.Errorf("cannot ScaleUp: %w", err)
	}

	opOut.Scale = op0.Scale.Mul(scale)

	return
}

// SetScale sets the scale of the ciphertext to the input scale (consumes a level).
func (eval *Evaluator) SetScale(ct *rlwe.Ciphertext, scale rlwe.Scale) (err error) {
	ratioFlo := scale.Div(ct.Scale).Value
	if err = eval.Mul(ct, &ratioFlo, ct); err != nil {
		return fmt.Errorf("cannot SetScale: %w", err)
	}
	if err = eval.Rescale(ct, ct); err != nil {
		return fmt.Errorf("cannot SetScale: %w", err)
	}
	ct.Scale = scale
	return
}

// DropLevelNew reduces the level of op0 by levels and returns the result in a newly created element.
// No rescaling is applied during this procedure.
func (eval *Evaluator) DropLevelNew(op0 *rlwe.Ciphertext, levels int) (opOut *rlwe.Ciphertext) {
	opOut = op0.Clone()
	eval.DropLevel(opOut, levels)
	return
}

// DropLevel reduces the level of op0 by levels and returns the result in op0.
// No rescaling is applied during this procedure.
func (eval *Evaluator) DropLevel(op0 *rlwe.Ciphertext, levels int) {
	op0.ResizeQ(op0.Level() - levels)
}

// Rescale divides op0 by the last prime of the moduli chain and repeats this procedure
// params.LevelsConsumedPerRescaling() times.
//
// Returns an error if:
//   - Either op0 or opOut MetaData are nil
//   - The level of op0 is too low to enable a rescale
func (eval *Evaluator) Rescale(op0, opOut *rlwe.Ciphertext) (err error) {

	if op0.MetaData == nil || opOut.MetaData == nil {
		return fmt.Errorf("cannot Rescale: op0.MetaData or opOut.MetaData is nil")
	}

	params := eval.Parameters()

	nbRescales := params.LevelsConsumedPerRescaling()

	if op0.Level() <= nbRescales-1 {
		return fmt.Errorf("cannot Rescale: input Ciphertext level is too low")
	}

	eval.divroundbylastmoduli(nbRescales, op0, opOut)

	return
}

// RescaleTo divides op0 by the last prime in the moduli chain, and repeats this procedure (consuming one level each time)
// and stops if the scale reaches `minScale` or if it would go below `minscale/2`, and returns the result in opOut.
// Returns an error if:
// - minScale <= 0
// - ct.Scale <= 0
// - ct.Level() = 0
func (eval *Evaluator) RescaleTo(op0 *rlwe.Ciphertext, minScale rlwe.Scale, opOut *rlwe.Ciphertext) (err error) {

	if op0.MetaData == nil || opOut.MetaData == nil {
		return fmt.Errorf("cannot RescaleTo: op0.MetaData or opOut.MetaData is nil")
	}

	if minScale.Cmp(rlwe.NewScale(0)) != 1 {
		return fmt.Errorf("cannot RescaleTo: minScale is <0")
	}

	minScale = minScale.Div(rlwe.NewScale(2))

	if op0.Scale.Cmp(rlwe.NewScale(0)) != 1 {
		return fmt.Errorf("cannot RescaleTo: ciphertext scale is <0")
	}

	if op0.Level() == 0 {
		return fmt.Errorf("cannot RescaleTo: input Ciphertext already at level 0")
	}

	*opOut.MetaData = *op0.MetaData

	newLevel := op0.Level()

	rQ := eval.Parameters().RingQ().AtLevel(op0.Level())

	// Divides the scale by each moduli of the modulus chain as long as the scale isn't smaller than minScale/2
	// or until the output Level() would be zero
	scale := opOut.Scale
	var nbRescales int
	for newLevel >= 0 {

		scale = scale.Div(rlwe.NewScale(rQ[newLevel].Modulus))

		if scale.Cmp(minScale) == -1 {
			break
		}

		nbRescales++
		newLevel--
	}

	eval.divroundbylastmoduli(nbRescales, op0, opOut)

	return nil
}

func (eval *Evaluator) divroundbylastmoduli(nbRescales int, op0, op1 *rlwe.Ciphertext) {

	rQ := eval.parameters.RingQ().AtLevel(op0.Level())

	if op0.Vector != op1.Vector {
		op1.ResizeQ(op0.Level() - nbRescales)
		*op1.MetaData = *op0.MetaData
	}

	if nbRescales > 0 {

		for i := range nbRescales {
			op1.Scale = op1.Scale.Div(rlwe.NewScale(rQ[op0.Level()-i].Modulus))
		}

		for i := range op1.Q {
			rQ.DivRoundByLastModulusManyNTT(nbRescales, op0.Q[i], eval.BuffQ[0], op1.Q[i])
		}
		op1.ResizeQ(op0.Level() - nbRescales)
	} else {
		if op0.Vector != op1.Vector {
			op1.Copy(op0)
		}
	}
}

// MulNew multiplies op0 with op1 without relinearization and returns the result in a newly created element opOut.
//
// op1.(type) can be
//   - rlwe.Element
//   - [he.Complex], [he.Float], [he.Int]
//   - []complex128, []float64, []big.Float or []bignum.Complex of size at most params.MaxSlots()
//
// If op1.(type) == rlwe.Element:
//   - The procedure will return an error if either op0.Degree or op1.Degree > 1.
func (eval *Evaluator) MulNew(op0 *rlwe.Ciphertext, op1 rlwe.Operand) (opOut *rlwe.Ciphertext, err error) {
	opOut = NewCiphertext(eval.Parameters(), op0.Degree(), op0.Level())
	return opOut, eval.Mul(op0, op1, opOut)
}

// Mul multiplies op0 with op1 without relinearization and returns the result in opOut.
//
// The following types are accepted for op1:
//   - rlwe.Element
//   - [he.Complex], [he.Float], [he.Int]
//   - []complex128, []float64, []big.Float or []bignum.Complex of size at most params.MaxSlots()
//
// Passing an invalid type will return an error.
//
// If op1.(type) == rlwe.Element:
//   - The procedure will return an error if either op0 or op1 are have a degree higher than 1.
//   - The procedure will return an error if opOut.Degree != op0.Degree + op1.Degree.
func (eval *Evaluator) Mul(op0 *rlwe.Ciphertext, op1 rlwe.Operand, opOut *rlwe.Ciphertext) (err error) {
	switch op1 := op1.(type) {
	case rlwe.Element:

		el := op1.AsCiphertext()

		_, level, err := eval.InitOutputBinaryOp(op0, el, 2, opOut)
		if err != nil {
			return fmt.Errorf("eval.InitOutputBinaryOp: %w", err)
		}

		opOut.ResizeQ(level)

		// Generic in place evaluation
		if err = eval.mulRelin(op0, el, false, opOut); err != nil {
			return fmt.Errorf("eval.mulRelin: %w", err)
		}

	case complex128, float64, int, int64, uint, uint64, *big.Int, *big.Float, *bignum.Complex, big.Int, big.Float, bignum.Complex:

		_, level, err := eval.InitOutputUnaryOp(op0, opOut)
		if err != nil {
			return fmt.Errorf("cannot Mul: %w", err)
		}

		opOut.ResizeQ(level)
		opOut.ResizeDegree(op0.Degree())

		// Convertes the scalar to a *bignum.Complex
		cmplxBig := bignum.ToComplex(op1, eval.Parameters().EncodingPrecision())

		// Gets the ring at the target level
		rQ := eval.Parameters().RingQ().AtLevel(level)

		var scale rlwe.Scale
		if cmplxBig.IsInt() {
			scale = rlwe.NewScale(1) // Scalar is a GaussianInteger, thus no scaling required
		} else {
			scale = rlwe.NewScale(rQ[level].Modulus) // Current modulus scaling factor

			// If DefaultScalingFactor > 2^60, then multiple moduli are used per single rescale
			// thus continues multiplying the scale with the appropriate number of moduli
			for i := 1; i < eval.Parameters().LevelsConsumedPerRescaling(); i++ {
				scale = scale.Mul(rlwe.NewScale(rQ[level-i].Modulus))
			}
		}

		// Convertes the *bignum.Complex to a complex RNS scalar
		RNSReal, RNSImag := bigComplexToRNSScalar(rQ, &scale.Value, cmplxBig)

		// Generic in place evaluation
		eval.evaluateWithScalar(level, op0.Q, RNSReal, RNSImag, opOut.Q, rQ.MulDoubleRNSScalar)

		// Copies the metadata on the output
		opOut.Scale = op0.Scale.Mul(scale) // updates the scaling factor

		return nil

	case []complex128, []float64, []big.Float, []bignum.Complex:

		_, level, err := eval.InitOutputUnaryOp(op0, opOut)
		if err != nil {
			return fmt.Errorf("cannot Mul: %w", err)
		}

		opOut.ResizeQ(level)
		opOut.ResizeDegree(op0.Degree())

		// Gets the ring at the target level
		rQ := eval.Parameters().RingQ().AtLevel(level)

		// Instantiates new plaintext from buffer
		pt, err := rlwe.NewPlaintextAtLevelFromPoly(level, -1, eval.BuffQ[0], ring.RNSPoly{})

		// Sanity check, this error should not happen unless the evaluator's buffers
		// were improperly tempered with.
		if err != nil {
			panic(err)
		}

		*pt.MetaData = *op0.MetaData
		pt.Scale = rlwe.NewScale(rQ[level].Modulus)

		// If DefaultScalingFactor > 2^60, then multiple moduli are used per single rescale
		// thus continues multiplying the scale with the appropriate number of moduli
		for i := 1; i < eval.Parameters().LevelsConsumedPerRescaling(); i++ {
			pt.Scale = pt.Scale.Mul(rlwe.NewScale(rQ[level-i].Modulus))
		}

		// Encodes the vector on the plaintext
		if err = eval.Encoder.Encode(op1, pt); err != nil {
			return fmt.Errorf("cannot Mul: %w", err)
		}

		// Generic in place evaluation
		if err = eval.mulRelin(op0, pt.AsCiphertext(), false, opOut); err != nil {
			return fmt.Errorf("cannot Mul: %w", err)
		}
	default:
		return fmt.Errorf("op1.(type) must be rlwe.Element, he.Complex, he.Float, he.Int, []complex128, []float64, []big.Float or []bignum.Complex, but is %T", op1)
	}
	return
}

// MulRelinNew multiplies op0 with op1 with relinearization and returns the result in a newly created element.
//
// The following types are accepted for op1:
//   - rlwe.Element
//   - [he.Complex], [he.Float], [he.Int]
//   - []complex128, []float64, []big.Float or []bignum.Complex of size at most params.MaxSlots()
//
// Passing an invalid type will return an error.
//
// The procedure will return an error if either op0.Degree or op1.Degree > 1.
// The procedure will return an error if the evaluator was not created with an relinearization key.
func (eval *Evaluator) MulRelinNew(op0 *rlwe.Ciphertext, op1 rlwe.Operand) (opOut *rlwe.Ciphertext, err error) {
	switch op1 := op1.(type) {
	case rlwe.Element:
		opOut = NewCiphertext(eval.Parameters(), 1, min(op0.Level(), op1.Level()))
	default:
		opOut = NewCiphertext(eval.Parameters(), 1, op0.Level())
	}

	return opOut, eval.MulRelin(op0, op1, opOut)
}

// MulRelin multiplies op0 with op1 with relinearization and returns the result in opOut.
//
// The following types are accepted for op1:
//   - rlwe.Element
//   - [he.Complex], [he.Float], [he.Int]
//   - []complex128, []float64, []big.Float or []bignum.Complex of size at most params.MaxSlots()
//
// Passing an invalid type will return an error.
//
// The procedure will return an error if either op0.Degree or op1.Degree > 1.
// The procedure will return an error if opOut.Degree != op0.Degree + op1.Degree.
// The procedure will return an error if the evaluator was not created with an relinearization key.
func (eval *Evaluator) MulRelin(op0 *rlwe.Ciphertext, op1 rlwe.Operand, opOut *rlwe.Ciphertext) (err error) {
	switch op1 := op1.(type) {
	case rlwe.Element:

		el := op1.AsCiphertext()

		_, level, err := eval.InitOutputBinaryOp(op0, el, 2, opOut)
		if err != nil {
			return fmt.Errorf("cannot MulRelin: %w", err)
		}

		opOut.ResizeQ(level)

		if err = eval.mulRelin(op0, el, true, opOut); err != nil {
			return fmt.Errorf("cannot MulRelin: %w", err)
		}
	default:
		if err = eval.Mul(op0, op1, opOut); err != nil {
			return fmt.Errorf("cannot MulRelin: %w", err)
		}
	}
	return
}

func (eval *Evaluator) tensorStandardDegreeTwo(LevelQ int, op0, op1, op2 *rlwe.Ciphertext, c2 ring.RNSPoly) {

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
	rQ.MForm(op0.Q[0], c00)
	rQ.MForm(op0.Q[1], c01)

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

func (eval *Evaluator) mulRelin(op0, op1 *rlwe.Ciphertext, relin bool, opOut *rlwe.Ciphertext) (err error) {

	level := opOut.Level()

	opOut.Scale = op0.Scale.Mul(op1.Scale)

	rQ := eval.parameters.RingQ().AtLevel(level)

	// Case Ciphertext (x) Ciphertext
	if op0.Degree() == 1 && op1.Degree() == 1 {

		if !relin {
			opOut.ResizeDegree(2)
			eval.tensorStandardDegreeTwo(level, op0, op1, opOut, opOut.Q[2])
		} else {
			opOut.ResizeDegree(1)
			eval.tensorStandardDegreeTwo(level, op0, op1, opOut, eval.BuffQ[2])

			if err = eval.RelinearizeInplace(opOut, eval.BuffQ[2]); err != nil {
				return fmt.Errorf("relinearize: %w", err)
			}
		}

		// Case Plaintext (x) Ciphertext or Ciphertext (x) Plaintext
	} else {

		if op0.Degree() < op1.Degree() {
			op0, op1 = op1, op0
		}

		c00 := eval.BuffQ[0]
		// Multiply by T * 2^{64} * 2^{64} -> result multipled by T and switched in the Montgomery domain
		rQ.MForm(op1.Q[0], c00)

		if relin && op0.Degree() == 2 {

			if op0 != opOut {
				opOut.ResizeDegree(1)
			}

			rQ.MulCoeffsMontgomery(op0.Q[0], c00, opOut.Q[0])
			rQ.MulCoeffsMontgomery(op0.Q[1], c00, opOut.Q[1])
			rQ.MulCoeffsMontgomery(op0.Q[2], c00, eval.BuffQ[2])

			if err = eval.RelinearizeInplace(opOut, eval.BuffQ[2]); err != nil {
				return fmt.Errorf("relinearize: %w", err)
			}

		} else {

			if op0 != opOut {
				opOut.ResizeDegree(op0.Degree())
			}

			for i := range op0.Q {
				rQ.MulCoeffsMontgomery(op0.Q[i], c00, opOut.Q[i])
			}
		}
	}

	return
}

// MulThenAdd evaluate opOut = opOut + op0 * op1.
//
// The following types are accepted for op1:
//   - rlwe.Element
//   - [he.Complex], [he.Float], [he.Int]
//   - []complex128, []float64, []big.Float or []bignum.Complex of size at most params.MaxSlots()
//
// Passing an invalid type will return an error.
//
// If op1.(type) is he.Complex, he.Float or he.Int (single value):
//
// This function will not modify op0 but will multiply opOut by Q[min(op0.Level(), opOut.Level())] if:
//   - op0.Scale == opOut.Scale
//   - constant is not a Gaussian integer.
//
// If op0.Scale == opOut.Scale, and constant is not a Gaussian integer, then the constant will be scaled by
// Q[min(op0.Level(), opOut.Level())] else if opOut.Scale > op0.Scale, the constant will be scaled by opOut.Scale/op0.Scale.
//
// To correctly use this function, make sure that either op0.Scale == opOut.Scale or
// opOut.Scale = op0.Scale * Q[min(op0.Level(), opOut.Level())].
//
// If op1.(type) is []complex128, []float64, []big.Float or []bignum.Complex:
//   - If opOut.Scale == op0.Scale, op1 will be encoded and scaled by Q[min(op0.Level(), opOut.Level())]
//   - If opOut.Scale > op0.Scale, op1 will be encoded ans scaled by opOut.Scale/op1.Scale.
//
// Then the method will recurse with op1 given as rlwe.Element.
//
// If op1.(type) is rlwe.Element, the multiplication is carried outwithout relinearization and:
//
// This function will return an error if op0.Scale > opOut.Scale and user must ensure that opOut.Scale <= op0.Scale * op1.Scale.
// If opOut.Scale < op0.Scale * op1.Scale, then scales up opOut before adding the result.
// Additionally, the procedure will return an error if:
//   - either op0 or op1 are have a degree higher than 1.
//   - opOut.Degree != op0.Degree + op1.Degree.
//   - opOut = op0 or op1.
func (eval *Evaluator) MulThenAdd(op0 *rlwe.Ciphertext, op1 rlwe.Operand, opOut *rlwe.Ciphertext) (err error) {
	switch op1 := op1.(type) {
	case rlwe.Element:

		_, level, err := eval.InitOutputBinaryOp(op0, op1.AsCiphertext(), 2, opOut)
		if err != nil {
			return fmt.Errorf("cannot MulThenAdd: %w", err)
		}

		if op0.Vector == opOut.Vector || op1.AsCiphertext().Vector == opOut.Vector {
			return fmt.Errorf("cannot MulThenAdd: opOut must be different from op0 and op1")
		}

		opOut.ResizeQ(level)

		if err = eval.mulRelinThenAdd(op0, op1.AsCiphertext(), false, opOut); err != nil {
			return fmt.Errorf("cannot MulThenAdd: %w", err)
		}

	case complex128, float64, int, int64, uint, uint64, *big.Int, *big.Float, *bignum.Complex, big.Int, big.Float, bignum.Complex:

		_, level, err := eval.InitOutputUnaryOp(op0, opOut)

		if err != nil {
			return fmt.Errorf("cannot MulThenAdd: %w", err)
		}

		opOut.ResizeQ(opOut.Level())

		// Gets the ring at the minimum level
		rQ := eval.Parameters().RingQ().AtLevel(level)

		// Convertes the scalar to a *bignum.Complex
		cmplxBig := bignum.ToComplex(op1, eval.Parameters().EncodingPrecision())

		var scaleRLWE rlwe.Scale

		// If op0 and opOut scales are identical, but the op1 is not a Gaussian integer then multiplies opOut by scaleRLWE.
		// This ensures noiseless addition with opOut = scaleRLWE * opOut + op0 * round(scalar * scaleRLWE).
		if cmp := op0.Scale.Cmp(opOut.Scale); cmp == 0 {

			if cmplxBig.IsInt() {
				scaleRLWE = rlwe.NewScale(1)
			} else {
				scaleRLWE = rlwe.NewScale(rQ[level].Modulus)

				for i := 1; i < eval.Parameters().LevelsConsumedPerRescaling(); i++ {
					scaleRLWE = scaleRLWE.Mul(rlwe.NewScale(rQ[level-i].Modulus))
				}

				scaleInt := new(big.Int)
				scaleRLWE.Value.Int(scaleInt)
				if err = eval.Mul(opOut, scaleInt, opOut); err != nil {
					return fmt.Errorf("cannot MulThenAdd: %w", err)
				}
				opOut.Scale = opOut.Scale.Mul(scaleRLWE)
			}

		} else if cmp == -1 { // opOut.Scale > op0.Scale then the scaling factor for op1 becomes the quotient between the two scales
			scaleRLWE = opOut.Scale.Div(op0.Scale)
		} else {
			return fmt.Errorf("cannot MulThenAdd: op0.Scale > opOut.Scale is not supported")
		}

		RNSReal, RNSImag := bigComplexToRNSScalar(rQ, &scaleRLWE.Value, cmplxBig)

		eval.evaluateWithScalar(level, op0.Q, RNSReal, RNSImag, opOut.Q, rQ.MulDoubleRNSScalarThenAdd)

	case []complex128, []float64, []big.Float, []bignum.Complex:

		_, level, err := eval.InitOutputUnaryOp(op0, opOut)

		if err != nil {
			return fmt.Errorf("cannot MulThenAdd: %w", err)
		}

		opOut.ResizeQ(opOut.Level())

		// Gets the ring at the target level
		rQ := eval.Parameters().RingQ().AtLevel(level)

		var scaleRLWE rlwe.Scale
		if cmp := op0.Scale.Cmp(opOut.Scale); cmp == 0 { // If op0 and opOut scales are identical then multiplies opOut by scaleRLWE.

			scaleRLWE = rlwe.NewScale(rQ[level].Modulus)

			for i := 1; i < eval.Parameters().LevelsConsumedPerRescaling(); i++ {
				scaleRLWE = scaleRLWE.Mul(rlwe.NewScale(rQ[level-i].Modulus))
			}

			scaleInt := new(big.Int)
			scaleRLWE.Value.Int(scaleInt)
			if err = eval.Mul(opOut, scaleInt, opOut); err != nil {
				return fmt.Errorf("cannot MulThenAdd: %w", err)
			}
			opOut.Scale = opOut.Scale.Mul(scaleRLWE)

		} else if cmp == -1 { // opOut.Scale > op0.Scale then the scaling factor for op1 becomes the quotient between the two scales
			scaleRLWE = opOut.Scale.Div(op0.Scale)
		} else {
			return fmt.Errorf("cannot MulThenAdd: op0.Scale > opOut.Scale is not supported")
		}

		// Instantiates new plaintext from buffer
		pt, err := rlwe.NewPlaintextAtLevelFromPoly(level, -1, eval.BuffQ[0], ring.RNSPoly{})

		// Sanity check, this error should not happen unless the evaluator's buffers
		// were improperly tempered with.
		if err != nil {
			panic(err)
		}
		pt.MetaData = op0.MetaData.Clone()
		pt.Scale = scaleRLWE

		// Encodes the vector on the plaintext
		if err := eval.Encoder.Encode(op1, pt); err != nil {
			return fmt.Errorf("cannot MulThenAdd: %w", err)
		}

		if err = eval.MulThenAdd(op0, pt, opOut); err != nil {
			return fmt.Errorf("cannot MulThenAdd: %w", err)
		}

	default:
		return fmt.Errorf("op1.(type) must be rlwe.Element, he.Complex, he.Float, he.Int, []complex128, []float64, []big.Float or []bignum.Complex, but is %T", op1)
	}

	return
}

// MulRelinThenAdd multiplies op0 with op1 with relinearization and adds the result on opOut.
//
// The following types are accepted for op1:
//   - rlwe.Element
//   - [he.Complex], [he.Float], [he.Int]
//   - []complex128, []float64, []big.Float or []bignum.Complex of size at most params.MaxSlots()
//
// Passing an invalid type will return an error.
//
// User must ensure that opOut.Scale <= op0.Scale * op1.Scale.
//
// If opOut.Scale < op0.Scale * op1.Scale, then scales up opOut before adding the result.
//
// The procedure will return an error if either op0.Degree or op1.Degree > 1.
// The procedure will return an error if opOut.Degree != op0.Degree + op1.Degree.
// The procedure will return an error if the evaluator was not created with an relinearization key.
// The procedure will return an error if opOut = op0 or op1.
func (eval *Evaluator) MulRelinThenAdd(op0 *rlwe.Ciphertext, op1 rlwe.Operand, opOut *rlwe.Ciphertext) (err error) {

	switch op1 := op1.(type) {
	case rlwe.Element:
		if op1.Degree() == 0 {
			return eval.MulThenAdd(op0, op1, opOut)
		} else {

			if op0.Vector == opOut.Vector || op1.AsCiphertext().Vector == opOut.Vector {
				return fmt.Errorf("cannot MulThenAdd: opOut must be different from op0 and op1")
			}

			_, level, err := eval.InitOutputBinaryOp(op0, op1.AsCiphertext(), 2, opOut)
			if err != nil {
				return fmt.Errorf("cannot MulThenAdd: %w", err)
			}

			opOut.ResizeQ(level)

			if err = eval.mulRelinThenAdd(op0, op1.AsCiphertext(), true, opOut); err != nil {
				return fmt.Errorf("cannot MulThenAdd: %w", err)
			}
		}
	default:
		return eval.MulThenAdd(op0, op1, opOut)
	}

	return
}

func (eval *Evaluator) mulRelinThenAdd(op0, op1 *rlwe.Ciphertext, relin bool, opOut *rlwe.Ciphertext) (err error) {

	level := opOut.Level()

	resScale := op0.Scale.Mul(op1.Scale)

	if opOut.Scale.Cmp(resScale) == -1 {
		ratio := resScale.Div(opOut.Scale)
		// Only scales up if int(ratio) >= 2
		if ratio.Float64() >= 2.0 {
			if err = eval.Mul(opOut, &ratio.Value, opOut); err != nil {
				return fmt.Errorf("cannot MulRelinThenAdd: %w", err)
			}
			opOut.Scale = resScale
		}
	}

	rQ := eval.Parameters().RingQ().AtLevel(level)

	var c00, c01, c0, c1, c2 ring.RNSPoly

	// Case Ciphertext (x) Ciphertext
	if op0.Degree() == 1 && op1.Degree() == 1 {

		c00 = eval.BuffQ[0]
		c01 = eval.BuffQ[1]

		c0 = opOut.Q[0]
		c1 = opOut.Q[1]

		if !relin {
			opOut.ResizeQ(level)
			opOut.ResizeDegree(2)
			c2 = opOut.Q[2]
		} else {
			opOut.ResizeQ(level)
			opOut.ResizeDegree(max(1, opOut.Degree()))
			c2 = eval.BuffQ[2]
		}

		tmp0, tmp1 := op0, op1

		rQ.MForm(tmp0.Q[0], c00)
		rQ.MForm(tmp0.Q[1], c01)

		rQ.MulCoeffsMontgomeryThenAdd(c00, tmp1.Q[0], c0) // c0 += c[0]*c[0]
		rQ.MulCoeffsMontgomeryThenAdd(c00, tmp1.Q[1], c1) // c1 += c[0]*c[1]
		rQ.MulCoeffsMontgomeryThenAdd(c01, tmp1.Q[0], c1) // c1 += c[1]*c[0]

		if relin {
			rQ.MulCoeffsMontgomery(c01, tmp1.Q[1], c2) // c2 += c[1]*c[1]
			if err := eval.RelinearizeInplace(opOut, c2); err != nil {
				return fmt.Errorf("eval.RelinearizeInplace: %w", err)
			}
		} else {
			rQ.MulCoeffsMontgomeryThenAdd(c01, tmp1.Q[1], c2) // c2 += c[1]*c[1]
		}

		// Case Plaintext (x) Ciphertext or Ciphertext (x) Plaintext
	} else {

		opOut.ResizeQ(level)
		opOut.ResizeDegree(max(op0.Degree(), opOut.Degree()))

		c00 := eval.BuffQ[0]

		rQ.MForm(op1.Q[0], c00)
		for i := range op0.Q {
			rQ.MulCoeffsMontgomeryThenAdd(op0.Q[i], c00, opOut.Q[i])
		}
	}

	return
}

// Relinearize applies the relinearization procedure on op0 and returns the result in opOut.
// The input Ciphertext must be of degree two.
func (eval *Evaluator) Relinearize(op0, opOut *rlwe.Ciphertext) (err error) {
	return eval.Evaluator.Relinearize(op0, opOut)
}

// RelinearizeNew applies the relinearization procedure on op0 and returns the result in a newly
// created Ciphertext. The input Ciphertext must be of degree two.
func (eval *Evaluator) RelinearizeNew(op0 *rlwe.Ciphertext) (opOut *rlwe.Ciphertext, err error) {
	opOut = NewCiphertext(eval.Parameters(), 1, op0.Level())
	return opOut, eval.Relinearize(op0, opOut)
}

// ApplyEvaluationKeyNew applies the rlwe.EvaluationKey on op0 and returns the result on a new ciphertext opOut.
func (eval *Evaluator) ApplyEvaluationKeyNew(op0 *rlwe.Ciphertext, evk *rlwe.EvaluationKey) (opOut *rlwe.Ciphertext, err error) {
	opOut = NewCiphertext(eval.Parameters(), op0.Degree(), op0.Level())
	return opOut, eval.ApplyEvaluationKey(op0, evk, opOut)
}

// RotateNew rotates the columns of op0 by k positions to the left, and returns the result in a newly created element.
// The method will return an error if the evaluator hasn't been given an evaluation key set with the appropriate GaloisKey.
func (eval *Evaluator) RotateNew(op0 *rlwe.Ciphertext, k int) (opOut *rlwe.Ciphertext, err error) {
	opOut = NewCiphertext(eval.Parameters(), op0.Degree(), op0.Level())
	return opOut, eval.Rotate(op0, k, opOut)
}

// Rotate rotates the columns of op0 by k positions to the left and returns the result in opOut.
// The method will return an error if the evaluator hasn't been given an evaluation key set with the appropriate GaloisKey.
func (eval *Evaluator) Rotate(op0 *rlwe.Ciphertext, k int, opOut *rlwe.Ciphertext) (err error) {
	if err = eval.Automorphism(op0, eval.Parameters().GaloisElement(k), opOut); err != nil {
		return fmt.Errorf("eval.Automorphism: %w", err)
	}
	return
}

// ConjugateNew conjugates op0 (which is equivalent to a row rotation) and returns the result in a newly created element.
// The method will return an error if the evaluator hasn't been given an evaluation key set with the appropriate GaloisKey.
func (eval *Evaluator) ConjugateNew(op0 *rlwe.Ciphertext) (opOut *rlwe.Ciphertext, err error) {
	opOut = NewCiphertext(eval.Parameters(), op0.Degree(), op0.Level())
	return opOut, eval.Conjugate(op0, opOut)
}

// Conjugate conjugates op0 (which is equivalent to a row rotation) and returns the result in opOut.
// The method will return an error if the evaluator hasn't been given an evaluation key set with the appropriate GaloisKey.
func (eval *Evaluator) Conjugate(op0 *rlwe.Ciphertext, opOut *rlwe.Ciphertext) (err error) {

	if eval.Parameters().RingType() == ring.ConjugateInvariant {
		return fmt.Errorf("method is not supported when parameters.RingType() == ring.ConjugateInvariant")
	}

	if err = eval.Automorphism(op0, eval.Parameters().GaloisElementOrderTwoOrthogonalSubgroup(), opOut); err != nil {
		return fmt.Errorf("eval.Automorphism: %w", err)
	}

	return
}

// RotateHoistedNew takes an input Ciphertext and a list of rotations and returns a map of Ciphertext, where each element of the map is the input Ciphertext
// rotation by one element of the list. It is much faster than sequential calls to Rotate.
func (eval *Evaluator) RotateHoistedNew(ctIn *rlwe.Ciphertext, rotations []int, buf rlwe.HoistingBuffer) (opOut map[int]*rlwe.Ciphertext, err error) {
	opOut = make(map[int]*rlwe.Ciphertext)
	for _, i := range rotations {
		opOut[i] = NewCiphertext(eval.Parameters(), 1, ctIn.Level())
	}

	return opOut, eval.RotateHoisted(ctIn, rotations, buf, opOut)
}

// RotateHoisted takes an input Ciphertext and a list of rotations and populates a map of pre-allocated Ciphertexts,
// where each element of the map is the input Ciphertext rotation by one element of the list.
// It is much faster than sequential calls to Rotate.
func (eval *Evaluator) RotateHoisted(ctIn *rlwe.Ciphertext, rotations []int, buf rlwe.HoistingBuffer, opOut map[int]*rlwe.Ciphertext) (err error) {
	eval.FillHoistingBuffer(ctIn.Level(), eval.Parameters().MaxLevelP(), ctIn.Q[1], ctIn.IsNTT, buf)
	for _, i := range rotations {
		if err = eval.AutomorphismHoisted(ctIn, buf, eval.Parameters().GaloisElement(i), opOut[i]); err != nil {
			return fmt.Errorf("cannot RotateHoisted: %w", err)
		}
	}

	return
}

func (eval *Evaluator) RotateHoistedLazyNew(level int, rotations []int, ct *rlwe.Ciphertext, buf rlwe.HoistingBuffer) (cOut map[int]*rlwe.Ciphertext, err error) {
	cOut = make(map[int]*rlwe.Ciphertext)
	for _, i := range rotations {
		if i != 0 {
			cOut[i] = rlwe.NewCiphertext(eval.Parameters(), 1, level, eval.Parameters().MaxLevelP())
			if err = eval.AutomorphismHoistedLazy(level, ct, buf, eval.Parameters().GaloisElement(i), cOut[i]); err != nil {
				return nil, fmt.Errorf("eval.AutomorphismHoistedLazy: %w", err)
			}
		}
	}

	return
}

// ShallowCopy creates a shallow copy of this evaluator in which all the read-only data-structures are
// shared with the receiver and the temporary buffers are reallocated. The receiver and the returned
// Evaluators can be used concurrently.
func (eval *Evaluator) ShallowCopy() *Evaluator {
	return &Evaluator{
		Encoder:   eval.Encoder.ShallowCopy(),
		Evaluator: eval.Evaluator.ShallowCopy(),
	}
}

// WithKey creates a shallow copy of the receiver Evaluator for which the new EvaluationKey is evaluationKey
// and where the temporary buffers are shared. The receiver and the returned Evaluators cannot be used concurrently.
func (eval *Evaluator) WithKey(evk rlwe.EvaluationKeySet) *Evaluator {
	return &Evaluator{
		Evaluator: eval.Evaluator.WithKey(evk),
		Encoder:   eval.Encoder,
	}
}
