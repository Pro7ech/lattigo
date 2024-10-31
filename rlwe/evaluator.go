package rlwe

import (
	"fmt"

	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/utils"
	"github.com/Pro7ech/lattigo/utils/structs"
)

// Evaluator is a struct that holds the necessary elements to execute general homomorphic
// operation on RLWE ciphertexts, such as automorphisms, key-switching and relinearization.
type Evaluator struct {
	params Parameters
	EvaluationKeySet
	*EvaluatorBuffers

	automorphismIndex map[uint64][]uint64

	// RingP holds extended ringPs for level-aware gadget product.
	// i-th element of RingP corresponds to the coalescing factor i.
	RingP structs.Vector[ring.RNSRing]
	// Decomposers holds Decomposers for level-aware gadget product.
	// i-th element of Decomposers corresponds to the coalescing factor i.
	Decomposers structs.Vector[ring.Decomposer]
}

type EvaluatorBuffers struct {
	BuffCt          *Ciphertext
	BuffQ           [6]ring.RNSPoly
	BuffP           [6]ring.RNSPoly
	BuffNTT         ring.RNSPoly    // Memory buffer for NTT(ct[1])
	BuffInvNTT      ring.RNSPoly    // Memory buffer for INTT(ct[1])
	BuffDigitDecomp [2][]uint64     // Memory buffer for digit decomposition
	BuffGadgetCt    []uint64        // Memroy buffer for coalesced gadget ciphertext
	BuffGadgetP     [2]ring.RNSPoly // Memory buffer for ciphertext auxiliary prime
	BuffGadgetQP    [2]ring.RNSPoly // Memory buffer for decomposed ciphertext
	BuffModDownQ    ring.RNSPoly
	BuffModDownP    ring.RNSPoly
}

func NewEvaluatorBuffers(p Parameters) *EvaluatorBuffers {

	buff := new(EvaluatorBuffers)
	rQ := p.RingQ()

	buff.BuffCt = NewCiphertext(p, 2, p.MaxLevel(), -1)

	buff.BuffQ = [6]ring.RNSPoly{
		rQ.NewRNSPoly(),
		rQ.NewRNSPoly(),
		rQ.NewRNSPoly(),
		rQ.NewRNSPoly(),
		rQ.NewRNSPoly(),
		rQ.NewRNSPoly(),
	}

	buff.BuffNTT = p.RingQ().NewRNSPoly()
	buff.BuffInvNTT = p.RingQ().NewRNSPoly()

	buff.BuffGadgetQP[0] = ring.NewRNSPoly(p.N(), p.QCount())

	if rP := p.RingP(); rP != nil {

		buff.BuffP = [6]ring.RNSPoly{
			rP.NewRNSPoly(),
			rP.NewRNSPoly(),
			rP.NewRNSPoly(),
			rP.NewRNSPoly(),
			rP.NewRNSPoly(),
			rP.NewRNSPoly(),
		}

		maxCoalescing := p.MaxCoalescing()

		buff.BuffGadgetP = [2]ring.RNSPoly{
			ring.NewRNSPoly(p.N(), (maxCoalescing+1)*p.PCount()),
			ring.NewRNSPoly(p.N(), (maxCoalescing+1)*p.PCount()),
		}

		buff.BuffGadgetQP[1] = ring.NewRNSPoly(p.N(), (maxCoalescing+1)*p.PCount())

		buff.BuffGadgetCt = make([]uint64, new(GadgetCiphertext).BufferSize(p, 1, p.MaxLevelQ(), p.MaxLevelP(), DigitDecomposition{}))

		buff.BuffModDownQ = ring.NewRNSPoly(p.N(), p.QCount())
		buff.BuffModDownP = ring.NewRNSPoly(p.N(), (maxCoalescing+1)*p.PCount())
	}

	buff.BuffDigitDecomp = [2][]uint64{
		make([]uint64, p.RingQ().N()),
		make([]uint64, p.RingQ().N()),
	}

	return buff
}

// NewEvaluator creates a new Evaluator.
func NewEvaluator(params ParameterProvider, evk EvaluationKeySet) (eval *Evaluator) {
	eval = new(Evaluator)
	p := params.GetRLWEParameters()
	eval.params = *p
	eval.EvaluatorBuffers = NewEvaluatorBuffers(eval.params)

	eval.EvaluationKeySet = evk

	var AutomorphismIndex map[uint64][]uint64

	if !utils.IsNil(evk) {
		if galEls := evk.GetGaloisKeysList(); len(galEls) != 0 {
			AutomorphismIndex = make(map[uint64][]uint64)

			N := p.N()
			NthRoot := p.RingQ().NthRoot()

			var err error
			for _, galEl := range galEls {
				if AutomorphismIndex[galEl], err = ring.AutomorphismNTTIndex(N, NthRoot, galEl); err != nil {
					// Sanity check, this error should not happen.
					panic(err)
				}
			}
		}
	}

	eval.automorphismIndex = AutomorphismIndex

	if p.ringP != nil {

		// We think QCount as a multiple of P (see PrecomputeLevelAware).
		PCount := p.PCount()
		QCount := PCount * (p.QCount() / PCount)

		maxCoalescing := p.MaxCoalescing()

		eval.RingP = make([]ring.RNSRing, maxCoalescing+1)
		eval.Decomposers = make([]ring.Decomposer, maxCoalescing+1)

		// Base cases
		eval.RingP[0] = p.RingP()
		eval.Decomposers[0] = *ring.NewDecomposer(p.RingQ(), eval.RingP[0])

		for i := 1; i < maxCoalescing+1; i++ {
			eval.RingP[i] = p.CoalescedRingP(i)
			rQ := p.RingQ().AtLevel(QCount - i*PCount)
			eval.Decomposers[i] = *ring.NewDecomposer(rQ, eval.RingP[i])
		}
	}

	return
}

func (eval *Evaluator) GetRLWEParameters() *Parameters {
	return &eval.params
}

// CheckAndGetGaloisKey returns an error if the GaloisKey for the given Galois element is missing or the EvaluationKey interface is nil.
func (eval Evaluator) CheckAndGetGaloisKey(galEl uint64) (evk *GaloisKey, err error) {
	if eval.EvaluationKeySet != nil {
		if evk, err = eval.GetGaloisKey(galEl); err != nil {
			return nil, fmt.Errorf("%w: key for galEl %d = 5^{%d} key is missing", err, galEl, eval.params.SolveDiscreteLogGaloisElement(galEl))
		}
	} else {
		return nil, fmt.Errorf("evaluation key interface is nil")
	}

	if eval.automorphismIndex == nil {
		eval.automorphismIndex = map[uint64][]uint64{}
	}

	if _, ok := eval.automorphismIndex[galEl]; !ok {
		if eval.automorphismIndex[galEl], err = ring.AutomorphismNTTIndex(eval.params.N(), eval.params.RingQ().NthRoot(), galEl); err != nil {
			// Sanity check, this error should not happen.
			panic(err)
		}
	}

	return
}

// CheckAndGetRelinearizationKey returns an error if the RelinearizationKey is missing or the EvaluationKey interface is nil.
func (eval Evaluator) CheckAndGetRelinearizationKey() (evk *RelinearizationKey, err error) {
	if eval.EvaluationKeySet != nil {
		if evk, err = eval.GetRelinearizationKey(); err != nil {
			return nil, fmt.Errorf("%w: relineariztion key is missing", err)
		}
	} else {
		return nil, fmt.Errorf("evaluation key interface is nil")
	}

	return
}

// InitOutputBinaryOp initializes the output Ciphertext opOut for receiving the result of a binary operation over
// op0 and op1. The method also performs the following checks:
//
// 1. Inputs are not nil
// 2. MetaData are not nil
// 3. op0.Degree() + op1.Degree() != 0 (i.e at least one Ciphertext is a ciphertext)
// 4. op0.IsNTT == op1.IsNTT == DefaultNTTFlag
// 5. op0.IsBatched == op1.IsBatched
//
// The opOut metadata are initilized as:
// IsNTT <- DefaultNTTFlag
// IsBatched <- op0.IsBatched
// LogDimensions <- max(op0.LogDimensions, op1.LogDimensions)
//
// The method returns max(op0.Degree(), op1.Degree(), opOut.Degree()) and min(op0.Level(), op1.Level(), opOut.Level())
func (eval Evaluator) InitOutputBinaryOp(op0, op1 *Ciphertext, opInTotalMaxDegree int, opOut *Ciphertext) (degree, level int, err error) {

	if op0 == nil || op1 == nil || opOut == nil {
		return 0, 0, fmt.Errorf("op0, op1 and opOut cannot be nil")
	}

	if op0.MetaData == nil || op1.MetaData == nil || opOut.MetaData == nil {
		return 0, 0, fmt.Errorf("op0, op1 and opOut MetaData cannot be nil")
	}

	degree = max(op0.Degree(), op1.Degree())
	degree = max(degree, opOut.Degree())
	level = min(op0.Level(), op1.Level())
	level = min(level, opOut.Level())

	totDegree := op0.Degree() + op1.Degree()

	if totDegree == 0 {
		return 0, 0, fmt.Errorf("op0 and op1 cannot be both plaintexts")
	}

	if totDegree > opInTotalMaxDegree {
		return 0, 0, fmt.Errorf("op0 and op1 total degree cannot exceed %d but is %d", opInTotalMaxDegree, totDegree)
	}

	if op0.IsNTT != op1.IsNTT || op0.IsNTT != eval.params.NTTFlag() {
		return 0, 0, fmt.Errorf("op0.IsNTT or op1.IsNTT != %t", eval.params.NTTFlag())
	} else {
		opOut.IsNTT = op0.IsNTT
	}

	if op0.IsBatched != op1.IsBatched {
		return 0, 0, fmt.Errorf("op1.IsBatched != opOut.IsBatched")
	} else {
		opOut.IsBatched = op0.IsBatched
	}

	opOut.LogDimensions.Rows = max(op0.LogDimensions.Rows, op1.LogDimensions.Rows)
	opOut.LogDimensions.Cols = max(op0.LogDimensions.Cols, op1.LogDimensions.Cols)

	return
}

// InitOutputUnaryOp initializes the output Ciphertext opOut for receiving the result of a unary operation over
// op0. The method also performs the following checks:
//
// 1. Input and output are not nil
// 2. Inoutp and output Metadata are not nil
// 2. op0.IsNTT == DefaultNTTFlag
//
// The method will also update the metadata of opOut:
//
// IsNTT <- NTTFlag
// IsBatched <- op0.IsBatched
// LogDimensions <- op0.LogDimensions
//
// The method returns max(op0.Degree(), opOut.Degree()) and min(op0.Level(), opOut.Level()).
func (eval Evaluator) InitOutputUnaryOp(op0, opOut *Ciphertext) (degree, level int, err error) {

	if op0 == nil || opOut == nil {
		return 0, 0, fmt.Errorf("op0 and opOut cannot be nil")
	}

	if op0.MetaData == nil || opOut.MetaData == nil {
		return 0, 0, fmt.Errorf("op0 and opOut MetaData cannot be nil")
	}

	if op0.IsNTT != eval.params.NTTFlag() {
		return 0, 0, fmt.Errorf("op0.IsNTT() != %t", eval.params.NTTFlag())
	} else {
		opOut.IsNTT = op0.IsNTT
	}

	opOut.IsBatched = op0.IsBatched
	opOut.LogDimensions = op0.LogDimensions

	return max(op0.Degree(), opOut.Degree()), min(op0.Level(), opOut.Level()), nil
}

// ShallowCopy creates a shallow copy of this Evaluator in which all the read-only data-structures are
// shared with the receiver and the temporary buffers are reallocated. The receiver and the returned
// Evaluators can be used concurrently.
func (eval Evaluator) ShallowCopy() *Evaluator {
	return &Evaluator{
		params:            eval.params,
		EvaluatorBuffers:  NewEvaluatorBuffers(eval.params),
		EvaluationKeySet:  eval.EvaluationKeySet,
		automorphismIndex: eval.automorphismIndex,
		RingP:             eval.RingP,
		Decomposers:       eval.Decomposers,
	}
}

// WithKey creates a shallow copy of the receiver Evaluator for which the new EvaluationKey is evaluationKey
// and where the temporary buffers are shared. The receiver and the returned Evaluators cannot be used concurrently.
func (eval Evaluator) WithKey(evk EvaluationKeySet) *Evaluator {

	var AutomorphismIndex map[uint64][]uint64

	if galEls := evk.GetGaloisKeysList(); len(galEls) != 0 {
		AutomorphismIndex = make(map[uint64][]uint64)

		N := eval.params.N()
		NthRoot := eval.params.RingQ().NthRoot()

		var err error
		for _, galEl := range galEls {
			if AutomorphismIndex[galEl], err = ring.AutomorphismNTTIndex(N, NthRoot, galEl); err != nil {
				// Sanity check, this error should not happen.
				panic(err)
			}
		}
	}

	return &Evaluator{
		params:            eval.params,
		EvaluatorBuffers:  eval.EvaluatorBuffers,
		EvaluationKeySet:  evk,
		automorphismIndex: AutomorphismIndex,
		RingP:             eval.RingP,
		Decomposers:       eval.Decomposers,
	}
}

func (eval Evaluator) AutomorphismIndex(galEl uint64) []uint64 {
	return eval.automorphismIndex[galEl]
}

func (eval Evaluator) GetEvaluatorBuffer() *EvaluatorBuffers {
	return eval.EvaluatorBuffers
}

func (eval Evaluator) GetBuffQ() [6]ring.RNSPoly {
	return eval.BuffQ
}

func (eval Evaluator) GetBuffP() [6]ring.RNSPoly {
	return eval.BuffP
}

func (eval Evaluator) GetBuffCt() *Ciphertext {
	return eval.BuffCt
}

func (eval Evaluator) ModDownNTT(LevelQ, LevelP int, p1Q, p1P, p2Q ring.RNSPoly) {
	rQ := eval.params.RingQ().AtLevel(LevelQ)
	coallescing := max(0, ((LevelP+1)/eval.params.PCount())-1)
	rP := eval.params.CoalescedRingP(coallescing).AtLevel(LevelP)
	rQ.ModDownNTT(rP, p1Q, p1P, eval.BuffModDownQ, eval.BuffModDownP, p2Q)
}

type HoistingBuffer structs.Vector[ring.Point]

func (eval Evaluator) NewHoistingBuffer(LevelQ, LevelP int) (buf HoistingBuffer) {
	N := eval.params.N()
	buf = make([]ring.Point, len(eval.params.DecompositionMatrixDimensions(LevelQ, LevelP, DigitDecomposition{})))
	for i := range buf {
		buf[i] = *ring.NewPoint(N, LevelQ, LevelP)
	}
	return
}
