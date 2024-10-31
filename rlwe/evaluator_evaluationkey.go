package rlwe

import (
	"fmt"

	"github.com/Pro7ech/lattigo/ring"
)

// ApplyEvaluationKey is a generic method to apply an EvaluationKey on a ciphertext.
// An EvaluationKey is a type of public key that is be used during the evaluation of
// a homomorphic circuit to provide additional functionalities, like relinearization
// or rotations.
//
// In a nutshell, an Evaluationkey encrypts a secret skIn under a secret skOut and
// enables the public and non interactive re-encryption of any ciphertext encrypted
// under skIn to a new ciphertext encrypted under skOut.
//
// The method will return an error if either ctIn or opOut degree isn't 1.
//
// This method can also be used to switch a ciphertext to one with a different ring degree.
// Note that the parameters of the smaller ring degree must be the same or a subset of the
// moduli Q and P of the one for the larger ring degree.
//
// To do so, it must be provided with the appropriate EvaluationKey, and have the operands
// matching the target ring degrees.
//
// To switch a ciphertext to a smaller ring degree:
//   - ctIn ring degree must match the evaluator's ring degree.
//   - opOut ring degree must match the smaller ring degree.
//   - evk must have been generated using the key-generator of the large ring degree with as input large-key -> small-key.
//
// To switch a ciphertext to a smaller ring degree:
//   - ctIn ring degree must match the smaller ring degree.
//   - opOut ring degree must match the evaluator's ring degree.
//   - evk must have been generated using the key-generator of the large ring degree with as input small-key -> large-key.
func (eval Evaluator) ApplyEvaluationKey(ctIn *Ciphertext, evk *EvaluationKey, opOut *Ciphertext) (err error) {

	if ctIn.Degree() != 1 || opOut.Degree() != 1 {
		return fmt.Errorf("cannot ApplyEvaluationKey: input and output [rlwe.Ciphertext] must be of degree 1")
	}

	level := min(ctIn.Level(), opOut.Level())
	rQ := eval.params.RingQ().AtLevel(level)

	NIn := ctIn.N()
	NOut := opOut.N()

	// Re-encryption to a larger ring degree.
	if NIn < NOut {

		if NOut != rQ.N() {
			return fmt.Errorf("cannot ApplyEvaluationKey: opOut ring degree does not match evaluator params ring degree")
		}

		ctIn.SwitchRingDegree(rQ, nil, eval.BuffDigitDecomp[0], opOut)

		// Re-encrypt opOut from the key from small to larger ring degree
		eval.applyEvaluationKey(level, opOut, evk, opOut)

		// Re-encryption to a smaller ring degree.
	} else if NIn > NOut {

		if NIn != rQ.N() {
			return fmt.Errorf("cannot ApplyEvaluationKey: ctIn ring degree does not match evaluator params ring degree")
		}

		level := min(ctIn.Level(), opOut.Level())

		ctTmp, err := NewCiphertextAtLevelFromPoly(level, -1, eval.BuffCt.Q, nil)

		// Sanity check, this error should not happen unless the
		// evaluator's buffer have been improperly tempered with.
		if err != nil {
			panic(err)
		}

		ctTmp.MetaData = ctIn.MetaData

		// Switches key from large to small degree
		eval.applyEvaluationKey(level, ctIn, evk, ctTmp)

		// Maps to smaller ring degree X -> Y = X^{N/n}
		ctTmp.SwitchRingDegree(rQ, nil, eval.BuffDigitDecomp[0], opOut)

		// Re-encryption to the same ring degree.
	} else {
		eval.applyEvaluationKey(level, ctIn, evk, opOut)
	}

	*opOut.MetaData = *ctIn.MetaData

	return
}

func (eval Evaluator) applyEvaluationKey(level int, ctIn *Ciphertext, evk *EvaluationKey, opOut *Ciphertext) {

	if ctIn != opOut {
		*opOut.MetaData = *ctIn.MetaData
		eval.GadgetProduct(level, ctIn.Q[1], ctIn.IsNTT, &evk.GadgetCiphertext, opOut)
		eval.params.RingQ().AtLevel(level).Add(opOut.Q[0], ctIn.Q[0], opOut.Q[0])
	} else {
		ctTmp := &Ciphertext{}
		ctTmp.Vector = &ring.Vector{}
		ctTmp.Q = []ring.RNSPoly{eval.BuffQ[0], eval.BuffQ[1]}
		ctTmp.MetaData = ctIn.MetaData
		eval.GadgetProduct(level, ctIn.Q[1], ctIn.IsNTT, &evk.GadgetCiphertext, ctTmp)
		eval.params.RingQ().AtLevel(level).Add(ctIn.Q[0], ctTmp.Q[0], opOut.Q[0])
		opOut.Q[1].CopyLvl(level, &ctTmp.Q[1])
	}
}

// Relinearize applies the relinearization procedure on ct0 and returns the result in opOut.
// Relinearization is a special procedure required to ensure ciphertext compactness.
// It takes as input a quadratic ciphertext, that decrypts with the key (1, sk, sk^2) and
// outputs a linear ciphertext that decrypts with the key (1, sk).
// In a nutshell, the relinearization re-encrypt the term that decrypts using sk^2 to one
// that decrypts using sk.
// The method will return an error if:
//   - The input ciphertext degree isn't 2.
//   - The corresponding relinearization key to the ciphertext degree
//
// is missing.
func (eval Evaluator) Relinearize(ctIn, opOut *Ciphertext) (err error) {

	if ctIn.Degree() != 2 {
		return fmt.Errorf("cannot relinearize: ctIn.Degree() should be 2 but is %d", ctIn.Degree())
	}

	var rlk *RelinearizationKey
	if rlk, err = eval.CheckAndGetRelinearizationKey(); err != nil {
		return fmt.Errorf("cannot relinearize: %w", err)
	}

	level := min(ctIn.Level(), opOut.Level())

	ringQ := eval.params.RingQ().AtLevel(level)

	ctTmp := &Ciphertext{}
	ctTmp.Vector = &ring.Vector{}
	ctTmp.Q = eval.BuffQ[:2]
	ctTmp.MetaData = ctIn.MetaData

	eval.GadgetProduct(level, ctIn.Q[2], ctIn.IsNTT, &rlk.GadgetCiphertext, ctTmp)
	ringQ.Add(ctIn.Q[0], ctTmp.Q[0], opOut.Q[0])
	ringQ.Add(ctIn.Q[1], ctTmp.Q[1], opOut.Q[1])

	opOut.ResizeQ(level)
	opOut.ResizeSize(2)

	*opOut.MetaData = *ctIn.MetaData

	return
}

func (eval Evaluator) RelinearizeInplace(op *Ciphertext, c2 ring.RNSPoly) (err error) {

	rQ := eval.params.RingQ().AtLevel(op.Level())

	var rlk *RelinearizationKey
	if rlk, err = eval.CheckAndGetRelinearizationKey(); err != nil {
		return fmt.Errorf("eval.CheckAndGetRelinearizationKey: %w", err)
	}

	tmpCt := &Ciphertext{}
	tmpCt.Vector = &ring.Vector{}
	tmpCt.Q = eval.BuffQ[:2]
	tmpCt.MetaData = &MetaData{}
	tmpCt.IsNTT = true

	eval.GadgetProduct(op.Level(), c2, true, &rlk.GadgetCiphertext, tmpCt)

	rQ.Add(op.Q[0], tmpCt.Q[0], op.Q[0])
	rQ.Add(op.Q[1], tmpCt.Q[1], op.Q[1])

	return
}
