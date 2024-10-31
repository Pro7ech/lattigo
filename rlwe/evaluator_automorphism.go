package rlwe

import (
	"fmt"

	"github.com/Pro7ech/lattigo/ring"
)

// Automorphism computes phi(ct), where phi is the map X -> X^galEl. The method requires
// that the corresponding RotationKey has been added to the Evaluator. The method will
// return an error if either ctIn or opOut degree is not equal to 1.
func (eval Evaluator) Automorphism(ctIn *Ciphertext, galEl uint64, opOut *Ciphertext) (err error) {

	if ctIn.Degree() != 1 || opOut.Degree() != 1 {
		return fmt.Errorf("cannot apply Automorphism: input and output [rlwe.Ciphertext] must be of degree 1")
	}

	if galEl == 1 {
		if opOut != ctIn {
			opOut.Copy(ctIn)
		}
		return
	}

	var evk *GaloisKey
	if evk, err = eval.CheckAndGetGaloisKey(galEl); err != nil {
		return fmt.Errorf("cannot apply Automorphism: %w", err)
	}

	level := min(ctIn.Level(), opOut.Level())

	opOut.ResizeQ(level)

	rQ := eval.params.RingQ().AtLevel(level)

	elTmp := &Ciphertext{}
	elTmp.Vector = &ring.Vector{}
	elTmp.Q = []ring.RNSPoly{eval.BuffQ[0], eval.BuffQ[1]}
	elTmp.MetaData = ctIn.MetaData

	eval.GadgetProduct(level, ctIn.Q[1], ctIn.IsNTT, &evk.GadgetCiphertext, elTmp)

	rQ.Add(elTmp.Q[0], ctIn.Q[0], elTmp.Q[0])

	if ctIn.IsNTT {
		rQ.AutomorphismNTTWithIndex(elTmp.Q[0], eval.automorphismIndex[galEl], opOut.Q[0])
		rQ.AutomorphismNTTWithIndex(elTmp.Q[1], eval.automorphismIndex[galEl], opOut.Q[1])
	} else {
		rQ.Automorphism(elTmp.Q[0], galEl, opOut.Q[0])
		rQ.Automorphism(elTmp.Q[1], galEl, opOut.Q[1])
	}

	*opOut.MetaData = *ctIn.MetaData

	return
}

// AutomorphismHoisted is similar to Automorphism, except that it takes as input ctIn and c1DecompQP, where c1DecompQP is the RNS
// decomposition of its element of degree 1. This decomposition can be obtained with DecomposeNTT.
// The method requires that the corresponding RotationKey has been added to the Evaluator.
// The method will return an error if either ctIn or opOut degree is not equal to 1.
func (eval Evaluator) AutomorphismHoisted(ctIn *Ciphertext, buf HoistingBuffer, galEl uint64, opOut *Ciphertext) (err error) {

	if ctIn.Degree() != 1 || opOut.Degree() != 1 {
		return fmt.Errorf("cannot apply AutomorphismHoisted: input and output [rlwe.Ciphertext] must be of degree 1")
	}

	level := min(ctIn.Level(), opOut.Level())

	if galEl == 1 {
		if ctIn != opOut {
			opOut.Copy(ctIn)
		}
		return
	}

	var evk *GaloisKey
	if evk, err = eval.CheckAndGetGaloisKey(galEl); err != nil {
		return fmt.Errorf("cannot apply AutomorphismHoisted: %w", err)
	}

	opOut.ResizeQ(level)

	ringQ := eval.params.RingQ().AtLevel(level)

	elTmp := &Ciphertext{}
	elTmp.Vector = &ring.Vector{}
	elTmp.Q = []ring.RNSPoly{eval.BuffQ[0], eval.BuffQ[1]} // GadgetProductHoisted uses the same buffers for its ciphertext QP
	elTmp.MetaData = ctIn.MetaData

	eval.GadgetProductHoisted(level, buf, &evk.EvaluationKey.GadgetCiphertext, elTmp)
	ringQ.Add(elTmp.Q[0], ctIn.Q[0], elTmp.Q[0])

	if ctIn.IsNTT {
		ringQ.AutomorphismNTTWithIndex(elTmp.Q[0], eval.automorphismIndex[galEl], opOut.Q[0])
		ringQ.AutomorphismNTTWithIndex(elTmp.Q[1], eval.automorphismIndex[galEl], opOut.Q[1])
	} else {
		ringQ.Automorphism(elTmp.Q[0], galEl, opOut.Q[0])
		ringQ.Automorphism(elTmp.Q[1], galEl, opOut.Q[1])
	}

	*opOut.MetaData = *ctIn.MetaData

	return
}

// AutomorphismHoistedLazy is similar to AutomorphismHoisted, except that it returns a ciphertext modulo QP and scaled by P.
// The method requires that the corresponding RotationKey has been added to the Evaluator.
// Accepts `ctIn` in NTT and outside of NTT domain, but `ctQP` is always returned in the NTT domain.
func (eval Evaluator) AutomorphismHoistedLazy(LevelQ int, ctIn *Ciphertext, buf HoistingBuffer, galEl uint64, ctQP *Ciphertext) (err error) {

	var evk *GaloisKey
	if evk, err = eval.CheckAndGetGaloisKey(galEl); err != nil {
		return fmt.Errorf("cannot apply AutomorphismHoistedLazy: %w", err)
	}

	LevelP := evk.LevelP()

	if ctQP.LevelP() < LevelP {
		return fmt.Errorf("ctQP.LevelP()=%d < GaloisKey[%d].LevelP()=%d", ctQP.LevelP(), galEl, LevelP)
	}

	ctTmp := &Ciphertext{}
	ctTmp.Vector = &ring.Vector{}
	ctTmp.Q = []ring.RNSPoly{eval.BuffQ[0], eval.BuffQ[1]}
	ctTmp.P = []ring.RNSPoly{eval.BuffP[0], eval.BuffP[1]}
	ctTmp.MetaData = ctIn.MetaData.Clone()
	ctTmp.IsNTT = true // GadgetProductHoistedLazy always returns in the NTT domain

	if err = eval.GadgetProductHoistedLazy(LevelQ, true, buf, &evk.GadgetCiphertext, ctTmp); err != nil {
		return fmt.Errorf("eval.GadgetProductHoistedLazy: %w", err)
	}

	rQ := eval.params.RingQAtLevel(LevelQ)
	rP := eval.params.RingPAtLevel(LevelP)

	index := eval.automorphismIndex[galEl]

	rQ.AutomorphismNTTWithIndex(ctTmp.Q[1], index, ctQP.Q[1])

	if LevelP > -1 {
		rP.AutomorphismNTTWithIndex(ctTmp.P[1], index, ctQP.P[1])
		rQ.MulScalarBigint(ctIn.Q[0], rP.Modulus(), ctTmp.Q[1])

		if !ctIn.IsNTT {
			rQ.NTT(ctTmp.Q[1], ctTmp.Q[1])
		}

		rQ.Add(ctTmp.Q[0], ctTmp.Q[1], ctTmp.Q[0])
	}

	rQ.AutomorphismNTTWithIndex(ctTmp.Q[0], index, ctQP.Q[0])
	if LevelP > -1 {
		rP.AutomorphismNTTWithIndex(ctTmp.P[0], index, ctQP.P[0])
	}

	ctQP.MetaData = ctTmp.MetaData.Clone()

	return
}
