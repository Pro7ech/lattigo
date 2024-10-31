package hefloat

import (
	"fmt"

	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
)

// DomainSwitcher is a type for switching between the standard CKKS domain (which encrypts vectors of complex numbers)
// and the conjugate invariant variant of CKKS (which encrypts vectors of real numbers).
type DomainSwitcher struct {
	stdRingQ, conjugateRingQ ring.RNSRing

	stdToci, ciToStd  *rlwe.EvaluationKey
	automorphismIndex []uint64
}

// NewDomainSwitcher instantiate a new DomainSwitcher type. It may be instantiated from parameters from either RingType.
// The method returns an error if the parameters cannot support the switching (e.g., the NTTs are undefined for
// either of the two ring types).
// The comlexToRealEvk and comlexToRealEvk EvaluationKeys can be generated using the rlwe.KeyGenerator.GenEvaluationKeysForRingSwap(*).
func NewDomainSwitcher(params Parameters, comlexToRealEvk, realToComplexEvk *rlwe.EvaluationKey) (DomainSwitcher, error) {

	s := DomainSwitcher{
		stdToci: comlexToRealEvk,
		ciToStd: realToComplexEvk,
	}
	var err error
	if s.stdRingQ, err = params.RingQ().Standard(); err != nil {
		return DomainSwitcher{}, fmt.Errorf("cannot NewDomainSwitcher because the standard NTT is undefined for params: %s", err)
	}
	if s.conjugateRingQ, err = params.RingQ().ConjugateInvariant(); err != nil {
		return DomainSwitcher{}, fmt.Errorf("cannot NewDomainSwitcher because the standard NTT is undefined for params: %s", err)
	}

	// Sanity check, this error should not happen unless the
	// algorithm has been modified to provide invalid inputs.
	if s.automorphismIndex, err = ring.AutomorphismNTTIndex(s.stdRingQ.N(), s.stdRingQ.NthRoot(), s.stdRingQ.NthRoot()-1); err != nil {
		panic(err)
	}

	return s, nil
}

// ComplexToReal switches the provided ciphertext `ctIn` from the standard domain to the conjugate
// invariant domain and writes the result into `opOut`.
// Given ctInCKKS = enc(real(m) + imag(m)) in Z[X](X^N + 1), returns opOutCI = enc(real(m))
// in Z[X+X^-1]/(X^N + 1) in compressed form (N/2 coefficients).
// The scale of the output ciphertext is twice the scale of the input one.
// Requires the ring degree of opOut to be half the ring degree of ctIn.
// The security is changed from Z[X]/(X^N+1) to Z[X]/(X^N/2+1).
// The method will return an error if the DomainSwitcher was not initialized with a the appropriate EvaluationKeys.
func (switcher DomainSwitcher) ComplexToReal(eval *Evaluator, ctIn, opOut *rlwe.Ciphertext) (err error) {

	evalRLWE := eval.Evaluator

	if evalRLWE.GetRLWEParameters().RingType() != ring.Standard {
		return fmt.Errorf("cannot ComplexToReal: provided evaluator is not instantiated with RingType ring.Standard")
	}

	level := min(ctIn.Level(), opOut.Level())

	if ctIn.N() != 2*opOut.N() {
		return fmt.Errorf("cannot ComplexToReal: ctIn ring degree must be twice opOut ring degree")
	}

	opOut.ResizeQ(level)
	opOut.ResizeSize(2)

	if switcher.stdToci == nil {
		return fmt.Errorf("cannot ComplexToReal: no realToComplexEvk provided to this DomainSwitcher")
	}

	ctTmp := &rlwe.Ciphertext{}
	ctTmp.Vector = &ring.Vector{}
	ctTmp.Q = []ring.RNSPoly{evalRLWE.BuffQ[1], evalRLWE.BuffQ[2]}
	ctTmp.MetaData = ctIn.MetaData

	evalRLWE.GadgetProduct(level, ctIn.Q[1], ctIn.IsNTT, &switcher.stdToci.GadgetCiphertext, ctTmp)
	switcher.stdRingQ.AtLevel(level).Add(evalRLWE.BuffQ[1], ctIn.Q[0], evalRLWE.BuffQ[1])

	switcher.conjugateRingQ.AtLevel(level).FoldStandardToConjugateInvariant(evalRLWE.BuffQ[1], switcher.automorphismIndex, opOut.Q[0])
	switcher.conjugateRingQ.AtLevel(level).FoldStandardToConjugateInvariant(evalRLWE.BuffQ[2], switcher.automorphismIndex, opOut.Q[1])
	*opOut.MetaData = *ctIn.MetaData
	opOut.Scale = ctIn.Scale.Mul(rlwe.NewScale(2))
	return
}

// RealToComplex switches the provided ciphertext `ctIn` from the conjugate invariant domain to the
// standard domain and writes the result into `opOut`.
// Given ctInCI = enc(real(m)) in Z[X+X^-1]/(X^2N+1) in compressed form (N coefficients), returns
// opOutCKKS = enc(real(m) + imag(0)) in Z[X]/(X^2N+1).
// Requires the ring degree of opOut to be twice the ring degree of ctIn.
// The security is changed from Z[X]/(X^N+1) to Z[X]/(X^2N+1).
// The method will return an error if the DomainSwitcher was not initialized with a the appropriate EvaluationKeys.
func (switcher DomainSwitcher) RealToComplex(eval *Evaluator, ctIn, opOut *rlwe.Ciphertext) (err error) {

	evalRLWE := eval.Evaluator

	if evalRLWE.GetRLWEParameters().RingType() != ring.Standard {
		return fmt.Errorf("cannot RealToComplex: provided evaluator is not instantiated with RingType ring.Standard")
	}

	level := min(ctIn.Level(), opOut.Level())

	if 2*ctIn.N() != opOut.N() {
		return fmt.Errorf("cannot RealToComplex: opOut ring degree must be twice ctIn ring degree")
	}

	opOut.ResizeQ(level)
	opOut.ResizeSize(2)

	if switcher.ciToStd == nil {
		return fmt.Errorf("cannot RealToComplex: no realToComplexEvk provided to this DomainSwitcher")
	}

	switcher.stdRingQ.AtLevel(level).UnfoldConjugateInvariantToStandard(ctIn.Q[0], opOut.Q[0])
	switcher.stdRingQ.AtLevel(level).UnfoldConjugateInvariantToStandard(ctIn.Q[1], opOut.Q[1])

	ctTmp := &rlwe.Ciphertext{}
	ctTmp.Vector = &ring.Vector{}
	ctTmp.Q = []ring.RNSPoly{evalRLWE.BuffQ[1], evalRLWE.BuffQ[2]}
	ctTmp.MetaData = ctIn.MetaData

	// Switches the RCKswitcher key [X+X^-1] to a CKswitcher key [X]
	evalRLWE.GadgetProduct(level, opOut.Q[1], opOut.IsNTT, &switcher.ciToStd.GadgetCiphertext, ctTmp)
	switcher.stdRingQ.AtLevel(level).Add(opOut.Q[0], evalRLWE.BuffQ[1], opOut.Q[0])
	opOut.Q[1].CopyLvl(level, &evalRLWE.BuffQ[2])
	*opOut.MetaData = *ctIn.MetaData
	return
}
