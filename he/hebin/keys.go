package hebin

import (
	"math/big"

	"github.com/Pro7ech/lattigo/rgsw"
	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils"
)

const (
	// Parameter w of Algorithm 3 in https://eprint.iacr.org/2022/198
	windowSize = 10
)

// BlindRotationEvaluationKeySet is a interface implementing methods
// to load the blind rotation keys (RGSW) and automorphism keys
// (via the rlwe.EvaluationKeySet interface).
// Implementation of this interface must be safe for concurrent use.
type BlindRotationEvaluationKeySet interface {

	// GetBlindRotationKey should return RGSW(X^{s[i]})
	GetBlindRotationKey(i int) (brk *rgsw.Ciphertext, err error)

	// GetEvaluationKeySet should return an rlwe.EvaluationKeySet
	// providing access to all the required automorphism keys.
	GetEvaluationKeySet() (evk rlwe.EvaluationKeySet, err error)
}

// MemBlindRotationEvaluationKeySet is a basic in-memory implementation of the BlindRotationEvaluationKeySet interface.
type MemBlindRotationEvaluationKeySet struct {
	BlindRotationKeys []*rgsw.Ciphertext
	AutomorphismKeys  []*rlwe.GaloisKey
}

func (evk MemBlindRotationEvaluationKeySet) GetBlindRotationKey(i int) (*rgsw.Ciphertext, error) {
	return evk.BlindRotationKeys[i], nil
}

func (evk MemBlindRotationEvaluationKeySet) GetEvaluationKeySet() (rlwe.EvaluationKeySet, error) {
	return rlwe.NewMemEvaluationKeySet(nil, evk.AutomorphismKeys...), nil
}

// GenEvaluationKeyNew generates a new Blind Rotation evaluation key
func GenEvaluationKeyNew(paramsRLWE rlwe.ParameterProvider, skRLWE *rlwe.SecretKey, paramsLWE rlwe.ParameterProvider, skLWE *rlwe.SecretKey, evkParams ...rlwe.EvaluationKeyParameters) (key MemBlindRotationEvaluationKeySet) {

	pRLWE := *paramsRLWE.GetRLWEParameters()
	pLWE := *paramsLWE.GetRLWEParameters()

	skLWECopy := skLWE.Clone()
	pLWE.RingQ().AtLevel(0).INTT(skLWECopy.Q, skLWECopy.Q)
	pLWE.RingQ().AtLevel(0).IMForm(skLWECopy.Q, skLWECopy.Q)
	sk := make([]big.Int, pLWE.N())
	pLWE.RingQ().AtLevel(0).PolyToBigintCentered(skLWECopy.Q, 1, sk)

	encryptor := rgsw.NewEncryptor(pRLWE, skRLWE)

	levelQ, levelP, dd := rlwe.ResolveEvaluationKeyParameters(pRLWE, evkParams)

	skiRGSW := make([]*rgsw.Ciphertext, pLWE.N())

	ptXi := make(map[int]*rlwe.Plaintext)

	for i, si := range sk {

		siInt := int(si.Int64())

		if _, ok := ptXi[siInt]; !ok {

			pt := &rlwe.Plaintext{}
			pt.Point = &ring.Point{}
			pt.MetaData = &rlwe.MetaData{}
			pt.IsNTT = true
			pt.Q = pRLWE.RingQ().NewMonomialXi(siInt)
			pRLWE.RingQ().NTT(pt.Q, pt.Q)

			ptXi[siInt] = pt
		}

		skiRGSW[i] = rgsw.NewCiphertext(pRLWE, levelQ, levelP, dd)

		// Sanity check, this error should never happen unless this algorithm
		// has been improperly modified to provides invalid inputs.
		if err := encryptor.Encrypt(ptXi[siInt], skiRGSW[i]); err != nil {
			panic(err)
		}
	}

	kgen := rlwe.NewKeyGenerator(pRLWE)

	galEls := make([]uint64, windowSize)
	for i := 0; i < windowSize; i++ {
		galEls[i] = pRLWE.GaloisElement(i + 1)
	}

	galEls = append(galEls, pRLWE.RingQ().NthRoot()-ring.GaloisGen)

	gks := kgen.GenGaloisKeysNew(galEls, skRLWE, rlwe.EvaluationKeyParameters{
		LevelQ:             utils.Pointy(levelQ),
		LevelP:             utils.Pointy(levelP),
		DigitDecomposition: dd,
	})

	return MemBlindRotationEvaluationKeySet{BlindRotationKeys: skiRGSW, AutomorphismKeys: gks}
}
