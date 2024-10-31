package main

import (
	"fmt"
	"time"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/mhe"
	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/sampling"
	"github.com/Pro7ech/lattigo/utils/structs"
)

var (
	// Digit decomposition used in the u -> s keyswitch for the 1-round RLK protocol
	RLKShareDigitDecomposition = rlwe.DigitDecomposition{Type: rlwe.Unsigned, Log2Basis: 14}

	// Auxiliary prime P for the 1-round RelinearizationKey generation protocol
	// This prime has to be taken into account in the parameters security (i.e. add 20 bits
	// to the total modulus)
	RLKSHareAuxLogP = 20

	// Public common reference string
	CRS = sampling.NewSeed()

	// Public list of rotations
	Rotations = []int{1 << 0, 1 << 1, 1 << 2, 1 << 3, 1 << 4, 1 << 5, 1 << 6, 1 << 7, 1 << 8, 1 << 9, 1 << 10, 1 << 11, 1 << 12, 1 << 13, 1 << 14}

	// Public Scheme Parameters
	ParametersLiteral = hefloat.ParametersLiteral{
		LogN:            15,
		LogQ:            []int{50, 40, 40, 40, 40, 40, 40, 40, 40},
		LogP:            []int{55, 55},
		LogDefaultScale: 40,
		RingType:        ring.ConjugateInvariant,
	}

	// Number of parties
	n = 8
)

func main() {

	var err error

	// 1-Round SETUP
	parties := make([]*Party, n)
	transcripts := make([]*PAT, n)
	for i := range parties {
		fmt.Printf("Party[%d] -> Gen PAT: ", i)
		now := time.Now()
		parties[i] = NewParty(ParametersLiteral)
		if transcripts[i], err = parties[i].Gen(CRS, Rotations); err != nil {
			panic(err)
		}
		fmt.Printf("%s\n", time.Since(now))
	}

	// Server Side
	server := NewServer(ParametersLiteral)
	for i := 1; i < n; i++ {
		fmt.Printf("Server -> Aggregate PAT[0] <- PAT[0] + PAT[%d]: ", i)
		now := time.Now()
		if err = server.Aggregate(transcripts[0], transcripts[i], transcripts[0]); err != nil {
			panic(err)
		}
		fmt.Printf("%s\n", time.Since(now))
	}

	fmt.Printf("Server -> Finalize EvaluationKeySet from PAT[0]: ")
	var evk *rlwe.MemEvaluationKeySet
	now := time.Now()
	if evk, err = server.Finalize(transcripts[0]); err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", time.Since(now))

	// Prints the noise of the EvaluationKeys
	skIdeal := GetIdealKey(parties)

	for key := range evk.GaloisKeys {
		fmt.Printf("Noise Gk[%6d]: %f\n", evk.GaloisKeys[key].GaloisElement, rlwe.NoiseGaloisKey(evk.GaloisKeys[key], skIdeal, parties[0].params))
	}
	fmt.Printf("Noise RLK: %f\n", rlwe.NoiseRelinearizationKey(evk.RelinearizationKey, skIdeal, parties[0].params))
}

type Server struct {
	params  hefloat.Parameters
	GKSProt mhe.GaloisKeyProtocol
	RLKProt mhe.CircularGadgetCiphertextProtocol
}

func NewServer(paramsLit hefloat.ParametersLiteral) *Server {

	params, err := hefloat.NewParametersFromLiteral(paramsLit)

	if err != nil {
		panic(err)
	}

	return &Server{
		params:  params,
		GKSProt: *mhe.NewGaloisKeyProtocol(params),
		RLKProt: *mhe.NewCircularGadgetCiphertextProtocol(params, RLKSHareAuxLogP),
	}
}

func (s *Server) Finalize(pat *PAT) (evk *rlwe.MemEvaluationKeySet, err error) {

	// RLK
	GRLWEU := pat.RlkShare.UShare.AsGadgetCiphertext(s.RLKProt.GetRLWEParameters())
	var rlkGCT *rlwe.GadgetCiphertext
	if rlkGCT, err = s.RLKProt.FinalizeNew(pat.RlkShare.Share, GRLWEU); err != nil {
		return
	}

	rlk := rlwe.RelinearizationKey{}
	rlk.GadgetCiphertext = *rlkGCT

	// GKS
	var gks []*rlwe.GaloisKey
	for _, share := range pat.GkShares {
		gks = append(gks, s.GKSProt.FinalizeNew(share))
	}

	return rlwe.NewMemEvaluationKeySet(&rlk, gks...), nil
}

func (s *Server) Aggregate(PAT1, PAT2, PAT3 *PAT) (err error) {

	if err = s.RLKProt.Aggregate(PAT1.RlkShare.Share, PAT2.RlkShare.Share, PAT3.RlkShare.Share); err != nil {
		return
	}

	if err = PAT3.RlkShare.UShare.Aggregate(s.RLKProt.GetRLWEParameters(), PAT2.RlkShare.UShare, PAT1.RlkShare.UShare); err != nil {
		return
	}

	for galEl := range PAT3.GkShares {
		if err = s.GKSProt.Aggregate(PAT1.GkShares[galEl], PAT2.GkShares[galEl], PAT3.GkShares[galEl]); err != nil {
			return
		}
	}

	return
}

func GetIdealKey(p []*Party) (sk *rlwe.SecretKey) {
	params := p[0].params
	sk = rlwe.NewSecretKey(params)
	rQ := params.RingQ()
	rP := params.RingP()

	for i := range p {
		rQ.Add(sk.Q, p[i].sk.Q, sk.Q)

		if rP != nil {
			rP.Add(sk.P, p[i].sk.P, sk.P)
		}
	}
	return
}

type Party struct {
	params             rlwe.Parameters
	*rlwe.KeyGenerator // Stores an encryptor
	sk                 *rlwe.SecretKey
	u                  *rlwe.SecretKey
}

func NewParty(paramsLit hefloat.ParametersLiteral) *Party {

	params, err := hefloat.NewParametersFromLiteral(paramsLit)

	if err != nil {
		panic(err)
	}

	kgen := rlwe.NewKeyGenerator(params)
	return &Party{
		params:       *params.GetRLWEParameters(),
		KeyGenerator: kgen,
		sk:           kgen.GenSecretKeyNew(),
		u:            kgen.GenSecretKeyNew(),
	}
}

func (p *Party) Gen(seed [32]byte, rotations []int) (pat *PAT, err error) {

	pat = &PAT{}

	source := sampling.NewSource(seed)

	// Relinearization Key
	if pat.RlkShare, err = p.GenRlkShare(source.NewSeed()); err != nil {
		return
	}

	gkProt := mhe.NewGaloisKeyProtocol(p.params)

	pat.GkShares = map[uint64]*mhe.GaloisKeyShare{}

	// Galois Keys
	for _, rot := range rotations {

		galEl := p.params.GaloisElement(rot)

		share := gkProt.Allocate()
		if err = gkProt.Gen(p.sk, galEl, source.NewSeed(), share); err != nil {
			return
		}

		pat.GkShares[galEl] = share
	}

	return
}

func (p *Party) GenRlkShare(seed [32]byte) (rlkShare *RlkShare, err error) {

	source := sampling.NewSource(seed) // Seed branching

	params := p.params

	prot := mhe.NewCircularGadgetCiphertextProtocol(params, RLKSHareAuxLogP)

	share := prot.Allocate(rlwe.DigitDecomposition{})

	var u *rlwe.SecretKey
	var uShare *mhe.GadgetCiphertextShare
	if u, uShare, err = prot.GenEphemeralSecret(p.sk, source.NewSeed(), RLKShareDigitDecomposition); err != nil {
		return
	}

	if err = prot.Gen(p.sk, u, p.sk.AsPlaintext(), source.NewSeed(), share); err != nil {
		return
	}

	return &RlkShare{
		Share:  share,
		UShare: uShare,
	}, nil
}

// PAT Public Aggregatable Transcript
type PAT struct {
	GkShares  structs.Map[uint64, mhe.GaloisKeyShare]
	UToSShare *mhe.GadgetCiphertextShare
	RlkShare  *RlkShare
}

type RlkShare struct {
	Share  *mhe.CircularGadgetCiphertextShare
	UShare *mhe.GadgetCiphertextShare
}
