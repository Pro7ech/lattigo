package mhefloat

import (
	"fmt"
	"math/big"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/mhe"
	"github.com/Pro7ech/lattigo/ring"

	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/bignum"
)

// MaskedTransformProtocol is a struct storing the parameters for the MaskedTransformProtocol protocol.
type MaskedTransformProtocol struct {
	e2s EncToShareProtocol
	s2e ShareToEncProtocol

	defaultScale *big.Int
	prec         uint

	mask    []big.Int
	encoder *hefloat.Encoder
}

// ShallowCopy creates a shallow copy of MaskedTransformProtocol in which all the read-only data-structures are
// shared with the receiver and the temporary buffers are reallocated. The receiver and the returned
// MaskedTransformProtocol can be used concurrently.
func (p MaskedTransformProtocol) ShallowCopy() *MaskedTransformProtocol {
	return &MaskedTransformProtocol{
		e2s:          *p.e2s.ShallowCopy(),
		s2e:          *p.s2e.ShallowCopy(),
		prec:         p.prec,
		defaultScale: p.defaultScale,
		mask:         make([]big.Int, p.e2s.params.N()),
		encoder:      p.encoder.ShallowCopy(),
	}
}

// WithParams creates a shallow copy of the target MaskedTransformProtocol but with new output parameters.
// The expected input parameters remain unchanged.
func (p MaskedTransformProtocol) WithParams(paramsOut hefloat.Parameters) *MaskedTransformProtocol {
	scale := paramsOut.DefaultScale().Value
	defaultScale, _ := new(big.Float).SetPrec(p.prec).Set(&scale).Int(nil)
	return &MaskedTransformProtocol{
		e2s:          *p.e2s.ShallowCopy(),
		s2e:          *NewShareToEncProtocol(paramsOut),
		prec:         p.prec,
		defaultScale: defaultScale,
		mask:         make([]big.Int, p.e2s.params.N()),
		encoder:      hefloat.NewEncoder(paramsOut, p.prec),
	}
}

// MaskedTransformFunc represents a user-defined in-place function that can be evaluated on masked float plaintexts, as a part of the
// Masked Transform Protocol.
// The function is called with a vector of *Complex modulo hefloat.Parameters.Slots() as input, and must write
// its output on the same buffer.
// Transform can be the identity.
// Decode: if true, then the masked float plaintext will be decoded before applying Transform.
// Recode: if true, then the masked float plaintext will be recoded after applying Transform.
// i.e. : Decode (true/false) -> Transform -> Recode (true/false).
type MaskedTransformFunc struct {
	Decode bool
	Func   func(coeffs []bignum.Complex)
	Encode bool
}

// NewMaskedTransformProtocol creates a new instance of the PermuteProtocol.
// paramsIn: the hefloat.Parameters of the ciphertext before the protocol.
// paramsOut: the hefloat.Parameters of the ciphertext after the protocol.
// prec : the log2 of decimal precision of the internal encoder.
// The method will return an error if the maximum number of slots of the output parameters is smaller than the number of slots of the input ciphertext.
func NewMaskedTransformProtocol(paramsIn, paramsOut hefloat.Parameters, prec uint) *MaskedTransformProtocol {
	scale := paramsOut.DefaultScale().Value
	defaultScale, _ := new(big.Float).SetPrec(prec).Set(&scale).Int(nil)
	return &MaskedTransformProtocol{
		e2s:          *NewEncToShareProtocol(paramsIn),
		s2e:          *NewShareToEncProtocol(paramsOut),
		prec:         prec,
		defaultScale: defaultScale,
		mask:         make([]big.Int, paramsIn.N()),
		encoder:      hefloat.NewEncoder(paramsOut, prec),
	}
}

// Allocate allocates the shares of the PermuteProtocol
func (p MaskedTransformProtocol) Allocate(levelDecrypt, levelRecrypt int) *mhe.RefreshShare {
	return &mhe.RefreshShare{EncToShareShare: *p.e2s.Allocate(levelDecrypt), ShareToEncShare: *p.s2e.Allocate(levelRecrypt)}
}

// Gen generates the shares of the PermuteProtocol
// This protocol requires additional inputs which are :
// skIn     : the secret-key if the input ciphertext.
// skOut    : the secret-key of the output ciphertext.
// logBound : the bit length of the masks.
// ct1      : the degree 1 element the ciphertext to refresh, i.e. ct1 = ckk.Ciphetext.Value[1].
// scale    : the scale of the ciphertext when entering the refresh.
// The method "GetMinimumLevelForBootstrapping" should be used to get the minimum level at which the masked transform can be called while still ensure 128-bits of security, as well as the
// value for logBound.
func (p MaskedTransformProtocol) Gen(skIn, skOut *rlwe.SecretKey, logBound uint, ct *rlwe.Ciphertext, seed [32]byte, transform *MaskedTransformFunc, shareOut *mhe.RefreshShare) (err error) {

	ct1 := ct.Q[1]

	if ct1.Level() < shareOut.EncToShareShare.Level() {
		return fmt.Errorf("ct[1] level must be at least equal to EncToShareShare level")
	}

	if transform != nil {

		if transform.Decode && !ct.IsBatched {
			return fmt.Errorf("cannot GenShare: trying to decode a non-batched ciphertext (transform.Decode = true but ciphertext.IsBatched = false)")
		}

		if transform.Encode && !transform.Decode && ct.IsBatched {
			return fmt.Errorf("cannot GenShare: trying to encode a batched ciphertext (transform.Decode = false, transform.Encode = true but ciphertext.IsBatched = true")
		}
	}

	dslots := ct.Slots()
	if p.e2s.params.RingType() == ring.Standard {
		dslots *= 2
	}

	mask := p.mask[:dslots]

	// Generates the decryption share
	// Returns [M_i] on p.tmpMask and [a*s_i -M_i + e] on EncToShareShare
	if err = p.e2s.Gen(skIn, logBound, ct, &mhe.AdditiveShareBigint{Value: mask}, &shareOut.EncToShareShare); err != nil {
		return
	}

	// Applies LT(M_i)
	if err = p.applyTransformAndScale(transform, *ct.MetaData, mask); err != nil {
		return
	}

	// Stores the metadata of the ciphertext
	shareOut.MetaData = *ct.MetaData

	// Returns [-a*s_i + LT(M_i) * diffscale + e] on ShareToEncShare
	return p.s2e.Gen(skOut, seed, ct.MetaData, &mhe.AdditiveShareBigint{Value: mask}, &shareOut.ShareToEncShare)
}

// Aggregate sums share1 and share2 on shareOut.
func (p MaskedTransformProtocol) Aggregate(share1, share2, share3 *mhe.RefreshShare) (err error) {

	if !share1.MetaData.Equal(&share2.MetaData) {
		return fmt.Errorf("shares metadata do not match")
	}

	if err = share3.EncToShareShare.VectorShare.Aggregate(p.e2s.params, &share1.EncToShareShare.VectorShare, &share2.EncToShareShare.VectorShare); err != nil {
		return
	}

	return share3.ShareToEncShare.VectorShare.Aggregate(p.s2e.params, &share1.ShareToEncShare.VectorShare, &share2.ShareToEncShare.VectorShare)
}

// Finalize decrypts the ciphertext to LSSS-shares, applies the linear transformation on the LSSS-shares and re-encrypts the LSSS-shares to an RLWE ciphertext.
// The re-encrypted ciphertext's scale is set to the default scaling factor of the output parameters.
func (p MaskedTransformProtocol) Finalize(ct *rlwe.Ciphertext, transform *MaskedTransformFunc, share *mhe.RefreshShare, ciphertextOut *rlwe.Ciphertext) (err error) {

	if ct.Level() < share.EncToShareShare.Level() {
		return fmt.Errorf("input ciphertext level must be at least equal to e2s level")
	}

	if !ct.MetaData.Equal(&share.MetaData) {
		return fmt.Errorf("input ciphertext MetaData is not equal to share.MetaData")
	}

	maxLevel := share.ShareToEncShare.Level()

	if transform != nil {

		if transform.Decode && !ct.IsBatched {
			return fmt.Errorf("trying to decode a non-batched ciphertext (transform.Decode = true but ciphertext.IsBatched = false)")
		}

		if transform.Encode && !transform.Decode && ct.IsBatched {
			return fmt.Errorf("trying to encode a batched ciphertext (transform.Decode = false, transform.Encode = true but ciphertext.IsBatched = true")
		}
	}

	ringQ := p.s2e.params.RingQ().AtLevel(maxLevel)

	dslots := ct.Slots()
	if ringQ.Type() == ring.Standard {
		dslots *= 2
	}

	mask := p.mask[:dslots]

	// Returns -sum(M_i) + x (outside of the NTT domain)
	if err = p.e2s.Finalize(nil, &share.EncToShareShare, ct, &mhe.AdditiveShareBigint{Value: mask}); err != nil {
		return fmt.Errorf("p.e2s.Finalize: %w", err)
	}

	// Returns LT(-sum(M_i) + x)
	if err = p.applyTransformAndScale(transform, *ct.MetaData, mask); err != nil {
		return fmt.Errorf("p.applyTransformAndScale: %w", err)
	}

	// Extend the levels of the ciphertext for future allocation
	if ciphertextOut.Q[0].N() != ringQ.N() {
		for i := range ciphertextOut.Q {
			ciphertextOut.Q[i] = ringQ.NewRNSPoly()
		}
	} else {
		ciphertextOut.ResizeQ(maxLevel)
	}

	// Updates the ciphertext metadata if the output dimensions is smaller
	if logSlots := p.s2e.params.LogMaxSlots(); logSlots < ct.LogSlots() {
		ct.LogDimensions.Cols = logSlots
	}

	// Sets LT(-sum(M_i) + x) * diffscale in the RNS domain
	// Positional -> RNS -> NTT
	ringQ.SetCoefficientsBigint(mask, ciphertextOut.Q[0])
	rlwe.NTTSparseAndMontgomery(ringQ, ct.MetaData, ciphertextOut.Q[0])

	// LT(-sum(M_i) + x) * diffscale + [-a*s + LT(M_i) * diffscale + e] = [-a*s + LT(x) * diffscale + e]
	ringQ.Add(ciphertextOut.Q[0], share.ShareToEncShare.Q[0], ciphertextOut.Q[0])

	shareOut := &mhe.KeySwitchingShare{}
	shareOut.Q = []ring.RNSPoly{ciphertextOut.Q[0]}
	shareOut.Seed = share.ShareToEncShare.Seed

	// Copies the result on the out ciphertext
	if err = p.s2e.Finalize(shareOut, ciphertextOut); err != nil {
		return fmt.Errorf("p.s2e.Finalize: %w", err)
	}

	*ciphertextOut.MetaData = *ct.MetaData

	if transform != nil {
		ciphertextOut.IsBatched = transform.Encode
	}

	ciphertextOut.Scale = p.s2e.params.DefaultScale()

	return
}

func (p MaskedTransformProtocol) applyTransformAndScale(transform *MaskedTransformFunc, metadata rlwe.MetaData, mask []big.Int) (err error) {

	slots := metadata.Slots()

	if transform != nil {

		bigComplex := make([]bignum.Complex, slots)

		for i := range bigComplex {
			bigComplex[i][0].SetPrec(p.prec)
			bigComplex[i][1].SetPrec(p.prec)
		}

		// Extracts sparse coefficients
		for i := 0; i < slots; i++ {
			bigComplex[i][0].SetInt(&mask[i])
		}

		switch p.e2s.params.RingType() {
		case ring.Standard:
			for i, j := 0, slots; i < slots; i, j = i+1, j+1 {
				bigComplex[i][1].SetInt(&mask[j])
			}
		case ring.ConjugateInvariant:
			for i := 1; i < slots; i++ {
				bigComplex[i][1].Neg(&bigComplex[slots-i][0])
			}
		default:
			return fmt.Errorf("cannot GenShare: invalid ring type")
		}

		// Decodes if asked to
		if transform.Decode {
			if err := p.encoder.FFT(bigComplex, metadata.LogSlots()); err != nil {
				return err
			}
		}

		// Applies the linear transform
		transform.Func(bigComplex)

		// Recodes if asked to
		if transform.Encode {
			if err := p.encoder.IFFT(bigComplex, metadata.LogSlots()); err != nil {
				return err
			}
		}

		// Puts the coefficient back
		for i := 0; i < slots; i++ {
			bigComplex[i].Real().Int(&mask[i])
		}

		if p.e2s.params.RingType() == ring.Standard {
			for i, j := 0, slots; i < slots; i, j = i+1, j+1 {
				bigComplex[i].Imag().Int(&mask[j])
			}
		}
	}

	// Applies LT(M_i) * diffscale
	inputScaleInt, d := new(big.Float).SetPrec(256).Set(&metadata.Scale.Value).Int(nil)

	// .Int truncates (i.e. does not round to the nearest integer)
	// Thus we check if we are below, and if yes add 1, which acts as rounding to the nearest integer
	if d == big.Below {
		inputScaleInt.Add(inputScaleInt, new(big.Int).SetInt64(1))
	}

	// Scales the mask by the ratio between the two scales
	for i := range mask {
		mask[i].Mul(&mask[i], p.defaultScale)
		mask[i].Quo(&mask[i], inputScaleInt)
	}

	return
}
