package ring

import (
	"math"
	"math/bits"
	"unsafe"

	"github.com/Pro7ech/lattigo/utils/bignum"
)

// ModUp takes pQ an [RNSPoly] of the [RNSRing] r and stores
// on pP its representation in the [RNSRing] other.
func (r RNSRing) ModUp(other RNSRing, pQ, buffQ, pP RNSPoly) {
	QHalf := bignum.NewInt(r.Modulus())
	QHalf.Rsh(QHalf, 1)
	r.AddScalarBigint(pQ, QHalf, buffQ)
	ModUpExact(r, other, buffQ, pP, r.ModUpConstants(other))
	other.SubScalarBigint(pP, QHalf, pP)
}

// ModDown takes p1QP = [p1Q, p1P] an [RNSPoly] of the [RNSRing] r and other and
// stores on p2Q its value divided by the moduli of the [RNSRing] other.
// Division is centered and rounded.
func (r RNSRing) ModDown(other RNSRing, p1Q, p1P, buffQ, buffP, p2Q RNSPoly) {
	other.ModUp(r, p1P, buffP, buffQ)
	modDownConstants := r.ModDownConstants(other)
	for i, s := range r {
		s.SubThenMulScalarMontgomeryTwoModulus(buffQ.At(i), p1Q.At(i), s.Modulus-modDownConstants[i], p2Q.At(i))
	}
}

// ModDownNTT takes p1QP = [p1Q, p1P] an [RNSPoly] of the [RNSRing] r and other and
// stores on p2Q its value divided by the moduli of the [RNSRing] other.
// Inputs are expected to be in the NTT domain, and output is given in the NTT domain.
// Division is centered and rounded.
func (r RNSRing) ModDownNTT(other RNSRing, p1Q, p1P, buffQ, buffP, p2Q RNSPoly) {
	other.INTTLazy(p1P, buffP)
	other.ModUp(r, buffP, buffP, buffQ)
	r.NTTLazy(buffQ, buffQ)
	modDownConstants := r.ModDownConstants(other)
	// Finally, for each level of p1 (and the buffer since they now share the same basis) we compute p2 = (P^-1) * (p1 - buff) mod Q
	for i, s := range r {
		// Then for each coefficient we compute (P^-1) * (p1[i][j] - buff[i][j]) mod qi
		s.SubThenMulScalarMontgomeryTwoModulus(buffQ.At(i), p1Q.At(i), s.Modulus-modDownConstants[i], p2Q.At(i))
	}
}

// ExtendBasisSmallNorm extends a small-norm polynomial pQ in R_Q to pP in R_P.
// User must ensure that len(P) <= pP.Level()+1
func ExtendBasisSmallNorm(Q uint64, P Poly, pQ, pP RNSPoly) {
	var coeff, sign uint64
	QHalf := Q >> 1

	N := pQ.N()

	for j := 0; j < N; j++ {

		coeff = pQ.At(0)[j]

		sign = 1
		if coeff > QHalf {
			coeff = Q - coeff
			sign = 0
		}

		for i, pi := range P {
			pP.At(i)[j] = (coeff * sign) | (pi-coeff)*(sign^1)
		}
	}
}

// ModUpConstants stores the necessary parameters for RNS basis extension.
type ModUpConstants struct {
	// Parameters for basis extension from Q to P
	// (Q/Qi)^-1) (mod each Qi) (in Montgomery form)
	qoverqiinvqi []uint64
	// Q/qi (mod each Pj) (in Montgomery form)
	qoverqimodp [][]uint64
	// Q*v (mod each Pj) for v in [1,...,k] where k is the number of Pj moduli
	vtimesqmodp [][]uint64
}

// ModUpConstants generates the ModUpConstants for basis extension from the receiver ring to the other ring.
func (r RNSRing) ModUpConstants(other RNSRing) ModUpConstants {

	qoverqiinvqi := make([]uint64, r.Level()+1)
	qoverqimodp := make([][]uint64, other.Level()+1)

	for i := range other.Level() + 1 {
		qoverqimodp[i] = make([]uint64, r.Level()+1)
	}

	var qiStar uint64
	for i, si := range r {

		brc := si.BRedConstant
		mrc := si.MRedConstant
		qi := si.Modulus

		qiStar = MForm(1, si.Modulus, brc)

		for j, sj := range r {
			if j != i {
				qiStar = MRed(qiStar, MForm(sj.Modulus, qi, brc), qi, mrc)
			}
		}

		// (Q/Qi)^-1) * r (mod Qi) (in Montgomery form)
		qoverqiinvqi[i] = ModExpMontgomery(qiStar, qi-2, qi, mrc, brc)

		for j, sj := range other {

			// (Q/qi * r) (mod Pj) (in Montgomery form)
			qiStar = 1
			for u := range r {
				if u != i {
					qiStar = MRed(qiStar, MForm(r[u].Modulus, sj.Modulus, sj.BRedConstant), sj.Modulus, sj.MRedConstant)
				}
			}

			qoverqimodp[j][i] = MForm(qiStar, sj.Modulus, sj.BRedConstant)
		}
	}

	vtimesqmodp := make([][]uint64, other.Level()+1)
	var QmodPi uint64
	for j, sj := range other {

		vtimesqmodp[j] = make([]uint64, r.Level()+2)
		// Correction Term (v*Q) mod each Pj

		QmodPi = 1
		for i := range r {
			QmodPi = MRed(QmodPi, MForm(r[i].Modulus, sj.Modulus, sj.BRedConstant), sj.Modulus, sj.MRedConstant)
		}

		v := sj.Modulus - QmodPi
		vtimesqmodp[j][0] = 0
		for i := 1; i < r.Level()+2; i++ {
			vtimesqmodp[j][i] = CRed(vtimesqmodp[j][i-1]+v, sj.Modulus)
		}
	}

	return ModUpConstants{qoverqiinvqi: qoverqiinvqi, qoverqimodp: qoverqimodp, vtimesqmodp: vtimesqmodp}
}

func (r RNSRing) ModDownConstants(other RNSRing) (constants []uint64) {

	constants = make([]uint64, r.ModuliChainLength())

	for i, rqi := range r {

		qi := rqi.Modulus
		pj := other[0].Modulus
		mrc := rqi.MRedConstant
		brc := rqi.BRedConstant

		constants[i] = ModExpMontgomery(MForm(pj, qi, brc), qi-2, qi, mrc, brc)

		for _, rpj := range other[1:] {
			constants[i] = MRed(constants[i], ModExpMontgomery(MForm(rpj.Modulus, qi, brc), qi-2, qi, mrc, brc), qi, mrc)
		}
	}

	return
}

// ModUpExact takes p1 mod Q and switches its basis to P, returning the result on p2.
// Caution: values are not centered and returned values are in [0, 2P-1].
func ModUpExact(rQ, rP RNSRing, p1, p2 RNSPoly, MUC ModUpConstants) {

	var v, rlo, rhi [8]uint64
	var y0, y1, y2, y3, y4, y5, y6, y7 [32]uint64

	LevelQ := rQ.Level()
	LevelP := rP.Level()

	Q := rQ.ModuliChain()
	mredQ := rQ.MRedConstants()

	P := rP.ModuliChain()
	mredP := rP.MRedConstants()

	vtimesqmodp := MUC.vtimesqmodp
	qoverqiinvqi := MUC.qoverqiinvqi
	qoverqimodp := MUC.qoverqimodp

	// We loop over each coefficient and apply the basis extension
	for x := 0; x < len(p1[0]); x = x + 8 {
		reconstructRNS(0, LevelQ+1, x, p1, &v, &y0, &y1, &y2, &y3, &y4, &y5, &y6, &y7, Q, mredQ, qoverqiinvqi)
		for j := 0; j < LevelP+1; j++ {
			/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2[j])%8 != 0*/
			multSum(LevelQ, (*[8]uint64)(unsafe.Pointer(&p2[j][x])), &rlo, &rhi, &v, &y0, &y1, &y2, &y3, &y4, &y5, &y6, &y7, P[j], mredP[j], vtimesqmodp[j], qoverqimodp[j])
		}
	}
}

// ReconstructModP takes p1 mod Q and switches its basis to P, returning the result on p2.
// Caution: values are not centered and returned values are in [0, 2P-1].
func ReconstructModP(p1 RNSPoly, p2 Poly, rQ RNSRing, rP *Ring, MUC ModUpConstants) {

	var v, rlo, rhi [8]uint64
	var y0, y1, y2, y3, y4, y5, y6, y7 [32]uint64

	LevelQ := len(p1) - 1

	Q := rQ.ModuliChain()
	mredQ := rQ.MRedConstants()

	P := rP.Modulus
	mredP := rP.MRedConstant

	vtimesqmodp := MUC.vtimesqmodp[0]
	qoverqiinvqi := MUC.qoverqiinvqi
	qoverqimodp := MUC.qoverqimodp[0]

	// We loop over each coefficient and apply the basis extension
	for x := 0; x < len(p1[0]); x = x + 8 {
		reconstructRNS(0, LevelQ+1, x, p1, &v, &y0, &y1, &y2, &y3, &y4, &y5, &y6, &y7, Q, mredQ, qoverqiinvqi)
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2[j])%8 != 0*/
		multSum(LevelQ, (*[8]uint64)(unsafe.Pointer(&p2[x])), &rlo, &rhi, &v, &y0, &y1, &y2, &y3, &y4, &y5, &y6, &y7, P, mredP, vtimesqmodp, qoverqimodp)
	}
}

// Decomposer is a structure that stores the parameters of the arbitrary decomposer.
// This decomposer takes a p(x)_Q (in basis Q) and returns p(x) mod qi in basis QP, where
// qi = prod(Q_i) for 0<=i<=L, where L is the number of factors in P.
type Decomposer struct {
	rQ, rP         RNSRing
	ModUpConstants [][][]ModUpConstants
}

// NewDecomposer creates a new Decomposer.
func NewDecomposer(rQ, rP RNSRing) (decomposer *Decomposer) {
	decomposer = new(Decomposer)

	decomposer.rQ = rQ
	decomposer.rP = rP

	if rP != nil {

		Q := rQ.ModuliChain()
		P := rP.ModuliChain()

		decomposer.ModUpConstants = make([][][]ModUpConstants, rP.MaxLevel())

		for lvlP := 0; lvlP < rP.MaxLevel(); lvlP++ {

			P := P[:lvlP+2]

			nbPi := len(P)
			BaseRNSDecompositionVectorSize := int(math.Ceil(float64(len(Q)) / float64(nbPi)))

			xnbPi := make([]int, BaseRNSDecompositionVectorSize)
			for i := range xnbPi {
				xnbPi[i] = nbPi
			}

			if len(Q)%nbPi != 0 {
				xnbPi[BaseRNSDecompositionVectorSize-1] = len(Q) % nbPi
			}

			decomposer.ModUpConstants[lvlP] = make([][]ModUpConstants, BaseRNSDecompositionVectorSize)

			// Create ModUpConstants for each possible combination of [Qi,Pj] according to xnbPi
			for i := 0; i < BaseRNSDecompositionVectorSize; i++ {

				decomposer.ModUpConstants[lvlP][i] = make([]ModUpConstants, xnbPi[i]-1)

				for j := 0; j < xnbPi[i]-1; j++ {

					Qi := RNSRing(make([]*Ring, j+2))
					Pi := RNSRing(make([]*Ring, len(Q)+len(P)))

					for k := 0; k < j+2; k++ {
						Qi[k] = rQ[i*nbPi+k]
					}

					copy(Pi, rQ)

					for k := len(Q); k < len(Q)+len(P); k++ {
						Pi[k] = rP[k-len(Q)]
					}

					decomposer.ModUpConstants[lvlP][i][j] = Qi.ModUpConstants(Pi)
				}
			}
		}
	}

	return
}

// DecomposeAndSplit decomposes a polynomial p(x) in basis Q, reduces it modulo qi, and returns
// the result in basis QP separately.
func (decomposer *Decomposer) DecomposeAndSplit(LevelQ, LevelP, BaseRNSDecompositionVectorSize int, p0Q, p1Q, p1P RNSPoly) {

	rQ := decomposer.rQ.AtLevel(LevelQ)

	var rP RNSRing
	if decomposer.rP != nil {
		rP = decomposer.rP.AtLevel(LevelP)
	}

	N := rQ.N()

	lvlQStart := BaseRNSDecompositionVectorSize * (LevelP + 1)

	var decompLvl int
	if LevelQ > (LevelP+1)*(BaseRNSDecompositionVectorSize+1)-1 {
		decompLvl = LevelP - 1
	} else {
		decompLvl = (LevelQ % (LevelP + 1)) - 1
	}

	// First we check if the vector can simply by coping and rearranging elements (the case where no reconstruction is needed)
	if decompLvl < 0 {

		var pos, neg, coeff, tmp uint64

		Q := rQ.ModuliChain()
		BRCQ := rQ.BRedConstants()

		var P []uint64
		var BRCP [][2]uint64

		if rP != nil {
			P = rP.ModuliChain()
			BRCP = rP.BRedConstants()
		}

		for j := 0; j < N; j++ {

			coeff = p0Q.At(lvlQStart)[j]
			pos, neg = 1, 0
			if coeff >= (Q[lvlQStart] >> 1) {
				coeff = Q[lvlQStart] - coeff
				pos, neg = 0, 1
			}

			for i := 0; i < LevelQ+1; i++ {
				tmp = BRedAdd(coeff, Q[i], BRCQ[i])
				p1Q.At(i)[j] = tmp*pos + (Q[i]-tmp)*neg

			}

			for i := 0; i < LevelP+1; i++ {
				tmp = BRedAdd(coeff, P[i], BRCP[i])
				p1P.At(i)[j] = tmp*pos + (P[i]-tmp)*neg
			}
		}

		// Otherwise, we apply a fast exact base conversion for the reconstruction
	} else {

		p0idxst := BaseRNSDecompositionVectorSize * (LevelP + 1)
		p0idxed := p0idxst + (LevelP + 1)

		if p0idxed > LevelQ+1 {
			p0idxed = LevelQ + 1
		}

		MUC := decomposer.ModUpConstants[LevelP-1][BaseRNSDecompositionVectorSize][decompLvl]

		var v, rlo, rhi [8]uint64
		var vi [8]float64
		var y0, y1, y2, y3, y4, y5, y6, y7 [32]uint64

		Q := rQ.ModuliChain()
		P := rP.ModuliChain()
		mredQ := rQ.MRedConstants()
		mredP := rP.MRedConstants()
		qoverqiinvqi := MUC.qoverqiinvqi
		vtimesqmodp := MUC.vtimesqmodp
		qoverqimodp := MUC.qoverqimodp

		QBig := bignum.NewInt(1)
		for i := p0idxst; i < p0idxed; i++ {
			QBig.Mul(QBig, bignum.NewInt(Q[i]))
		}

		QHalf := bignum.NewInt(QBig)
		QHalf.Rsh(QHalf, 1)
		QHalfModqi := make([]uint64, p0idxed-p0idxst)
		tmp := bignum.NewInt(0)
		for i, j := 0, p0idxst; j < p0idxed; i, j = i+1, j+1 {
			QHalfModqi[i] = tmp.Mod(QHalf, bignum.NewInt(Q[j])).Uint64()
		}

		QCount := decomposer.rQ.Level() + 1

		// We loop over each coefficient and apply the basis extension
		for x := 0; x < N; x = x + 8 {

			reconstructRNSCentered(p0idxst, p0idxed, x, p0Q, &v, &vi, &y0, &y1, &y2, &y3, &y4, &y5, &y6, &y7, QHalfModqi, Q, mredQ, qoverqiinvqi)

			// Coefficients of index smaller than the ones to be decomposed
			for j := 0; j < p0idxst; j++ {
				/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1Q.At(j))%8 != 0 */
				multSum(decompLvl+1, (*[8]uint64)(unsafe.Pointer(&p1Q.At(j)[x])), &rlo, &rhi, &v, &y0, &y1, &y2, &y3, &y4, &y5, &y6, &y7, Q[j], mredQ[j], vtimesqmodp[j], qoverqimodp[j])
			}

			// Coefficients of index greater than the ones to be decomposed
			for j := p0idxed; j < LevelQ+1; j++ {
				/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1Q.At(j))%8 != 0 */
				multSum(decompLvl+1, (*[8]uint64)(unsafe.Pointer(&p1Q.At(j)[x])), &rlo, &rhi, &v, &y0, &y1, &y2, &y3, &y4, &y5, &y6, &y7, Q[j], mredQ[j], vtimesqmodp[j], qoverqimodp[j])
			}

			// Coefficients of the special primes Pi
			for j, u := 0, QCount; j < LevelP+1; j, u = j+1, u+1 {
				/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1P.At(j))%8 != 0 */
				multSum(decompLvl+1, (*[8]uint64)(unsafe.Pointer(&p1P.At(j)[x])), &rlo, &rhi, &v, &y0, &y1, &y2, &y3, &y4, &y5, &y6, &y7, P[j], mredP[j], vtimesqmodp[u], qoverqimodp[u])
			}
		}

		rQ.SubScalarBigint(p1Q, QHalf, p1Q)
		rP.SubScalarBigint(p1P, QHalf, p1P)
	}
}

func reconstructRNSCentered(start, end, x int, p RNSPoly, v *[8]uint64, vi *[8]float64, y0, y1, y2, y3, y4, y5, y6, y7 *[32]uint64, QHalfModqi, Q, mredQ, qoverqiinvqi []uint64) {

	vi[0], vi[1], vi[2], vi[3], vi[4], vi[5], vi[6], vi[7] = 0, 0, 0, 0, 0, 0, 0, 0

	for i, j := 0, start; j < end; i, j = i+1, j+1 {

		qqiinv := qoverqiinvqi[i]
		qi := Q[j]
		qHalf := QHalfModqi[i]
		mredConstant := mredQ[j]
		qif := float64(qi)

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p[j])%8 != 0 */
		px := (*[8]uint64)(unsafe.Pointer(&p[j][x]))

		y0[i] = MRed(px[0]+qHalf, qqiinv, qi, mredConstant)
		y1[i] = MRed(px[1]+qHalf, qqiinv, qi, mredConstant)
		y2[i] = MRed(px[2]+qHalf, qqiinv, qi, mredConstant)
		y3[i] = MRed(px[3]+qHalf, qqiinv, qi, mredConstant)
		y4[i] = MRed(px[4]+qHalf, qqiinv, qi, mredConstant)
		y5[i] = MRed(px[5]+qHalf, qqiinv, qi, mredConstant)
		y6[i] = MRed(px[6]+qHalf, qqiinv, qi, mredConstant)
		y7[i] = MRed(px[7]+qHalf, qqiinv, qi, mredConstant)

		// Computation of the correction term v * Q%pi
		vi[0] += float64(y0[i]) / qif
		vi[1] += float64(y1[i]) / qif
		vi[2] += float64(y2[i]) / qif
		vi[3] += float64(y3[i]) / qif
		vi[4] += float64(y4[i]) / qif
		vi[5] += float64(y5[i]) / qif
		vi[6] += float64(y6[i]) / qif
		vi[7] += float64(y7[i]) / qif
	}

	// Index of the correction term
	v[0] = uint64(vi[0])
	v[1] = uint64(vi[1])
	v[2] = uint64(vi[2])
	v[3] = uint64(vi[3])
	v[4] = uint64(vi[4])
	v[5] = uint64(vi[5])
	v[6] = uint64(vi[6])
	v[7] = uint64(vi[7])
}

func reconstructRNS(start, end, x int, p RNSPoly, v *[8]uint64, y0, y1, y2, y3, y4, y5, y6, y7 *[32]uint64, Q, QInv, QbMont []uint64) {

	var vi [8]float64
	var qi, qiInv, qoverqiinvqi uint64
	var qif float64

	for i, j := start, 0; i < end; i, j = i+1, j+1 {

		qoverqiinvqi = QbMont[i]
		qi = Q[i]
		qiInv = QInv[i]
		qif = float64(qi)

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p[i])%8 != 0 */
		pTmp := (*[8]uint64)(unsafe.Pointer(&p[i][x]))

		y0[j] = MRed(pTmp[0], qoverqiinvqi, qi, qiInv)
		y1[j] = MRed(pTmp[1], qoverqiinvqi, qi, qiInv)
		y2[j] = MRed(pTmp[2], qoverqiinvqi, qi, qiInv)
		y3[j] = MRed(pTmp[3], qoverqiinvqi, qi, qiInv)
		y4[j] = MRed(pTmp[4], qoverqiinvqi, qi, qiInv)
		y5[j] = MRed(pTmp[5], qoverqiinvqi, qi, qiInv)
		y6[j] = MRed(pTmp[6], qoverqiinvqi, qi, qiInv)
		y7[j] = MRed(pTmp[7], qoverqiinvqi, qi, qiInv)

		// Computation of the correction term v * Q%pi
		vi[0] += float64(y0[j]) / qif
		vi[1] += float64(y1[j]) / qif
		vi[2] += float64(y2[j]) / qif
		vi[3] += float64(y3[j]) / qif
		vi[4] += float64(y4[j]) / qif
		vi[5] += float64(y5[j]) / qif
		vi[6] += float64(y6[j]) / qif
		vi[7] += float64(y7[j]) / qif
	}

	v[0] = uint64(vi[0])
	v[1] = uint64(vi[1])
	v[2] = uint64(vi[2])
	v[3] = uint64(vi[3])
	v[4] = uint64(vi[4])
	v[5] = uint64(vi[5])
	v[6] = uint64(vi[6])
	v[7] = uint64(vi[7])
}

// Caution, returns the values in [0, 2q-1]
func multSum(level int, res, rlo, rhi, v *[8]uint64, y0, y1, y2, y3, y4, y5, y6, y7 *[32]uint64, q, qInv uint64, vtimesqmodp, qoverqimodp []uint64) {

	var mhi, mlo, c, hhi, qqip uint64

	qqip = qoverqimodp[0]

	rhi[0], rlo[0] = bits.Mul64(y0[0], qqip)
	rhi[1], rlo[1] = bits.Mul64(y1[0], qqip)
	rhi[2], rlo[2] = bits.Mul64(y2[0], qqip)
	rhi[3], rlo[3] = bits.Mul64(y3[0], qqip)
	rhi[4], rlo[4] = bits.Mul64(y4[0], qqip)
	rhi[5], rlo[5] = bits.Mul64(y5[0], qqip)
	rhi[6], rlo[6] = bits.Mul64(y6[0], qqip)
	rhi[7], rlo[7] = bits.Mul64(y7[0], qqip)

	// Accumulates the sum on uint128 and does a lazy montgomery reduction at the end
	for i := 1; i < level+1; i++ {

		qqip = qoverqimodp[i]

		mhi, mlo = bits.Mul64(y0[i], qqip)
		rlo[0], c = bits.Add64(rlo[0], mlo, 0)
		rhi[0] += mhi + c

		mhi, mlo = bits.Mul64(y1[i], qqip)
		rlo[1], c = bits.Add64(rlo[1], mlo, 0)
		rhi[1] += mhi + c

		mhi, mlo = bits.Mul64(y2[i], qqip)
		rlo[2], c = bits.Add64(rlo[2], mlo, 0)
		rhi[2] += mhi + c

		mhi, mlo = bits.Mul64(y3[i], qqip)
		rlo[3], c = bits.Add64(rlo[3], mlo, 0)
		rhi[3] += mhi + c

		mhi, mlo = bits.Mul64(y4[i], qqip)
		rlo[4], c = bits.Add64(rlo[4], mlo, 0)
		rhi[4] += mhi + c

		mhi, mlo = bits.Mul64(y5[i], qqip)
		rlo[5], c = bits.Add64(rlo[5], mlo, 0)
		rhi[5] += mhi + c

		mhi, mlo = bits.Mul64(y6[i], qqip)
		rlo[6], c = bits.Add64(rlo[6], mlo, 0)
		rhi[6] += mhi + c

		mhi, mlo = bits.Mul64(y7[i], qqip)
		rlo[7], c = bits.Add64(rlo[7], mlo, 0)
		rhi[7] += mhi + c
	}

	hhi, _ = bits.Mul64(rlo[0]*qInv, q)
	res[0] = rhi[0] - hhi + q + vtimesqmodp[v[0]]

	hhi, _ = bits.Mul64(rlo[1]*qInv, q)
	res[1] = rhi[1] - hhi + q + vtimesqmodp[v[1]]

	hhi, _ = bits.Mul64(rlo[2]*qInv, q)
	res[2] = rhi[2] - hhi + q + vtimesqmodp[v[2]]

	hhi, _ = bits.Mul64(rlo[3]*qInv, q)
	res[3] = rhi[3] - hhi + q + vtimesqmodp[v[3]]

	hhi, _ = bits.Mul64(rlo[4]*qInv, q)
	res[4] = rhi[4] - hhi + q + vtimesqmodp[v[4]]

	hhi, _ = bits.Mul64(rlo[5]*qInv, q)
	res[5] = rhi[5] - hhi + q + vtimesqmodp[v[5]]

	hhi, _ = bits.Mul64(rlo[6]*qInv, q)
	res[6] = rhi[6] - hhi + q + vtimesqmodp[v[6]]

	hhi, _ = bits.Mul64(rlo[7]*qInv, q)
	res[7] = rhi[7] - hhi + q + vtimesqmodp[v[7]]
}
