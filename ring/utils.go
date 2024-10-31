package ring

import (
	"math/big"
	"math/bits"

	"github.com/Pro7ech/lattigo/utils/bignum"
)

type Dimensions struct {
	Rows, Cols int
}

// HenselLift returns (psi + a * P)^{m} = 1 mod P^{k} given psi^{m} = 1 mod P.
func HenselLift(psi, m uint64, P uint64, k int) uint64 {

	if bits.Len64(P)*k > 64 {
		panic("P^{k} uint64 overflow")
	}

	Pk := P
	phiMinusOne := P - 1
	for i := 1; i < k; i++ {
		Pk *= P
		phiMinusOne *= P
	}
	phiMinusOne--

	brc := GetBRedConstant(Pk)
	mrc := GetMRedConstant(Pk)

	//a*P = (1-psi^{2N})/(psi^{2N-1}*m) mod P^{k+1}

	psi = MForm(psi, Pk, brc)

	for i := 1; i < k; i++ {

		// psi^{m-1}
		tmp := ModExpMontgomery(psi, m-1, Pk, mrc, brc)

		// 1 - psi^{m}
		num := MForm(1, Pk, brc) + Pk - MRed(tmp, psi, Pk, mrc)

		// m * psi^{m-1}
		den := MRed(MForm(m, Pk, brc), tmp, Pk, mrc)

		// (m * psi^{m-1})^{-1}
		den = ModExpMontgomery(den, phiMinusOne, Pk, mrc, brc)

		// psi += (1 - psi^{m}) / (m * psi^{m-1})
		psi = BRedAdd(psi+MRed(num, den, Pk, mrc), Pk, brc)
	}

	return IMForm(psi, Pk, mrc)
}

// EvalPolyModP evaluates y = sum poly[i] * x^{i} mod p.
func EvalPolyModP(x uint64, poly []uint64, p uint64) (y uint64) {
	brc := GetBRedConstant(p)
	y = poly[len(poly)-1]
	for i := len(poly) - 2; i >= 0; i-- {
		y = BRed(y, x, p, brc)
		y = CRed(y+poly[i], p)
	}

	return BRedAdd(y, p, brc)
}

// Min returns the minimum between to int
func Min(x, y int) int {
	if x > y {
		return y
	}

	return x
}

// ModExp return y = x^e mod q,
// x and p are required to be at most 64 bits to avoid an overflow.
func ModExp(x, e, q uint64) (y uint64) {

	brc := GetBRedConstant(q)

	y = 1

	if q&(q-1) != 0 {

		mrc := GetMRedConstant(q)

		y = MForm(y, q, brc)
		x = MForm(x, q, brc)

		for i := e; i > 0; i >>= 1 {
			if i&1 == 1 {
				y = MRed(y, x, q, mrc)
			}
			x = MRed(x, x, q, mrc)
		}

		return IMForm(y, q, mrc)
	} else {

		for i := e; i > 0; i >>= 1 {
			if i&1 == 1 {
				y = BRed(y, x, q, brc)
			}
			x = BRed(x, x, q, brc)
		}

		return
	}
}

// ModExpPow2 performs the modular exponentiation x^e mod p, where p is a power of two,
// x and p are required to be at most 64 bits to avoid an overflow.
func ModExpPow2(x, e, p uint64) (result uint64) {

	result = 1
	for i := e; i > 0; i >>= 1 {
		if i&1 == 1 {
			result *= x
		}
		x *= x
	}
	return result & (p - 1)
}

// ModExpMontgomery performs the modular exponentiation x^e mod p,
// where x is in Montgomery form, and returns x^e in Montgomery form.
func ModExpMontgomery(x, e, q, mrc uint64, bredconstant [2]uint64) (result uint64) {

	result = MForm(1, q, bredconstant)

	for i := e; i > 0; i >>= 1 {
		if i&1 == 1 {
			result = MRed(result, x, q, mrc)
		}
		x = MRed(x, x, q, mrc)
	}
	return result
}

// PolyToBigintCentered reconstructs [p]_{QP} and returns the result in an array of Int.
// Coefficients are centered around QP/2
// gap defines coefficients X^{i*gap} that will be reconstructed.
// For example, if gap = 1, then all coefficients are reconstructed, while
// if gap = 2 then only coefficients X^{2*i} are reconstructed.
func PolyToBigintCentered(rQ, rP RNSRing, pQ RNSPoly, pP *RNSPoly, gap int, values []big.Int) {

	LevelQ := rQ.Level()

	var LevelP int
	if rP != nil {
		LevelP = pP.Level()
	} else {
		LevelP = -1
	}

	ICRTQ := make([]big.Int, LevelQ+1)
	ICRTP := make([]big.Int, LevelP+1)

	tmp := new(big.Int)

	QP := new(big.Int).SetUint64(1)
	QP.Mul(QP, rQ.Modulus())

	if LevelP > -1 {
		QP.Mul(QP, rP.Modulus())
	}

	// Q
	var QiB = new(big.Int)
	for i, table := range rQ {
		QiB.SetUint64(table.Modulus)
		ICRTQ[i].Quo(QP, QiB)
		tmp.ModInverse(&ICRTQ[i], QiB)
		tmp.Mod(tmp, QiB)
		ICRTQ[i].Mul(&ICRTQ[i], tmp)
	}

	// P
	if LevelP > -1 {
		var PiB = new(big.Int)
		for i, table := range rP {
			PiB.SetUint64(table.Modulus)
			ICRTP[i].Quo(QP, PiB)
			tmp.ModInverse(&ICRTP[i], PiB)
			tmp.Mod(tmp, PiB)
			ICRTP[i].Mul(&ICRTP[i], tmp)
		}
	}

	QPHalf := new(big.Int)
	QPHalf.Rsh(QP, 1)

	N := rQ.N()

	for i, j := 0, 0; j < N; i, j = i+1, j+gap {

		tmp.SetUint64(0)
		values[i].SetUint64(0)

		for k := 0; k < LevelQ+1; k++ {
			values[i].Add(&values[i], tmp.Mul(bignum.NewInt(pQ.At(k)[j]), &ICRTQ[k]))
		}

		if LevelP > -1 {
			for k := 0; k < LevelP+1; k++ {
				values[i].Add(&values[i], tmp.Mul(bignum.NewInt(pP.At(k)[j]), &ICRTP[k]))
			}
		}

		values[i].Mod(&values[i], QP)

		// Centers the coefficients
		if values[i].Cmp(QPHalf) > -1 {
			values[i].Sub(&values[i], QP)
		}
	}
}
