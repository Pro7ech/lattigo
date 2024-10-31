package ring

import (
	"math/big"

	"github.com/Pro7ech/lattigo/utils"
	"github.com/Pro7ech/lattigo/utils/bignum"
)

// Add evaluates p3 = p1 + p2 coefficient-wise in the ring.
func (r RNSRing) Add(p1, p2, p3 RNSPoly) {
	for i, s := range r {
		s.Add(p1.At(i), p2.At(i), p3.At(i))
	}
}

// AddLazy evaluates p3 = p1 + p2 coefficient-wise in the ring, with p3 in [0, 2*modulus-1].
func (r RNSRing) AddLazy(p1, p2, p3 RNSPoly) {
	for i, s := range r {
		s.AddLazy(p1.At(i), p2.At(i), p3.At(i))
	}
}

// Sub evaluates p3 = p1 - p2 coefficient-wise in the ring.
func (r RNSRing) Sub(p1, p2, p3 RNSPoly) {
	for i, s := range r {
		s.Sub(p1.At(i), p2.At(i), p3.At(i))
	}
}

// SubLazy evaluates p3 = p1 - p2 coefficient-wise in the ring, with p3 in [0, 2*modulus-1].
func (r RNSRing) SubLazy(p1, p2, p3 RNSPoly) {
	for i, s := range r {
		s.SubLazy(p1.At(i), p2.At(i), p3.At(i))
	}
}

// Neg evaluates p2 = -p1 coefficient-wise in the ring.
func (r RNSRing) Neg(p1, p2 RNSPoly) {
	for i, s := range r {
		s.Neg(p1.At(i), p2.At(i))
	}
}

// Reduce evaluates p2 = p1 coefficient-wise mod modulus in the ring.
func (r RNSRing) Reduce(p1, p2 RNSPoly) {
	for i, s := range r {
		s.Reduce(p1.At(i), p2.At(i))
	}
}

// ReduceLazy evaluates p2 = p1 coefficient-wise mod modulus in the ring, with p2 in [0, 2*modulus-1].
func (r RNSRing) ReduceLazy(p1, p2 RNSPoly) {
	for i, s := range r {
		s.ReduceLazy(p1.At(i), p2.At(i))
	}
}

// MulCoeffsBarrett evaluates p3 = p1 * p2 coefficient-wise in the ring, with Barrett reduction.
func (r RNSRing) MulCoeffsBarrett(p1, p2, p3 RNSPoly) {
	for i, s := range r {
		s.MulCoeffsBarrett(p1.At(i), p2.At(i), p3.At(i))
	}
}

// MulCoeffsBarrettLazy evaluates p3 = p1 * p2 coefficient-wise in the ring, with Barrett reduction, with p3 in [0, 2*modulus-1].
func (r RNSRing) MulCoeffsBarrettLazy(p1, p2, p3 RNSPoly) {
	for i, s := range r {
		s.MulCoeffsBarrettLazy(p1.At(i), p2.At(i), p3.At(i))
	}
}

// MulCoeffsBarrettThenAdd evaluates p3 = p3 + p1 * p2 coefficient-wise in the ring, with Barrett reduction.
func (r RNSRing) MulCoeffsBarrettThenAdd(p1, p2, p3 RNSPoly) {
	for i, s := range r {
		s.MulCoeffsBarrettThenAdd(p1.At(i), p2.At(i), p3.At(i))
	}
}

// MulCoeffsBarrettThenAddLazy evaluates p3 = p1 * p2 coefficient-wise in the ring, with Barrett reduction, with p3 in [0, 2*modulus-1].
func (r RNSRing) MulCoeffsBarrettThenAddLazy(p1, p2, p3 RNSPoly) {
	for i, s := range r {
		s.MulCoeffsBarrettThenAddLazy(p1.At(i), p2.At(i), p3.At(i))
	}
}

// MulCoeffsMontgomery evaluates p3 = p1 * p2 coefficient-wise in the ring, with Montgomery reduction.
func (r RNSRing) MulCoeffsMontgomery(p1, p2, p3 RNSPoly) {
	for i, s := range r {
		s.MulCoeffsMontgomery(p1.At(i), p2.At(i), p3.At(i))
	}
}

// MulCoeffsMontgomeryLazy evaluates p3 = p1 * p2 coefficient-wise in the ring, with Montgomery reduction, with p3 in [0, 2*modulus-1].
func (r RNSRing) MulCoeffsMontgomeryLazy(p1, p2, p3 RNSPoly) {
	for i, s := range r {
		s.MulCoeffsMontgomeryLazy(p1.At(i), p2.At(i), p3.At(i))
	}
}

// MulCoeffsMontgomeryLazyThenNeg evaluates p3 = -p1 * p2 coefficient-wise in the ring, with Montgomery reduction, with p3 in [0, 2*modulus-1].
func (r RNSRing) MulCoeffsMontgomeryLazyThenNeg(p1, p2, p3 RNSPoly) {
	for i, s := range r {
		s.MulCoeffsMontgomeryLazyThenNeg(p1.At(i), p2.At(i), p3.At(i))
	}
}

// MulCoeffsMontgomeryThenAdd evaluates p3 = p3 + p1 * p2 coefficient-wise in the ring, with Montgomery reduction, with p3 in [0, 2*modulus-1].
func (r RNSRing) MulCoeffsMontgomeryThenAdd(p1, p2, p3 RNSPoly) {
	for i, s := range r {
		s.MulCoeffsMontgomeryThenAdd(p1.At(i), p2.At(i), p3.At(i))
	}
}

// MulCoeffsMontgomeryThenAddLazy evaluates p3 = p3 + p1 * p2 coefficient-wise in the ring, with Montgomery reduction, with p3 in [0, 2*modulus-1].
func (r RNSRing) MulCoeffsMontgomeryThenAddLazy(p1, p2, p3 RNSPoly) {
	for i, s := range r {
		s.MulCoeffsMontgomeryThenAddLazy(p1.At(i), p2.At(i), p3.At(i))
	}
}

// MulCoeffsMontgomeryLazyThenAddLazy evaluates p3 = p3 + p1 * p2 coefficient-wise in the ring, with Montgomery reduction, with p3 in [0, 3*modulus-2].
func (r RNSRing) MulCoeffsMontgomeryLazyThenAddLazy(p1, p2, p3 RNSPoly) {
	for i, s := range r {
		s.MulCoeffsMontgomeryLazyThenAddLazy(p1.At(i), p2.At(i), p3.At(i))
	}
}

// MulCoeffsMontgomeryThenSub evaluates p3 = p3 - p1 * p2 coefficient-wise in the ring, with Montgomery reduction.
func (r RNSRing) MulCoeffsMontgomeryThenSub(p1, p2, p3 RNSPoly) {
	for i, s := range r {
		s.MulCoeffsMontgomeryThenSub(p1.At(i), p2.At(i), p3.At(i))
	}
}

// MulCoeffsMontgomeryThenSubLazy evaluates p3 = p3 - p1 * p2 coefficient-wise in the ring, with Montgomery reduction, with p3 in [0, 2*modulus-1].
func (r RNSRing) MulCoeffsMontgomeryThenSubLazy(p1, p2, p3 RNSPoly) {
	for i, s := range r {
		s.MulCoeffsMontgomeryThenSubLazy(p1.At(i), p2.At(i), p3.At(i))
	}
}

// MulCoeffsMontgomeryLazyThenSubLazy evaluates p3 = p3 - p1 * p2 coefficient-wise in the ring, with Montgomery reduction, with p3 in [0, 3*modulus-2].
func (r RNSRing) MulCoeffsMontgomeryLazyThenSubLazy(p1, p2, p3 RNSPoly) {
	for i, s := range r {
		s.MulCoeffsMontgomeryLazyThenSubLazy(p1.At(i), p2.At(i), p3.At(i))
	}
}

// AddScalar evaluates p2 = p1 + scalar coefficient-wise in the ring.
func (r RNSRing) AddScalar(p1 RNSPoly, scalar uint64, p2 RNSPoly) {
	for i, s := range r {
		s.AddScalar(p1.At(i), scalar, p2.At(i))
	}
}

// AddScalarBigint evaluates p2 = p1 + scalar coefficient-wise in the ring.
func (r RNSRing) AddScalarBigint(p1 RNSPoly, scalar *big.Int, p2 RNSPoly) {
	tmp := new(big.Int)
	for i, s := range r {
		s.AddScalar(p1.At(i), tmp.Mod(scalar, bignum.NewInt(s.Modulus)).Uint64(), p2.At(i))
	}
}

// AddDoubleRNSScalar evaluates p2 = p1[:N/2] + scalar0 || p1[N/2] + scalar1 coefficient-wise in the ring,
// with the scalar values expressed in the CRT decomposition at a given level.
func (r RNSRing) AddDoubleRNSScalar(p1 RNSPoly, scalar0, scalar1 RNSScalar, p2 RNSPoly) {
	NHalf := r.N() >> 1
	for i, s := range r {
		s.AddScalar(p1.At(i)[:NHalf], scalar0[i], p2.At(i)[:NHalf])
		s.AddScalar(p1.At(i)[NHalf:], scalar1[i], p2.At(i)[NHalf:])
	}
}

// SubDoubleRNSScalar evaluates p2 = p1[:N/2] - scalar0 || p1[N/2] - scalar1 coefficient-wise in the ring,
// with the scalar values expressed in the CRT decomposition at a given level.
func (r RNSRing) SubDoubleRNSScalar(p1 RNSPoly, scalar0, scalar1 RNSScalar, p2 RNSPoly) {
	NHalf := r.N() >> 1
	for i, s := range r {
		s.SubScalar(p1.At(i)[:NHalf], scalar0[i], p2.At(i)[:NHalf])
		s.SubScalar(p1.At(i)[NHalf:], scalar1[i], p2.At(i)[NHalf:])
	}
}

// SubScalar evaluates p2 = p1 - scalar coefficient-wise in the ring.
func (r RNSRing) SubScalar(p1 RNSPoly, scalar uint64, p2 RNSPoly) {
	for i, s := range r {
		s.SubScalar(p1.At(i), scalar, p2.At(i))
	}
}

// SubScalarBigint evaluates p2 = p1 - scalar coefficient-wise in the ring.
func (r RNSRing) SubScalarBigint(p1 RNSPoly, scalar *big.Int, p2 RNSPoly) {
	tmp := new(big.Int)
	for i, s := range r {
		s.SubScalar(p1.At(i), tmp.Mod(scalar, bignum.NewInt(s.Modulus)).Uint64(), p2.At(i))
	}
}

// MulScalar evaluates p2 = p1 * scalar coefficient-wise in the ring.
func (r RNSRing) MulScalar(p1 RNSPoly, scalar uint64, p2 RNSPoly) {
	for i, s := range r {
		s.MulScalarMontgomery(p1.At(i), MForm(scalar, s.Modulus, s.BRedConstant), p2.At(i))
	}
}

// MulScalarThenAdd evaluates p2 = p2 + p1 * scalar coefficient-wise in the ring.
func (r RNSRing) MulScalarThenAdd(p1 RNSPoly, scalar uint64, p2 RNSPoly) {
	for i, s := range r {
		s.MulScalarMontgomeryThenAdd(p1.At(i), MForm(scalar, s.Modulus, s.BRedConstant), p2.At(i))
	}
}

// MulRNSScalarMontgomery evaluates p2 = p1 * scalar coefficient-wise in the ring, with a scalar value expressed in the CRT decomposition at a given level.
// It assumes the scalar decomposition to be in Montgomery form.
func (r RNSRing) MulRNSScalarMontgomery(p1 RNSPoly, scalar RNSScalar, p2 RNSPoly) {
	for i, s := range r {
		s.MulScalarMontgomery(p1.At(i), scalar[i], p2.At(i))
	}
}

// MulScalarThenSub evaluates p2 = p2 - p1 * scalar coefficient-wise in the ring.
func (r RNSRing) MulScalarThenSub(p1 RNSPoly, scalar uint64, p2 RNSPoly) {
	for i, s := range r {
		scalarNeg := MForm(s.Modulus-BRedAdd(scalar, s.Modulus, s.BRedConstant), s.Modulus, s.BRedConstant)
		s.MulScalarMontgomeryThenAdd(p1.At(i), scalarNeg, p2.At(i))
	}
}

// MulScalarBigint evaluates p2 = p1 * scalar coefficient-wise in the ring.
func (r RNSRing) MulScalarBigint(p1 RNSPoly, scalar *big.Int, p2 RNSPoly) {
	scalarQi := new(big.Int)
	for i, s := range r {
		scalarQi.Mod(scalar, bignum.NewInt(s.Modulus))
		s.MulScalarMontgomery(p1.At(i), MForm(scalarQi.Uint64(), s.Modulus, s.BRedConstant), p2.At(i))
	}
}

// MulScalarBigintThenAdd evaluates p2 = p1 * scalar coefficient-wise in the ring.
func (r RNSRing) MulScalarBigintThenAdd(p1 RNSPoly, scalar *big.Int, p2 RNSPoly) {
	scalarQi := new(big.Int)
	for i, s := range r {
		scalarQi.Mod(scalar, bignum.NewInt(s.Modulus))
		s.MulScalarMontgomeryThenAdd(p1.At(i), MForm(scalarQi.Uint64(), s.Modulus, s.BRedConstant), p2.At(i))
	}
}

// MulDoubleRNSScalar evaluates p2 = p1[:N/2] * scalar0 || p1[N/2] * scalar1 coefficient-wise in the ring,
// with the scalar values expressed in the CRT decomposition at a given level.
func (r RNSRing) MulDoubleRNSScalar(p1 RNSPoly, scalar0, scalar1 RNSScalar, p2 RNSPoly) {
	NHalf := r.N() >> 1
	for i, s := range r {
		s.MulScalarMontgomery(p1.At(i)[:NHalf], MForm(scalar0[i], s.Modulus, s.BRedConstant), p2.At(i)[:NHalf])
		s.MulScalarMontgomery(p1.At(i)[NHalf:], MForm(scalar1[i], s.Modulus, s.BRedConstant), p2.At(i)[NHalf:])
	}
}

// MulDoubleRNSScalarThenAdd evaluates p2 = p2 + p1[:N/2] * scalar0 || p1[N/2] * scalar1 coefficient-wise in the ring,
// with the scalar values expressed in the CRT decomposition at a given level.
func (r RNSRing) MulDoubleRNSScalarThenAdd(p1 RNSPoly, scalar0, scalar1 RNSScalar, p2 RNSPoly) {
	NHalf := r.N() >> 1
	for i, s := range r {
		s.MulScalarMontgomeryThenAdd(p1.At(i)[:NHalf], MForm(scalar0[i], s.Modulus, s.BRedConstant), p2.At(i)[:NHalf])
		s.MulScalarMontgomeryThenAdd(p1.At(i)[NHalf:], MForm(scalar1[i], s.Modulus, s.BRedConstant), p2.At(i)[NHalf:])
	}
}

// EvalPolyScalar evaluate p2 = p1(scalar) coefficient-wise in the ring.
func (r RNSRing) EvalPolyScalar(p1 []RNSPoly, scalar uint64, p2 RNSPoly) {
	p2.Copy(&p1[len(p1)-1])
	for i := len(p1) - 1; i > 0; i-- {
		r.MulScalar(p2, scalar, p2)
		r.Add(p2, p1[i-1], p2)
	}
}

// Shift evaluates p2 = p2<<<k coefficient-wise in the ring.
func (r RNSRing) Shift(p1 RNSPoly, k int, p2 RNSPoly) {
	for i := range p1 {
		utils.RotateSliceAllocFree(p1.At(i), k, p2.At(i))
	}
}

// MForm evaluates p2 = p1 * (2^64)^-1 coefficient-wise in the ring.
func (r RNSRing) MForm(p1, p2 RNSPoly) {
	for i, s := range r {
		s.MForm(p1.At(i), p2.At(i))
	}
}

// MFormLazy evaluates p2 = p1 * (2^64)^-1 coefficient-wise in the ring with p2 in [0, 2*modulus-1].
func (r RNSRing) MFormLazy(p1, p2 RNSPoly) {
	for i, s := range r {
		s.MFormLazy(p1.At(i), p2.At(i))
	}
}

// IMForm evaluates p2 = p1 * 2^64 coefficient-wise in the ring.
func (r RNSRing) IMForm(p1, p2 RNSPoly) {
	for i, s := range r {
		s.IMForm(p1.At(i), p2.At(i))
	}
}

// MultByMonomial evaluates p2 = p1 * X^k coefficient-wise in the ring.
func (r RNSRing) MultByMonomial(p1 RNSPoly, k int, p2 RNSPoly) {

	N := r.N()

	shift := (k + (N << 1)) % (N << 1)

	if shift == 0 {

		for i := range r {
			p1tmp, p2tmp := p1.At(i), p2.At(i)
			for j := 0; j < N; j++ {
				p2tmp[j] = p1tmp[j]
			}
		}

	} else {

		tmpx := r.NewRNSPoly()

		if shift < N {

			for i := range r {
				p1tmp, tmpxT := p1.At(i), tmpx.At(i)
				for j := 0; j < N; j++ {
					tmpxT[j] = p1tmp[j]
				}
			}

		} else {

			for i, s := range r {
				qi := s.Modulus
				p1tmp, tmpxT := p1.At(i), tmpx.At(i)
				for j := 0; j < N; j++ {
					tmpxT[j] = qi - p1tmp[j]
				}
			}
		}

		shift %= N

		for i, s := range r {
			qi := s.Modulus
			p2tmp, tmpxT := p2.At(i), tmpx.At(i)
			for j := 0; j < shift; j++ {
				p2tmp[j] = qi - tmpxT[N-shift+j]
			}
		}

		for i := range r {
			p2tmp, tmpxT := p2.At(i), tmpx.At(i)
			for j := shift; j < N; j++ {
				p2tmp[j] = tmpxT[j-shift]

			}
		}
	}
}

// MulByVectorMontgomery evaluates p2 = p1 * vector coefficient-wise in the ring.
func (r RNSRing) MulByVectorMontgomery(p1 RNSPoly, vector []uint64, p2 RNSPoly) {
	for i, s := range r {
		s.MulCoeffsMontgomery(p1.At(i), vector, p2.At(i))
	}
}

// MulByVectorMontgomeryThenAddLazy evaluates p2 = p2 + p1 * vector coefficient-wise in the ring.
func (r RNSRing) MulByVectorMontgomeryThenAddLazy(p1 RNSPoly, vector []uint64, p2 RNSPoly) {
	for i, s := range r {
		s.MulCoeffsMontgomeryThenAddLazy(p1.At(i), vector, p2.At(i))
	}
}
