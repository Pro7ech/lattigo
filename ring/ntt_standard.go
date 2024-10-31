package ring

import (
	"fmt"
	"math/bits"
	"unsafe"
)

func NewNumberTheoreticTransformerStandard(r *Ring, n int) NumberTheoreticTransformer {
	return NumberTheoreticTransformerStandard{
		numberTheoreticTransformerBase: numberTheoreticTransformerBase{
			N:            r.N,
			Modulus:      r.Modulus,
			MRedConstant: r.MRedConstant,
			BRedConstant: r.BRedConstant,
			NTTTable:     r.NTTTable,
		},
	}
}

// Forward writes the forward NTT in Z[X]/(X^N+1) of p1 on p2.
func (rntt NumberTheoreticTransformerStandard) Forward(p1, p2 []uint64) {
	NTTStandard(p1, p2, rntt.N, rntt.Modulus, rntt.MRedConstant, rntt.BRedConstant, rntt.RootsForward)
}

// ForwardLazy writes the forward NTT in Z[X]/(X^N+1) of p1 on p2.
// Returns values in the range [0, 2q-1].
func (rntt NumberTheoreticTransformerStandard) ForwardLazy(p1, p2 []uint64) {
	NTTStandardLazy(p1, p2, rntt.N, rntt.Modulus, rntt.MRedConstant, rntt.RootsForward)
}

// Backward writes the backward NTT in Z[X]/(X^N+1) of p1 on p2.
func (rntt NumberTheoreticTransformerStandard) Backward(p1, p2 []uint64) {
	INTTStandard(p1, p2, rntt.N, rntt.NInv, rntt.Modulus, rntt.MRedConstant, rntt.RootsBackward)
}

// BackwardLazy writes the backward NTT in Z[X]/(X^N+1) p1 on p2.
// Returns values in the range [0, 2q-1].
func (rntt NumberTheoreticTransformerStandard) BackwardLazy(p1, p2 []uint64) {
	INTTStandardLazy(p1, p2, rntt.N, rntt.NInv, rntt.Modulus, rntt.MRedConstant, rntt.RootsBackward)
}

// NTTStandard computes the forward NTT in the given [Ring].
func NTTStandard(p1, p2 []uint64, N int, Q, MRedConstant uint64, BRedConstant [2]uint64, roots []uint64) {
	nttCoreLazy(p1, p2, N, Q, MRedConstant, roots)
	BarrettReduceVec(p2, p2, Q, BRedConstant)
}

// NTTStandardLazy computes the forward NTT in the given [Ring] with p2 in [0, 2*modulus-1].
func NTTStandardLazy(p1, p2 []uint64, N int, Q, MRedConstant uint64, roots []uint64) {
	nttCoreLazy(p1, p2, N, Q, MRedConstant, roots)
}

// INTTStandard computes the backward NTT in the given [Ring].
func INTTStandard(p1, p2 []uint64, N int, NInv, Q, MRedConstant uint64, roots []uint64) {
	inttCoreLazy(p1, p2, N, Q, MRedConstant, roots)
	MulScalarMontgomeryReduceVec(p2, NInv, p2, Q, MRedConstant)
}

// INTTStandardLazy backward NTT in the given [Ring] with p2 in [0, 2*modulus-1].
func INTTStandardLazy(p1, p2 []uint64, N int, NInv, Q, MRedConstant uint64, roots []uint64) {
	inttCoreLazy(p1, p2, N, Q, MRedConstant, roots)
	MulScalarMontgomeryReduceLazyVec(p2, NInv, p2, Q, MRedConstant)
}

// nttCoreLazy computes the NTT on the input coefficients using the input parameters with output values in the range [0, 2*modulus-1].
func nttCoreLazy(p1, p2 []uint64, N int, Q, MRedConstant uint64, roots []uint64) {

	// Sanity check
	if len(p1) < N || len(p2) < N || len(roots) < N {
		panic(fmt.Sprintf("cannot nttCoreLazy: ensure that len(p1)=%d, len(p2)=%d and len(roots)=%d >= N=%d", len(p1), len(p2), len(roots), N))
	}

	if N < MinimumRingDegreeForLoopUnrolledNTT {
		nttLazy(p1, p2, N, Q, MRedConstant, roots)
	} else {
		nttUnrolled16Lazy(p1, p2, N, Q, MRedConstant, roots)
	}
}

func nttLazy(p1, p2 []uint64, N int, Q, MRedConstant uint64, roots []uint64) {

	var j1, j2, t int
	var F uint64

	fourQ := 4 * Q
	twoQ := 2 * Q

	t = N >> 1
	F = roots[1]
	j1 = 0
	j2 = j1 + t

	for jx, jy := j1, j1+t; jx < j2; jx, jy = jx+1, jy+1 {
		p2[jx], p2[jy] = butterfly(p1[jx], p1[jy], F, twoQ, fourQ, Q, MRedConstant)
	}

	for m := 2; m < N; m <<= 1 {

		t >>= 1

		for i := 0; i < m; i++ {

			j1 = (i * t) << 1

			j2 = j1 + t

			F = roots[m+i]

			for jx, jy := j1, j1+t; jx < j2; jx, jy = jx+1, jy+1 {
				p2[jx], p2[jy] = butterfly(p2[jx], p2[jy], F, twoQ, fourQ, Q, MRedConstant)
			}
		}
	}
}
func nttUnrolled16Lazy(p1, p2 []uint64, N int, Q, MRedConstant uint64, roots []uint64) {

	// Sanity check
	if len(p2) < MinimumRingDegreeForLoopUnrolledNTT {
		panic(fmt.Sprintf("unsafe call of nttUnrolled16Lazy: receiver len(p2)=%d < %d", len(p2), MinimumRingDegreeForLoopUnrolledNTT))
	}

	var j1, j2, t int
	var F, V uint64

	fourQ := 4 * Q
	twoQ := 2 * Q

	// Copy the result of the first round of butterflies on p2 with approximate reduction
	t = N >> 1
	F = roots[1]

	for jx, jy := 0, t; jx < t; jx, jy = jx+8, jy+8 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 != 0 */
		xin := (*[8]uint64)(unsafe.Pointer(&p1[jx]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%8 != 0 */
		yin := (*[8]uint64)(unsafe.Pointer(&p1[jy]))

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 != 0 */
		xout := (*[8]uint64)(unsafe.Pointer(&p2[jx]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 != 0 */
		yout := (*[8]uint64)(unsafe.Pointer(&p2[jy]))

		V = MRedLazy(yin[0], F, Q, MRedConstant)
		xout[0], yout[0] = xin[0]+V, xin[0]+twoQ-V

		V = MRedLazy(yin[1], F, Q, MRedConstant)
		xout[1], yout[1] = xin[1]+V, xin[1]+twoQ-V

		V = MRedLazy(yin[2], F, Q, MRedConstant)
		xout[2], yout[2] = xin[2]+V, xin[2]+twoQ-V

		V = MRedLazy(yin[3], F, Q, MRedConstant)
		xout[3], yout[3] = xin[3]+V, xin[3]+twoQ-V

		V = MRedLazy(yin[4], F, Q, MRedConstant)
		xout[4], yout[4] = xin[4]+V, xin[4]+twoQ-V

		V = MRedLazy(yin[5], F, Q, MRedConstant)
		xout[5], yout[5] = xin[5]+V, xin[5]+twoQ-V

		V = MRedLazy(yin[6], F, Q, MRedConstant)
		xout[6], yout[6] = xin[6]+V, xin[6]+twoQ-V

		V = MRedLazy(yin[7], F, Q, MRedConstant)
		xout[7], yout[7] = xin[7]+V, xin[7]+twoQ-V
	}

	// Continue the rest of the second to the n-1 butterflies on p2 with approximate reduction
	var reduce bool

	for m := 2; m < N; m <<= 1 {

		reduce = (bits.Len64(uint64(m))&1 == 1)

		t >>= 1

		if t >= 8 {

			for i := 0; i < m; i++ {

				j1 = (i * t) << 1

				j2 = j1 + t

				F = roots[m+i]

				if reduce {

					for jx, jy := j1, j1+t; jx < j2; jx, jy = jx+8, jy+8 {

						/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 != 0 */
						x := (*[8]uint64)(unsafe.Pointer(&p2[jx]))
						/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 != 0 */
						y := (*[8]uint64)(unsafe.Pointer(&p2[jy]))

						x[0], y[0] = butterfly(x[0], y[0], F, twoQ, fourQ, Q, MRedConstant)
						x[1], y[1] = butterfly(x[1], y[1], F, twoQ, fourQ, Q, MRedConstant)
						x[2], y[2] = butterfly(x[2], y[2], F, twoQ, fourQ, Q, MRedConstant)
						x[3], y[3] = butterfly(x[3], y[3], F, twoQ, fourQ, Q, MRedConstant)
						x[4], y[4] = butterfly(x[4], y[4], F, twoQ, fourQ, Q, MRedConstant)
						x[5], y[5] = butterfly(x[5], y[5], F, twoQ, fourQ, Q, MRedConstant)
						x[6], y[6] = butterfly(x[6], y[6], F, twoQ, fourQ, Q, MRedConstant)
						x[7], y[7] = butterfly(x[7], y[7], F, twoQ, fourQ, Q, MRedConstant)
					}

				} else {

					for jx, jy := j1, j1+t; jx < j2; jx, jy = jx+8, jy+8 {

						/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 != 0 */
						x := (*[8]uint64)(unsafe.Pointer(&p2[jx]))
						/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 != 0 */
						y := (*[8]uint64)(unsafe.Pointer(&p2[jy]))

						V = MRedLazy(y[0], F, Q, MRedConstant)
						x[0], y[0] = x[0]+V, x[0]+twoQ-V

						V = MRedLazy(y[1], F, Q, MRedConstant)
						x[1], y[1] = x[1]+V, x[1]+twoQ-V

						V = MRedLazy(y[2], F, Q, MRedConstant)
						x[2], y[2] = x[2]+V, x[2]+twoQ-V

						V = MRedLazy(y[3], F, Q, MRedConstant)
						x[3], y[3] = x[3]+V, x[3]+twoQ-V

						V = MRedLazy(y[4], F, Q, MRedConstant)
						x[4], y[4] = x[4]+V, x[4]+twoQ-V

						V = MRedLazy(y[5], F, Q, MRedConstant)
						x[5], y[5] = x[5]+V, x[5]+twoQ-V

						V = MRedLazy(y[6], F, Q, MRedConstant)
						x[6], y[6] = x[6]+V, x[6]+twoQ-V

						V = MRedLazy(y[7], F, Q, MRedConstant)
						x[7], y[7] = x[7]+V, x[7]+twoQ-V
					}
				}
			}

		} else if t == 4 {

			if reduce {

				for i, j1 := m, 0; i < 2*m; i, j1 = i+2, j1+4*t {

					/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(roots)%2 != 0 */
					psi := (*[2]uint64)(unsafe.Pointer(&roots[i]))
					/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%16 != 0 */
					x := (*[16]uint64)(unsafe.Pointer(&p2[j1]))

					x[0], x[4] = butterfly(x[0], x[4], psi[0], twoQ, fourQ, Q, MRedConstant)
					x[1], x[5] = butterfly(x[1], x[5], psi[0], twoQ, fourQ, Q, MRedConstant)
					x[2], x[6] = butterfly(x[2], x[6], psi[0], twoQ, fourQ, Q, MRedConstant)
					x[3], x[7] = butterfly(x[3], x[7], psi[0], twoQ, fourQ, Q, MRedConstant)
					x[8], x[12] = butterfly(x[8], x[12], psi[1], twoQ, fourQ, Q, MRedConstant)
					x[9], x[13] = butterfly(x[9], x[13], psi[1], twoQ, fourQ, Q, MRedConstant)
					x[10], x[14] = butterfly(x[10], x[14], psi[1], twoQ, fourQ, Q, MRedConstant)
					x[11], x[15] = butterfly(x[11], x[15], psi[1], twoQ, fourQ, Q, MRedConstant)

				}
			} else {

				for i, j1 := m, 0; i < 2*m; i, j1 = i+2, j1+4*t {

					/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(roots)%2 != 0 */
					psi := (*[2]uint64)(unsafe.Pointer(&roots[i]))
					/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%16 != 0 */
					x := (*[16]uint64)(unsafe.Pointer(&p2[j1]))

					V = MRedLazy(x[4], psi[0], Q, MRedConstant)
					x[0], x[4] = x[0]+V, x[0]+twoQ-V

					V = MRedLazy(x[5], psi[0], Q, MRedConstant)
					x[1], x[5] = x[1]+V, x[1]+twoQ-V

					V = MRedLazy(x[6], psi[0], Q, MRedConstant)
					x[2], x[6] = x[2]+V, x[2]+twoQ-V

					V = MRedLazy(x[7], psi[0], Q, MRedConstant)
					x[3], x[7] = x[3]+V, x[3]+twoQ-V

					V = MRedLazy(x[12], psi[1], Q, MRedConstant)
					x[8], x[12] = x[8]+V, x[8]+twoQ-V

					V = MRedLazy(x[13], psi[1], Q, MRedConstant)
					x[9], x[13] = x[9]+V, x[9]+twoQ-V

					V = MRedLazy(x[14], psi[1], Q, MRedConstant)
					x[10], x[14] = x[10]+V, x[10]+twoQ-V

					V = MRedLazy(x[15], psi[1], Q, MRedConstant)
					x[11], x[15] = x[11]+V, x[11]+twoQ-V

				}

			}

		} else if t == 2 {

			if reduce {

				for i, j1 := m, 0; i < 2*m; i, j1 = i+4, j1+8*t {

					/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(roots)%4 != 0 */
					psi := (*[4]uint64)(unsafe.Pointer(&roots[i]))
					/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%16 != 0 */
					x := (*[16]uint64)(unsafe.Pointer(&p2[j1]))

					x[0], x[2] = butterfly(x[0], x[2], psi[0], twoQ, fourQ, Q, MRedConstant)
					x[1], x[3] = butterfly(x[1], x[3], psi[0], twoQ, fourQ, Q, MRedConstant)
					x[4], x[6] = butterfly(x[4], x[6], psi[1], twoQ, fourQ, Q, MRedConstant)
					x[5], x[7] = butterfly(x[5], x[7], psi[1], twoQ, fourQ, Q, MRedConstant)
					x[8], x[10] = butterfly(x[8], x[10], psi[2], twoQ, fourQ, Q, MRedConstant)
					x[9], x[11] = butterfly(x[9], x[11], psi[2], twoQ, fourQ, Q, MRedConstant)
					x[12], x[14] = butterfly(x[12], x[14], psi[3], twoQ, fourQ, Q, MRedConstant)
					x[13], x[15] = butterfly(x[13], x[15], psi[3], twoQ, fourQ, Q, MRedConstant)
				}
			} else {

				for i, j1 := m, 0; i < 2*m; i, j1 = i+4, j1+8*t {

					/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(roots)%4 != 0 */
					psi := (*[4]uint64)(unsafe.Pointer(&roots[i]))
					/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%16 != 0 */
					x := (*[16]uint64)(unsafe.Pointer(&p2[j1]))

					V = MRedLazy(x[2], psi[0], Q, MRedConstant)
					x[0], x[2] = x[0]+V, x[0]+twoQ-V

					V = MRedLazy(x[3], psi[0], Q, MRedConstant)
					x[1], x[3] = x[1]+V, x[1]+twoQ-V

					V = MRedLazy(x[6], psi[1], Q, MRedConstant)
					x[4], x[6] = x[4]+V, x[4]+twoQ-V

					V = MRedLazy(x[7], psi[1], Q, MRedConstant)
					x[5], x[7] = x[5]+V, x[5]+twoQ-V

					V = MRedLazy(x[10], psi[2], Q, MRedConstant)
					x[8], x[10] = x[8]+V, x[8]+twoQ-V

					V = MRedLazy(x[11], psi[2], Q, MRedConstant)
					x[9], x[11] = x[9]+V, x[9]+twoQ-V

					V = MRedLazy(x[14], psi[3], Q, MRedConstant)
					x[12], x[14] = x[12]+V, x[12]+twoQ-V

					V = MRedLazy(x[15], psi[3], Q, MRedConstant)
					x[13], x[15] = x[13]+V, x[13]+twoQ-V
				}
			}

		} else {

			for i, j1 := m, 0; i < 2*m; i, j1 = i+8, j1+16 {

				/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(roots)%8 != 0 */
				psi := (*[8]uint64)(unsafe.Pointer(&roots[i]))
				/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%16 != 0 */
				x := (*[16]uint64)(unsafe.Pointer(&p2[j1]))

				x[0], x[1] = butterfly(x[0], x[1], psi[0], twoQ, fourQ, Q, MRedConstant)
				x[2], x[3] = butterfly(x[2], x[3], psi[1], twoQ, fourQ, Q, MRedConstant)
				x[4], x[5] = butterfly(x[4], x[5], psi[2], twoQ, fourQ, Q, MRedConstant)
				x[6], x[7] = butterfly(x[6], x[7], psi[3], twoQ, fourQ, Q, MRedConstant)
				x[8], x[9] = butterfly(x[8], x[9], psi[4], twoQ, fourQ, Q, MRedConstant)
				x[10], x[11] = butterfly(x[10], x[11], psi[5], twoQ, fourQ, Q, MRedConstant)
				x[12], x[13] = butterfly(x[12], x[13], psi[6], twoQ, fourQ, Q, MRedConstant)
				x[14], x[15] = butterfly(x[14], x[15], psi[7], twoQ, fourQ, Q, MRedConstant)
			}

			/*
				for i := uint64(0); i < m; i = i + 8 {

					psi := (*[8]uint64)(unsafe.Pointer(&roots[m+i]))
					x := (*[16]uint64)(unsafe.Pointer(&p2[2*i]))

					V = MRedLazy(x[1], psi[0], Q, MRedConstant)
					x[0], x[1] = x[0]+V, x[0]+twoQ-V

					V = MRedLazy(x[3], psi[1], Q, MRedConstant)
					x[2], x[3] = x[2]+V, x[2]+twoQ-V

					V = MRedLazy(x[5], psi[2], Q, MRedConstant)
					x[4], x[5] = x[4]+V, x[4]+twoQ-V

					V = MRedLazy(x[7], psi[3], Q, MRedConstant)
					x[6], x[7] = x[6]+V, x[6]+twoQ-V

					V = MRedLazy(x[9], psi[4], Q, MRedConstant)
					x[8], x[9] = x[8]+V, x[8]+twoQ-V

					V = MRedLazy(x[11], psi[5], Q, MRedConstant)
					x[10], x[11] = x[10]+V, x[10]+twoQ-V

					V = MRedLazy(x[13], psi[6], Q, MRedConstant)
					x[12], x[13] = x[12]+V, x[12]+twoQ-V

					V = MRedLazy(x[15], psi[7], Q, MRedConstant)
					x[14], x[15] = x[14]+V, x[14]+twoQ-V
				}
			*/
		}
	}
}

func inttCoreLazy(p1, p2 []uint64, N int, Q, MRedConstant uint64, roots []uint64) {

	// Sanity check
	if len(p1) < N || len(p2) < N || len(roots) < N {
		panic(fmt.Sprintf("cannot inttCoreLazy: ensure that len(p1)=%d, len(p2)=%d and len(roots)=%d >= N=%d", len(p1), len(p2), len(roots), N))
	}

	if N < MinimumRingDegreeForLoopUnrolledNTT {
		inttLazy(p1, p2, N, Q, MRedConstant, roots)
	} else {
		inttLazyUnrolled16(p1, p2, N, Q, MRedConstant, roots)
	}
}

func inttLazy(p1, p2 []uint64, N int, Q, MRedConstant uint64, roots []uint64) {
	var h, t int
	var F uint64

	// Copy the result of the first round of butterflies on p2 with approximate reduction
	t = 1
	h = N >> 1
	twoQ := Q << 1
	fourQ := Q << 2

	for i, j1, j2 := 0, 0, t; i < h; i, j1, j2 = i+1, j1+2*t, j2+2*t {

		F = roots[h+i]

		for jx, jy := j1, j1+t; jx < j2; jx, jy = jx+1, jy+1 {
			p2[jx], p2[jy] = invbutterfly(p1[jx], p1[jy], F, twoQ, fourQ, Q, MRedConstant)

		}
	}

	t <<= 1

	for m := N >> 1; m > 1; m >>= 1 {

		h = m >> 1

		for i, j1, j2 := 0, 0, t; i < h; i, j1, j2 = i+1, j1+2*t, j2+2*t {

			F = roots[h+i]

			for jx, jy := j1, j1+t; jx < j2; jx, jy = jx+1, jy+1 {
				p2[jx], p2[jy] = invbutterfly(p2[jx], p2[jy], F, twoQ, fourQ, Q, MRedConstant)

			}
		}

		t <<= 1
	}
}

func inttLazyUnrolled16(p1, p2 []uint64, N int, Q, MRedConstant uint64, roots []uint64) {

	// Sanity check
	if len(p2) < MinimumRingDegreeForLoopUnrolledNTT {
		panic(fmt.Sprintf("unsafe call of inttCoreUnrolled16Lazy: receiver len(p2)=%d < %d", len(p2), MinimumRingDegreeForLoopUnrolledNTT))
	}

	var h, t int
	var F uint64

	// Copy the result of the first round of butterflies on p2 with approximate reduction
	t = 1
	h = N >> 1
	twoQ := Q << 1
	fourQ := Q << 2

	for i, j := h, 0; i < 2*h; i, j = i+8, j+16 {

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(roots)%8 != 0 */
		psi := (*[8]uint64)(unsafe.Pointer(&roots[i]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p1)%16 != 0 */
		xin := (*[16]uint64)(unsafe.Pointer(&p1[j]))
		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%16 != 0 */
		xout := (*[16]uint64)(unsafe.Pointer(&p2[j]))

		xout[0], xout[1] = invbutterfly(xin[0], xin[1], psi[0], twoQ, fourQ, Q, MRedConstant)
		xout[2], xout[3] = invbutterfly(xin[2], xin[3], psi[1], twoQ, fourQ, Q, MRedConstant)
		xout[4], xout[5] = invbutterfly(xin[4], xin[5], psi[2], twoQ, fourQ, Q, MRedConstant)
		xout[6], xout[7] = invbutterfly(xin[6], xin[7], psi[3], twoQ, fourQ, Q, MRedConstant)
		xout[8], xout[9] = invbutterfly(xin[8], xin[9], psi[4], twoQ, fourQ, Q, MRedConstant)
		xout[10], xout[11] = invbutterfly(xin[10], xin[11], psi[5], twoQ, fourQ, Q, MRedConstant)
		xout[12], xout[13] = invbutterfly(xin[12], xin[13], psi[6], twoQ, fourQ, Q, MRedConstant)
		xout[14], xout[15] = invbutterfly(xin[14], xin[15], psi[7], twoQ, fourQ, Q, MRedConstant)
	}

	// Continue the rest of the second to the n-1 butterflies on p2 with approximate reduction
	t <<= 1
	for m := N >> 1; m > 1; m >>= 1 {

		h = m >> 1

		if t >= 8 {

			for i, j1, j2 := 0, 0, t; i < h; i, j1, j2 = i+1, j1+2*t, j2+2*t {

				F = roots[h+i]

				for jx, jy := j1, j1+t; jx < j2; jx, jy = jx+8, jy+8 {

					/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 != 0 */
					x := (*[8]uint64)(unsafe.Pointer(&p2[jx]))
					/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%8 != 0 */
					y := (*[8]uint64)(unsafe.Pointer(&p2[jy]))

					x[0], y[0] = invbutterfly(x[0], y[0], F, twoQ, fourQ, Q, MRedConstant)
					x[1], y[1] = invbutterfly(x[1], y[1], F, twoQ, fourQ, Q, MRedConstant)
					x[2], y[2] = invbutterfly(x[2], y[2], F, twoQ, fourQ, Q, MRedConstant)
					x[3], y[3] = invbutterfly(x[3], y[3], F, twoQ, fourQ, Q, MRedConstant)
					x[4], y[4] = invbutterfly(x[4], y[4], F, twoQ, fourQ, Q, MRedConstant)
					x[5], y[5] = invbutterfly(x[5], y[5], F, twoQ, fourQ, Q, MRedConstant)
					x[6], y[6] = invbutterfly(x[6], y[6], F, twoQ, fourQ, Q, MRedConstant)
					x[7], y[7] = invbutterfly(x[7], y[7], F, twoQ, fourQ, Q, MRedConstant)
				}
			}

		} else if t == 4 {

			for i, j1 := h, 0; i < 2*h; i, j1 = i+2, j1+4*t {

				/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(roots)%2 != 0 */
				psi := (*[2]uint64)(unsafe.Pointer(&roots[i]))
				/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%16 != 0 */
				x := (*[16]uint64)(unsafe.Pointer(&p2[j1]))

				x[0], x[4] = invbutterfly(x[0], x[4], psi[0], twoQ, fourQ, Q, MRedConstant)
				x[1], x[5] = invbutterfly(x[1], x[5], psi[0], twoQ, fourQ, Q, MRedConstant)
				x[2], x[6] = invbutterfly(x[2], x[6], psi[0], twoQ, fourQ, Q, MRedConstant)
				x[3], x[7] = invbutterfly(x[3], x[7], psi[0], twoQ, fourQ, Q, MRedConstant)
				x[8], x[12] = invbutterfly(x[8], x[12], psi[1], twoQ, fourQ, Q, MRedConstant)
				x[9], x[13] = invbutterfly(x[9], x[13], psi[1], twoQ, fourQ, Q, MRedConstant)
				x[10], x[14] = invbutterfly(x[10], x[14], psi[1], twoQ, fourQ, Q, MRedConstant)
				x[11], x[15] = invbutterfly(x[11], x[15], psi[1], twoQ, fourQ, Q, MRedConstant)
			}

		} else {

			for i, j1 := h, 0; i < 2*h; i, j1 = i+4, j1+8*t {

				/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(roots)%4 != 0 */
				psi := (*[4]uint64)(unsafe.Pointer(&roots[i]))
				/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2)%16 != 0 */
				x := (*[16]uint64)(unsafe.Pointer(&p2[j1]))

				x[0], x[2] = invbutterfly(x[0], x[2], psi[0], twoQ, fourQ, Q, MRedConstant)
				x[1], x[3] = invbutterfly(x[1], x[3], psi[0], twoQ, fourQ, Q, MRedConstant)
				x[4], x[6] = invbutterfly(x[4], x[6], psi[1], twoQ, fourQ, Q, MRedConstant)
				x[5], x[7] = invbutterfly(x[5], x[7], psi[1], twoQ, fourQ, Q, MRedConstant)
				x[8], x[10] = invbutterfly(x[8], x[10], psi[2], twoQ, fourQ, Q, MRedConstant)
				x[9], x[11] = invbutterfly(x[9], x[11], psi[2], twoQ, fourQ, Q, MRedConstant)
				x[12], x[14] = invbutterfly(x[12], x[14], psi[3], twoQ, fourQ, Q, MRedConstant)
				x[13], x[15] = invbutterfly(x[13], x[15], psi[3], twoQ, fourQ, Q, MRedConstant)
			}
		}

		t <<= 1
	}
}
