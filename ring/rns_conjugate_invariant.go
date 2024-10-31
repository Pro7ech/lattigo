package ring

// UnfoldConjugateInvariantToStandard maps the compressed representation (N/2 coefficients)
// of Z_Q[X+X^-1]/(X^2N + 1) to full representation in Z_Q[X]/(X^2N+1).
// Requires degree(polyConjugateInvariant) = 2*degree(polyStandard).
// Requires that polyStandard and polyConjugateInvariant share the same moduli.
func (r RNSRing) UnfoldConjugateInvariantToStandard(polyConjugateInvariant, polyStandard RNSPoly) {

	// Sanity check
	if 2*polyConjugateInvariant.N() != polyStandard.N() {
		panic("cannot UnfoldConjugateInvariantToStandard: Ring degree of polyConjugateInvariant must be twice the ring degree of polyStandard")
	}

	N := polyConjugateInvariant.N()

	for i := range r {
		tmp2, tmp1 := polyStandard.At(i), polyConjugateInvariant.At(i)
		copy(tmp2, tmp1)
		for idx, jdx := N-1, N; jdx < 2*N; idx, jdx = idx-1, jdx+1 {
			tmp2[jdx] = tmp1[idx]
		}
	}
}

// FoldStandardToConjugateInvariant folds [X]/(X^N+1) to [X+X^-1]/(X^N+1) in compressed form (N/2 coefficients).
// Requires degree(polyConjugateInvariant) = 2*degree(polyStandard).
// Requires that polyStandard and polyConjugateInvariant share the same moduli.
func (r RNSRing) FoldStandardToConjugateInvariant(polyStandard RNSPoly, permuteNTTIndexInv []uint64, polyConjugateInvariant RNSPoly) {

	// Sanity check
	if polyStandard.N() != 2*polyConjugateInvariant.N() {
		panic("cannot FoldStandardToConjugateInvariant: Ring degree of polyStandard must be 2N and ring degree of polyConjugateInvariant must be N")
	}

	N := r.N()

	r.AutomorphismNTTWithIndex(polyStandard, permuteNTTIndexInv, polyConjugateInvariant)

	for i, s := range r {
		s.Add(polyConjugateInvariant.At(i)[:N], polyStandard.At(i)[:N], polyConjugateInvariant.At(i)[:N])
	}
}

// PadDefaultRingToConjugateInvariant converts a polynomial in Z[X]/(X^N +1) to a polynomial in Z[X+X^-1]/(X^2N+1).
func (r RNSRing) PadDefaultRingToConjugateInvariant(polyStandard RNSPoly, IsNTT bool, polyConjugateInvariant RNSPoly) {

	// Sanity check
	if polyConjugateInvariant.N() != 2*polyStandard.N() {
		panic("cannot PadDefaultRingToConjugateInvariant: polyConjugateInvariant degree must be twice the one of polyStandard")
	}

	N := polyStandard.N()

	for i := range r {
		qi := r[i].Modulus

		copy(polyConjugateInvariant.At(i), polyStandard.At(i))

		tmp := polyConjugateInvariant.At(i)
		if IsNTT {
			for j := 0; j < N; j++ {
				tmp[N-j-1] = tmp[j]
			}
		} else {
			tmp[0] = 0
			for j := 1; j < N; j++ {
				tmp[N-j] = qi - tmp[j]
			}
		}
	}
}
