package ring

// NTT evaluates p2 = NTT(P1).
func (r RNSRing) NTT(p1, p2 RNSPoly) {
	for i, s := range r {
		s.NTT(p1.At(i), p2.At(i))
	}
}

// NTTLazy evaluates p2 = NTT(p1) with p2 in [0, 2*modulus-1].
func (r RNSRing) NTTLazy(p1, p2 RNSPoly) {
	for i, s := range r {
		s.NTTLazy(p1.At(i), p2.At(i))
	}
}

// INTT evaluates p2 = INTT(p1).
func (r RNSRing) INTT(p1, p2 RNSPoly) {
	for i, s := range r {
		s.INTT(p1.At(i), p2.At(i))
	}
}

// INTTLazy evaluates p2 = INTT(p1) with p2 in [0, 2*modulus-1].
func (r RNSRing) INTTLazy(p1, p2 RNSPoly) {
	for i, s := range r {
		s.INTTLazy(p1.At(i), p2.At(i))
	}
}
