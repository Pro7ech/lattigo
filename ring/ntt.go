package ring

const (
	// MinimumRingDegreeForLoopUnrolledNTT is the minimum ring degree
	// necessary for memory safe loop unrolling
	MinimumRingDegreeForLoopUnrolledNTT = 16
)

// NumberTheoreticTransformer is an interface to provide
// flexibility on what type of NTT is used by the struct Ring.
type NumberTheoreticTransformer interface {
	Forward(p1, p2 []uint64)
	ForwardLazy(p1, p2 []uint64)
	Backward(p1, p2 []uint64)
	BackwardLazy(p1, p2 []uint64)
}

type numberTheoreticTransformerBase struct {
	*NTTTable
	N            int
	Modulus      uint64
	MRedConstant uint64
	BRedConstant [2]uint64
}

// NumberTheoreticTransformerStandard computes the standard nega-cyclic NTT in the ring Z[X]/(X^N+1).
type NumberTheoreticTransformerStandard struct {
	numberTheoreticTransformerBase
}

// NTTTable store all the constants that are specifically tied to the NTT.
type NTTTable struct {
	NthRoot       uint64   // Nthroot used for the NTT
	PrimitiveRoot uint64   // 2N-th primitive root
	RootsForward  []uint64 //powers of the 2N-th primitive root in Montgomery form (in bit-reversed order)
	RootsBackward []uint64 //powers of the inverse of the 2N-th primitive root in Montgomery form (in bit-reversed order)
	NInv          uint64   //[N^-1] mod Modulus in Montgomery form
}

// NTT evaluates p2 = NTT(p1).
func (r Ring) NTT(p1, p2 []uint64) {
	r.Forward(p1, p2)
}

// NTTLazy evaluates p2 = NTT(p1) with p2 in [0, 2*modulus-1].
func (r Ring) NTTLazy(p1, p2 []uint64) {
	r.ForwardLazy(p1, p2)
}

// INTT evaluates p2 = INTT(p1).
func (r Ring) INTT(p1, p2 []uint64) {
	r.Backward(p1, p2)
}

// INTTLazy evaluates p2 = INTT(p1) with p2 in [0, 2*modulus-1].
func (r Ring) INTTLazy(p1, p2 []uint64) {
	r.BackwardLazy(p1, p2)
}
