package bootstrapping

import (
	"bufio"
	"fmt"
	"io"
	"math/bits"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/buffer"
	"github.com/Pro7ech/lattigo/utils/structs"
)

// ParametersLiteral is an unchecked struct that is given to the method [NewParametersFromLiteral]
// to validate them and create a [Parameter] struct, which is used to instantiate an [Evaluator].
//
// The fields can set manually to customize the bootstrapping circuit, but it is recommanded
// to first instantiate the struct with the method [NewParametersLiteral], which will return
// a new [ParametersLiteral] struct with the default bootstrapping parameterization (see
// [NewParametersLiteral] for information about its performance).
type ParametersLiteral struct {
	// Initialized is  boolean flag set to true if the struct
	// was intantiated with the method [NewParametersLiteral].
	Initialized bool

	// EvalRound is a boolean flag indicating if the circuit
	// follows the approach of https://eprint.iacr.org/2024/1379.
	EvalRound bool

	// LogN is the base two logarithm of the ring degree of the bootstrapping parameters.
	LogN int

	// LogSlots is the maximum number of slots of the ciphertext.
	LogSlots int

	// LogP is the base two logarithm of the auxiliary primes during the key-switching operation of the bootstrapping parameters.
	LogP structs.Vector[int]

	// Xs is the distribution of the secret-key used to generate the bootstrapping evaluation keys.
	Xs ring.DistributionParameters

	// Xe is the distribution of the error sampled to generate the bootstrapping evaluation keys.
	Xe ring.DistributionParameters

	// C2S: the scaling factor and distribution of the moduli for the SlotsToCoeffs (homomorphic encoding) step.
	// See [hefloat.DFTMatrix] for additional information.
	C2S structs.Matrix[int]

	// S2C: the scaling factor and distribution of the moduli for the CoeffsToSlots (homomorphic decoding) step.
	// See [hefloat.DFTMatrix] for additional information.
	S2C structs.Matrix[int]

	// EphemeralSecretWeight: the Hamming weight of the ephemeral secret.
	//	The user can set this value to 0 to use the regular bootstrapping
	//  circuit without the ephemeral secret encapsulation.
	//	Be aware that doing so will impact the security, precision,
	//  and failure probability of the bootstrapping circuit.
	//	See https://eprint.iacr.org/2022/024 for more information.
	EphemeralSecretWeight int

	// Iterations : by treating the bootstrapping as a black box with precision logprec,
	// we can construct a bootstrapping of precision ~k*logprec by iteration (see https://eprint.iacr.org/2022/1167).
	// - BootstrappingPrecision: []float64, the list of iterations (after the initial bootstrapping) given by the
	//   expected precision of each previous iteration.
	// - ReservedPrimeBitSize: the size of the reserved prime for the scaling after the initial bootstrapping.
	Iterations Iterations

	// LogMessageRation is Log(Q/Scale). This ratio directly impacts the precision of the bootstrapping.
	// The homomorphic modular reduction x mod 1 is approximated with by sin(2*pi*x)/(2*pi),
	// which is a good approximation when x is close to the origin.
	// Thus a large message ratio (i.e. 2^8) implies that x is small
	// with respect to Q, and thus close to the origin.
	// When using a small ratio (i.e. 2^4), for example if ct.Scale
	// is close to Q[0] is small or if |m| is large, the Mod1InvDegree can be set to
	// a non zero value (i.e. 5 or 7). This will greatly improve the precision of the
	// bootstrapping, at the expense of slightly increasing its depth.
	LogMessageRatio int

	// Mod1Type: the type of approximation for the modular reduction polynomial.
	Mod1Type hefloat.Mod1Type

	// Mod1LogScale: the scaling factor used during the EvalMod step (all primes will have this bit-size).
	Mod1LogScale int

	// Mod1Degree is the degree of f: x mod 1.
	Mod1Degree int

	// Mod1Interval is the range of the approximation interval of Mod1.
	Mod1Interval int

	// DoubleAngle is the number of double angle evaluation.
	DoubleAngle int

	// Mod1InvDegree: the degree of f^-1: (x mod 1)^-1.
	Mod1InvDegree int
}

// NewParametersLiteral returns a [bootstrapping.ParametersLiteral] with default value,
// ensuring a bootstrapping with the following standardized performance:
//
// Depth:
// - 2 for CoeffsToSlots
// - 8 for EvalMod
// - 3 for SlotsToCoeffs
// for a total 13 and a bit consumption of 713.
//
// Precision:
// - 27.25 bits for H=192
// - 23.8 bits for H=32768
// for complex values with both real and imaginary parts uniformly distributed in [-1, 1].
//
// Failure probability:
// - 2^{-133} for 2^{15} slots.
func NewParametersLiteral() (p ParametersLiteral) {
	p.EvalRound = true
	p.LogN = 16
	p.LogSlots = 15
	p.LogMessageRatio = 8
	p.LogP = []int{61, 61, 61, 61, 61}
	p.Xs = &ring.Ternary{H: 192}
	p.Xe = &rlwe.DefaultXe
	p.EvalRound = true
	p.C2S = [][]int{{29, 29}, {29, 29}}
	p.S2C = [][]int{{39}, {39}, {39}}
	p.Mod1Type = hefloat.CosDiscrete
	p.Mod1Degree = 30
	p.Mod1Interval = 16
	p.Mod1LogScale = 60
	p.DoubleAngle = 3
	p.EphemeralSecretWeight = 32 // >> 128-bit for LogN=16 & Log(QP) ~ 121 bits.
	p.Iterations = Iterations{}
	p.Initialized = true
	return
}

type CircuitOrder int

const (
	ModUpThenEncode = CircuitOrder(0) // ScaleDown -> ModUp -> CoeffsToSlots -> EvalMod -> SlotsToCoeffs.
	DecodeThenModUp = CircuitOrder(1) // SlotsToCoeffs -> ScaleDown -> ModUp -> CoeffsToSlots -> EvalMod.
	Custom          = CircuitOrder(2) // Custom order (e.g. partial bootstrapping), disables checks.
)

// Iterations is a struct storing the iterations parameters of the bootstrapping.
//
// For example: &bootstrapping.Iterations{BootstrappingPrecision: []float64{16}, ReservedPrimeBitSize: 16} will define a two iteration bootstrapping (the first iteration being the initial bootstrapping)
// with a additional prime close to 2^{16} reserved for the scaling of the error during the second iteration.
//
// Here is an example for a two iterations bootstrapping of an input message mod [logq0=55, logq1=45] with scaling factor 2^{90}:
//
// INPUT:
// 1) The input is a ciphertext encrypting [2^{90} * M]_{q0, q1}
// ITERATION N°0
// 2) Rescale  [M^{90}]_{q0, q1} to [M^{90}/q1]_{q0} (ensure that M^{90}/q1 ~ q0/messageratio by additional scaling if necessary)
// 3) Bootsrap [M^{90}/q1]_{q0} to [M^{90}/q1 + e^{90 - logprec}/q1]_{q0, q1, q2, ...}
// 4) Scale up [M^{90}/q1 + e^{90 - logprec}/q1]_{q0, q1, q2, ...} to [M^{d} + e^{d - logprec}]_{q0, q1, q2, ...}
// ITERATION N°1
// 5) Subtract [M^{d}]_{q0, q1} to [M^{d} + e^{d - logprec}]_{q0, q1, q2, ...} to get [e^{d - logprec}]_{q0, q1}
// 6) Scale up [e^{90 - logprec}]_{q0, q1} by 2^{logprec} to get [e^{d}]_{q0, q1}
// 7) Rescale  [e^{90}]_{q0, q1} to [{90}/q1]_{q0}
// 8) Bootsrap [e^{90}/q1]_{q0} to [e^{90}/q1 + e'^{90 - logprec}/q1]_{q0, q1, q2, ...}
// 9) Scale up [e^{90}/q1 + e'^{90 - logprec}/q0]_{q0, q1, q2, ...} by round(q1/2^{logprec}) to get [e^{90-logprec} + e'^{90 - 2logprec}]_{q0, q1, q2, ...}
// 10) Subtract [e^{d - logprec} + e'^{d - 2logprec}]_{q0, q1, q2, ...} to [M^{d} + e^{d - logprec}]_{q0, q1, q2, ...} to get [M^{d} + e'^{d - 2logprec}]_{q0, q1, q2, ...}
// 11) Go back to step 5 for more iterations until 2^{k * logprec} >= 2^{90}
//
// This example can be generalized to input messages of any scaling factor and desired output precision by increasing the input scaling factor and substituting q1 by a larger product of primes.
//
// Notes:
//   - The bootstrapping precision cannot exceed the original input ciphertext precision.
//   - Although the rescalings of 2) and 7) are approximate, we can ignore them and treat them as being part of the bootstrapping error
//   - As long as round(q1/2^{k*logprec}) >= 2^{logprec}, for k the iteration number, we are guaranteed that the error due to the approximate scale up of step 8) is smaller than 2^{logprec}
//   - The gain in precision for each iteration is proportional to min(round(q1/2^{k*logprec}), 2^{logprec})
//   - If round(q1/2^{k * logprec}) < 2^{logprec}, where k is the iteration number, then the gain in precision will be less than the expected logprec.
//     This can happen during the last iteration when q1/2^{k * logprec} < 1, and gets rounded to 1 or 0.
//     To solve this issue, we can reduce logprec for the last iterations, but this increases the number of iterations, or reserve a prime of size at least 2^{logprec} to get
//     a proper scaling by q1/2^{k * logprec} (i.e. not a integer rounded scaling).
//   - If the input ciphertext is at level 0, we must reserve a prime because everything happens within Q[0] and we have no other prime to use for rescaling.
type Iterations struct {
	BootstrappingPrecision structs.Vector[float64]
	ReservedPrimeBitSize   int
}

// GetCircuitParametersLiteral returns the parameters literal of CoeffsToSlots, SlotsToCoeffs, Mod1.
// This method will panic if the depth allocated to CoeffsToSlots or SlotsToCoeffs is larger than LogSlots.
func (p ParametersLiteral) GetCircuitParametersLiteral(params hefloat.Parameters) (C2S, S2C hefloat.DFTMatrixLiteral, Mod1 hefloat.Mod1ParametersLiteral) {

	if !p.Initialized {
		panic(fmt.Errorf("struct was not created with [bootstrapping.NewParametersLiteral] or not set as initialized"))
	}

	var hasReservedIterationPrime int
	if p.Iterations.ReservedPrimeBitSize > 0 {
		hasReservedIterationPrime = 1
	}

	S2CLevels := make([]int, len(p.S2C))
	depth := 0
	for i := range p.S2C {
		S2CLevels[i] = len(p.S2C[i])
		depth += S2CLevels[i]
	}

	if depth > p.LogSlots {
		panic(fmt.Errorf("LogSlots=%d > SlotsToCoeffs depth=%d", p.LogSlots, depth))
	}

	S2C = hefloat.DFTMatrixLiteral{
		Type:     hefloat.HomomorphicDecode,
		LogSlots: p.LogSlots,
		Format:   hefloat.RepackImagAsReal,
		LevelQ:   params.MaxLevel() + len(S2CLevels) + hasReservedIterationPrime,
		Levels:   S2CLevels,
	}

	Mod1 = hefloat.Mod1ParametersLiteral{
		LogScale:        p.Mod1LogScale,
		Mod1Type:        p.Mod1Type,
		Mod1Degree:      p.Mod1Degree,
		DoubleAngle:     p.DoubleAngle,
		Mod1Interval:    p.Mod1Interval,
		LogMessageRatio: p.LogMessageRatio,
		Mod1InvDegree:   p.Mod1InvDegree,
	}

	Mod1.LevelQ = params.MaxLevel() + len(S2CLevels) + hasReservedIterationPrime + Mod1.Depth()

	C2SLevels := make([]int, len(p.C2S))
	depth = 0
	for i := range p.C2S {
		C2SLevels[i] = len(p.C2S[i])
		depth += C2SLevels[i]
	}

	if depth > p.LogSlots {
		panic(fmt.Errorf("LogSlots=%d > CoeffsToSlots depth=%d", p.LogSlots, depth))
	}

	C2S = hefloat.DFTMatrixLiteral{
		Type:     hefloat.HomomorphicEncode,
		Format:   hefloat.RepackImagAsReal,
		LogSlots: p.LogSlots,
		LevelQ:   params.MaxLevel() + hasReservedIterationPrime + len(S2CLevels) + Mod1.Depth() + len(C2SLevels),
		Levels:   C2SLevels,
	}

	return
}

// FailureProbability returns the base 2 logarithm of the failure probability of the bootstrapping parameters.
// This method only supports Xs.(type) = *ring.Ternary and will panic otherwise.
func (p ParametersLiteral) FailureProbability() (logfailure float64) {

	if !p.Initialized {
		panic(fmt.Errorf("[bootstrapping.ParametersLiteral] has not been initialized"))
	}

	H := p.EphemeralSecretWeight

	var P float64
	if H == 0 {
		switch Xs := p.Xs.(type) {
		case *ring.Ternary:
			P = Xs.P
		default:
			panic(fmt.Errorf("method is only supported *ring.Ternary but Xs.(type) = %T", Xs))
		}
	}

	return FailureProbability(&ring.Ternary{H: H, P: P}, p.Mod1Interval, p.LogN, p.LogSlots)
}

// BitConsumption returns the expected consumption in bits of
// bootstrapping circuit of the target ParametersLiteral.
// The value is rounded up and thus will overestimate the value by up to 1 bit.
func (p ParametersLiteral) BitConsumption() (logQ int, err error) {

	for i := range p.C2S {
		for _, logQi := range p.C2S[i] {
			logQ += logQi
		}
	}

	for i := range p.S2C {
		for _, logQi := range p.S2C[i] {
			logQ += logQi
		}
	}

	logQ += 1 + p.Mod1LogScale*(bits.Len64(uint64(p.Mod1Degree))+p.DoubleAngle+bits.Len64(uint64(p.Mod1InvDegree))) + p.Iterations.ReservedPrimeBitSize

	return
}

// BinarySize returns the serialized size of the object in bytes.
func (p ParametersLiteral) BinarySize() (size int) {
	// p.EvalRound, p.Initialized, p.LogN, p.LogSlots,
	// p.LogMessageRatio, p.Mod1Type, p.Mod1LogScale
	// p.DoubleAngle, p.Mod1InvDegree
	size += 9
	// p.Mod1Degree, p.Mod1Interval, p.EphemeralSecretWeight
	size += 6
	// p.Iterations.ReservedPrimeBitSize
	size += 8
	size += p.LogP.BinarySize()
	size += p.Xs.BinarySize()
	size += p.Xe.BinarySize()
	size += p.C2S.BinarySize()
	size += p.S2C.BinarySize()
	size += p.Iterations.BootstrappingPrecision.BinarySize()
	return
}

// WriteTo writes the object on an io.Writer. It implements the io.WriterTo
// interface, and will write exactly object.BinarySize() bytes on w.
//
// Unless w implements the buffer.Writer interface (see lattigo/utils/buffer/writer.go),
// it will be wrapped into a bufio.Writer. Since this requires allocations, it
// is preferable to pass a buffer.Writer directly:
//
//   - When writing multiple times to a io.Writer, it is preferable to first wrap the
//     io.Writer in a pre-allocated bufio.Writer.
//   - When writing to a pre-allocated var b []byte, it is preferable to pass
//     buffer.NewBuffer(b) as w (see lattigo/utils/buffer/buffer.go).
func (p ParametersLiteral) WriteTo(w io.Writer) (n int64, err error) {
	switch w := w.(type) {
	case buffer.Writer:

		var inc int64

		if inc, err = buffer.WriteAsUint8(w, p.Initialized); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.WriteAsUint8(w, p.EvalRound); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.WriteAsUint8(w, p.LogN); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.WriteAsUint8(w, p.LogSlots); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = p.LogP.WriteTo(w); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = p.Xe.WriteTo(w); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = p.Xs.WriteTo(w); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = p.C2S.WriteTo(w); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = p.S2C.WriteTo(w); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.WriteAsUint16(w, p.EphemeralSecretWeight); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = p.Iterations.BootstrappingPrecision.WriteTo(w); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.WriteAsUint64(w, p.Iterations.ReservedPrimeBitSize); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.WriteAsUint8(w, p.LogMessageRatio); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.WriteAsUint8(w, p.Mod1Type); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.WriteAsUint8(w, p.Mod1LogScale); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.WriteAsUint16(w, p.Mod1Degree); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.WriteAsUint16(w, p.Mod1Interval); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.WriteAsUint8(w, p.DoubleAngle); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.WriteAsUint8(w, p.Mod1InvDegree); err != nil {
			return n + inc, err
		}

		n += inc

		return n, w.Flush()
	default:
		return p.WriteTo(bufio.NewWriter(w))
	}
}

// ReadFrom reads on the object from an io.Writer. It implements the
// io.ReaderFrom interface.
//
// Unless r implements the buffer.Reader interface (see see lattigo/utils/buffer/reader.go),
// it will be wrapped into a bufio.Reader. Since this requires allocation, it
// is preferable to pass a buffer.Reader directly:
//
//   - When reading multiple values from a io.Reader, it is preferable to first
//     first wrap io.Reader in a pre-allocated bufio.Reader.
//   - When reading from a var b []byte, it is preferable to pass a buffer.NewBuffer(b)
//     as w (see lattigo/utils/buffer/buffer.go).
func (p *ParametersLiteral) ReadFrom(r io.Reader) (n int64, err error) {

	switch r := r.(type) {
	case buffer.Reader:

		var inc int64

		if inc, err = buffer.ReadAsUint8(r, &p.Initialized); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.ReadAsUint8(r, &p.EvalRound); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.ReadAsUint8(r, &p.LogN); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.ReadAsUint8(r, &p.LogSlots); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = p.LogP.ReadFrom(r); err != nil {
			return n + inc, err
		}

		n += inc

		if p.Xe, inc, err = ring.DistributionParametersFromReader(r); err != nil {
			return n + inc, err
		}

		n += inc

		if p.Xs, inc, err = ring.DistributionParametersFromReader(r); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = p.C2S.ReadFrom(r); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = p.S2C.ReadFrom(r); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.ReadAsUint16(r, &p.EphemeralSecretWeight); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = p.Iterations.BootstrappingPrecision.ReadFrom(r); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.ReadAsUint64(r, &p.Iterations.ReservedPrimeBitSize); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.ReadAsUint8(r, &p.LogMessageRatio); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.ReadAsUint8(r, &p.Mod1Type); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.ReadAsUint8(r, &p.Mod1LogScale); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.ReadAsUint16(r, &p.Mod1Degree); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.ReadAsUint16(r, &p.Mod1Interval); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.ReadAsUint8(r, &p.DoubleAngle); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.ReadAsUint8(r, &p.Mod1InvDegree); err != nil {
			return n + inc, err
		}

		n += inc

		return

	default:
		return p.ReadFrom(bufio.NewReader(r))
	}
}

// MarshalBinary encodes the object into a binary form on a newly allocated slice of bytes.
func (p ParametersLiteral) MarshalBinary() (data []byte, err error) {
	buf := buffer.NewBufferSize(p.BinarySize())
	_, err = p.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary decodes a slice of bytes generated by
// MarshalBinary or WriteTo on the object.
func (p *ParametersLiteral) UnmarshalBinary(data []byte) (err error) {
	_, err = p.ReadFrom(buffer.NewBuffer(data))
	return
}
