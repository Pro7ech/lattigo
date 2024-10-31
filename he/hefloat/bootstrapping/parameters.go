package bootstrapping

import (
	"fmt"
	"maps"
	"slices"

	"github.com/google/go-cmp/cmp"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/ring"
)

// Parameters is a struct storing the parameters
// of the bootstrapping circuit.
type Parameters struct {
	EvalRound bool
	// ResidualParameters: Parameters outside of the bootstrapping circuit
	ResidualParameters hefloat.Parameters
	// BootstrappingParameters: Parameters during the bootstrapping circuit
	BootstrappingParameters hefloat.Parameters
	// S2C Parameters of the homomorphic decoding linear transformation
	S2C hefloat.DFTMatrixLiteral
	// Mod1: Parameters of the homomorphic modular reduction
	Mod1 hefloat.Mod1ParametersLiteral
	// C2S: Parameters of the homomorphic encoding linear transformation
	C2S hefloat.DFTMatrixLiteral
	// Iterations: Parameters of the bootstrapping iterations (META-BTS)
	Iterations Iterations
	// EphemeralSecretWeight: Hamming weight of the ephemeral secret. If 0, no ephemeral secret is used during the bootstrapping.
	EphemeralSecretWeight int
	// CircuitOrder: Value indicating the order of the circuit (default: ModUpThenEncode)
	CircuitOrder CircuitOrder
}

// NewParametersFromLiteral instantiates a Parameters from the residual hefloat.Parameters and
// a bootstrapping.ParametersLiteral struct.
//
// The residualParameters corresponds to the hefloat.Parameters that are left after the bootstrapping circuit is evaluated.
// These are entirely independent of the bootstrapping parameters with one exception: the ciphertext primes Qi must be
// congruent to 1 mod 2N of the bootstrapping parameters (note that the auxiliary primes Pi do not need to be).
// This is required because the primes Qi of the residual parameters and the bootstrapping parameters are the same between
// the two sets of parameters.
//
// The user can ensure that this condition is met by setting the appropriate LogNThRoot in the hefloat.ParametersLiteral before
// instantiating them.
//
// The method NewParametersFromLiteral will automatically allocate the hefloat.Parameters of the bootstrapping circuit based on
// the provided residualParameters and the information given in the bootstrapping.ParametersLiteral.
func NewParametersFromLiteral(residualParameters hefloat.Parameters, btpLit ParametersLiteral) (Parameters, error) {

	if !btpLit.Initialized {
		return Parameters{}, fmt.Errorf("[bootstrapping.ParametersLiteral] have not been initialized")
	}

	var err error

	// Retrieve the LogN of the bootstrapping circuit
	LogN := btpLit.LogN

	// Retrieve the NthRoot
	var NthRoot uint64
	switch residualParameters.RingType() {
	case ring.ConjugateInvariant:

		// If ConjugateInvariant, then the bootstrapping LogN must be at least 1 greater
		// than the residualParameters LogN
		if LogN != residualParameters.LogN()+1 {
			return Parameters{}, fmt.Errorf("cannot NewParametersFromLiteral: LogN of bootstrapping parameters must be equal to LogN+ of residual parameters if ringtype is ConjugateInvariant")
		}

		// Takes the greatest NthRoot between the residualParameters NthRoot and the bootstrapping NthRoot
		NthRoot = max(uint64(residualParameters.N()<<2), uint64(2<<LogN))

	default:

		// The LogN of the bootstrapping parameters cannot be smaller than the LogN of the residualParameters.
		if LogN < residualParameters.LogN() {
			return Parameters{}, fmt.Errorf("cannot NewParametersFromLiteral: LogN of bootstrapping parameters must be greater or equal to LogN of residual parameters")
		}

		// Takes the greatest NthRoot between the residualParameters NthRoot and the bootstrapping NthRoot
		NthRoot = max(uint64(residualParameters.N()<<1), uint64(2<<LogN))
	}

	// Checks that all primes Qi of the residualParameters are congruent to 1 mod NthRoot of the bootstrapping parameters.
	for i, q := range residualParameters.Q() {
		if q&(NthRoot-1) != 1 {
			return Parameters{}, fmt.Errorf("cannot NewParametersFromLiteral: Q[%d]=%d != 1 mod NthRoot=%d", i, q, NthRoot)
		}
	}

	if btpLit.LogSlots >= btpLit.LogN {
		return Parameters{}, fmt.Errorf("cannot NewParametersFromLiteral: LogSlots >= LogN")
	}

	// Circuit parameters literal
	C2SParams, S2CParams, Mod1Params := btpLit.GetCircuitParametersLiteral(residualParameters)

	// List of the prime-size of all primes required by the bootstrapping circuit.
	LogQBootstrappingCircuit := []int{}

	// appends the reserved prime first for multiple iteration, if any
	if btpLit.Iterations.ReservedPrimeBitSize != 0 {
		LogQBootstrappingCircuit = append(LogQBootstrappingCircuit, btpLit.Iterations.ReservedPrimeBitSize)
	}

	// Appends all other primes in reverse order of the circuit
	for i := range btpLit.S2C {
		var qi int
		for _, qj := range btpLit.S2C[i] {
			qi += qj
		}
		if qi+residualParameters.LogDefaultScale() < 61 {
			qi += residualParameters.LogDefaultScale()
		}
		LogQBootstrappingCircuit = append(LogQBootstrappingCircuit, qi)
	}

	for i := 0; i < Mod1Params.Depth(); i++ {
		LogQBootstrappingCircuit = append(LogQBootstrappingCircuit, Mod1Params.LogScale)
	}

	for i := range btpLit.C2S {
		var qi int
		for _, qj := range btpLit.C2S[i] {
			qi += qj
		}
		LogQBootstrappingCircuit = append(LogQBootstrappingCircuit, qi)
	}

	var Q, P []uint64

	// Extracts all the different primes Qi that are
	// in the residualParameters
	primesHave := map[uint64]bool{}
	for _, qi := range residualParameters.Q() {
		primesHave[qi] = true
	}

	// Maps the number of primes per bit size
	primesBitLenNew := map[int]int{}
	for _, logqi := range LogQBootstrappingCircuit {
		primesBitLenNew[logqi]++
	}

	// Retrieve the number of primes #Pi of the bootstrapping circuit
	// and adds them to the list of bit-size
	LogP := btpLit.LogP

	for _, logpj := range LogP {
		primesBitLenNew[logpj]++
	}

	S2CParams.LevelP = len(LogP) - 1
	C2SParams.LevelP = len(LogP) - 1

	// Map to store [bit-size][]primes
	primesNew := map[int][]uint64{}

	// For each bit-size sample a pair-wise coprime prime
	for logqi, k := range primesBitLenNew {

		// Creates a new prime generator
		g := ring.NewNTTFriendlyPrimesGenerator(uint64(logqi), NthRoot)

		// Populates the list with primes that aren't yet in primesHave
		primes := make([]uint64, k)
		var i int
		for i < k {

			for {
				qi, err := g.NextAlternatingPrime()

				if err != nil {
					return Parameters{}, fmt.Errorf("cannot NewParametersFromLiteral: NextAlternatingPrime for 2^{%d} +/- k*2N + 1: %w", logqi, err)

				}

				if _, ok := primesHave[qi]; !ok {
					primes[i] = qi
					i++
					break
				}
			}
		}

		primesNew[logqi] = primes
	}

	// Constructs the set of primes Qi
	Q = make([]uint64, len(residualParameters.Q()))
	copy(Q, residualParameters.Q())

	// Appends to the residual moduli
	for _, qi := range LogQBootstrappingCircuit {
		Q = append(Q, primesNew[qi][0])
		primesNew[qi] = primesNew[qi][1:]
	}

	// Constructs the set of primes Pi
	P = make([]uint64, len(LogP))
	for i, logpi := range LogP {
		P[i] = primesNew[logpi][0]
		primesNew[logpi] = primesNew[logpi][1:]
	}

	// Ensure that hefloat.PrecisionMode = PREC64 when using PREC128 residual parameters.
	var LogDefaultScale int
	switch residualParameters.PrecisionMode() {
	case hefloat.PREC64:
		LogDefaultScale = residualParameters.LogDefaultScale()
	case hefloat.PREC128:
		LogDefaultScale = residualParameters.LogQi()[0] - btpLit.LogMessageRatio
	}

	// Instantiates the hefloat.Parameters of the bootstrapping circuit.
	params, err := hefloat.NewParametersFromLiteral(hefloat.ParametersLiteral{
		LogN:            LogN,
		Q:               Q,
		P:               P,
		LogDefaultScale: LogDefaultScale,
		Xs:              btpLit.Xs,
		Xe:              btpLit.Xe,
	})

	if err != nil {
		return Parameters{}, err
	}

	return Parameters{
		EvalRound:               btpLit.EvalRound,
		ResidualParameters:      residualParameters,
		BootstrappingParameters: params,
		EphemeralSecretWeight:   btpLit.EphemeralSecretWeight,
		S2C:                     S2CParams,
		Mod1:                    Mod1Params,
		C2S:                     C2SParams,
		Iterations:              btpLit.Iterations,
	}, nil
}

// GetC2SBypass returns the [hefloat.DFTMatrixLiteral] of the high precision
// CoeffsToSlots bypass for the EvalRound+ approach.
// See https://eprint.iacr.org/2024/1379).
func (p Parameters) GetC2SBypass() hefloat.DFTMatrixLiteral {

	LogSlots := p.C2S.LogSlots

	// At least 1, at most p.Mod1.Depth(), if possible LogSlots.
	C2SBypassDepth := min(p.Mod1.Depth(), max(LogSlots, 1))

	C2SBypassLevels := make([]int, C2SBypassDepth)
	for i := range C2SBypassLevels {
		C2SBypassLevels[i] = 1
	}

	return hefloat.DFTMatrixLiteral{
		Type:     hefloat.HomomorphicEncode,
		Format:   hefloat.RepackImagAsReal,
		LogSlots: LogSlots,
		LevelQ:   p.S2C.LevelQ + C2SBypassDepth,
		LevelP:   p.C2S.LevelP,
		Levels:   C2SBypassLevels,
	}
}

func (p Parameters) Equal(other *Parameters) (res bool) {
	res = p.ResidualParameters.Equal(&other.ResidualParameters)
	res = res && p.BootstrappingParameters.Equal(&other.BootstrappingParameters)
	res = res && p.EphemeralSecretWeight == other.EphemeralSecretWeight
	res = res && cmp.Equal(p.S2C, other.S2C)
	res = res && cmp.Equal(p.Mod1, other.Mod1)
	res = res && cmp.Equal(p.C2S, other.C2S)
	res = res && cmp.Equal(p.Iterations, other.Iterations)
	return
}

// LogMaxDimensions returns the log plaintext dimensions of the target Parameters.
func (p Parameters) LogMaxDimensions() ring.Dimensions {
	return ring.Dimensions{Rows: 0, Cols: p.C2S.LogSlots}
}

// LogMaxSlots returns the log of the maximum number of slots.
func (p Parameters) LogMaxSlots() int {
	return p.C2S.LogSlots
}

// C2SDepth returns the depth of the Coeffs to Slots of the bootstrapping.
func (p Parameters) C2SDepth() (depth int) {
	return p.C2S.Depth(true)
}

// Mod1Depth returns the depth of the EvalMod step of the bootstrapping.
func (p Parameters) Mod1Depth() (depth int) {
	return p.Mod1.Depth()
}

// S2CDepth returns the depth of the Slots to Coeffs step of the bootstrapping.
func (p Parameters) S2CDepth() (depth int) {
	return p.C2S.Depth(true)
}

// Depth returns the depth of the full bootstrapping circuit.
func (p Parameters) Depth() (depth int) {
	return p.C2SDepth() + p.Mod1Depth() + p.S2CDepth()
}

// GaloisElements returns the list of Galois elements required to evaluate the bootstrapping.
func (p Parameters) GaloisElements(params hefloat.Parameters) (galEls []uint64) {

	logN := params.LogN()

	// List of the rotation key values to needed for the bootstrap
	m := make(map[uint64]bool)

	//SubSum rotation needed X -> Y^slots rotations
	for i := p.LogMaxDimensions().Cols; i < logN-1; i++ {
		m[params.GaloisElement(1<<i)] = true
	}

	for _, galEl := range p.C2S.GaloisElements(params) {
		m[galEl] = true
	}

	if p.EvalRound {
		for _, galEl := range p.GetC2SBypass().GaloisElements(params) {
			m[galEl] = true
		}
	}

	for _, galEl := range p.S2C.GaloisElements(params) {
		m[galEl] = true
	}

	m[params.GaloisElementForComplexConjugation()] = true

	return slices.Sorted(maps.Keys(m))
}
