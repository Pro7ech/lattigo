package ring

import (
	"fmt"
	"math"
	"math/bits"

	"github.com/Pro7ech/lattigo/utils/sampling"
)

const ternarySamplerPrecision = uint64(56)

// TernarySampler keeps the state of a polynomial sampler in the ternary distribution.
type TernarySampler struct {
	Moduli []uint64
	*sampling.Source
	matrixProba  [2][ternarySamplerPrecision - 1]uint8
	matrixValues [][3]uint64
	invDensity   float64
	hw           int
	sample       func(source *sampling.Source, poly RNSPoly, f func(a, b, c uint64) uint64)
}

// NewTernarySampler creates a new instance of [TernarySampler] from a [sampling.Source],
// a moduli chain and and a ternary distribution parameters (see type [Ternary]).
func NewTernarySampler(source *sampling.Source, moduli []uint64, X Ternary) (s *TernarySampler, err error) {
	s = new(TernarySampler)
	s.Moduli = moduli
	s.Source = source
	s.initializeMatrix()
	switch {
	case X.P != 0 && X.H == 0:
		s.invDensity = 1 - X.P
		s.sample = s.sampleProba
		if s.invDensity != 0.5 {
			s.computeMatrixTernary(s.invDensity)
		}
	case X.P == 0 && X.H != 0:
		s.hw = X.H
		s.sample = s.sampleSparse
	default:
		return nil, fmt.Errorf("invalid TernaryDistribution: at exactly one of (H, P) should be > 0")
	}

	return
}

// GetSource returns the underlying [sampling.Source] used by the sampler.
func (s TernarySampler) GetSource() *sampling.Source {
	return s.Source
}

// WithSource returns an instance of the underlying sampler with
// a new [sampling.Source].
// It can be used concurrently with the original sampler.
func (s TernarySampler) WithSource(source *sampling.Source) Sampler {
	return &TernarySampler{
		Moduli:       s.Moduli,
		Source:       source,
		matrixProba:  s.matrixProba,
		matrixValues: s.matrixValues,
		invDensity:   s.invDensity,
		hw:           s.hw,
		sample:       s.sample,
	}
}

// AtLevel returns an instance of the target TernarySampler to sample at the given level.
// The returned sampler cannot be used concurrently to the original sampler.
func (s TernarySampler) AtLevel(level int) Sampler {
	return &TernarySampler{
		Moduli:       s.Moduli[:level+1],
		Source:       s.Source,
		matrixProba:  s.matrixProba,
		matrixValues: s.matrixValues,
		invDensity:   s.invDensity,
		hw:           s.hw,
		sample:       s.sample,
	}
}

// Read samples a polynomial into pol.
func (s *TernarySampler) Read(pol RNSPoly) {
	s.sample(s.Source, pol, func(a, b, c uint64) uint64 {
		return b
	})
}

// ReadNew allocates and samples a polynomial at the max level.
func (s *TernarySampler) ReadNew(N int) (pol RNSPoly) {
	pol = NewRNSPoly(N, len(s.Moduli)-1)
	s.Read(pol)
	return pol
}

func (s *TernarySampler) ReadAndAdd(pol RNSPoly) {
	s.sample(s.Source, pol, func(a, b, c uint64) uint64 {
		return CRed(a+b, c)
	})
}

func (s *TernarySampler) initializeMatrix() {
	s.matrixValues = make([][3]uint64, len(s.Moduli))
	// [0] = 0
	// [1] = 1 * 2^64 mod qi
	// [2] = (qi - 1) * 2^64 mod qi
	for i, qi := range s.Moduli {
		s.matrixValues[i][0] = 0
		s.matrixValues[i][1] = 1
		s.matrixValues[i][2] = qi - 1
	}
}

func (s *TernarySampler) computeMatrixTernary(p float64) {
	var g float64
	var x uint64

	g = p
	g *= math.Exp2(float64(ternarySamplerPrecision))
	x = uint64(g)

	for j := uint64(0); j < ternarySamplerPrecision-1; j++ {
		s.matrixProba[0][j] = uint8((x >> (ternarySamplerPrecision - j - 1)) & 1)
	}

	g = 1 - p
	g *= math.Exp2(float64(ternarySamplerPrecision))
	x = uint64(g)

	for j := uint64(0); j < ternarySamplerPrecision-1; j++ {
		s.matrixProba[1][j] = uint8((x >> (ternarySamplerPrecision - j - 1)) & 1)
	}

}

func (s *TernarySampler) sampleProba(source *sampling.Source, pol RNSPoly, f func(a, b, c uint64) uint64) {

	// Sanity check for invalid parameters
	if s.invDensity == 0 {
		panic("cannot sample -> p = 0")
	}

	var coeff uint64
	var sign uint64
	var index uint64

	moduli := s.Moduli

	N := pol.N()

	lut := s.matrixValues

	if s.invDensity == 0.5 {

		randomBytesCoeffs := make([]byte, N>>3)
		randomBytesSign := make([]byte, N>>3)

		if _, err := source.Read(randomBytesCoeffs); err != nil {
			// Sanity check, this error should not happen.
			panic(err)
		}

		if _, err := source.Read(randomBytesSign); err != nil {
			// Sanity check, this error should not happen.
			panic(err)
		}

		for i := 0; i < N; i++ {
			coeff = uint64(uint8(randomBytesCoeffs[i>>3])>>(i&7)) & 1
			sign = uint64(uint8(randomBytesSign[i>>3])>>(i&7)) & 1

			index = (coeff & (sign ^ 1)) | ((sign & coeff) << 1)

			for j, qi := range moduli {
				pol.At(j)[i] = f(pol.At(j)[i], lut[j][index], qi)
			}
		}

	} else {

		randomBytes := make([]byte, N)

		pointer := uint8(0)
		var bytePointer int

		if _, err := source.Read(randomBytes); err != nil {
			// Sanity check, this error should not happen.
			panic(err)
		}

		for i := 0; i < N; i++ {

			coeff, sign, randomBytes, pointer, bytePointer = kysampling(source, s.matrixProba, randomBytes, pointer, bytePointer, N)

			index = (coeff & (sign ^ 1)) | ((sign & coeff) << 1)

			for j, qi := range moduli {
				pol.At(j)[i] = f(pol.At(j)[i], lut[j][index], qi)
			}
		}
	}
}

func (s *TernarySampler) sampleSparse(source *sampling.Source, pol RNSPoly, f func(a, b, c uint64) uint64) {

	N := pol.N()

	if s.hw > N {
		s.hw = N
	}

	var mask, j uint64
	var coeff uint8

	moduli := s.Moduli

	index := make([]int, N)
	for i := 0; i < N; i++ {
		index[i] = i
	}

	// ceil(hw/8) bytes
	size := (s.hw + 7) >> 3

	// Padds to the next multiple of 8
	size += size & 7

	randomBytes := make([]byte, size)

	if _, err := source.Read(randomBytes); err != nil {
		// Sanity check, this error should not happen.
		panic(err)
	}

	var ptr uint8

	coeffs := pol

	m := s.matrixValues

	for i := 0; i < s.hw; i++ {
		mask = (1 << uint64(bits.Len64(uint64(N-i)))) - 1 // rejection sampling of a random variable between [0, len(index)]

		j = source.Uint64() & mask
		for j >= uint64(N-i) {
			j = source.Uint64() & mask
		}

		coeff = (uint8(randomBytes[0]) >> (i & 7)) & 1 // random binary digit [0, 1] from the random bytes (0 = 1, 1 = -1)

		idxj := index[j]

		for k, qi := range moduli {
			coeffs[k][idxj] = f(coeffs[k][idxj], m[k][coeff+1], qi)
		}

		// Remove the element in position j of the slice (order not preserved)
		index[j] = index[len(index)-1]
		index = index[:len(index)-1]

		ptr++

		if ptr == 8 {
			randomBytes = randomBytes[1:]
			ptr = 0
		}
	}

	for _, i := range index {
		for k := range moduli {
			coeffs[k][i] = 0
		}
	}
}

// kysampling uses the binary expansion and random bytes matrix to sample a discrete Gaussian value and its sign.
func kysampling(source *sampling.Source, matrixProba [2][ternarySamplerPrecision - 1]uint8, randomBytes []byte, pointer uint8, bytePointer, byteLength int) (uint64, uint64, []byte, uint8, int) {

	var sign uint8

	d := 0
	col := 0
	colLen := len(matrixProba)

	for {

		// Use one random byte per cycle and cycle through the randomBytes
		for i := pointer; i < 8; i++ {

			d = (d << 1) + 1 - int((uint8(randomBytes[bytePointer])>>i)&1)

			// There is small probability that it will get out of the bound, then
			// rerun until it gets a proper output

			if d > colLen-1 {
				return kysampling(source, matrixProba, randomBytes, i, bytePointer, byteLength)
			}

			for row := colLen - 1; row >= 0; row-- {

				d -= int(matrixProba[row][col])

				if d == -1 {

					// Sign
					if i == 7 {
						pointer = 0
						// If the last bit of the array was read, sample a new one
						bytePointer++

						if bytePointer >= byteLength {
							bytePointer = 0
							if _, err := source.Read(randomBytes); err != nil {
								// Sanity check, this error should not happen.
								panic(err)
							}
						}

						sign = uint8(randomBytes[bytePointer]) & 1

					} else {
						pointer = i
						// Otherwise, the sign is the next bit of the byte
						sign = uint8(randomBytes[bytePointer]>>(i+1)) & 1
					}

					return uint64(row), uint64(sign), randomBytes, pointer + 1, bytePointer
				}
			}

			col++
		}

		// Reset the bit pointer and discard the used byte
		pointer = 0
		// If the last bit of the array was read, sample a new one
		bytePointer++

		if bytePointer >= byteLength {
			bytePointer = 0
			if _, err := source.Read(randomBytes); err != nil {
				// Sanity check, this error should not happen.
				panic(err)
			}
		}
	}
}
