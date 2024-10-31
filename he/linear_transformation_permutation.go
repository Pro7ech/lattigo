package he

import (
	"maps"
	"slices"

	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
)

// Permutation is a struct that defines a linear transformation
// acting as a permutation over a vector.
// The defined permutation can be injective but not surjective.
type Permutation[T any] []struct {
	X int // Start index
	Y int // End index
	C T   // Scalar factor
}

// NewPermutation allocates a new [hefloat.Permutation] that can
// then be populated manually.
func NewPermutation[T any](size int) Permutation[T] {
	return make([]struct {
		X int
		Y int
		C T
	}, size)
}

func (p Permutation[T]) Indexes(LogDimensions ring.Dimensions) (indexes []int) {
	cols := 1 << LogDimensions.Cols
	m := map[int]bool{}
	for _, pi := range p {
		m[(cols+pi.X-pi.Y)&(cols-1)] = true
	}
	return slices.Collect(maps.Keys(m))
}

// Diagonals returns the [hefloat.Diagonals] representation
// of the permutation.
// The [hefloat.Diagonals] struct is used to instantiate an
// [hefloat.LinearTransformationParameters].
func (p Permutation[T]) Diagonals(LogDimensions ring.Dimensions) Diagonals[T] {

	rows := 1 << LogDimensions.Rows
	cols := 1 << LogDimensions.Cols

	diagonals := map[int][]T{}

	for _, m := range p {

		idx := (cols + m.X - m.Y) & (cols - 1)

		if _, ok := diagonals[idx]; !ok {
			diagonals[idx] = make([]T, rows*cols)
		}

		diagonals[idx][m.Y] = m.C
	}

	return Diagonals[T](diagonals)
}

func (p Permutation[T]) GaloisElements(params rlwe.ParameterProvider, LogDimensions ring.Dimensions) (galEls []uint64) {
	ltParams := &LinearTransformationParameters{
		Indexes:       p.Indexes(LogDimensions),
		LogDimensions: LogDimensions,
	}
	return ltParams.GaloisElements(params)
}
