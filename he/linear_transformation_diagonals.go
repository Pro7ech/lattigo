package he

import (
	"fmt"
	"maps"
	"slices"

	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils"
)

type Diagonals[T any] map[int][]T

func (m Diagonals[T]) Add(d Diagonals[T], add func(a, b, c []T), clone func(a []T) (b []T)) {
	for i, di := range d {
		if mi, ok := m[i]; ok {
			add(mi, di, mi)
		} else {
			m[i] = clone(di)
		}
	}
}

func (m Diagonals[T]) Mul(d Diagonals[T], buff []T, add func(a, b, c []T), rot func(a []T, k int, b []T), mul func(a, b []T, c []T), clone func(a []T) (b []T)) {

	tmp := map[int][]T{}

	dim := len(buff)

	for i, mi := range m {
		for j, dj := range d {

			rot(mi, j, buff)
			mul(buff, dj, buff)

			k := (i + j) % dim

			if _, ok := tmp[k]; !ok {
				tmp[k] = clone(buff)
			} else {
				add(tmp[k], buff, tmp[k])
			}
		}
	}

	for i := range m {
		delete(m, i)
	}
	for i := range tmp {
		m[i] = tmp[i]
	}
}

// Indexes returns the list of the non-zero diagonals of the square matrix.
// A non zero diagonals is a diagonal with a least one non-zero element.
func (m Diagonals[T]) Indexes() (indexes []int) {
	return slices.Collect(maps.Keys(m))
}

func (m Diagonals[T]) GaloisElements(params rlwe.ParameterProvider, LogDimensions ring.Dimensions, GiantStep int) (galEls []uint64) {
	ltParams := &LinearTransformationParameters{
		Indexes:       m.Indexes(),
		LogDimensions: LogDimensions,
		GiantStep:     GiantStep,
	}
	return ltParams.GaloisElements(params)
}

// At returns the i-th non-zero diagonal.
// Method accepts negative values with the equivalency -i = n - i.
func (m Diagonals[T]) At(i, slots int) ([]T, error) {

	v, ok := m[i]

	if !ok {

		var j int
		if i > 0 {
			j = i - slots
		} else if j < 0 {
			j = i + slots
		} else {
			return nil, fmt.Errorf("cannot At[0]: diagonal does not exist")
		}

		v, ok := m[j]

		if !ok {
			return nil, fmt.Errorf("cannot At[%d or %d]: diagonal does not exist", i, j)
		}

		return v, nil
	}

	return v, nil
}

// Evaluate evaluates the [hefloat.Diagonals] on the input vector.
// - zero: evaluates c[i] = 0
// - add: evaluates c[i] = a[i] + b[i]
// - muladd: evaluates c[i] = a[i] * b[i]
func (m Diagonals[T]) Evaluate(in, buff, out []T, LTParams LinearTransformationParameters, zero func(a []T), add func(a, b, c []T), muladd func(a, b, c []T)) {

	rows := 1 << LTParams.LogDimensions.Rows
	cols := 1 << LTParams.LogDimensions.Cols

	n := len(in)

	keys := slices.Collect(maps.Keys(m))
	slices.Sort(keys)

	zero(out)

	if LTParams.GiantStep > 0 {

		index, _, _ := BSGSIndex(keys, n, LTParams.GiantStep)

		keys = slices.Collect(maps.Keys(index))
		slices.Sort(keys)

		for _, j := range keys {

			rot := -j & (n - 1)

			zero(buff)

			for _, i := range index[j] {

				v, ok := m[j+i]
				if !ok {
					v = m[j+i-n]
				}

				for k := 0; k < rows; k++ {
					muladd(utils.RotateSlice(in[k*cols:(k+1)*cols], i), utils.RotateSlice(v[k*cols:(k+1)*cols], rot), buff[k*cols:(k+1)*cols])
				}
			}

			for k := 0; k < rows; k++ {
				add(out[k*cols:(k+1)*cols], utils.RotateSlice(buff[k*cols:(k+1)*cols], j), out[k*cols:(k+1)*cols])
			}
		}
	} else {
		for _, j := range keys {
			for k := 0; k < rows; k++ {
				muladd(utils.RotateSlice(in[k*cols:(k+1)*cols], j), m[j][k*cols:(k+1)*cols], out[k*cols:(k+1)*cols])
			}
		}
	}
}
