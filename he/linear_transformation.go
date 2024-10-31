package he

import (
	"fmt"
	"maps"
	"slices"

	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils"
)

// LinearTransformationParameters is a struct storing the parameterization of a
// linear transformation.
//
// A homomorphic linear transformations on a ciphertext acts as evaluating:
//
// Ciphertext([1 x n] vector) <- Ciphertext([1 x n] vector) x Plaintext([n x n] matrix)
//
// where n is the number of plaintext slots.
//
// The diagonal representation of a linear transformations is defined by first expressing
// the linear transformation through its nxn matrix and then traversing the matrix diagonally.
//
// For example, the following nxn for n=4 matrix:
//
// 0 1 2 3 (diagonal index)
// | 1 2 3 0 |
// | 0 1 2 3 |
// | 3 0 1 2 |
// | 2 3 0 1 |
//
// its diagonal traversal representation is comprised of 3 non-zero diagonals at indexes [0, 1, 2]:
// 0: [1, 1, 1, 1]
// 1: [2, 2, 2, 2]
// 2: [3, 3, 3, 3]
// 3: [0, 0, 0, 0] -> this diagonal is omitted as it is composed only of zero values.
//
// Note that negative indexes can be used and will be interpreted modulo the matrix dimension.
//
// The diagonal representation is well suited for two reasons:
//  1. It is the effective format used during the homomorphic evaluation.
//  2. It enables on average a more compact and efficient representation of linear transformations
//     than their matrix representation by being able to only store the non-zero diagonals.
//
// Finally, some metrics about the time and storage complexity of homomorphic linear transformations:
//   - Storage: #diagonals polynomials mod Q * P
//   - Evaluation: #diagonals multiplications and 2sqrt(#diagonals) ciphertexts rotations.
type LinearTransformationParameters struct {
	// Indexes is the list of the non-zero diagonals of the square matrix.
	// A non zero diagonals is a diagonal with a least one non-zero element.
	Indexes []int

	// LevelQ is the level at which to encode the linear transformation.
	LevelQ int

	// LevelP is the level of the auxliary prime used during the automorphisms
	// User must ensure that this value is the same as the one used to generate
	// the evaluation keys used to perform the automorphisms.
	LevelP int

	// Scale is the plaintext scale at which to encode the linear transformation.
	Scale rlwe.Scale

	// LogDimensions is the log2 dimensions of the matrix that can be SIMD packed
	// in a single plaintext polynomial.
	// This method is equivalent to params.PlaintextDimensions().
	// Note that the linear transformation is evaluated independently on each rows of
	// the SIMD packed matrix.
	LogDimensions ring.Dimensions

	// Size of the giant step in the BSGS algorithm. If left to zero, then the optimal
	// value is derived. If set to -1, then indicates that the naive evaluation should
	// be used.
	GiantStep int
}

// GaloisElements returns the list of Galois elements needed for the evaluation of the linear transformation.
func (ltParams *LinearTransformationParameters) GaloisElements(params rlwe.ParameterProvider) (galEls []uint64) {

	p := params.GetRLWEParameters()

	slots := 1 << ltParams.LogDimensions.Cols

	GiantStep := ltParams.GiantStep

	if GiantStep == -1 {

		_, _, rotN2 := BSGSIndex(ltParams.Indexes, slots, slots)

		galEls = make([]uint64, len(rotN2))
		for i := range rotN2 {
			galEls[i] = p.GaloisElement(rotN2[i])
		}

		return
	}

	if GiantStep == 0 {
		GiantStep = OptimalLinearTransformationGiantStep(ltParams.Indexes, slots)
	}

	_, rotN1, rotN2 := BSGSIndex(ltParams.Indexes, slots, GiantStep)

	return p.GaloisElements(utils.GetDistincts(append(rotN1, rotN2...)))
}

// LinearTransformation is a type for linear transformations on ciphertexts.
// It stores a plaintext matrix in diagonal form and can be evaluated on a
// ciphertext using a LinearTransformationEvaluator.
type LinearTransformation struct {
	*rlwe.MetaData
	GiantStep int // If left to zero, indicates naive evaluation.
	LevelQ    int
	LevelP    int
	Vec       map[int]ring.Point
}

// GetParameters returns the [he.LinearTransformationParameters] of the receiver.
func (lt LinearTransformation) GetParameters() *LinearTransformationParameters {
	return &LinearTransformationParameters{
		Indexes:       slices.Collect(maps.Keys(lt.Vec)),
		LevelQ:        lt.LevelQ,
		LevelP:        lt.LevelP,
		Scale:         lt.Scale,
		LogDimensions: lt.LogDimensions,
		GiantStep:     lt.GiantStep,
	}
}

// GaloisElements returns the list of Galois elements needed for the evaluation of the linear transformation.
func (lt LinearTransformation) GaloisElements(params rlwe.ParameterProvider) (galEls []uint64) {
	return lt.GetParameters().GaloisElements(params)
}

// BSGSIndex returns the BSGSIndex of the target linear transformation.
func (lt LinearTransformation) BSGSIndex() (index map[int][]int, n1, n2 []int) {
	return BSGSIndex(slices.Collect(maps.Keys(lt.Vec)), 1<<lt.LogDimensions.Cols, lt.GiantStep)
}

// NewLinearTransformation allocates a new LinearTransformation with zero values according to the parameters specified by the LinearTransformationParameters.
func NewLinearTransformation(params rlwe.ParameterProvider, ltparams LinearTransformationParameters) *LinearTransformation {

	vec := make(map[int]ring.Point)
	cols := 1 << ltparams.LogDimensions.Cols

	N := params.GetRLWEParameters().N()
	LevelQ := ltparams.LevelQ
	LevelP := ltparams.LevelP

	diagslislt := ltparams.Indexes

	GiantStep := ltparams.GiantStep

	if GiantStep == -1 {
		for _, i := range diagslislt {
			idx := i
			if idx < 0 {
				idx += cols
			}
			vec[idx] = *ring.NewPoint(N, LevelQ, LevelP)
		}
	} else {
		if GiantStep == 0 {
			GiantStep = OptimalLinearTransformationGiantStep(diagslislt, cols)
		}
		index, _, _ := BSGSIndex(diagslislt, cols, GiantStep)
		for j := range index {
			for _, i := range index[j] {
				vec[j+i] = *ring.NewPoint(N, LevelQ, LevelP)
			}
		}
	}

	metadata := &rlwe.MetaData{
		LogDimensions: ltparams.LogDimensions,
		Scale:         ltparams.Scale,
		IsBatched:     true,
		IsNTT:         true,
		IsMontgomery:  true,
	}

	return &LinearTransformation{
		MetaData:  metadata,
		GiantStep: GiantStep,
		LevelQ:    ltparams.LevelQ,
		LevelP:    ltparams.LevelP,
		Vec:       vec,
	}
}

// EncodeLinearTransformation encodes on a pre-allocated LinearTransformation a set of non-zero diagonaes of a matrix representing a linear transformation.
func EncodeLinearTransformation[T any](encoder Encoder, diagonals Diagonals[T], allocated *LinearTransformation) (err error) {

	rows := 1 << allocated.LogDimensions.Rows
	cols := 1 << allocated.LogDimensions.Cols
	GiantStep := allocated.GiantStep

	diags := diagonals.Indexes()

	buf := make([]T, rows*cols)

	metaData := allocated.MetaData

	metaData.Scale = allocated.Scale

	var v []T

	if GiantStep == -1 {
		for _, i := range diags {

			idx := i
			if idx < 0 {
				idx += cols
			}

			if vec, ok := allocated.Vec[idx]; !ok {
				return fmt.Errorf("cannot EncodeLinearTransformation: error encoding on LinearTransformation: plaintext diagonal [%d] does not exist", idx)
			} else {

				if v, err = diagonals.At(i, cols); err != nil {
					return fmt.Errorf("cannot EncodeLinearTransformation: %w", err)
				}

				if err = encoder.Embed(v, metaData, vec); err != nil {
					return
				}
			}
		}
	} else {

		if GiantStep == 0 {
			return fmt.Errorf("cannot EncodeLinearTransformation: GiantStep == 0 -> invalid initialization")
		}

		index, _, _ := allocated.BSGSIndex()

		for j := range index {

			rot := -j & (cols - 1)

			for _, i := range index[j] {

				if vec, ok := allocated.Vec[i+j]; !ok {
					return fmt.Errorf("cannot Encode: error encoding on LinearTransformation BSGS: input does not match the same non-zero diagonals")
				} else {

					if v, err = diagonals.At(i+j, cols); err != nil {
						return fmt.Errorf("cannot EncodeLinearTransformation: %w", err)
					}

					if err = encoder.Embed(rotateDiagonal(v, rot, metaData, buf), metaData, vec); err != nil {
						return
					}
				}
			}
		}
	}

	return
}

func rotateDiagonal[T any](v []T, rot int, metaData *rlwe.MetaData, buf []T) (values []T) {

	rows := 1 << metaData.LogDimensions.Rows
	cols := 1 << metaData.LogDimensions.Cols

	rot &= (cols - 1)

	if rot != 0 {

		values = buf

		for i := 0; i < rows; i++ {
			utils.RotateSliceAllocFree(v[i*cols:(i+1)*cols], rot, values[i*cols:(i+1)*cols])
		}

	} else {
		values = v
	}

	return
}

// OptimalLinearTransformationGiantStep returns the giant step that minimize
// N1 + N2 + |N1 - N2| where:
// - N1 is the number of giant steps (one rotation per giant step)
// - N2 is the maximum number of baby steps per giant step (one rotation per baby step)
func OptimalLinearTransformationGiantStep(nonZeroDiags []int, slots int) (opt int) {

	slices.Sort(nonZeroDiags)

	step := nonZeroDiags[1] - nonZeroDiags[0]
	for i := 1; i < len(nonZeroDiags); i++ {
		step = min(step, nonZeroDiags[i]-nonZeroDiags[i-1])
	}

	tot := slots

	abs := func(x int) (y int) {
		if x < 0 {
			return -x
		}
		return x
	}

	for i := step; i < slots; i += step {
		N1, N2 := NumBSGSGalEls(nonZeroDiags, slots, i)
		if newtot := (N1 + N2) + abs(N1-N2); newtot <= tot {
			opt = i
			tot = newtot
		}
	}

	return
}

func NumBSGSGalEls(nonZeroDiags []int, slots, N1 int) (rotN1, rotN2 int) {
	rotN1Map := make(map[int]bool)
	rotN2Map := make(map[int]bool)
	for _, rot := range nonZeroDiags {
		rot &= (slots - 1)
		idxN1 := ((rot / N1) * N1) & (slots - 1)
		idxN2 := rot % N1
		rotN1Map[idxN1] = true
		rotN2Map[idxN2] = true
	}
	return len(rotN1Map), len(rotN2Map)
}

// BSGSIndex returns the index map and needed rotation for the BSGS matrix-vector multiplication algorithm.
func BSGSIndex(nonZeroDiags []int, slots, N1 int) (index map[int][]int, rotN1, rotN2 []int) {
	index = make(map[int][]int)
	rotN1Map := make(map[int]bool)
	rotN2Map := make(map[int]bool)

	for _, rot := range nonZeroDiags {
		rot &= (slots - 1)
		idxN1 := ((rot / N1) * N1) & (slots - 1)
		idxN2 := rot % N1
		if index[idxN1] == nil {
			index[idxN1] = []int{idxN2}
		} else {
			index[idxN1] = append(index[idxN1], idxN2)
		}
		rotN1Map[idxN1] = true
		rotN2Map[idxN2] = true
	}

	for k := range index {
		slices.Sort(index[k])
	}

	rotN1 = slices.Collect(maps.Keys(rotN1Map))
	slices.Sort(rotN1)

	rotN2 = slices.Collect(maps.Keys(rotN2Map))
	slices.Sort(rotN2)

	return
}
