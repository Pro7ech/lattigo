package ring

import (
	"bufio"
	"encoding"
	"fmt"
	"io"

	"github.com/Pro7ech/lattigo/utils/buffer"
)

const (
	discreteGaussianType = 0
	ternaryType          = 1
	uniformType          = 2
	discreteGaussianName = "DiscreteGaussian"
	ternaryDistName      = "Ternary"
	uniformDistName      = "Uniform"
)

// DistributionParameters is an interface for distribution
// parameters in the ring.
// There are three implementation of this interface:
//   - DiscreteGaussian for sampling polynomials with discretized
//     gaussian coefficient of given standard deviation and bound.
//   - Ternary for sampling polynomials with coefficients in [-1, 1].
//   - Uniform for sampling polynomial with uniformly random
//     coefficients in the ring.
type DistributionParameters interface {
	Equal(DistributionParameters) bool
	mustBeDist()
	BinarySize() int
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	io.WriterTo
	io.ReaderFrom
}

// DiscreteGaussian represents the parameters of a
// discrete Gaussian distribution with standard
// deviation Sigma and bounds [-Bound, Bound].
type DiscreteGaussian struct {
	Sigma float64
	Bound float64
}

// Ternary represent the parameters of a distribution with coefficients
// in [-1, 0, 1]. Only one of its field must be set to a non-zero value:
//
//   - If P is set, each coefficient in the polynomial is sampled in [-1, 0, 1]
//     with probabilities [0.5*P, 1-P, 0.5*P].
//   - if H is set, the coefficients are sampled uniformly in the set of ternary
//     polynomials with H non-zero coefficients (i.e., of hamming weight H).
type Ternary struct {
	P float64
	H int
}

// Uniform represents the parameters of a uniform distribution
// i.e., with coefficients uniformly distributed in the given ring.
type Uniform struct{}

func (d DiscreteGaussian) Equal(other DistributionParameters) bool {
	switch other := other.(type) {
	case *DiscreteGaussian:
		return d.Sigma == other.Sigma && d.Bound == other.Bound
	default:
		return false
	}
}

func (d DiscreteGaussian) BinarySize() int {
	return 17
}

func (d DiscreteGaussian) WriteTo(w io.Writer) (n int64, err error) {
	switch w := w.(type) {
	case buffer.Writer:
		var inc int64

		if inc, err = buffer.WriteAsUint8(w, discreteGaussianType); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.WriteAsUint64(w, d.Sigma); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.WriteAsUint64(w, d.Bound); err != nil {
			return n + inc, err
		}

		n += inc

		return n, w.Flush()
	default:
		return d.WriteTo(bufio.NewWriter(w))
	}
}

func (d *DiscreteGaussian) ReadFrom(r io.Reader) (n int64, err error) {
	switch r := r.(type) {
	case buffer.Reader:
		var inc int64

		var Type int

		if inc, err = buffer.ReadAsUint8(r, &Type); err != nil {
			return n + inc, err
		}

		n += inc

		if Type != discreteGaussianType {
			return n, fmt.Errorf("invalid distribution Type: expected %d but got %d", discreteGaussianType, Type)
		}

		if inc, err = buffer.ReadAsUint64(r, &d.Sigma); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.ReadAsUint64(r, &d.Bound); err != nil {
			return n + inc, err
		}

		n += inc

		return
	default:
		return d.ReadFrom(bufio.NewReader(r))
	}
}

func (d DiscreteGaussian) MarshalBinary() (p []byte, err error) {
	buf := buffer.NewBufferSize(d.BinarySize())
	_, err = d.WriteTo(buf)
	return buf.Bytes(), err
}

func (d *DiscreteGaussian) UnmarshalBinary(p []byte) (err error) {
	_, err = d.ReadFrom(buffer.NewBuffer(p))
	return
}

func (d DiscreteGaussian) mustBeDist() {}

func (d Ternary) Equal(other DistributionParameters) bool {
	switch other := other.(type) {
	case *Ternary:
		return d.H == other.H && d.P == other.P
	default:
		return false
	}
}

func (d Ternary) BinarySize() int {
	return 17
}

func (d Ternary) WriteTo(w io.Writer) (n int64, err error) {
	switch w := w.(type) {
	case buffer.Writer:
		var inc int64

		if inc, err = buffer.WriteAsUint8(w, ternaryType); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.WriteAsUint64(w, d.H); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.WriteAsUint64(w, d.P); err != nil {
			return n + inc, err
		}

		n += inc

		return n, w.Flush()
	default:
		return d.WriteTo(bufio.NewWriter(w))
	}
}

func (d *Ternary) ReadFrom(r io.Reader) (n int64, err error) {
	switch r := r.(type) {
	case buffer.Reader:
		var inc int64

		var Type int

		if inc, err = buffer.ReadAsUint8(r, &Type); err != nil {
			return n + inc, err
		}

		n += inc

		if Type != ternaryType {
			return n, fmt.Errorf("invalid distribution Type: expected %d but got %d", ternaryType, Type)
		}

		if inc, err = buffer.ReadAsUint64(r, &d.H); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.ReadAsUint64(r, &d.P); err != nil {
			return n + inc, err
		}

		n += inc

		return
	default:
		return d.ReadFrom(bufio.NewReader(r))
	}
}

func (d Ternary) MarshalBinary() (p []byte, err error) {
	buf := buffer.NewBufferSize(d.BinarySize())
	_, err = d.WriteTo(buf)
	return buf.Bytes(), err
}

func (d *Ternary) UnmarshalBinary(p []byte) (err error) {
	_, err = d.ReadFrom(buffer.NewBuffer(p))
	return
}

func (d Ternary) mustBeDist() {}

func (d Uniform) Equal(other DistributionParameters) bool {
	switch other.(type) {
	case *Uniform:
		return true
	default:
		return false
	}
}

func (d Uniform) BinarySize() int {
	return 1
}

func (d Uniform) WriteTo(w io.Writer) (n int64, err error) {
	switch w := w.(type) {
	case buffer.Writer:
		var inc int64

		if inc, err = buffer.WriteAsUint8(w, uniformType); err != nil {
			return n + inc, err
		}

		n += inc

		return n, w.Flush()
	default:
		return d.WriteTo(bufio.NewWriter(w))
	}
}

func (d *Uniform) ReadFrom(r io.Reader) (n int64, err error) {
	switch r := r.(type) {
	case buffer.Reader:
		var inc int64

		var Type int

		if inc, err = buffer.ReadAsUint8(r, &Type); err != nil {
			return n + inc, err
		}

		n += inc

		if Type != uniformType {
			return n, fmt.Errorf("invalid distribution Type: expected %d but got %d", uniformType, Type)
		}

		return
	default:
		return d.ReadFrom(bufio.NewReader(r))
	}
}

func (d Uniform) MarshalBinary() (p []byte, err error) {
	buf := buffer.NewBufferSize(d.BinarySize())
	_, err = d.WriteTo(buf)
	return buf.Bytes(), err
}

func (d *Uniform) UnmarshalBinary(p []byte) (err error) {
	_, err = d.ReadFrom(buffer.NewBuffer(p))
	return
}

func (d Uniform) mustBeDist() {}

func DistributionParametersFromReader(r io.Reader) (distribution DistributionParameters, n int64, err error) {
	switch r := r.(type) {
	case buffer.Reader:
		var inc int64

		var Type int

		if inc, err = buffer.ReadAsUint8(r, &Type); err != nil {
			return nil, n + inc, err
		}

		n += inc

		switch Type {
		case discreteGaussianType:

			d := DiscreteGaussian{}

			if inc, err = buffer.ReadAsUint64(r, &d.Sigma); err != nil {
				return nil, n + inc, err
			}

			n += inc

			if inc, err = buffer.ReadAsUint64(r, &d.Bound); err != nil {
				return nil, n + inc, err
			}

			n += inc

			return &d, n, nil

		case ternaryType:

			d := Ternary{}

			if inc, err = buffer.ReadAsUint64(r, &d.H); err != nil {
				return nil, n + inc, err
			}

			n += inc

			if inc, err = buffer.ReadAsUint64(r, &d.P); err != nil {
				return nil, n + inc, err
			}

			n += inc

			return &d, n, nil

		case uniformType:
			return &Uniform{}, n, nil
		default:
			return nil, n, fmt.Errorf("invalid distribution Type: expected 0, 1, 2 but got %d", Type)
		}
	default:
		return DistributionParametersFromReader(bufio.NewReader(r))
	}
}

func getFloatFromMap(distDef map[string]interface{}, key string) (float64, error) {
	val, hasVal := distDef[key]
	if !hasVal {
		return 0, fmt.Errorf("map specifies no value for %s", key)
	}
	f, isFloat := val.(float64)
	if !isFloat {
		return 0, fmt.Errorf("value for key %s in map should be of type float", key)
	}
	return f, nil
}

func getIntFromMap(distDef map[string]interface{}, key string) (int, error) {
	val, hasVal := distDef[key]
	if !hasVal {
		return 0, fmt.Errorf("map specifies no value for %s", key)
	}
	f, isNumeric := val.(float64)
	if !isNumeric && f == float64(int(f)) {
		return 0, fmt.Errorf("value for key %s in map should be an integer", key)
	}
	return int(f), nil
}

func DistributionParametersFromMap(distDef map[string]interface{}) (DistributionParameters, error) {
	distTypeVal, specified := distDef["Type"]
	if !specified {
		return nil, fmt.Errorf("map specifies no distribution type")
	}
	distTypeStr, isString := distTypeVal.(string)
	if !isString {
		return nil, fmt.Errorf("value for key Type of map should be of type string")
	}
	switch distTypeStr {
	case uniformDistName:
		return &Uniform{}, nil
	case ternaryDistName:
		_, hasP := distDef["P"]
		_, hasH := distDef["H"]

		if !hasP && !hasH {
			return nil, fmt.Errorf("exactly one of the field P or H must be non-zero")
		}

		var p float64
		var h int
		var err error

		if hasP {
			if p, err = getFloatFromMap(distDef, "P"); err != nil {
				return nil, err
			}
		}

		if hasH {
			if h, err = getIntFromMap(distDef, "H"); err != nil {
				return nil, err
			}
		}

		if p != 0 && h != 0 {
			return nil, fmt.Errorf("exactly one of the field P or H must be non-zero")
		}

		return &Ternary{P: p, H: h}, nil
	case discreteGaussianName:
		sigma, errSigma := getFloatFromMap(distDef, "Sigma")
		if errSigma != nil {
			return nil, errSigma
		}
		bound, errBound := getFloatFromMap(distDef, "Bound")
		if errBound != nil {
			return nil, errBound
		}
		return &DiscreteGaussian{Sigma: sigma, Bound: bound}, nil
	default:
		return nil, fmt.Errorf("distribution type %s does not exist", distTypeStr)
	}
}
