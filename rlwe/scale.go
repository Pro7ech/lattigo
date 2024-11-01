package rlwe

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"math/big"

	"github.com/Pro7ech/lattigo/utils/bignum"
	"github.com/Pro7ech/lattigo/utils/buffer"
)

const (
	// ScalePrecision is the default precision of the scale.
	ScalePrecision = uint(128)
)

var ScalePrecisionLog10 = int(math.Ceil(float64(ScalePrecision) / math.Log2(10)))

// Scale is a struct used to track the scaling factor
// of Plaintext and Ciphertext structs.
// The scale is managed as an 128-bit precision real and can
// be either a floating point value or a mod T
// prime integer, which is determined at instantiation.
type Scale struct {
	Value big.Float //`json:",omitempty"`
	Mod   *big.Int  //`json:",omitempty"`
}

// NewScale instantiates a new floating point Scale.
// Accepted types for s are int, int64, uint64, float64, *big.Int, *big.Float and *Scale.
// If the input type is not an accepted type, returns an error.
func NewScale(s interface{}) Scale {
	v := scaleToBigFloat(s)
	return Scale{Value: *v}
}

// NewScaleModT instantiates a new integer mod T Scale.
// Accepted types for s are int, int64, uint64, float64, *big.Int, *big.Float and *Scale.
// If the input type is not an accepted type, returns an error.
func NewScaleModT(s interface{}, mod uint64) Scale {
	scale := NewScale(s)
	if mod != 0 {
		scale.Mod = big.NewInt(0).SetUint64(mod)
	}
	return scale
}

// BigInt returns the scale as a big.Int, truncating the rational part and rounding ot the nearest integer.
// The rounding assumes that the scale is a positive value.
func (s Scale) BigInt() (sInt *big.Int) {
	sInt = new(big.Int)
	new(big.Float).SetPrec(s.Value.Prec()).Add(&s.Value, new(big.Float).SetFloat64(0.5)).Int(sInt)
	return
}

// Float64 returns the underlying scale as a float64 value.
func (s Scale) Float64() float64 {
	f64, _ := s.Value.Float64()
	return f64
}

// Uint64 returns the underlying scale as an uint64 value.
func (s Scale) Uint64() uint64 {
	u64, _ := s.Value.Uint64()
	return u64
}

// Mul multiplies the target s with s1, returning the result in
// a new Scale struct. If mod is specified, performs the multiplication
// modulo mod.
func (s Scale) Mul(s1 Scale) Scale {

	res := new(big.Float)

	if s.Mod != nil {
		si, _ := s.Value.Int(nil)
		s1i, _ := s1.Value.Int(nil)
		s1i.Mul(si, s1i)
		s1i.Mod(s1i, s.Mod)
		res.SetPrec(ScalePrecision)
		res.SetInt(s1i)
	} else {
		res.Mul(&s.Value, &s1.Value)
	}

	return Scale{Value: *res, Mod: s.Mod}
}

// Div multiplies the target s with s1^-1, returning the result in
// a new Scale struct. If mod is specified, performs the multiplication
// modulo t with the multiplicative inverse of s1. Otherwise, performs
// the quotient operation.
func (s Scale) Div(s1 Scale) Scale {

	res := new(big.Float)

	if s.Mod != nil {
		s1i, _ := s.Value.Int(nil)
		s2i, _ := s1.Value.Int(nil)

		s2i.ModInverse(s2i, s.Mod)

		s1i.Mul(s1i, s2i)
		s1i.Mod(s1i, s.Mod)

		res.SetPrec(ScalePrecision)
		res.SetInt(s1i)
	} else {
		res.Quo(&s.Value, &s1.Value)
	}

	return Scale{Value: *res, Mod: s.Mod}
}

// Cmp compares the target scale with s1.
// Returns 0 if the scales are equal, 1 if
// the target scale is greater and -1 if
// the target scale is smaller.
func (s Scale) Cmp(s1 Scale) (cmp int) {
	return s.Value.Cmp(&s1.Value)
}

// Equal returns true if a == b.
func (s Scale) Equal(s1 Scale) bool {
	return s.Cmp(s1) == 0
}

// Log2 returns the base two logarithm of the Scale.
func (s Scale) Log2() float64 {
	ln := bignum.Log(&s.Value)
	ln.Quo(ln, bignum.Log2(ln.Prec()))
	log2, _ := ln.Float64()
	return log2
}

// InDelta returns true if abs(a-b) <= 2^{-log2Delta}
func (s Scale) InDelta(s1 Scale, log2Delta float64) bool {
	return s.Log2Delta(s1) >= log2Delta
}

// Log2Delta returns -log2(abs(a-b)/max(a, b))
func (s Scale) Log2Delta(s1 Scale) float64 {
	d := new(big.Float).Sub(&s.Value, &s1.Value)
	d.Abs(d)
	max := s.Max(s1)
	d.Quo(d, &max.Value)
	d.Quo(bignum.Log(d), bignum.Log2(s.Value.Prec()))
	d.Neg(d)
	f64, _ := d.Float64()
	return f64
}

// Max returns the a new scale which is the maximum
// between the target scale and s1.
func (s Scale) Max(s1 Scale) (max Scale) {

	if s.Cmp(s1) < 0 {
		return s1
	}

	return s
}

// Min returns the a new scale which is the minimum
// between the target scale and s1.
func (s Scale) Min(s1 Scale) (max Scale) {

	if s.Cmp(s1) > 0 {
		return s1
	}

	return s
}

// BinarySize returns the serialized size of the object in bytes.
// Each value is encoded with .Text('e', ceil(ScalePrecision / log2(10))).
func (s Scale) BinarySize() int {
	return (ScalePrecisionLog10 + 6) << 1
}

func (s Scale) MarshalJSON() (p []byte, err error) {
	p, err = s.MarshalBinary()
	return
}

func (s Scale) UnnMarshalJSON(p []byte) (err error) {
	return s.UnmarshalBinary(p)
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
func (s Scale) WriteTo(w io.Writer) (n int64, err error) {
	switch w := w.(type) {
	case buffer.Writer:

		var mod string

		if s.Mod != nil {
			mod = new(big.Float).SetPrec(ScalePrecision).SetInt(s.Mod).Text('e', ScalePrecisionLog10)
		} else {

			var m string
			for i := 0; i < ScalePrecisionLog10; i++ {
				m += "0"
			}

			mod = "0." + m + "e+00"
		}

		var inc int64

		if inc, err = buffer.Write(w, []byte(mod)); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.Write(w, []byte(s.Value.Text('e', ScalePrecisionLog10))); err != nil {
			return n + inc, err
		}

		n += inc

		return n, w.Flush()
	default:
		return s.WriteTo(bufio.NewWriter(w))
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
func (s *Scale) ReadFrom(r io.Reader) (n int64, err error) {
	switch r := r.(type) {
	case buffer.Reader:

		buf := make([]byte, ScalePrecisionLog10+6)

		var inc int64

		if inc, err = buffer.Read(r, buf); err != nil {
			return n + inc, err
		}

		n += inc

		mod, bool := new(big.Float).SetString(string(buf))

		if mod.Cmp(new(big.Float)) != 0 {

			if s.Mod == nil {
				s.Mod = new(big.Int)
			}

			if !bool {
				return n, fmt.Errorf("s.Mod != exact")
			}

			mod.Int(s.Mod)
		}

		if inc, err = buffer.Read(r, buf); err != nil {
			return n + inc, err
		}

		n += inc

		s.Value.SetPrec(ScalePrecision)
		s.Value.SetString(string(buf))

		return n, nil

	default:
		return s.ReadFrom(bufio.NewReader(r))
	}
}

// MarshalBinary encodes the object into a binary form on a newly allocated slice of bytes.
func (s Scale) MarshalBinary() (p []byte, err error) {
	buf := buffer.NewBufferSize(s.BinarySize())
	_, err = s.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary decodes a slice of bytes generated by
// MarshalBinary or WriteTo on the object.
func (s *Scale) UnmarshalBinary(p []byte) (err error) {
	_, err = s.ReadFrom(buffer.NewBuffer(p))
	return
}

func scaleToBigFloat(scale interface{}) (s *big.Float) {

	switch scale := scale.(type) {
	case float64:
		if scale < 0 || math.IsNaN(scale) || math.IsInf(scale, 0) {
			panic(fmt.Errorf("scale cannot be negative, NaN or Inf, but is %f", scale))
		}

		s = new(big.Float).SetPrec(ScalePrecision)
		s.SetFloat64(scale)
	case *big.Float:
		if scale.Cmp(new(big.Float).SetFloat64(0)) < 0 || scale.IsInf() {
			panic(fmt.Errorf("scale cannot be negative, but is %f", scale))
		}
		s = new(big.Float).SetPrec(ScalePrecision)
		s.Set(scale)
	case big.Float:
		if scale.Cmp(new(big.Float).SetFloat64(0)) < 0 || scale.IsInf() {
			panic(fmt.Errorf("scale cannot be negative, but is %f", &scale))
		}
		s = new(big.Float).SetPrec(ScalePrecision)
		s.Set(&scale)
	case *big.Int:
		if scale.Cmp(new(big.Int).SetInt64(0)) < 0 {
			panic(fmt.Errorf("scale cannot be negative, but is %f", scale))
		}
		s = new(big.Float).SetPrec(ScalePrecision)
		s.SetInt(scale)
	case big.Int:
		if scale.Cmp(new(big.Int).SetInt64(0)) < 0 {
			panic(fmt.Errorf("scale cannot be negative, but is %f", &scale))
		}
		s = new(big.Float).SetPrec(ScalePrecision)
		s.SetInt(&scale)
	case int:
		return scaleToBigFloat(new(big.Int).SetInt64(int64(scale)))
	case int64:
		return scaleToBigFloat(new(big.Int).SetInt64(scale))
	case uint64:
		return scaleToBigFloat(new(big.Int).SetUint64(scale))
	case Scale:
		return scaleToBigFloat(scale.Value)
	default:
		panic(fmt.Errorf("invalid scale.(type): must be int, int64, uint64, float64, *big.Int, *big.Float or *Scale but is %T", scale))
	}

	// Although the big.Float has 128 bits of precision, it will be
	// initialized with mant:big.nat{0x0}, i.e. only one mantissa word.
	// This forces two mantissa words: mant:big.nat{0x0, 0x0}.
	s.SetString(s.Text('e', ScalePrecisionLog10))
	return
}
