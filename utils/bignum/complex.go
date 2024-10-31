package bignum

import (
	"fmt"
	"math/big"
)

// Complex is a type for arbitrary precision complex number
type Complex [2]big.Float

// ToComplex takes a
// - complex32, complex128
// - float32, float64,
// - int, int64, uint, uint64,
// - *big.Int, big.Int,
// - *big.Float, big.Float
// - *bignum.Complex, bignum.Complex
// and returns a *bignum.Complex set to the given precision.
func ToComplex(value interface{}, prec uint) (cmplx *Complex) {

	cmplx = new(Complex)
	cmplx[0].SetPrec(prec)
	cmplx[1].SetPrec(prec)

	switch value := value.(type) {
	case complex64:
		cmplx[0].SetFloat64(float64(real(value)))
		cmplx[1].SetFloat64(float64(imag(value)))
	case complex128:
		cmplx[0].SetFloat64(real(value))
		cmplx[1].SetFloat64(imag(value))
	case float32:
		cmplx[0].SetFloat64(float64(value))
	case float64:
		cmplx[0].SetFloat64(value)
	case int:
		cmplx[0].SetInt64(int64(value))
	case int64:
		cmplx[0].SetInt64(value)
	case uint64:
		return ToComplex(new(big.Int).SetUint64(value), prec)
	case *big.Int:
		cmplx[0].SetPrec(prec).SetInt(value)
	case *big.Float:
		cmplx[0].SetPrec(prec).Set(value)
	case *Complex:
		cmplx[0].Set(&value[0])
		cmplx[1].Set(&value[1])
	case big.Int:
		cmplx[0].SetInt(&value)
	case big.Float:
		cmplx[0].SetPrec(prec).Set(&value)
	case Complex:
		cmplx[0].Set(&value[0])
		cmplx[1].Set(&value[1])
	default:
		panic(fmt.Errorf("invalid value.(type): must be int, int64, uint64, float32, float64, complex64, complex128, *big.Int, big.Int, *big.Float, big.Float or *bignum.Complex, bignum.Complex but is %T", value))
	}

	return
}

// ToComplexSlice takes a
// - []complex32, []complex128
// - []float32, []float64,
// - []int, []int64, []uint, []uint64,
// - []big.Int
// - []big.Float
// - []bignum.Complex
// and returns a []bignum.Complex set to the given precision.
func ToComplexSlice(values interface{}, prec uint, cmplxSlice []Complex) (err error) {

	switch values := values.(type) {
	case []complex64:
		for i := range min(len(values), len(cmplxSlice)) {
			cmplxSlice[i][0].SetPrec(prec).SetFloat64(float64(real(values[i])))
			cmplxSlice[i][1].SetPrec(prec).SetFloat64(float64(imag(values[i])))
		}
	case []complex128:
		for i := range min(len(values), len(cmplxSlice)) {
			cmplxSlice[i][0].SetPrec(prec).SetFloat64(real(values[i]))
			cmplxSlice[i][1].SetPrec(prec).SetFloat64(imag(values[i]))
		}
	case []float32:
		for i := range min(len(values), len(cmplxSlice)) {
			cmplxSlice[i][0].SetPrec(prec).SetFloat64(float64(values[i]))
			cmplxSlice[i][1].SetPrec(prec).SetFloat64(0)
		}
	case []float64:
		for i := range min(len(values), len(cmplxSlice)) {
			cmplxSlice[i][0].SetPrec(prec).SetFloat64(values[i])
			cmplxSlice[i][1].SetPrec(prec).SetFloat64(0)
		}
	case []int:
		for i := range min(len(values), len(cmplxSlice)) {
			cmplxSlice[i][0].SetPrec(prec).SetInt64(int64(values[i]))
			cmplxSlice[i][1].SetPrec(prec).SetInt64(0)
		}
	case []int64:
		for i := range min(len(values), len(cmplxSlice)) {
			cmplxSlice[i][0].SetPrec(prec).SetInt64(values[i])
			cmplxSlice[i][1].SetPrec(prec).SetInt64(0)
		}
	case []uint64:
		tmp := new(big.Int)
		for i := range min(len(values), len(cmplxSlice)) {
			tmp.SetUint64(values[i])
			cmplxSlice[i][0].SetPrec(prec).SetInt(tmp)
			cmplxSlice[i][1].SetPrec(prec).SetInt64(0)
		}
	case []big.Int:
		for i := range min(len(values), len(cmplxSlice)) {
			cmplxSlice[i][0].SetPrec(prec).SetInt(&values[i])
			cmplxSlice[i][1].SetPrec(prec).SetInt64(0)
		}
	case []big.Float:
		for i := range min(len(values), len(cmplxSlice)) {
			cmplxSlice[i][0].SetPrec(prec).Set(&values[i])
			cmplxSlice[i][1].SetPrec(prec).SetInt64(0)
		}
	case []Complex:
		for i := range min(len(values), len(cmplxSlice)) {
			cmplxSlice[i][0].SetPrec(prec).Set(&values[i][0])
			cmplxSlice[i][1].SetPrec(prec).Set(&values[i][1])
		}
	default:
		panic(fmt.Errorf("invalid value.(type): must be []int, []int64, []uint64, []float32, []float64, []complex64, []complex128, []big.Int, []big.Float, []bignum.Complex, but is %T", values))
	}

	return
}

// IsInt returns true if both the real and imaginary parts are integers.
func (c *Complex) IsInt() bool {
	return c[0].IsInt() && c[1].IsInt()
}

func (c *Complex) IsReal() bool {
	return c[1].Cmp(new(big.Float)) == 0
}

func (c *Complex) SetComplex128(x complex128) *Complex {
	c[0].SetFloat64(real(x))
	c[1].SetFloat64(imag(x))
	return c
}

// Set sets an arbitrary precision complex number
func (c *Complex) Set(a *Complex) *Complex {
	c[0].Set(&a[0])
	c[1].Set(&a[1])
	return c
}

// Zero sets the receiver to zero.
func (c *Complex) Zero() *Complex {
	c[0].SetInt64(0)
	c[1].SetInt64(0)
	return c
}

func (c *Complex) Prec() uint {
	return min(c[0].Prec(), c[1].Prec())
}

func (c *Complex) SetPrec(prec uint) *Complex {
	c[0].SetPrec(prec)
	c[1].SetPrec(prec)
	return c
}

// Clone returns a new copy of the target arbitrary precision complex number
func (c *Complex) Clone() (clone *Complex) {
	clone = &Complex{}
	clone[0].Set(&c[0])
	clone[1].Set(&c[1])
	return
}

// IsZero return true if the receiver is zero
func (c *Complex) IsZero() bool {
	return c[0].Cmp(new(big.Float)) == 0 && c[1].Cmp(new(big.Float)) == 0
}

// Real returns the real part as a big.Float
func (c *Complex) Real() *big.Float {
	return &c[0]
}

// Imag returns the imaginary part as a big.Float
func (c *Complex) Imag() *big.Float {
	return &c[1]
}

// Complex128 returns the arbitrary precision complex number as a complex128
func (c *Complex) Complex128() complex128 {

	real, _ := c[0].Float64()
	imag, _ := c[1].Float64()

	return complex(real, imag)
}

// Uint64 returns the real part of the complex number as an uint64.
func (c *Complex) Uint64() (u64 uint64) {
	u64, _ = c[0].Uint64()
	return
}

// Int returns the real part of the complex number as a *big.Int.
func (c *Complex) Int() (bInt *big.Int) {
	bInt = new(big.Int)
	c[0].Int(bInt)
	return
}

// Add adds two arbitrary precision complex numbers together
func (c *Complex) Add(a, b *Complex) *Complex {
	c[0].Add(&a[0], &b[0])
	c[1].Add(&a[1], &b[1])
	return c
}

// Sub subtracts two arbitrary precision complex numbers together
func (c *Complex) Sub(a, b *Complex) *Complex {
	c[0].Sub(&a[0], &b[0])
	c[1].Sub(&a[1], &b[1])
	return c
}

// Neg negates a and writes the result on c.
func (c *Complex) Neg(a *Complex) *Complex {
	c[0].Neg(&a[0])
	c[1].Neg(&a[1])
	return c
}

// ComplexMultiplier is a struct for the multiplication or division of two arbitrary precision complex numbers
type ComplexMultiplier struct {
	tmp0 *big.Float
	tmp1 *big.Float
	tmp2 *big.Float
	tmp3 *big.Float
}

// NewComplexMultiplier creates a new ComplexMultiplier
func NewComplexMultiplier() (cEval *ComplexMultiplier) {
	cEval = new(ComplexMultiplier)
	cEval.tmp0 = new(big.Float)
	cEval.tmp1 = new(big.Float)
	cEval.tmp2 = new(big.Float)
	cEval.tmp3 = new(big.Float)
	return
}

// Mul evaluates c = a * b.
func (cEval *ComplexMultiplier) Mul(a, b, c *Complex) {

	if a.IsReal() {
		if b.IsReal() {
			c[0].Mul(&a[0], &b[0])
			c[1].SetFloat64(0)
		} else {
			c[1].Mul(&a[0], &b[1])
			c[0].Mul(&a[0], &b[0])
		}
	} else {
		if b.IsReal() {
			c[1].Mul(&a[1], &b[0])
			c[0].Mul(&a[0], &b[0])
		} else {
			cEval.tmp0.Mul(&a[0], &b[0])
			cEval.tmp1.Mul(&a[1], &b[1])
			cEval.tmp2.Mul(&a[0], &b[1])
			cEval.tmp3.Mul(&a[1], &b[0])

			c[0].Sub(cEval.tmp0, cEval.tmp1)
			c[1].Add(cEval.tmp2, cEval.tmp3)
		}
	}
}

// Quo evaluates c = a / b.
func (cEval *ComplexMultiplier) Quo(a, b, c *Complex) {

	if a.IsReal() {
		if b.IsReal() {
			c[0].Quo(&a[0], &b[0])
			c[1].SetFloat64(0)
		} else {
			c[1].Quo(&a[0], &b[1])
			c[0].Quo(&a[0], &b[0])
		}
	} else {
		if b.IsReal() {
			c[1].Quo(&a[1], &b[0])
			c[0].Quo(&a[0], &b[0])
		} else {
			// tmp0 = (a[0] * b[0]) + (a[1] * b[1]) real part
			// tmp1 = (a[1] * b[0]) - (a[0] * b[0]) imag part
			// tmp2 = (b[0] * b[0]) + (b[1] * b[1]) denominator

			cEval.tmp0.Mul(&a[0], &b[0])
			cEval.tmp1.Mul(&a[1], &b[1])
			cEval.tmp2.Mul(&a[1], &b[0])
			cEval.tmp3.Mul(&a[0], &b[1])

			cEval.tmp0.Add(cEval.tmp0, cEval.tmp1)
			cEval.tmp1.Sub(cEval.tmp2, cEval.tmp3)

			cEval.tmp2.Mul(&b[0], &b[0])
			cEval.tmp3.Mul(&b[1], &b[1])
			cEval.tmp2.Add(cEval.tmp2, cEval.tmp3)

			c[0].Quo(cEval.tmp0, cEval.tmp2)
			c[1].Quo(cEval.tmp1, cEval.tmp2)
		}
	}
}
