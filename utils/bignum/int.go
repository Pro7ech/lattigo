package bignum

import (
	"crypto/rand"
	"fmt"
	"io"
	"math"
	"math/big"
)

// NewInt allocates a new *big.Int.
// Accepted types are: string, uint, uint64, int64, int, *big.Float or *big.Int.
func NewInt(x interface{}) (y *big.Int) {

	y = new(big.Int)

	if x == nil {
		return
	}

	switch x := x.(type) {
	case string:
		y.SetString(x, 0)
	case uint:
		y.SetUint64(uint64(x))
	case uint64:
		y.SetUint64(x)
	case int64:
		y.SetInt64(x)
	case int:
		y.SetInt64(int64(x))
	case *big.Float:
		x.Int(y)
	case *big.Int:
		y.Set(x)
	default:
		panic(fmt.Sprintf("cannot Newint: accepted types are string, uint, uint64, int, int64, *big.Float, *big.Int, but is %T", x))
	}

	return
}

// RandInt generates a random Int in [0, max-1].
func RandInt(reader io.Reader, max *big.Int) (n *big.Int) {
	var err error
	if n, err = rand.Int(reader, max); err != nil {
		panic(fmt.Errorf("rand.Int: %w", err))
	}
	return
}

// DivRound sets the target i to round(a/b).
func DivRound(a, b, i *big.Int) {
	_a := new(big.Int).Set(a)
	i.Quo(_a, b)
	r := new(big.Int).Rem(_a, b)
	r2 := new(big.Int).Mul(r, NewInt(2))
	if r2.CmpAbs(b) != -1.0 {
		if _a.Sign() == b.Sign() {
			i.Add(i, NewInt(1))
		} else {
			i.Sub(i, NewInt(1))
		}
	}
}

func Stats(values []big.Int, prec uint) [2]float64 {

	N := len(values)

	mean := NewFloat(0, prec)
	tmp := NewFloat(0, prec)

	for i := 0; i < N; i++ {
		mean.Add(mean, tmp.SetInt(&values[i]))
	}

	mean.Quo(mean, NewFloat(float64(N), prec))

	stdFloat := NewFloat(0, prec)

	for i := 0; i < N; i++ {
		tmp.SetInt(&values[i])
		tmp.Sub(tmp, mean)
		tmp.Mul(tmp, tmp)
		stdFloat.Add(stdFloat, tmp)
	}

	stdFloat.Quo(stdFloat, NewFloat(float64(N-1), prec))

	stdFloat.Sqrt(stdFloat)

	stdF64, _ := stdFloat.Float64()
	meanF64, _ := mean.Float64()

	return [2]float64{math.Log2(stdF64), meanF64}
}
