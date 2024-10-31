package he

import (
	"math/big"

	"github.com/Pro7ech/lattigo/utils/bignum"
)

type Integer interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | big.Int
}

type Float interface {
	~float32 | ~float64 | big.Float
}

type Complex interface {
	~complex64 | ~complex128 | bignum.Complex
}
