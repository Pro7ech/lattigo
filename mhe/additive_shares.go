package mhe

import (
	"math/big"
)

// AdditiveShare is a type for storing additively shared values in Z_Q[X] (RNS domain).
type AdditiveShare struct {
	Value []uint64
}

// AdditiveShareBigint is a type for storing additively shared values
// in Z (positional domain).
type AdditiveShareBigint struct {
	Value []big.Int
}

// NewAdditiveShare instantiates a new additive share struct for the ring defined
// by the given parameters at maximum level.
func NewAdditiveShare(N int) *AdditiveShare {
	return &AdditiveShare{Value: make([]uint64, N)}
}

// NewAdditiveShareBigint instantiates a new additive share struct composed of n big.Int elements.
func NewAdditiveShareBigint(n int) *AdditiveShareBigint {
	return &AdditiveShareBigint{Value: make([]big.Int, n)}
}
