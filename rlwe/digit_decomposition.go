package rlwe

import (
	"fmt"
)

// DigitDecompositionType defines the type of the
// digit decomposition.
type DigitDecompositionType int

const (
	// 0 = no digit decomposition (i.e. plain RNS)

	// Unsigned: unsigned digit decomposition, Var[X] = 2^{w}/12, E[X] = 2^{w-1}
	// Fastest decomposition, but greatest error.
	Unsigned = DigitDecompositionType(1)

	// Signed: signed digit decomposition, Var[X] = 2^{w}/12, E[X] = -0.5
	// Sligthly slower than unsigned (up to 15%), close to optimal error.
	Signed = DigitDecompositionType(2)

	// SignedBalanced: signed balanced digit decomposition, Var[X] = (2^{w}+0.25)/12, E[X] = 0
	// Much slower than unsigned (up to 50%), but optimal error.
	SignedBalanced = DigitDecompositionType(3)
)

// DigitDecomposition is a struct that stores
// the parameters for the digit decomposition.
type DigitDecomposition struct {
	Type      DigitDecompositionType
	Log2Basis int
}

func (dd DigitDecomposition) ToString() string {
	switch dd.Type {
	case Unsigned:
		return fmt.Sprintf("Unsigned:%d", dd.Log2Basis)
	case Signed:
		return fmt.Sprintf("Signed:%d", dd.Log2Basis)
	case SignedBalanced:
		return fmt.Sprintf("SignedBalanced:%d", dd.Log2Basis)
	default:
		return fmt.Sprintf("None:%d", dd.Log2Basis)
	}
}
