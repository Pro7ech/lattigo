package rgsw

import (
	"github.com/Pro7ech/lattigo/rlwe"
)

type TestParametersLiteral struct {
	rlwe.DigitDecomposition
	rlwe.ParametersLiteral
}

var (
	logN = 10
	logQ = []int{45, 35, 35}
	logP = []int{50, 50}

	// testInsecure are insecure parameters used for the sole purpose of fast testing.
	testInsecure = []TestParametersLiteral{
		// RNS decomposition, no Pw2 decomposition
		{
			DigitDecomposition: rlwe.DigitDecomposition{},

			ParametersLiteral: rlwe.ParametersLiteral{
				LogN:    logN,
				LogQ:    logQ,
				LogP:    logP,
				NTTFlag: true,
			},
		},
		// RNS decomposition, Pw2 decomposition
		{
			DigitDecomposition: rlwe.DigitDecomposition{
				Type:      rlwe.SignedBalanced,
				Log2Basis: 16,
			},

			ParametersLiteral: rlwe.ParametersLiteral{
				LogN:    logN,
				LogQ:    logQ,
				LogP:    logP[:1],
				NTTFlag: true,
			},
		},
		// No RNS decomposition, Pw2 decomposition
		{
			DigitDecomposition: rlwe.DigitDecomposition{
				Type:      rlwe.Unsigned,
				Log2Basis: 2,
			},

			ParametersLiteral: rlwe.ParametersLiteral{
				LogN:    logN,
				LogQ:    logQ[:1],
				LogP:    nil,
				NTTFlag: true,
			},
		},
	}
)
