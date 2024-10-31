package rlwe

type TestParametersLiteral struct {
	DigitDecomposition
	ParametersLiteral
}

var (
	logN = 10
	logQ = []int{45, 35, 35}
	logP = []int{50, 50}

	// testInsecure are insecure parameters used for the sole purpose of fast testing.
	testInsecure = []TestParametersLiteral{
		// RNS decomposition, no Pw2 decomposition
		{
			DigitDecomposition: DigitDecomposition{},

			ParametersLiteral: ParametersLiteral{
				LogN:    logN,
				LogQ:    logQ,
				LogP:    logP,
				NTTFlag: true,
			},
		},
		// RNS decomposition, Pw2 decomposition
		{
			DigitDecomposition: DigitDecomposition{
				Type:      Unsigned,
				Log2Basis: 16,
			},

			ParametersLiteral: ParametersLiteral{
				LogN:    logN,
				LogQ:    logQ,
				LogP:    logP[:1],
				NTTFlag: true,
			},
		},
		// No RNS decomposition, Pw2 decomposition
		{
			DigitDecomposition: DigitDecomposition{
				Type:      SignedBalanced,
				Log2Basis: 2,
			},

			ParametersLiteral: ParametersLiteral{
				LogN:    logN,
				LogQ:    logQ[:1],
				LogP:    nil,
				NTTFlag: true,
			},
		},
	}
)
