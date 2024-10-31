package heint

var (
	// ExampleParameters128BitLogN14LogQP438 is an example parameters set with logN=14, logQP=438
	// and a 16-bit plaintext modulus, offering 128-bit of security.
	ExampleParameters128BitLogN14LogQP438 = ParametersLiteral{
		LogN: 14,
		LogQ: []int{
			40, 29, 29,
			29, 29, 29,
			29, 29, 29,
			29, 29, 29}, // 40 + 11*29 bits
		LogP: []int{40, 39}, // 40 + 39 bits
		T:    65537,         // 16 bits
		R:    1,             // T^{R}
	}
)
