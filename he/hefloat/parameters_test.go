package hefloat_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/stretchr/testify/require"
)

func testParameters(tc *testContext, t *testing.T) {

	t.Run(GetTestName(tc.params, "Parameters/NewParameters"), func(t *testing.T) {
		params, err := hefloat.NewParametersFromLiteral(hefloat.ParametersLiteral{
			LogN:            4,
			LogQ:            []int{60, 60},
			LogP:            []int{60},
			LogDefaultScale: 0,
		})
		require.NoError(t, err)
		require.Equal(t, ring.Standard, params.RingType()) // Default ring type should be standard
		require.True(t, params.Xe().Equal(&rlwe.DefaultXe))
		require.True(t, params.Xs().Equal(&rlwe.DefaultXs))
	})

	t.Run(GetTestName(tc.params, "Parameters/StandardRing"), func(t *testing.T) {
		params, err := tc.params.StandardParameters()
		switch tc.params.RingType() {
		case ring.Standard:
			require.True(t, params.Equal(&tc.params))
			require.NoError(t, err)
		case ring.ConjugateInvariant:
			require.Equal(t, params.LogN(), tc.params.LogN()+1)
			require.NoError(t, err)
		default:
			t.Fatal("invalid RingType")
		}
	})

	t.Run(GetTestName(tc.params, "Parameters/Marshaller/Binary"), func(t *testing.T) {

		bytes, err := tc.params.MarshalBinary()
		require.Nil(t, err)
		var p hefloat.Parameters
		require.Nil(t, p.UnmarshalBinary(bytes))
		require.True(t, tc.params.Equal(&p))
	})

	t.Run(GetTestName(tc.params, "Parameters/Marshaller/JSON"), func(t *testing.T) {

		var err error

		// checks that ckks.Parameters can be unmarshalled with log-moduli definition without error
		dataWithLogModuli := []byte(fmt.Sprintf(`{"LogN":%d,"LogQ":[50,50],"LogP":[60], "LogDefaultScale":30}`, tc.params.LogN()))
		var paramsWithLogModuli hefloat.Parameters
		err = json.Unmarshal(dataWithLogModuli, &paramsWithLogModuli)
		require.Nil(t, err)
		require.Equal(t, 2, paramsWithLogModuli.QCount())
		require.Equal(t, 1, paramsWithLogModuli.PCount())
		require.Equal(t, ring.Standard, paramsWithLogModuli.RingType())  // Omitting the RingType field should result in a standard instance
		require.True(t, paramsWithLogModuli.Xe().Equal(&rlwe.DefaultXe)) // Omitting Xe should result in Default being used
		require.True(t, paramsWithLogModuli.Xs().Equal(&rlwe.DefaultXs)) // Omitting Xe should result in Default being used
		require.Equal(t, 30, paramsWithLogModuli.LogDefaultScale())

		// checks that ckks.Parameters can be unmarshalled with log-moduli definition with empty P without error
		dataWithLogModuliNoP := []byte(fmt.Sprintf(`{"LogN":%d,"LogQ":[50,50],"LogP":[], "RingType": "ConjugateInvariant"}`, tc.params.LogN()))
		var paramsWithLogModuliNoP hefloat.Parameters
		err = json.Unmarshal(dataWithLogModuliNoP, &paramsWithLogModuliNoP)
		require.Nil(t, err)
		require.Equal(t, 2, paramsWithLogModuliNoP.QCount())
		require.Equal(t, 0, paramsWithLogModuliNoP.PCount())
		require.Equal(t, ring.ConjugateInvariant, paramsWithLogModuliNoP.RingType())

		// checks that one can provide custom parameters for the secret-key and error distributions
		dataWithCustomSecrets := []byte(fmt.Sprintf(`{"LogN":%d,"LogQ":[50,50],"LogP":[60], "Xs": {"Type": "Ternary", "H": 192}, "Xe": {"Type": "DiscreteGaussian", "Sigma": 6.6, "Bound": 39.6}}`, tc.params.LogN()))
		var paramsWithCustomSecrets hefloat.Parameters
		err = json.Unmarshal(dataWithCustomSecrets, &paramsWithCustomSecrets)
		require.Nil(t, err)
		require.True(t, paramsWithCustomSecrets.Xe().Equal(&ring.DiscreteGaussian{Sigma: 6.6, Bound: 39.6}))
		require.True(t, paramsWithCustomSecrets.Xs().Equal(&ring.Ternary{H: 192}))
	})
}
