package heint_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/Pro7ech/lattigo/he/heint"
	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/buffer"
	"github.com/stretchr/testify/require"
)

func testParameters(tc *testContext, t *testing.T) {
	t.Run(GetTestName("Parameters/Binary", tc.params, 0), func(t *testing.T) {
		buffer.RequireSerializerCorrect(t, &tc.params)

	})

	t.Run(GetTestName("Parameters/JSON", tc.params, 0), func(t *testing.T) {
		var err error
		// checks that the Parameters can be unmarshalled with log-moduli definition without error
		dataWithLogModuli := []byte(fmt.Sprintf(`{"LogN":%d,"LogQ":[50,50],"LogP":[60], "T":65537, "R":1}`, tc.params.LogN()))
		var paramsWithLogModuli heint.Parameters
		err = json.Unmarshal(dataWithLogModuli, &paramsWithLogModuli)
		require.Nil(t, err)
		require.Equal(t, 2, paramsWithLogModuli.QCount())
		require.Equal(t, 1, paramsWithLogModuli.PCount())
		require.True(t, paramsWithLogModuli.Xe().Equal(&rlwe.DefaultXe)) // Omitting Xe should result in Default being used
		require.True(t, paramsWithLogModuli.Xs().Equal(&rlwe.DefaultXs)) // Omitting Xe should result in Default being used

		// checks that one can provide custom parameters for the secret-key and error distributions
		dataWithCustomSecrets := []byte(fmt.Sprintf(`{"LogN":%d,"LogQ":[50,50],"LogP":[60], "T":65537, "R":1, "Xs": {"Type": "Ternary", "H": 192}, "Xe": {"Type": "DiscreteGaussian", "Sigma": 6.6, "Bound": 39.6}}`, tc.params.LogN()))
		var paramsWithCustomSecrets heint.Parameters
		err = json.Unmarshal(dataWithCustomSecrets, &paramsWithCustomSecrets)
		require.Nil(t, err)
		require.True(t, paramsWithCustomSecrets.Xe().Equal(&ring.DiscreteGaussian{Sigma: 6.6, Bound: 39.6}))
		require.True(t, paramsWithCustomSecrets.Xs().Equal(&ring.Ternary{H: 192}))
	})
}
