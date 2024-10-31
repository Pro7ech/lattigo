package concurrency

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConcurrency(t *testing.T) {

	t.Run("NoError", func(t *testing.T) {

		acc := make([]int, 8)

		ressources := make([]bool, 4)

		rm := NewRessourceManager(ressources)

		for i := range acc {
			rm.Run(func(r bool) (err error) {
				acc[i]++
				return
			})
		}

		require.NoError(t, rm.Wait())

		for i := range acc {
			require.Equal(t, acc[i], 1)
		}
	})

	t.Run("WithError", func(t *testing.T) {
		acc := make([]int, 8)

		ressources := make([]bool, 4)

		rm := NewRessourceManager(ressources)

		for i := range acc {
			rm.Run(func(r bool) (err error) {
				acc[i]++
				if i == 2 {
					return fmt.Errorf("something bad happened")
				}

				return
			})
		}

		require.Error(t, rm.Wait())
	})
}
