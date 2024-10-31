package ring

import (
	"fmt"
	"testing"

	"github.com/Pro7ech/lattigo/utils/sampling"
)

func BenchmarkNTT(b *testing.B) {
	benchNTT(10, 1, b)
	benchNTT(11, 1, b)
	benchNTT(12, 1, b)
	benchNTT(13, 1, b)
	benchNTT(14, 1, b)
	benchNTT(15, 1, b)
	benchNTT(16, 1, b)
	benchINTT(10, 1, b)
	benchINTT(11, 1, b)
	benchINTT(12, 1, b)
	benchINTT(13, 1, b)
	benchINTT(14, 1, b)
	benchINTT(15, 1, b)
	benchINTT(16, 1, b)
}

func benchNTT(LogN, Qi int, b *testing.B) {
	b.Run(fmt.Sprintf("Forward/N=%d/Qi=%d", 1<<LogN, Qi), func(b *testing.B) {
		r, err := NewRNSRing(1<<LogN, Qi60[:Qi])
		if err != nil {
			b.Fatal(err)
		}

		p := NewUniformSampler(sampling.NewSource([32]byte{}), r.ModuliChain()).ReadNew(r.N())
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			r.NTT(p, p)
		}
	})
}

func benchINTT(LogN, Qi int, b *testing.B) {
	b.Run(fmt.Sprintf("Backward/N=%d/Qi=%d", 1<<LogN, Qi), func(b *testing.B) {
		r, err := NewRNSRing(1<<LogN, Qi60[:Qi])
		if err != nil {
			b.Fatal(err)
		}

		p := NewUniformSampler(sampling.NewSource([32]byte{}), r.ModuliChain()).ReadNew(r.N())
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			r.INTT(p, p)
		}
	})
}
