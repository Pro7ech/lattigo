package mhe

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils"
	"github.com/Pro7ech/lattigo/utils/sampling"
)

func BenchmarkMHE(b *testing.B) {

	thresholdInc := 5

	var err error

	defaultParamsLiteral := testInsecure

	if *flagParamString != "" {
		var jsonParams TestParametersLiteral
		if err = json.Unmarshal([]byte(*flagParamString), &jsonParams); err != nil {
			b.Fatal(err)
		}
		defaultParamsLiteral = []TestParametersLiteral{jsonParams} // the custom test suite reads the parameters from the -params flag
	}

	for _, paramsLit := range defaultParamsLiteral {

		for _, NTTFlag := range []bool{true, false} {

			for _, RingType := range []ring.Type{ring.Standard, ring.ConjugateInvariant}[:] {

				paramsLit.NTTFlag = NTTFlag
				paramsLit.RingType = RingType

				var params rlwe.Parameters
				if params, err = rlwe.NewParametersFromLiteral(paramsLit.ParametersLiteral); err != nil {
					b.Fatal(err)
				}

				levelQ := params.MaxLevelQ()
				levelP := params.MaxLevelP()
				dd := paramsLit.DigitDecomposition

				benchPublicKeyGen(params, levelQ, levelP, dd, b)
				benchRelinearizationKeyGen(params, levelQ, levelP, dd, b)
				benchRotKeyGen(params, levelQ, levelP, dd, b)

				// Varying t
				for t := 2; t <= 19; t += thresholdInc {
					benchThreshold(params, levelQ, levelP, dd, t, b)
				}
			}
		}
	}
}

func benchString(params rlwe.Parameters, opname string, levelQ, levelP int, dd rlwe.DigitDecomposition) string {
	return fmt.Sprintf("%s/logN=%d/#Qi=%d/#Pi=%d/Digits=%s/NTT=%t/RingType=%s",
		opname,
		params.LogN(),
		levelQ+1,
		levelP+1,
		dd.ToString(),
		params.NTTFlag(),
		params.RingType())
}

func benchPublicKeyGen(params rlwe.Parameters, levelQ, levelP int, dd rlwe.DigitDecomposition, b *testing.B) {

	ckg := NewPublicKeyProtocol(params)
	sk := rlwe.NewKeyGenerator(params).GenSecretKeyNew()
	share := ckg.Allocate()

	b.Run(benchString(params, "PublicKeyGen/Round1/Gen", levelQ, levelP, dd), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ckg.Gen(sk, sampling.NewSeed(), share)
		}
	})

	b.Run(benchString(params, "PublicKeyGen/Round1/Agg", levelQ, levelP, dd), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ckg.Aggregate(share, share, share)
		}
	})

	pk := rlwe.NewPublicKey(params)
	b.Run(benchString(params, "PublicKeyGen/Finalize", levelQ, levelP, dd), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ckg.Finalize(share, pk)
		}
	})
}

func benchRelinearizationKeyGen(params rlwe.Parameters, levelQ, levelP int, dd rlwe.DigitDecomposition, b *testing.B) {

	evkParams := rlwe.EvaluationKeyParameters{LevelQ: utils.Pointy(levelQ), LevelP: utils.Pointy(levelP), DigitDecomposition: dd}

	rkg := NewRelinearizationKeyProtocol(params)
	sk, pk := rlwe.NewKeyGenerator(params).GenKeyPairNew()
	share := rkg.Allocate(evkParams)
	rlk := rlwe.NewRelinearizationKey(params, evkParams)

	b.Run(benchString(params, "RelinearizationKeyGen/Gen", levelQ, levelP, dd), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rkg.Gen(sk, pk, share)
		}
	})

	b.Run(benchString(params, "RelinearizationKeyGen/Agg", levelQ, levelP, dd), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rkg.Aggregate(share, share, share)
		}
	})

	b.Run(benchString(params, "RelinearizationKeyGen/Finalize", levelQ, levelP, dd), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rkg.Finalize(share, rlk)
		}
	})
}

func benchRotKeyGen(params rlwe.Parameters, levelQ, levelP int, dd rlwe.DigitDecomposition, b *testing.B) {

	evkParams := rlwe.EvaluationKeyParameters{LevelQ: utils.Pointy(levelQ), LevelP: utils.Pointy(levelP), DigitDecomposition: dd}

	rtg := NewGaloisKeyProtocol(params)
	sk := rlwe.NewKeyGenerator(params).GenSecretKeyNew()
	share := rtg.Allocate(evkParams)

	b.Run(benchString(params, "RotKeyGen/Round1/Gen", levelQ, levelP, dd), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rtg.Gen(sk, params.GaloisElement(1), sampling.NewSeed(), share)
		}
	})

	b.Run(benchString(params, "RotKeyGen/Round1/Agg", levelQ, levelP, dd), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rtg.Aggregate(share, share, share)
		}
	})

	gkey := rlwe.NewGaloisKey(params, evkParams)
	b.Run(benchString(params, "RotKeyGen/Finalize", levelQ, levelP, dd), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rtg.Finalize(share, gkey)
		}
	})
}

func benchThreshold(params rlwe.Parameters, levelQ, levelP int, dd rlwe.DigitDecomposition, t int, b *testing.B) {

	type Party struct {
		Thresholdizer
		Combiner
		gen *ShamirPolynomial
		s   *rlwe.SecretKey
		sk  *rlwe.SecretKey
		tsk *ShamirSecretShare
	}

	shamirPks := make([]ShamirPublicPoint, t)
	for i := range shamirPks {
		shamirPks[i] = ShamirPublicPoint(i + 1)
	}

	p := new(Party)
	p.s = rlwe.NewSecretKey(params)
	p.Thresholdizer = *NewThresholdizer(params)
	p.tsk = p.Thresholdizer.Allocate()
	p.sk = rlwe.NewSecretKey(params)

	b.Run(benchString(params, "Thresholdizer/Gen", levelQ, levelP, dd)+fmt.Sprintf("/threshold=%d", t), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			p.gen, _ = p.Thresholdizer.Gen(t, p.s)
		}
	})

	shamirShare := p.Thresholdizer.Allocate()

	b.Run(benchString(params, "Thresholdizer/Finalize", levelQ, levelP, dd)+fmt.Sprintf("/threshold=%d", t), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			p.Thresholdizer.Finalize(shamirPks[0], p.gen, shamirShare)
		}
	})

	b.Run(benchString(params, "Thresholdizer/Aggregate", levelQ, levelP, dd)+fmt.Sprintf("/threshold=%d", t), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			p.Thresholdizer.Aggregate(shamirShare, shamirShare, shamirShare)
		}
	})

	p.Combiner = *NewCombiner(params, shamirPks[0], shamirPks, t)

	b.Run(benchString(params, "Combiner/Finalize", levelQ, levelP, dd)+fmt.Sprintf("/threshold=%d", t), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			p.Combiner.Finalize(shamirPks, shamirPks[0], p.tsk, p.sk)
		}
	})
}
