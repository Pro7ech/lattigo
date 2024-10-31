package hefloat

import (
	"fmt"
	"math"
	"math/big"
	"sort"
	"testing"

	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/bignum"
	"github.com/stretchr/testify/require"
)

// PrecisionStats is a struct storing statistic about the precision of a CKKS plaintext
type PrecisionStats struct {
	MaxPrec Stats
	MinPrec Stats
	AvgPrec Stats
	MedPrec Stats
	StdPrec Stats

	MaxErr Stats
	MinErr Stats
	AvgErr Stats
	MedErr Stats
	StdErr Stats

	RealDist, ImagDist, L2Dist []struct {
		Prec  big.Float
		Count int
	}

	cdfResol int
}

// Stats is a struct storing the real, imaginary and L2 norm (modulus)
// about the precision of a complex value.
type Stats struct {
	Real, Imag, L2 float64
}

type stats struct {
	Real, Imag, L2 big.Float
}

func (prec PrecisionStats) String() string {
	return fmt.Sprintf(`
┌─────────┬───────┬───────┬───────┐
│    Log2 │ REAL  │ IMAG  │ L2    │
├─────────┼───────┼───────┼───────┤
│MIN Prec │ %5.2f │ %5.2f │ %5.2f │
│MAX Prec │ %5.2f │ %5.2f │ %5.2f │
│AVG Prec │ %5.2f │ %5.2f │ %5.2f │
│MED Prec │ %5.2f │ %5.2f │ %5.2f │
│STD Prec │ %5.2f │ %5.2f │ %5.2f │
├─────────┼───────┼───────┼───────┤
│MIN Err  │ %5.2f │ %5.2f │ %5.2f │
│MAX Err  │ %5.2f │ %5.2f │ %5.2f │
│AVG Err  │ %5.2f │ %5.2f │ %5.2f │
│MED Err  │ %5.2f │ %5.2f │ %5.2f │
│STD Err  │ %5.2f │ %5.2f │ %5.2f │
└─────────┴───────┴───────┴───────┘
`,
		prec.MinPrec.Real, prec.MinPrec.Imag, prec.MinPrec.L2,
		prec.MaxPrec.Real, prec.MaxPrec.Imag, prec.MaxPrec.L2,
		prec.AvgPrec.Real, prec.AvgPrec.Imag, prec.AvgPrec.L2,
		prec.MedPrec.Real, prec.MedPrec.Imag, prec.MedPrec.L2,
		prec.StdPrec.Real, prec.StdPrec.Imag, prec.StdPrec.L2,
		prec.MinErr.Real, prec.MinErr.Imag, prec.MinErr.L2,
		prec.MaxErr.Real, prec.MaxErr.Imag, prec.MaxErr.L2,
		prec.AvgErr.Real, prec.AvgErr.Imag, prec.AvgErr.L2,
		prec.MedErr.Real, prec.MedErr.Imag, prec.MedErr.L2,
		prec.StdErr.Real, prec.StdErr.Imag, prec.StdErr.L2,
	)
}

// GetPrecisionStats generates a PrecisionStats struct from the reference values and the decrypted values
// vWant.(type) must be either []complex128 or []float64
// element.(type) must be either *Plaintext, *Ciphertext, []complex128 or []float64. If not *Ciphertext, then decryptor can be nil.
func GetPrecisionStats(params Parameters, encoder *Encoder, decryptor *rlwe.Decryptor, want, have interface{}, logprec float64, computeDCF bool) (prec PrecisionStats) {

	if encoder.Prec() <= 53 {
		return getPrecisionStatsF64(params, encoder, decryptor, want, have, logprec, computeDCF)
	}

	return getPrecisionStatsF128(params, encoder, decryptor, want, have, logprec, computeDCF)
}

func VerifyTestVectors(params Parameters, encoder *Encoder, decryptor *rlwe.Decryptor, valuesWant, valuesHave interface{}, log2MinPrec int, logprec float64, printPrecisionStats bool, t *testing.T) {

	precStats := GetPrecisionStats(params, encoder, decryptor, valuesWant, valuesHave, logprec, false)

	if printPrecisionStats {
		t.Log(precStats.String())
	}

	switch params.RingType() {
	case ring.Standard:
		log2MinPrec -= params.LogN() + 2 // Z[X]/(X^{N} + 1)
	case ring.ConjugateInvariant:
		log2MinPrec -= params.LogN() + 3 // Z[X + X^1]/(X^{2N} + 1)
	}
	if log2MinPrec < 0 {
		log2MinPrec = 0
	}

	require.GreaterOrEqual(t, precStats.AvgPrec.Real, float64(log2MinPrec))
	require.GreaterOrEqual(t, precStats.AvgPrec.Imag, float64(log2MinPrec))
}

func getPrecisionStatsF64(params Parameters, encoder *Encoder, decryptor *rlwe.Decryptor, want, have interface{}, logprec float64, computeDCF bool) (prec PrecisionStats) {

	var valuesWant []complex128

	switch want := want.(type) {
	case []complex128:
		valuesWant = make([]complex128, len(want))
		copy(valuesWant, want)
	case []float64:
		valuesWant = make([]complex128, len(want))
		for i := range want {
			valuesWant[i] = complex(want[i], 0)
		}
	case []big.Float:
		valuesWant = make([]complex128, len(want))
		for i := range want {
			f64, _ := want[i].Float64()
			valuesWant[i] = complex(f64, 0)
		}
	case []bignum.Complex:
		valuesWant = make([]complex128, len(want))
		for i := range want {
			valuesWant[i] = want[i].Complex128()
		}
	}

	var valuesHave = make([]complex128, len(valuesWant))

	switch have := have.(type) {
	case *rlwe.Ciphertext:
		if err := encoder.DecodePublic(decryptor.DecryptNew(have), valuesHave, logprec); err != nil {
			// Sanity check, this error should never happen.
			panic(err)
		}
	case *rlwe.Plaintext:
		if err := encoder.DecodePublic(have, valuesHave, logprec); err != nil {
			// Sanity check, this error should never happen.
			panic(err)
		}
	case []complex128:
		copy(valuesHave, have)
	case []float64:
		for i := range have {
			valuesHave[i] = complex(have[i], 0)
		}
	case []big.Float:
		for i := range have {
			f64, _ := have[i].Float64()
			valuesHave[i] = complex(f64, 0)
		}
	case []bignum.Complex:
		for i := range have {
			valuesHave[i] = have[i].Complex128()
		}
	}

	slots := len(valuesWant)

	var precReal, precImag, precL2 []float64

	if computeDCF {
		precReal = make([]float64, len(valuesWant))
		precImag = make([]float64, len(valuesWant))
		precL2 = make([]float64, len(valuesWant))
	}

	var deltaReal, deltaImag, deltaL2 float64
	var AvgDeltaReal, AvgDeltaImag, AvgDeltaL2 float64
	var MaxDeltaReal, MaxDeltaImag, MaxDeltaL2 float64
	var MinDeltaReal, MinDeltaImag, MinDeltaL2 float64 = 1, 1, 1

	diffReal := make([]float64, len(valuesWant))
	diffImag := make([]float64, len(valuesWant))
	diffL2 := make([]float64, len(valuesWant))

	for i := range valuesWant {

		deltaReal = math.Abs(real(valuesHave[i]) - real(valuesWant[i]))
		deltaImag = math.Abs(imag(valuesHave[i]) - imag(valuesWant[i]))
		deltaL2 = math.Sqrt(deltaReal*deltaReal + deltaReal*deltaReal)

		if computeDCF {
			precReal[i] = -math.Log2(deltaReal)
			precImag[i] = -math.Log2(deltaImag)
			precL2[i] = -math.Log2(deltaL2)
		}

		diffReal[i] = deltaReal
		diffImag[i] = deltaImag
		diffL2[i] = deltaL2

		AvgDeltaReal += deltaReal
		AvgDeltaImag += deltaImag
		AvgDeltaL2 += deltaL2

		if deltaReal > MaxDeltaReal {
			MaxDeltaReal = deltaReal
		}

		if deltaImag > MaxDeltaImag {
			MaxDeltaImag = deltaImag
		}

		if deltaL2 > MaxDeltaL2 {
			MaxDeltaL2 = deltaL2
		}

		if deltaReal < MinDeltaReal {
			MinDeltaReal = deltaReal
		}

		if deltaImag < MinDeltaImag {
			MinDeltaImag = deltaImag
		}

		if deltaL2 < MinDeltaL2 {
			MinDeltaL2 = deltaL2
		}
	}

	if computeDCF {

		prec.cdfResol = 500

		prec.RealDist = make([]struct {
			Prec  big.Float
			Count int
		}, prec.cdfResol)
		prec.ImagDist = make([]struct {
			Prec  big.Float
			Count int
		}, prec.cdfResol)
		prec.L2Dist = make([]struct {
			Prec  big.Float
			Count int
		}, prec.cdfResol)

		prec.calcCDFF64(precReal, prec.RealDist)
		prec.calcCDFF64(precImag, prec.ImagDist)
		prec.calcCDFF64(precL2, prec.L2Dist)
	}

	logScale := float64(params.LogDefaultScale())

	prec.MinPrec = deltaToPrecisionF64(Stats{
		Real: MaxDeltaReal,
		Imag: MaxDeltaImag,
		L2:   MaxDeltaL2,
	}, logScale)

	prec.MaxPrec = deltaToPrecisionF64(Stats{
		Real: MinDeltaReal,
		Imag: MinDeltaImag,
		L2:   MinDeltaL2,
	}, logScale)

	prec.AvgPrec = deltaToPrecisionF64(Stats{
		Real: AvgDeltaReal / float64(slots),
		Imag: AvgDeltaImag / float64(slots),
		L2:   AvgDeltaL2 / float64(slots),
	}, logScale)

	MedReal := calcmedianF64(diffReal)
	MedImag := calcmedianF64(diffImag)
	MedL2 := calcmedianF64(diffL2)

	prec.MedPrec = deltaToPrecisionF64(Stats{Real: MedReal, Imag: MedImag, L2: MedL2}, logScale)

	prec.StdPrec = deltaToPrecisionF64(Stats{
		Real: calcstdF64(diffReal),
		Imag: calcstdF64(diffImag),
		L2:   calcstdF64(diffL2),
	}, logScale)

	prec.MinErr = Stats{
		Real: -prec.MaxPrec.Real + logScale,
		Imag: -prec.MaxPrec.Imag + logScale,
		L2:   -prec.MaxPrec.L2 + logScale,
	}

	prec.MaxErr = Stats{
		Real: -prec.MinPrec.Real + logScale,
		Imag: -prec.MinPrec.Imag + logScale,
		L2:   -prec.MinPrec.L2 + logScale,
	}

	prec.MaxErr = Stats{
		Real: -prec.MinPrec.Real + logScale,
		Imag: -prec.MinPrec.Imag + logScale,
		L2:   -prec.MinPrec.L2 + logScale,
	}

	prec.AvgErr = Stats{
		Real: -prec.AvgPrec.Real + logScale,
		Imag: -prec.AvgPrec.Imag + logScale,
		L2:   -prec.AvgPrec.L2 + logScale,
	}

	prec.MedErr = Stats{
		Real: -prec.MedPrec.Real + logScale,
		Imag: -prec.MedPrec.Imag + logScale,
		L2:   -prec.MedPrec.L2 + logScale,
	}

	prec.StdErr = Stats{
		Real: -prec.StdPrec.Real + logScale,
		Imag: -prec.StdPrec.Imag + logScale,
		L2:   -prec.StdPrec.L2 + logScale,
	}

	return prec
}

func deltaToPrecisionF64(c Stats, logScale float64) (s Stats) {

	if c.Real <= 0 {
		c.Real = math.Exp2(-logScale)
	}

	if c.Imag <= 0 {
		c.Imag = math.Exp2(-logScale)
	}

	if c.L2 <= 0 {
		c.L2 = math.Exp2(-logScale)
	}

	return Stats{
		-math.Log2(c.Real),
		-math.Log2(c.Imag),
		-math.Log2(c.L2),
	}
}

func (prec *PrecisionStats) calcCDFF64(precs []float64, res []struct {
	Prec  big.Float
	Count int
}) {
	sortedPrecs := make([]float64, len(precs))
	copy(sortedPrecs, precs)
	sort.Float64s(sortedPrecs)
	minPrec := sortedPrecs[0]
	maxPrec := sortedPrecs[len(sortedPrecs)-1]
	for i := 0; i < prec.cdfResol; i++ {
		curPrec := minPrec + float64(i)*(maxPrec-minPrec)/float64(prec.cdfResol)
		for countSmaller, p := range sortedPrecs {
			if p >= curPrec {
				res[i].Prec.SetFloat64(curPrec)
				res[i].Count = countSmaller
				break
			}
		}
	}
}

func calcmedianF64(values []float64) (median float64) {

	sort.Float64s(values)

	index := len(values) / 2

	if len(values)&1 == 1 || index+1 == len(values) {
		return values[index]
	}

	return (values[index-1] + values[index]) / 2
}

func calcstdF64(values []float64) (std float64) {
	var avg float64
	for i := range values {
		avg += values[i]
	}

	avg /= float64(len(values))

	for i := range values {
		x := values[i] - avg
		std += x * x
	}

	return math.Sqrt(std / float64(len(values)))
}

func getPrecisionStatsF128(params Parameters, encoder *Encoder, decryptor *rlwe.Decryptor, want, have interface{}, logprec float64, computeDCF bool) (prec PrecisionStats) {
	precision := encoder.Prec()

	var valuesWant []bignum.Complex
	switch want := want.(type) {
	case []complex128:
		valuesWant = make([]bignum.Complex, len(want))
		for i := range want {
			valuesWant[i].SetPrec(precision)
			valuesWant[i][0].SetFloat64(real(want[i]))
			valuesWant[i][1].SetFloat64(imag(want[i]))
		}
	case []float64:
		valuesWant = make([]bignum.Complex, len(want))
		for i := range want {
			valuesWant[i].SetPrec(precision)
			valuesWant[i][0].SetFloat64(want[i])
		}
	case []big.Float:
		valuesWant = make([]bignum.Complex, len(want))
		for i := range want {
			valuesWant[i].SetPrec(precision)
			valuesWant[i][0].Set(&want[i])
		}
	case []bignum.Complex:
		valuesWant = want
	}

	var valuesHave []bignum.Complex

	switch have := have.(type) {
	case *rlwe.Ciphertext:
		valuesHave = make([]bignum.Complex, len(valuesWant))
		if err := encoder.DecodePublic(decryptor.DecryptNew(have), valuesHave, logprec); err != nil {
			// Sanity check, this error should never happen.
			panic(err)
		}
	case *rlwe.Plaintext:
		valuesHave = make([]bignum.Complex, len(valuesWant))
		if err := encoder.DecodePublic(have, valuesHave, logprec); err != nil {
			// Sanity check, this error should never happen.
			panic(err)
		}
	case []complex128:
		valuesHave = make([]bignum.Complex, len(have))
		for i := range have {
			valuesHave[i].SetPrec(precision)
			valuesHave[i][0].SetFloat64(real(have[i]))
			valuesHave[i][1].SetFloat64(imag(have[i]))
		}
	case []float64:
		valuesHave = make([]bignum.Complex, len(have))
		for i := range have {
			valuesHave[i].SetPrec(precision)
			valuesHave[i][0].SetFloat64(have[i])
		}
	case []big.Float:
		valuesHave = make([]bignum.Complex, len(have))
		for i := range have {
			valuesHave[i].SetPrec(precision)
			valuesHave[i][0].Set(&have[i])
		}
	case []bignum.Complex:
		valuesHave = have
	}

	slots := len(valuesWant)

	precReal := make([]big.Float, len(valuesWant))
	precImag := make([]big.Float, len(valuesWant))
	precL2 := make([]big.Float, len(valuesWant))

	deltaReal := new(big.Float)
	deltaImag := new(big.Float)
	deltaL2 := new(big.Float)

	tmp := new(big.Float)

	ln2 := bignum.Log(new(big.Float).SetPrec(precision).SetInt64(2))

	AvgDelta := stats{}
	MaxDelta := stats{}
	MinDelta := stats{}

	diffReal := make([]big.Float, slots)
	diffImag := make([]big.Float, slots)
	diffL2 := make([]big.Float, slots)

	for i := range valuesWant {

		deltaReal.Sub(&valuesHave[i][0], &valuesWant[i][0])
		deltaReal.Abs(deltaReal)

		deltaImag.Sub(&valuesHave[i][1], &valuesWant[i][1])
		deltaImag.Abs(deltaImag)

		deltaL2.Mul(deltaReal, deltaReal)
		deltaL2.Add(deltaL2, tmp.Mul(deltaImag, deltaImag))
		deltaL2.Sqrt(deltaL2)

		precReal[i] = *bignum.Log(deltaReal)
		precReal[i].Quo(&precReal[i], ln2)
		precReal[i].Neg(&precReal[i])

		precImag[i] = *bignum.Log(deltaImag)
		precImag[i].Quo(&precImag[i], ln2)
		precImag[i].Neg(&precImag[i])

		precL2[i] = *bignum.Log(deltaL2)
		precL2[i].Quo(&precL2[i], ln2)
		precL2[i].Neg(&precL2[i])

		diffReal[i].Set(deltaReal)
		diffImag[i].Set(deltaImag)
		diffL2[i].Set(deltaL2)

		AvgDelta.Real.Add(&AvgDelta.Real, deltaReal)
		AvgDelta.Imag.Add(&AvgDelta.Imag, deltaImag)
		AvgDelta.L2.Add(&AvgDelta.L2, deltaL2)

		if deltaReal.Cmp(&MaxDelta.Real) == 1 {
			MaxDelta.Real.Set(deltaReal)
		}

		if deltaImag.Cmp(&MaxDelta.Imag) == 1 {
			MaxDelta.Imag.Set(deltaImag)
		}

		if deltaL2.Cmp(&MaxDelta.L2) == 1 {
			MaxDelta.L2.Set(deltaL2)
		}

		if deltaReal.Cmp(&MinDelta.Real) == -1 {
			MinDelta.Real.Set(deltaReal)
		}

		if deltaImag.Cmp(&MinDelta.Imag) == -1 {
			MinDelta.Imag.Set(deltaImag)
		}

		if deltaL2.Cmp(&MinDelta.L2) == -1 {
			MinDelta.L2.Set(deltaL2)
		}
	}

	if computeDCF {

		prec.cdfResol = 500

		prec.RealDist = make([]struct {
			Prec  big.Float
			Count int
		}, prec.cdfResol)
		prec.ImagDist = make([]struct {
			Prec  big.Float
			Count int
		}, prec.cdfResol)
		prec.L2Dist = make([]struct {
			Prec  big.Float
			Count int
		}, prec.cdfResol)

		prec.calcCDFF128(precReal, prec.RealDist)
		prec.calcCDFF128(precImag, prec.ImagDist)
		prec.calcCDFF128(precL2, prec.L2Dist)
	}

	logScale := float64(params.LogDefaultScale())

	prec.MinPrec = deltaToPrecisionF128(MaxDelta, ln2, logScale)
	prec.MaxPrec = deltaToPrecisionF128(MinDelta, ln2, logScale)

	AvgDelta.Real.Quo(&AvgDelta.Real, new(big.Float).SetPrec(precision).SetInt64(int64(slots)))
	AvgDelta.Imag.Quo(&AvgDelta.Imag, new(big.Float).SetPrec(precision).SetInt64(int64(slots)))
	AvgDelta.L2.Quo(&AvgDelta.L2, new(big.Float).SetPrec(precision).SetInt64(int64(slots)))

	prec.AvgPrec = deltaToPrecisionF128(AvgDelta, ln2, logScale)

	prec.MedPrec = deltaToPrecisionF128(stats{
		Real: calcmedianF128(diffReal),
		Imag: calcmedianF128(diffImag),
		L2:   calcmedianF128(diffL2),
	}, ln2, logScale)

	prec.StdPrec = deltaToPrecisionF128(stats{
		Real: calcstdF128(diffReal),
		Imag: calcstdF128(diffImag),
		L2:   calcstdF128(diffL2),
	}, ln2, logScale)

	prec.MinErr = Stats{
		Real: -prec.MaxPrec.Real + logScale,
		Imag: -prec.MaxPrec.Imag + logScale,
		L2:   -prec.MaxPrec.L2 + logScale,
	}

	prec.MaxErr = Stats{
		Real: -prec.MinPrec.Real + logScale,
		Imag: -prec.MinPrec.Imag + logScale,
		L2:   -prec.MinPrec.L2 + logScale,
	}

	prec.MaxErr = Stats{
		Real: -prec.MinPrec.Real + logScale,
		Imag: -prec.MinPrec.Imag + logScale,
		L2:   -prec.MinPrec.L2 + logScale,
	}

	prec.AvgErr = Stats{
		Real: -prec.AvgPrec.Real + logScale,
		Imag: -prec.AvgPrec.Imag + logScale,
		L2:   -prec.AvgPrec.L2 + logScale,
	}

	prec.MedErr = Stats{
		Real: -prec.MedPrec.Real + logScale,
		Imag: -prec.MedPrec.Imag + logScale,
		L2:   -prec.MedPrec.L2 + logScale,
	}

	prec.StdErr = Stats{
		Real: -prec.StdPrec.Real + logScale,
		Imag: -prec.StdPrec.Imag + logScale,
		L2:   -prec.StdPrec.L2 + logScale,
	}

	return prec
}

func deltaToPrecisionF128(c stats, ln2 *big.Float, logScale float64) Stats {

	real := bignum.Log(&c.Real)
	real.Quo(real, ln2)
	real.Neg(real)

	imag := bignum.Log(&c.Imag)
	imag.Quo(imag, ln2)
	imag.Neg(imag)

	l2 := bignum.Log(&c.L2)
	l2.Quo(l2, ln2)
	l2.Neg(l2)

	rF64, _ := real.Float64()
	iF64, _ := imag.Float64()
	l2F64, _ := l2.Float64()

	if math.IsInf(rF64, -1) {
		rF64 = 0
	}

	if math.IsInf(rF64, 1) {
		rF64 = logScale
	}

	if math.IsInf(iF64, -1) {
		iF64 = 0
	}

	if math.IsInf(iF64, 1) {
		iF64 = logScale
	}

	if math.IsInf(l2F64, -1) {
		l2F64 = 0
	}

	if math.IsInf(l2F64, 1) {
		l2F64 = logScale
	}

	return Stats{
		rF64,
		iF64,
		l2F64,
	}
}

func calcstdF128(values []big.Float) (std big.Float) {
	prec := values[0].Prec()
	avg := new(big.Float).SetPrec(prec)
	for i := range values {
		avg.Add(avg, &values[i])
	}

	n := new(big.Float).SetPrec(values[0].Prec()).SetInt64(int64(len(values)))

	avg.Quo(avg, n)

	x := new(big.Float)
	std.SetPrec(prec)
	for i := range values {
		x.Sub(&values[i], avg)
		x.Mul(x, x)
		std.Add(&std, x)
	}

	std.Quo(&std, n)

	return *std.Sqrt(&std)
}

func (prec *PrecisionStats) calcCDFF128(precs []big.Float, res []struct {
	Prec  big.Float
	Count int
}) {
	sortedPrecs := make([]big.Float, len(precs))
	copy(sortedPrecs, precs)

	sort.Slice(sortedPrecs, func(i, j int) bool {
		return sortedPrecs[i].Cmp(&sortedPrecs[j]) > 0
	})

	minPrec := &sortedPrecs[0]
	maxPrec := &sortedPrecs[len(sortedPrecs)-1]

	curPrec := new(big.Float)

	a := new(big.Float).Sub(maxPrec, minPrec)
	a.Quo(a, new(big.Float).SetInt64(int64(prec.cdfResol)))

	b := new(big.Float).Quo(minPrec, new(big.Float).SetInt64(int64(prec.cdfResol)))

	for i := 0; i < prec.cdfResol; i++ {

		curPrec.Mul(new(big.Float).SetInt64(int64(i)), a)
		curPrec.Add(curPrec, b)

		for countSmaller, p := range sortedPrecs {
			if p.Cmp(curPrec) >= 0 {
				res[i].Prec.Set(curPrec)
				res[i].Count = countSmaller
				break
			}
		}
	}
}

func calcmedianF128(values []big.Float) (median big.Float) {

	sort.Slice(values, func(i, j int) bool {
		return values[i].Cmp(&values[j]) > 0
	})

	index := len(values) / 2

	if len(values)&1 == 1 || index+1 == len(values) {
		median.Set(&values[index])
		return
	}

	median.Add(&values[index-1], &values[index])
	median.Quo(&median, new(big.Float).SetInt64(2))

	return
}
