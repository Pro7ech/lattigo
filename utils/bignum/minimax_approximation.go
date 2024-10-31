package bignum

import (
	"fmt"
	"math"
	"math/big"
	//"sync"
)

// Remez implements the optimized multi-interval minimax approximation
// algorithm of Lee et al. (https://eprint.iacr.org/2020/552).
// This is an iterative algorithm that returns the minimax polynomial
// approximation of any function that is smooth over a set of interval
// [a0, b0] U [a1, b1] U ... U [ai, bi].
type Remez struct {
	RemezParameters
	Degree int

	extrema      []point
	localExtrema []point
	nbExtrema    int

	MaxErr, MinErr *big.Float

	Nodes     []point
	Matrix    [][]big.Float
	Vector    []big.Float
	Coeffs    []big.Float
	Iteration int
}

type point struct {
	x, y big.Float
	sign int
}

// RemezParameters is a struct storing the parameters
// required to initialize the Remez algorithm.
type RemezParameters struct {
	// Function is the function to approximate.
	// It has to be smooth in the defined intervals.
	Function func(x *big.Float) (y *big.Float)

	// Basis is the basis to use.
	// Supported basis are: Monomial and Chebyshev
	Basis Basis

	// Intervals is the set of interval [ai, bi] on which to approximate
	// the function. Each interval also define the number of nodes (points)
	// that will be used to approximate the function inside this interval.
	// This allows the user to implement a separate algorithm that allocates
	// an optimal number of nodes per interval.
	Intervals []Interval

	// Prec defines the bit precision of the overall computation.
	Prec uint

	// Prints things, bruteforces extrema, generate graphs of the error, interval, nodes & extrema
	// (must be configured manually in this file)
	Debug bool
}

// NewRemez instantiates a new Remez algorithm from the provided parameters.
func NewRemez(p RemezParameters) (r *Remez) {

	r = &Remez{
		RemezParameters: p,
		MaxErr:          new(big.Float).SetPrec(p.Prec),
		MinErr:          new(big.Float).SetPrec(p.Prec),
	}

	for i := range r.Intervals {
		r.Degree += r.Intervals[i].Nodes
	}

	r.Degree -= 2

	r.Nodes = make([]point, r.Degree+2)

	r.Coeffs = make([]big.Float, r.Degree+1)
	r.extrema = make([]point, 16*r.Degree)
	r.localExtrema = make([]point, 16*r.Degree)

	r.Matrix = make([][]big.Float, r.Degree+2)
	for i := range r.Matrix {
		r.Matrix[i] = make([]big.Float, r.Degree+2)
	}

	r.Vector = make([]big.Float, r.Degree+2)

	return r
}

// Approximate starts the approximation process.
// maxIter: the maximum number of iterations before the approximation process is terminated.
// threshold: the minimum value that (maxErr-minErr)/minErr (the normalized absolute difference
// between the maximum and minimum approximation error over the defined intervals) must take
// before the approximation process is terminated.
func (r *Remez) Approximate(maxIter int, threshold float64) {

	decimals := int(-math.Log(threshold)/math.Log(10)+0.5) + 10

	r.initialize()

	for i := 0; i < maxIter; i++ {

		r.Iteration = i

		// Solves the linear system and gets the new set of coefficients
		r.getCoefficients()

		//r.ShowCoeffs(16)

		// Finds the extreme points of p(x) - f(x) (where the absolute error is max)
		r.findextrema()

		// Choose the new nodes based on the set of extreme points
		r.chooseNewNodes()

		/*
			fmt.Println("NewNodes")
			for i := range r.Nodes{
				fmt.Println(i, &r.Nodes[i].x)
			}
		*/

		nErr := new(big.Float).Sub(r.MaxErr, r.MinErr)
		nErr.Quo(nErr, r.MinErr)

		fmt.Printf("Iteration: %2d - %.*f %.*f\n", i, decimals, r.MinErr, decimals, r.MaxErr)

		if nErr.Cmp(new(big.Float).SetFloat64(threshold)) < 1 {
			break
		}

	}
}

// ShowCoeffs prints the coefficient of the approximate
// prec: the bit precision of the printed values.
func (r *Remez) ShowCoeffs(prec int) {
	fmt.Printf("{")
	for _, c := range r.Coeffs {
		fmt.Printf("%.*f, ", prec, &c)
	}
	fmt.Println("}")
}

// ShowError prints the minimum and maximum error of the approximate
// prec: the bit precision of the printed values.
func (r *Remez) ShowError(prec int) {
	fmt.Printf("MaxErr: %.*f\n", prec, r.MaxErr)
	fmt.Printf("MinErr: %.*f\n", prec, r.MinErr)
}

func (r *Remez) initialize() {

	var idx int

	switch r.Basis {
	case Monomial:

		for _, inter := range r.Intervals {

			/* #nosec G601 -- Implicit memory aliasing in for loop acknowledged */
			A := &inter.A
			/* #nosec G601 -- Implicit memory aliasing in for loop acknowledged */
			B := &inter.B

			nodes := inter.Nodes

			x := new(big.Float)

			for j := 0; j < nodes; j++ {

				x.Sub(B, A)
				x.Mul(x, NewFloat(float64(j+1)/float64(nodes+1), r.Prec))
				x.Add(x, A)

				r.Nodes[idx+j].x.Set(x)
				r.Nodes[idx+j].y.Set(r.Function(x))
			}

			idx += nodes
		}

	case Chebyshev:

		for _, inter := range r.Intervals {

			nodes := chebyshevNodes(inter.Nodes, inter)

			for j := range nodes {
				r.Nodes[idx+j].x.Set(&nodes[j])
				r.Nodes[idx+j].y.Set(r.Function(&nodes[j]))
			}

			idx += len(nodes)
		}
	}
}

func (r *Remez) getCoefficients() {

	// Constructs the linear system
	// | 1 x0 x0^2 x0^3 ...  1 | f(x0)
	// | 1 x1 x1^2 x1^3 ... -1 | f(x1)
	// | 1 x2 x2^2 x2^3 ...  1 | f(x2)
	// | 1 x3 x3^2 x3^3 ... -1 | f(x3)
	// |          .            |   .
	// |          .            |   .
	// |          .            |   .

	switch r.Basis {
	case Monomial:
		for i := 0; i < r.Degree+2; i++ {
			r.Matrix[i][0].SetPrec(r.Prec).SetInt64(1)
			for j := 1; j < r.Degree+1; j++ {
				r.Matrix[i][j].Mul(&r.Nodes[i].x, &r.Matrix[i][j-1])
			}
		}
	case Chebyshev:
		for i := 0; i < r.Degree+2; i++ {
			chebyshevBasisInPlace(r.Degree+1, &r.Nodes[i].x, Interval{A: r.Intervals[0].A, B: r.Intervals[len(r.Intervals)-1].B}, r.Matrix[i])
		}
	}

	for i := 0; i < r.Degree+2; i++ {
		if i&1 == 0 {
			r.Matrix[i][r.Degree+1].SetPrec(r.Prec).SetInt64(-1)
		} else {
			r.Matrix[i][r.Degree+1].SetPrec(r.Prec).SetInt64(1)
		}
	}

	for i := 0; i < r.Degree+2; i++ {
		r.Vector[i].Set(&r.Nodes[i].y)
	}

	// Solves the linear system
	if err := solveLinearSystemInPlace(r.Matrix, r.Vector); err != nil {
		panic(fmt.Errorf("solveLinearSystemInPlace: %w", err))
	}

	// Updates the new [x0, x1, ..., xi]
	for i := 0; i < r.Degree+1; i++ {
		r.Coeffs[i].Set(&r.Vector[i])
		//fmt.Printf("%20.15f, ", &r.Coeffs[i])
	}
	//fmt.Println()
}

func (r *Remez) findextrema() {

	r.nbExtrema = 0

	// e = p(x) - f(x) over [a, b]
	fErr := func(x *big.Float) (y *big.Float) {
		if y = r.Function(x); y == nil {
			fmt.Println(x)
		}
		return y.Sub(r.eval(x), y)
	}

	idx := 0
	for j := 0; j < len(r.Intervals); j++ {

		interval := r.Intervals[j]

		nbLocalExtrema := 0

		var A, B *big.Float
		for k := 0; k < interval.Nodes+1; k++ {

			if interval.Nodes == 0 {
				A = &interval.A
				B = &interval.B
			} else if k == 0 {
				A = &interval.A
				B = &r.Nodes[idx+k].x
			} else if k == interval.Nodes {
				A = &r.Nodes[idx+k-1].x
				B = &interval.B
			} else {
				A = &r.Nodes[idx+k-1].x
				B = &r.Nodes[idx+k].x
			}

			if A.Cmp(B) == 0 {
				continue
			}

			AIsInterval := A.Cmp(&interval.A) == 0
			BIsInterval := B.Cmp(&interval.B) == 0

			//if true || r.Debug{
			//	fmt.Printf("%20.17f %20.17f %v %v\n", A, B, AIsInterval, BIsInterval)
			//}

			points := r.findExtrema(fErr, A, B, AIsInterval, BIsInterval)

			//for i := range points{
			//	fmt.Printf("%3d %20.17f %20.17f\n", j, &points[i].x, &points[i].y)
			//}

			for i := range points {
				if r.nbExtrema == 0 || points[i].x.Cmp(&r.extrema[r.nbExtrema-1].x) != 0 {
					r.extrema[r.nbExtrema].x.Set(&points[i].x)
					r.extrema[r.nbExtrema].y.Set(&points[i].y)
					r.extrema[r.nbExtrema].sign = points[i].sign
					r.nbExtrema++
					nbLocalExtrema++
				}
			}

			if BIsInterval {
				break
			}
		}

		idx += interval.Nodes
	}

	/*
		for i := range r.nbExtrema{
			fmt.Printf("%3d (%26.17f %26.17f %2d)\n", i,
					&r.extrema[i].x, &r.extrema[i].y, r.extrema[i].sign)
		}
	*/

	if r.Debug {

		nbExtrema := 0
		extrema := []point{}

		for j := 0; j < len(r.Intervals); j++ {

			//fmt.Println(&r.Intervals[j].A, &r.Intervals[j].B)

			x0 := new(big.Float).SetPrec(r.Prec).Set(&r.Intervals[j].A)
			x1 := new(big.Float).SetPrec(r.Prec)

			a := new(big.Float).SetPrec(r.Prec)
			b := fErr(x0)

			step := new(big.Float).Sub(&r.Intervals[j].B, &r.Intervals[j].A)

			closestPow2, _ := step.Float64()
			closestPow2 = math.Round(math.Log2(math.Abs(closestPow2)))

			// Divides the interval into chuncks of 1/2^{20}
			k := 20 + int(closestPow2)

			step.Quo(step, NewFloat(math.Exp2(float64(k)), r.Prec))

			var sign, s int

			for i := 0; i < 1<<k; i++ {

				x1.Add(x0, step)

				a.Set(b)
				b.Set(fErr(x1))

				if b.Cmp(a) < 0 {
					s = -1
				} else {
					s = 1
				}

				if i == 0 || s != sign {
					sign = s
					extrema = append(extrema, point{})
					extrema[nbExtrema].x.SetPrec(r.Prec).Set(x0)
					extrema[nbExtrema].y.SetPrec(r.Prec).Set(a)
					extrema[nbExtrema].sign = sign
					nbExtrema++
				}

				x0.Set(x1)
			}
			extrema = append(extrema, point{})
			extrema[nbExtrema].x.SetPrec(r.Prec).Set(&r.Intervals[j].B)
			extrema[nbExtrema].y = *fErr(&extrema[nbExtrema].x)
			extrema[nbExtrema].sign = -extrema[nbExtrema-1].sign
			nbExtrema++
		}

		for i := range min(r.nbExtrema, nbExtrema) {
			fmt.Printf("%3d (%26.17f %26.17f %2d) (%26.17f %26.17f %2d)\n", i,
				&extrema[i].x, &extrema[i].y, extrema[i].sign,
				&r.extrema[i].x, &r.extrema[i].y, r.extrema[i].sign)
		}

		if r.nbExtrema > nbExtrema {
			for i := nbExtrema; i < r.nbExtrema; i++ {
				fmt.Printf("%3d (%26.17f %26.17f %2d) (%26.17f %26.17f %2d)\n", i,
					0.0, 0.0, 0,
					&r.extrema[i].x, &r.extrema[i].y, r.extrema[i].sign)
			}
		}

		if nbExtrema > r.nbExtrema {
			for i := r.nbExtrema; i < nbExtrema; i++ {
				fmt.Printf("%3d (%26.17f %26.17f %2d) (%26.17f %26.17f %2d)\n", i,
					&extrema[i].x, &extrema[i].y, extrema[i].sign,
					0.0, 0.0, 0)
			}
		}
	}

	// show error message
	if r.nbExtrema < r.Degree+2 {
		panic(fmt.Errorf("number of extrem points=%d is smaller than deg + 2=%d, some points have been missed, consider reducing the size of the initial scan step or the approximation degree", r.nbExtrema, r.Degree+2))
	}
}

// findExtrema finds local nbExtrema/minima of a function.
// It starts by scanning the interval with a pre-defined window size, until it finds that the function is concave or convex
// in this window. Then it uses a binary search to find the local maximum/minimum in this window. The process is repeated
// until the entire interval has been scanned.
// This is an optimized Go re-implementation of the method find_extreme that can be found at
// https://github.com/snu-ccl/FHE-MP-CNN/blob/main-3.6.6/cnn_ckks/common/MinicompFunc.cpp
func (r *Remez) findExtrema(fErr func(*big.Float) (y *big.Float), A, B *big.Float, AIsInterval, BIsInterval bool) []point {

	/*
		var verbose bool
		if A.Cmp(NewFloat(-1.0013, r.Prec)) >= 0 && B.Cmp(NewFloat(-0.995, r.Prec)) <= 0{
			verbose = true
		}
	*/

	localExtrema := r.localExtrema
	prec := r.Prec

	scan := new(big.Float).Sub(B, A)
	scan.Quo(scan, NewFloat(1024, prec))

	nbExtrema := 0

	tmp := new(big.Float)

	two := NewFloat(2, prec)
	for scan.Cmp(tmp.Sub(B, A)) != -1 {
		scan.Quo(scan, two)
	}

	AM := fErr(A)

	var AR, BL, BM *big.Float
	if A.Cmp(B) != 0 {
		AR = fErr(tmp.Add(A, scan))
		BL, BM = fErr(tmp.Sub(B, scan)), fErr(B)
	} else {
		localExtrema[nbExtrema].x.Set(A)
		localExtrema[nbExtrema].y.Set(AM)
		nbExtrema++
		return localExtrema[:nbExtrema]
	}

	signSlopeLeft := AR.Cmp(AM)
	signSlopeRight := BM.Cmp(BL)

	if signSlopeLeft == 0 || signSlopeRight == 0 {
		panic("slope 0 of error function: consider increasing the precision")
	}

	// Adds nodes, to avoid case where an extrema is missed because
	// it is exactly at a node. If this is not an extremum, it will
	// be ignored afterward
	localExtrema[nbExtrema].x.Set(A)
	localExtrema[nbExtrema].y.Set(AM)
	localExtrema[nbExtrema].sign = AM.Cmp(new(big.Float))
	nbExtrema++

	// Positive and negative slope (concave) -> one extremum
	if signSlopeLeft == 1 && signSlopeRight == -1 {
		findLocalExtremum(fErr, A, B, prec, 1, &localExtrema[nbExtrema])
		nbExtrema++
		// Negative and positive slope (convex) -> one extremum
	} else if signSlopeLeft == -1 && signSlopeRight == 1 {
		findLocalExtremum(fErr, A, B, prec, -1, &localExtrema[nbExtrema])
		nbExtrema++
		// Monotonic local function -> (zero or two extrema) or (one extrema = node)
	} else {

		var s int

		scan := NewFloat(1/32.0, prec)

		scanLeft := new(big.Float).SetPrec(r.Prec)
		scanRight := new(big.Float).SetPrec(r.Prec)
		fErrLeft := new(big.Float).SetPrec(r.Prec)
		fErrRight := new(big.Float).SetPrec(r.Prec)

		optScan := NewFloat(scan, prec)

		s = 15
		optScan.Quo(scan, NewFloat(1e15, prec))

		scanLeft.Set(A)
		scanRight.Add(A, optScan)
		fErrLeft.Set(fErr(scanLeft))
		fErrRight.Set(fErr(scanRight))

		if signSlopeRight = fErrRight.Cmp(fErrLeft); signSlopeRight == 0 {
			panic("slope 0 occurred: consider increasing the precision")
		}

		expectedPoints := 0

		for {

			for i := 0; i < s; i++ {

				pow10 := NewFloat(math.Pow(10, float64(i)), prec)

				// start + 10*scan/pow(10,i)
				a := new(big.Float).Mul(scan, NewFloat(10, prec))
				a.Quo(a, pow10)
				a.Add(A, a)

				// end - 10*scan/pow(10,i)
				b := new(big.Float).Mul(scan, NewFloat(10, prec))
				b.Quo(b, pow10)
				b.Sub(B, b)

				// a < scanRight && scanRight < b
				if a.Cmp(scanRight) == -1 && scanRight.Cmp(b) == -1 {
					optScan.Quo(scan, pow10)
					break
				}

				if i == s-1 {
					optScan.Quo(scan, pow10)
					optScan.Quo(optScan, NewFloat(10, prec))
				}
			}

			// Breaks when the scan window gets out of the interval
			if expectedPoints == 2 || new(big.Float).Add(scanRight, optScan).Cmp(B) >= 0 {
				break
			}

			signSlopeLeft = signSlopeRight
			scanLeft.Set(scanRight)
			scanRight.Add(scanLeft, optScan)

			fErrLeft.Set(fErrRight)
			fErrRight.Set(fErr(scanRight))

			if signSlopeRight = fErrRight.Cmp(fErrLeft); signSlopeRight == 0 {
				panic("slope 0 occurred: consider increasing the precision")
			}

			// Positive and negative slope (concave)
			if signSlopeLeft == 1 && signSlopeRight == -1 {
				findLocalExtremum(fErr, scanLeft, scanRight, prec, 1, &localExtrema[nbExtrema])
				nbExtrema++
				expectedPoints++
				// Negative and positive slope (convex)
			} else if signSlopeLeft == -1 && signSlopeRight == 1 {
				findLocalExtremum(fErr, scanLeft, scanRight, prec, -1, &localExtrema[nbExtrema])
				nbExtrema++
				expectedPoints++
			}
		}
	}

	// Adds nodes, to avoid case where an extrema is missed because
	// it is exactly at a node. If this is not an extremum, it will
	// be ignored afterward
	localExtrema[nbExtrema].x.Set(B)
	localExtrema[nbExtrema].y.Set(BM)
	localExtrema[nbExtrema].sign = BM.Cmp(new(big.Float))
	nbExtrema++

	return localExtrema[:nbExtrema]
}

// findLocalExtremum finds the local extremum of a function that is concave or convex in a given window.
func findLocalExtremum(fErr func(x *big.Float) (y *big.Float), start, end *big.Float, prec uint, slopSign int, p *point) {

	a := new(big.Float).SetPrec(prec).Set(start)
	c := new(big.Float).SetPrec(prec).Set(end)
	two := NewFloat(2, prec)
	b := new(big.Float).Sub(c, a)
	b.Quo(b, two)
	b.Add(b, a)

	scan := new(big.Float).Sub(end, start)
	scan.Quo(scan, NewFloat(1024, prec))

	//left := new(big.Float)
	mid := new(big.Float)
	//end := new(big.Float)
	tmp0 := new(big.Float)
	tmp1 := new(big.Float)

	for i := 0; i < int(64); i++ {

		//left.Sub(fErr(tmp0.Sub(a, scan), tmp1.Add(a, scan)))
		mid.Sub(fErr(tmp1.Add(b, scan)), fErr(tmp0.Sub(b, scan)))
		//end.Sub(fErr(tmp0.Sub(c, scan), tmp1.Add(c, scan)))

		//x0 := left.Cmp(new(bib.Float))
		x1 := mid.Cmp(new(big.Float))
		//x2 := end.Cmp(new(big.Float))

		if x1 == slopSign {
			a.Set(b)
		} else {
			c.Set(b)
		}

		b.Sub(c, a)
		b.Quo(b, two)
		b.Add(b, a)
		scan.Quo(scan, two)
	}

	p.x.Set(b)
	p.y.Set(fErr(&p.x))
	p.sign = slopSign
}

func (r *Remez) eval(x *big.Float) (y *big.Float) {
	switch r.Basis {
	case Monomial:
		return MonomialEval(x, r.Coeffs)
	case Chebyshev:
		return ChebyshevEval(x, r.Coeffs, Interval{A: r.Intervals[0].A, B: r.Intervals[len(r.Intervals)-1].B, Nodes: r.Degree + 1})
	default:
		panic("invalid Basis")
	}
}

// solves for y the system matrix * y = vector using Gaussian elimination.
func solveLinearSystemInPlace(matrix [][]big.Float, vector []big.Float) (err error) {

	vMax := new(big.Float).SetPrec(matrix[0][0].Prec())

	n, m := len(matrix), len(matrix[0])

	var tmp = new(big.Float)
	for i := 0; i < n; i++ {

		iMax := i
		vMax.Abs(&matrix[iMax][i])

		for j := i + 1; j < n; j++ {
			if tmp.Abs(&matrix[j][i]).Cmp(vMax) == 1 {
				vMax.Abs(&matrix[j][i])
				iMax = j
			}
		}

		if iMax != i {
			swap(matrix, i, iMax)
			vector[i], vector[iMax] = vector[iMax], vector[i]
		}

		/*
			for j := range matrix{
				for k := range matrix[j]{
					fmt.Printf("%8.4f ", &matrix[j][k])
				}
				fmt.Printf("%8.4f", &vector[j])
				fmt.Println()
			}
			fmt.Println()
			fmt.Println()
		*/

		a := &matrix[i][i]

		if a.Cmp(new(big.Float)) == 0 {
			return fmt.Errorf("singular system")
		}

		vector[i].Quo(&vector[i], a)

		for j := m - 1; j >= i; j-- {
			b := &matrix[i][j]
			b.Quo(b, a)
		}

		for j := i + 1; j < m; j++ {
			c := &matrix[j][i]
			vector[j].Sub(&vector[j], tmp.Mul(&vector[i], c))
			for k := m - 1; k >= i; k-- {
				matrix[j][k].Sub(&matrix[j][k], tmp.Mul(&matrix[i][k], c))
			}
		}
	}

	for i := m - 1; i > 0; i-- {
		c := &vector[i]
		for j := i - 1; j >= 0; j-- {
			vector[j].Sub(&vector[j], tmp.Mul(&matrix[j][i], c))
		}
	}

	return
}

func swap(matrix [][]big.Float, i, j int) {
	for k := range matrix {
		matrix[i][k], matrix[j][k] = matrix[j][k], matrix[i][k]
	}
}

// ChooseNewNodes implements Algorithm 3 of High-Precision Bootstrapping
// of RNS-CKKS Homomorphic Encryption Using Optimal Minimax Polynomial
// Approximation and Inverse Sine Function (https://eprint.iacr.org/2020/552).
// This is an optimized Go reimplementation of Remez::choosemaxs at
// https://github.com/snu-ccl/FHE-MP-CNN/blob/main-3.6.6/cnn_ckks/common/Remez.cpp
func (r *Remez) chooseNewNodes() {

	// Allocates the list of new nodes
	newNodes := []point{}

	// Retrieve the list of extrem points
	extrema := r.extrema

	// Resets max and min error
	r.MaxErr.SetFloat64(0)
	r.MinErr.SetFloat64(1e15)

	//=========================
	//========= PART 1 ========
	//=========================

	// Line 1 to 8 of Algorithm 3

	// The first part of the algorithm is to remove
	// consecutive extreme points with the same slope sign,
	// which will ensure that new linear system has a
	// solution by the Haar condition.

	// Stores consecutive extreme points with the same slope sign
	// It is unlikely that more that two consecutive extreme points
	// will have the same slope sign.
	idxAdjSameSign := []int{}

	// To find the maximum value between extreme points that have the
	// same slope sign.
	maxpoint := NewFloat(0, r.Prec)

	// Tracks the total number of extreme points iterated on
	ind := 0
	for ind < r.nbExtrema {

		// If idxAdjSameSign is empty then adds the next point
		if len(idxAdjSameSign) == 0 {
			idxAdjSameSign = append(idxAdjSameSign, ind)
			ind++
		} else {

			// If the sign of two consecutive extream is not alternating
			// then adds the extremum index to the temporary array
			if extrema[ind-1].sign*extrema[ind].sign == 1 {
				mid := new(big.Float).Add(&extrema[ind-1].x, &extrema[ind].x)
				mid.Quo(mid, NewFloat(2, r.Prec))
				idxAdjSameSign = append(idxAdjSameSign, ind)
				ind++
			} else {

				maxpoint.SetFloat64(0)

				// If the next extrema has alternating sign, then iterates over all the index in the temporary array
				// with extrema whose sign the same and looks for the one with the largest value
				maxIdx := 0
				for i := range idxAdjSameSign {
					if maxpoint.Cmp(new(big.Float).Abs(&extrema[idxAdjSameSign[i]].y)) == -1 {
						maxpoint.Abs(&extrema[idxAdjSameSign[i]].y)
						maxIdx = idxAdjSameSign[i]
					}
				}

				// Adds to the new nodes the extremum whose absolute value is the largest
				// between all consecutive extreme points with the same slope sign
				newNodes = append(newNodes, extrema[maxIdx])
				idxAdjSameSign = []int{}
			}
		}
	}

	// The above loop might terminate without flushing the array of extreme points
	// with the same slope sign, the second part of the loop is called one last time.
	maxpoint.SetInt64(0)
	maxIdx := 0
	for i := range idxAdjSameSign {
		if maxpoint.Cmp(new(big.Float).Abs(&extrema[idxAdjSameSign[i]].y)) == -1 {
			maxpoint.Abs(&extrema[idxAdjSameSign[i]].y)
			maxIdx = idxAdjSameSign[i]
		}
	}

	newNodes = append(newNodes, extrema[maxIdx])

	if len(newNodes) < r.Degree+2 {
		panic(fmt.Errorf("number of alternating extreme points=%d is less than deg+2=%d, some points have been missed, consider reducing the size of the initial scan step or the approximation degree", len(newNodes), r.Degree+2))
	}

	//=========================
	//========= PART 2 ========
	//=========================

	// Lines 11 to 24 of Algorithm 3

	// Choosing the new nodes if the set of alternating extreme points
	// is larger than degree+2.

	minPair := NewFloat(0, r.Prec)
	tmp := NewFloat(0, r.Prec)

	// Loops run as long as the number of extreme points is not equal to deg+2 (the dimension of the linear system)
	var minIdx int
	for len(newNodes) > r.Degree+2 {

		minPair.SetFloat64(1e300)

		// If the number of remaining extreme points is one more than the number needed
		// then we can remove only one point
		if len(newNodes) == r.Degree+3 {

			// Removes the largest one between the first and the last
			if new(big.Float).Abs(&newNodes[0].y).Cmp(new(big.Float).Abs(&newNodes[len(newNodes)-1].y)) == 1 {
				newNodes = newNodes[:len(newNodes)-1]
			} else {
				newNodes = newNodes[1:]
			}

			// If the number of remaining extreme points is two more than the number needed
			// then we can remove two points.
		} else if len(newNodes) == r.Degree+4 {

			// Finds the minimum index of the sum of two adjacent points
			for i := range newNodes {
				tmp.Add(new(big.Float).Abs(&newNodes[i].y), new(big.Float).Abs(&newNodes[(i+1)%len(newNodes)].y))
				if minPair.Cmp(tmp) == 1 {
					minPair.Set(tmp)
					minIdx = i
				}
			}

			// If the index is the last, then remove the first and last points
			if minIdx == len(newNodes)-1 {
				newNodes = newNodes[1:]
				// Else remove the two consecutive points
			} else {
				newNodes = append(newNodes[:minIdx], newNodes[minIdx+2:]...)
			}

			// If the number of remaining extreme points is more four over the number needed
			// then remove up to two points, prioritizing the first and last points.
		} else {

			// Finds the minimum index of the sum of two adjacent points
			for i := range newNodes[:len(newNodes)-1] {

				tmp.Add(new(big.Float).Abs(&newNodes[i].y), new(big.Float).Abs(&newNodes[i+1].y))

				if minPair.Cmp(tmp) == 1 {
					minPair.Set(tmp)
					minIdx = i
				}
			}

			// If the first element is included in the smallest sum, then removes it
			if minIdx == 0 {
				newNodes = newNodes[1:]
				// If the last element is included in the smallest sum, then removes it
			} else if minIdx == len(newNodes)-2 {
				newNodes = newNodes[:len(newNodes)-1]
				// Else removes the two consecutive points adding to the smallest sum
			} else {
				newNodes = append(newNodes[:minIdx], newNodes[minIdx+2:]...)
			}
		}
	}

	// Assigns the new points to the nodes and computes the min and max error
	for i := 0; i < r.Degree+2; i++ {

		// Deep copy
		r.Nodes[i].x.Copy(&newNodes[i].x)
		r.Nodes[i].y.Copy(r.Function(&r.Nodes[i].x)) // we must evaluate, because Y was the error Function)
		r.Nodes[i].sign = newNodes[i].sign           // should have alternating sign

		if r.MaxErr.Cmp(new(big.Float).Abs(&newNodes[i].y)) == -1 {
			r.MaxErr.Abs(&newNodes[i].y)
		}

		if r.MinErr.Cmp(new(big.Float).Abs(&newNodes[i].y)) == 1 {
			r.MinErr.Abs(&newNodes[i].y)
		}
	}

	// Updates the interval nodes count if #Intervals > 1 as
	// chosing the new nodes might end up moving nodes between
	// intervals
	if len(r.Intervals) > 1 {
		idx := 0
		for i := range r.Intervals {

			interval := &r.Intervals[i]

			A := &interval.A
			B := &interval.B

			newNodesCount := 0
			j := 0
			for {

				if idx+j == len(r.Nodes) {
					break
				}

				node := &r.Nodes[idx+j].x
				if node.Cmp(A) >= 0 && node.Cmp(B) <= 0 {
					newNodesCount++
				} else {
					break
				}
				j++
			}

			idx += newNodesCount
			interval.Nodes = newNodesCount
		}
	}
}
