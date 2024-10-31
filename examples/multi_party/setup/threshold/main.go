package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/Pro7ech/lattigo/mhe"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/sampling"
)

// This example showcases the use of the mhe package to generate an evaluation key in a multiparty setting.
// It simulate multiple parties and their interactions within a single Go program using multiple goroutines.
// The parties use the t-out-of-N-threshold RLWE encryption scheme as described in "An Efficient Threshold
// Access-Structure for RLWE-Based Multiparty Homomorphic Encryption" (2022) by Mouchet, C., Bertrand, E. and
// Hubaux, J. P. (https://eprint.iacr.org/2022/780). Moreover, this scenario showcases the use of a cloud
// server that assists the parties in the execution of the protocol, by collecting and aggregating their public
// shares.
//
// The scenario can be parameterized by the program arguments. Notably:
// 	- the total number of parties,
//  - the corruption threshold, as the number of guaranteed honest parties,
//  - the number of parties being online to generate the evaluation key,
//  - the parameters of the RLWE cryptosystem for which the evaluation-key is generated
//  - the size of the evaluation-key to be generated, as the number of GaloisKeys.
//
// If the number of online parties is greater than the threshold, the scenario simulates the distribution of the
// workload among the set of online parties.

// party represents a party in the scenario.
type party struct {
	mhe.GaloisKeyProtocol
	mhe.Thresholdizer
	mhe.Combiner

	i        int
	sk       *rlwe.SecretKey
	tsk      *mhe.ShamirSecretShare
	ssp      *mhe.ShamirPolynomial
	shamirPk mhe.ShamirPublicPoint

	genTaskQueue chan genTask
}

// cloud represents the cloud server assisting the parties.
type cloud struct {
	mhe.GaloisKeyProtocol

	aggTaskQueue chan genTaskResult
	finDone      chan rlwe.GaloisKey
}

var seeds map[uint64][32]byte

// Run simulate the behavior of a party during the key generation protocol. The parties process
// a queue of share-generation tasks which is attributed to them by a protocol orchestrator
// (simulated in this example).
func (p *party) Run(wg *sync.WaitGroup, params rlwe.Parameters, N int, P []*party, C *cloud) {

	var nShares, nTasks int
	var start time.Time
	var cpuTime time.Duration
	var byteSent int
	for task := range p.genTaskQueue {

		start = time.Now()
		var sk *rlwe.SecretKey
		t := len(task.group)
		if t == N {
			sk = p.sk
		} else {
			activePk := make([]mhe.ShamirPublicPoint, 0)
			for _, pi := range task.group {
				activePk = append(activePk, pi.shamirPk)
			}
			sk = rlwe.NewSecretKey(params)
			if err := p.Combiner.Finalize(activePk, p.shamirPk, p.tsk, sk); err != nil {
				panic(err)
			}
		}

		for _, galEl := range task.galoisEls {
			rtgShare := p.GaloisKeyProtocol.Allocate()

			if err := p.GaloisKeyProtocol.Gen(sk, galEl, seeds[galEl], rtgShare); err != nil {
				panic(err)
			}

			C.aggTaskQueue <- genTaskResult{galEl: galEl, rtgShare: rtgShare}
			nShares++
			byteSent += rtgShare.BinarySize()
		}
		nTasks++
		cpuTime += time.Since(start)
	}
	wg.Done()
	fmt.Printf("\tParty %d finished generating %d shares of %d tasks in %s, sent %s\n", p.i, nShares, nTasks, cpuTime, formatByteSize(byteSent))
}

func (p *party) String() string {
	return fmt.Sprintf("Party#%d", p.i)
}

// Run simulate the behavior of the cloud during the key generation protocol.
// The cloud process aggregation requests and generates the GaloisKeys keys when
// all the parties' shares have been aggregated.
func (c *cloud) Run(galEls []uint64, params rlwe.Parameters, t int) {

	shares := make(map[uint64]*struct {
		share  *mhe.GaloisKeyShare
		needed int
	}, len(galEls))
	for _, galEl := range galEls {
		shares[galEl] = &struct {
			share  *mhe.GaloisKeyShare
			needed int
		}{c.GaloisKeyProtocol.Allocate(), t}
		shares[galEl].share.GaloisElement = galEl
	}

	var i int
	var cpuTime time.Duration
	var byteRecv int
	for task := range c.aggTaskQueue {
		start := time.Now()
		acc := shares[task.galEl]
		acc.share.Seed = task.rtgShare.Seed
		if err := c.GaloisKeyProtocol.Aggregate(acc.share, task.rtgShare, acc.share); err != nil {
			panic(err)
		}
		acc.needed--
		if acc.needed == 0 {
			gk := rlwe.NewGaloisKey(params)
			if err := c.Finalize(acc.share, gk); err != nil {
				panic(err)
			}
			c.finDone <- *gk
		}
		i++
		cpuTime += time.Since(start)
		byteRecv += acc.share.BinarySize()
	}
	close(c.finDone)
	fmt.Printf("\tCloud finished aggregating %d shares in %s, received %s\n", i, cpuTime, formatByteSize(byteRecv))

}

var flagN = flag.Int("N", 3, "the number of parties")
var flagT = flag.Int("t", 2, "the threshold")
var flagO = flag.Int("o", 0, "the number of online parties")
var flagK = flag.Int("k", 10, "number of rotation keys to generate")
var flagJSONParams = flag.String("json", "", "the JSON encoded parameter set to use")

func main() {

	flag.Parse()

	paramsLit := rlwe.ExampleParametersLogN14LogQP438

	if *flagJSONParams != "" {
		if err := json.Unmarshal([]byte(*flagJSONParams), &paramsLit); err != nil {
			panic(err)
		}
	}

	params, err := rlwe.NewParametersFromLiteral(paramsLit)
	if err != nil {
		panic(err)
	}

	if *flagN < 2 {
		panic("-N should be >= 2")
	}
	N := *flagN

	if *flagT > N {
		panic("-t should be <= N")
	}
	t := *flagT

	var o int
	if *flagO <= 0 {
		o = N
	} else {
		o = *flagO
	}

	if *flagK < 1 {
		panic("-k should be >= 1")
	}
	k := *flagK

	galEls := make([]uint64, k)
	for i := range galEls {
		galEls[i] = params.GaloisElement(i + 1)
	}

	fmt.Printf("Starting for N=%d, t=%d\n", N, t)
	fmt.Printf("LogN=%d, LogQP=%f, L=%d, k=%d\n", params.LogN(), params.LogQP(), params.QPCount(), k)

	kg := rlwe.NewKeyGenerator(params)

	source := sampling.NewSource(sampling.NewSeed())

	wg := new(sync.WaitGroup)
	C := &cloud{
		GaloisKeyProtocol: *mhe.NewGaloisKeyProtocol(params),
		aggTaskQueue:      make(chan genTaskResult, len(galEls)*N),
		finDone:           make(chan rlwe.GaloisKey, len(galEls)),
	}

	// Initialize the parties' state
	P := make([]*party, N)
	skIdeal := rlwe.NewSecretKey(params)
	shamirPks := make([]mhe.ShamirPublicPoint, 0)

	for i := range P {
		pi := new(party)
		pi.GaloisKeyProtocol = *mhe.NewGaloisKeyProtocol(params)
		pi.i = i
		pi.sk = kg.GenSecretKeyNew()
		pi.genTaskQueue = make(chan genTask, k)

		if t != N {
			pi.Thresholdizer = *mhe.NewThresholdizer(params)
			pi.tsk = pi.Thresholdizer.Allocate()
			var err error
			pi.ssp, err = pi.Thresholdizer.Gen(t, pi.sk)
			if err != nil {
				panic(err)
			}
			pi.shamirPk = mhe.ShamirPublicPoint(i + 1)
		}

		P[i] = pi

		// computes the ideal sk for the sake of the example
		params.RingQ().Add(skIdeal.Q, pi.sk.Q, skIdeal.Q)
		params.RingP().Add(skIdeal.P, pi.sk.P, skIdeal.P)

		shamirPks = append(shamirPks, pi.shamirPk)
	}

	// if t < N, use the t-out-of-N scheme and performs the share-resharing procedure.
	if t != N {
		for _, pi := range P {
			pi.Combiner = *mhe.NewCombiner(params, pi.shamirPk, shamirPks, t)
		}

		fmt.Println("Performing threshold setup")
		shares := make(map[*party]map[*party]*mhe.ShamirSecretShare, len(P))
		for _, pi := range P {

			shares[pi] = make(map[*party]*mhe.ShamirSecretShare)

			for _, pj := range P {
				share := pi.Thresholdizer.Allocate()
				if err := pi.Thresholdizer.Finalize(pj.shamirPk, pi.ssp, share); err != nil {
					panic(err)
				}
				shares[pi][pj] = share
			}
		}

		for _, pi := range P {
			for _, pj := range P {
				share := shares[pj][pi]
				/* #nosec G601 -- Implicit memory aliasing in for loop acknowledged */
				if err := pi.Thresholdizer.Aggregate(pi.tsk, share, pi.tsk); err != nil {
					panic(err)
				}
			}
		}
	}

	P = P[:o] // reduce the set of parties to the online ones.

	groups := getSubGroups(P, t, k)
	fmt.Printf("Generating %d rotation keys with %d parties in %d groups\n", len(galEls), len(P), len(groups))

	// Sample the common random polynomials from the source.
	// For the scenario, we consider it is provided as-is to the parties.
	seeds = make(map[uint64][32]byte)
	for _, galEl := range galEls {
		seeds[galEl] = source.NewSeed()
	}

	// Start the cloud and the parties
	go C.Run(galEls, params, t)
	for _, pi := range P {
		go pi.Run(wg, params, N, P, C)
	}
	wg.Add(len(P))
	start := time.Now()

	// distribute the key generation sub-tasks among the online parties. This
	// simulates a protocol orchestrator affecting each party with the tasks
	// of generating specific GaloisKeys.
	tasks := getTasks(galEls, groups)
	for _, task := range tasks {
		for _, p := range task.group {
			p.genTaskQueue <- task
		}
	}
	for _, pi := range P {
		close(pi.genTaskQueue)
	}
	wg.Wait()
	close(C.aggTaskQueue)

	// collects the results in an EvaluationKeySet
	gks := []*rlwe.GaloisKey{}
	for task := range C.finDone {
		gk := task
		gks = append(gks, &gk)
	}
	evk := rlwe.NewMemEvaluationKeySet(nil, gks...)

	fmt.Printf("Generation of %d keys completed in %s\n", len(galEls), time.Since(start))

	fmt.Printf("Checking the keys... ")

	noise := mhe.NoiseGaloisKey(params, t)

	for _, galEl := range galEls {

		if gk, err := evk.GetGaloisKey(galEl); err != nil {
			fmt.Printf("missing GaloisKey for galEl=%d\n", galEl)
			os.Exit(1)
		} else {
			if noise < rlwe.NoiseGaloisKey(gk, skIdeal, params) {
				fmt.Printf("invalid GaloisKey for galEl=%d\n", galEl)
				os.Exit(1)
			}
		}
	}
	fmt.Println("done")
}

type genTask struct {
	group     []*party
	galoisEls []uint64
}

type genTaskResult struct {
	galEl    uint64
	rtgShare *mhe.GaloisKeyShare
}

func getTasks(galEls []uint64, groups [][]*party) []genTask {
	tasks := make([]genTask, len(groups))
	for i := range tasks {
		tasks[i].group = groups[i]
	}
	for i, galEl := range galEls {
		tasks[i%len(groups)].galoisEls = append(tasks[i%len(groups)].galoisEls, galEl)
	}
	return tasks
}

func getSubGroups(P []*party, t, k int) [][]*party {
	if t == len(P) {
		return [][]*party{P}
	}
	if t > len(P) {
		panic("t > len(P)")
	}

	groups := [][]*party{}
	for i := 0; i < k; i++ {
		start := (i * t) % len(P)
		end := ((i + 1) * t) % len(P)
		switch {
		case i > 0 && start == 0 && end == t:
			return groups
		case start > end:
			group := make([]*party, t)
			copy(group, P[0:end])
			copy(group[end:], P[start:])
			groups = append(groups, group)
		default:
			groups = append(groups, P[start:end])
		}
	}

	return groups
}

func formatByteSize(b int) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB",
		float64(b)/float64(div), "kMGTPE"[exp])
}
