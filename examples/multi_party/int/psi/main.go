package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/Pro7ech/lattigo/he/heint"
	"github.com/Pro7ech/lattigo/mhe"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/sampling"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func runTimed(f func()) time.Duration {
	start := time.Now()
	f()
	return time.Since(start)
}

func runTimedParty(f func(), N int) time.Duration {
	start := time.Now()
	f()
	return time.Duration(time.Since(start).Nanoseconds() / int64(N))
}

type party struct {
	sk *rlwe.SecretKey

	ckgShare *mhe.PublicKeyShare
	rkgShare *mhe.RelinearizationKeyShare
	ksShare  *mhe.KeySwitchingShare

	input []uint64
}
type multTask struct {
	wg              *sync.WaitGroup
	op1             *rlwe.Ciphertext
	opOut           *rlwe.Ciphertext
	res             *rlwe.Ciphertext
	elapsedmultTask time.Duration
}

var elapsedEncryptParty time.Duration
var elapsedEncryptCloud time.Duration
var elapsedCKGCloud time.Duration
var elapsedCKGParty time.Duration
var elapsedRKGCloud time.Duration
var elapsedRKGParty time.Duration
var elapsedPCKSCloud time.Duration
var elapsedPCKSParty time.Duration
var elapsedEvalCloudCPU time.Duration
var elapsedEvalCloud time.Duration
var elapsedEvalParty time.Duration

func main() {
	// For more details about the PSI example see
	//     Multiparty Homomorphic Encryption: From Theory to Practice (<https://eprint.iacr.org/2020/304>)

	l := log.New(os.Stderr, "", 0)

	// $go run main.go arg1 arg2
	// arg1: number of parties
	// arg2: number of Go routines

	// Largest for n=8192: 512 parties
	N := 8 // Default number of parties
	var err error
	if len(os.Args[1:]) >= 1 {
		N, err = strconv.Atoi(os.Args[1])
		check(err)
	}

	NGoRoutine := 1 // Default number of Go routines
	if len(os.Args[1:]) >= 2 {
		NGoRoutine, err = strconv.Atoi(os.Args[2])
		check(err)
	}

	// Creating encryption parameters from a default params with logN=14, logQP=438 with a plaintext modulus T=65537
	params, err := heint.NewParametersFromLiteral(heint.ParametersLiteral{
		LogN: 14,
		LogQ: []int{56, 55, 55, 54, 54, 54},
		LogP: []int{55, 55},
		T:    0x10001,
		R:    1,
	})
	if err != nil {
		panic(err)
	}

	encoder := heint.NewEncoder(params)

	// Target private and public keys
	tsk, tpk := rlwe.NewKeyGenerator(params).GenKeyPairNew()

	// Create each party, and allocate the memory for all the shares that the protocols will need
	P := genparties(params, N)

	// Inputs & expected result
	expRes := genInputs(params, P)

	// 1) Collective public key generation
	pk := ckgphase(params, sampling.NewSeed(), P)

	// 2) Collective RelinearizationKey generation
	rlk := rkgphase(params, pk, P)

	evk := rlwe.NewMemEvaluationKeySet(rlk)

	l.Printf("\tdone (cloud: %s, party: %s)\n",
		elapsedRKGCloud, elapsedRKGParty)
	l.Printf("\tSetup done (cloud: %s, party: %s)\n",
		elapsedRKGCloud+elapsedCKGCloud, elapsedRKGParty+elapsedCKGParty)

	encInputs := encPhase(params, P, pk, encoder)

	encRes := evalPhase(params, NGoRoutine, encInputs, evk)

	encOut := pcksPhase(params, tpk, encRes, P)

	// Decrypt the result with the target secret key
	l.Println("> ResulPlaintextModulus:")
	decryptor := rlwe.NewDecryptor(params, tsk)
	ptres := heint.NewPlaintext(params, params.MaxLevel())
	elapsedDecParty := runTimed(func() {
		decryptor.Decrypt(encOut, ptres)
	})

	// Check the result
	res := make([]uint64, params.MaxSlots())
	if err := encoder.Decode(ptres, res); err != nil {
		panic(err)
	}
	l.Printf("\t%v\n", res[:16])
	for i := range expRes {
		if expRes[i] != res[i] {
			//l.Printf("\t%v\n", expRes)
			l.Println("\tincorrect")
			return
		}
	}
	l.Println("\tcorrect")
	l.Printf("> Finished (total cloud: %s, total party: %s)\n",
		elapsedCKGCloud+elapsedRKGCloud+elapsedEncryptCloud+elapsedEvalCloud+elapsedPCKSCloud,
		elapsedCKGParty+elapsedRKGParty+elapsedEncryptParty+elapsedEvalParty+elapsedPCKSParty+elapsedDecParty)

}

func encPhase(params heint.Parameters, P []*party, pk *rlwe.PublicKey, encoder *heint.Encoder) (encInputs []*rlwe.Ciphertext) {

	l := log.New(os.Stderr, "", 0)

	encInputs = make([]*rlwe.Ciphertext, len(P))
	for i := range encInputs {
		encInputs[i] = heint.NewCiphertext(params, 1, params.MaxLevel())
	}

	// Each party encrypts its input vector
	l.Println("> Encrypt Phase")
	encryptor := rlwe.NewEncryptor(params, pk)

	pt := heint.NewPlaintext(params, params.MaxLevel())
	elapsedEncryptParty = runTimedParty(func() {
		for i, pi := range P {
			if err := encoder.Encode(pi.input, pt); err != nil {
				panic(err)
			}
			if err := encryptor.Encrypt(pt, encInputs[i]); err != nil {
				panic(err)
			}
		}
	}, len(P))

	elapsedEncryptCloud = time.Duration(0)
	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedEncryptCloud, elapsedEncryptParty)

	return
}

func evalPhase(params heint.Parameters, NGoRoutine int, encInputs []*rlwe.Ciphertext, evk rlwe.EvaluationKeySet) (encRes *rlwe.Ciphertext) {

	l := log.New(os.Stderr, "", 0)

	encLvls := make([][]*rlwe.Ciphertext, 0)
	encLvls = append(encLvls, encInputs)
	for nLvl := len(encInputs) / 2; nLvl > 0; nLvl = nLvl >> 1 {
		encLvl := make([]*rlwe.Ciphertext, nLvl)
		for i := range encLvl {
			encLvl[i] = heint.NewCiphertext(params, 2, params.MaxLevel())
		}
		encLvls = append(encLvls, encLvl)
	}
	encRes = encLvls[len(encLvls)-1][0]

	evaluator := heint.NewEvaluator(params, evk)
	// Split the task among the Go routines
	tasks := make(chan *multTask)
	workers := &sync.WaitGroup{}
	workers.Add(NGoRoutine)
	//l.Println("> Spawning", NGoRoutine, "evaluator goroutine")
	for i := 1; i <= NGoRoutine; i++ {
		go func(i int) {
			evaluator := evaluator.ShallowCopy() // creates a shallow evaluator copy for this goroutine
			for task := range tasks {
				task.elapsedmultTask = runTimed(func() {
					// 1) Multiplication of two input vectors
					if err := evaluator.Mul(task.op1, task.opOut, task.res); err != nil {
						panic(err)
					}
					// 2) Relinearization
					if err := evaluator.Relinearize(task.res, task.res); err != nil {
						panic(err)
					}
				})
				task.wg.Done()
			}
			//l.Println("\t evaluator", i, "down")
			workers.Done()
		}(i)
		//l.Println("\t evaluator", i, "started")
	}

	// Start the tasks
	taskList := make([]*multTask, 0)
	l.Println("> Eval Phase")
	elapsedEvalCloud = runTimed(func() {
		for i, lvl := range encLvls[:len(encLvls)-1] {
			nextLvl := encLvls[i+1]
			l.Println("\tlevel", i, len(lvl), "->", len(nextLvl))
			wg := &sync.WaitGroup{}
			wg.Add(len(nextLvl))
			for j, nextLvlCt := range nextLvl {
				task := multTask{wg, lvl[2*j], lvl[2*j+1], nextLvlCt, 0}
				taskList = append(taskList, &task)
				tasks <- &task
			}
			wg.Wait()
		}
	})
	elapsedEvalCloudCPU = time.Duration(0)
	for _, t := range taskList {
		elapsedEvalCloudCPU += t.elapsedmultTask
	}
	elapsedEvalParty = time.Duration(0)
	l.Printf("\tdone (cloud: %s (wall: %s), party: %s)\n",
		elapsedEvalCloudCPU, elapsedEvalCloud, elapsedEvalParty)

	//l.Println("> Shutting down workers")
	close(tasks)
	workers.Wait()

	return
}

func genparties(params heint.Parameters, N int) []*party {

	// Create each party, and allocate the memory for all the shares that the protocols will need
	P := make([]*party, N)
	for i := range P {
		pi := &party{}
		pi.sk = rlwe.NewKeyGenerator(params).GenSecretKeyNew()

		P[i] = pi
	}

	return P
}

func genInputs(params heint.Parameters, P []*party) (expRes []uint64) {

	expRes = make([]uint64, params.N())
	for i := range expRes {
		expRes[i] = 1
	}

	r := sampling.NewSource(sampling.NewSeed())

	for _, pi := range P {

		pi.input = make([]uint64, params.N())
		for i := range pi.input {
			if r.Float64(0, 1) > 0.3 || i == 4 {
				pi.input[i] = 1
			}
			expRes[i] *= pi.input[i]
		}

	}

	return
}

func pcksPhase(params heint.Parameters, pk *rlwe.PublicKey, encRes *rlwe.Ciphertext, P []*party) (encOut *rlwe.Ciphertext) {

	l := log.New(os.Stderr, "", 0)

	// Collective key switching from the collective secret key to
	// the target public key

	pcks := mhe.NewKeySwitchingProtocol[rlwe.PublicKey](params)

	for _, pi := range P {
		pi.ksShare = pcks.Allocate(params.MaxLevel())
	}

	noise := float64(1 << 30)

	l.Println("> PublicKeySwitch Phase")
	elapsedPCKSParty = runTimedParty(func() {
		for _, pi := range P {
			/* #nosec G601 -- Implicit memory aliasing in for loop acknowledged */
			if err := pcks.Gen(pi.sk, pk, noise, encRes, pi.ksShare); err != nil {
				panic(fmt.Errorf("pcksPhase -> Gen: %w", err))
			}
		}
	}, len(P))

	ksCombined := pcks.Allocate(params.MaxLevel())
	encOut = encRes.Clone()
	elapsedPCKSCloud = runTimed(func() {
		for _, pi := range P {
			if err := pcks.Aggregate(ksCombined, pi.ksShare, ksCombined); err != nil {
				panic(fmt.Errorf("pcksPhase -> Aggregate: %w", err))
			}
		}

		if err := pcks.Finalize(encOut, ksCombined, encOut); err != nil {
			panic(fmt.Errorf("pcksPhase -> Finalize: %w", err))
		}
	})
	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedPCKSCloud, elapsedPCKSParty)

	return
}

func ckgphase(params heint.Parameters, seed [32]byte, P []*party) (pk *rlwe.PublicKey) {

	l := log.New(os.Stderr, "", 0)

	l.Println("> PublicKeyGen Phase")

	ckg := mhe.NewPublicKeyProtocol(params) // Public key generation

	ckgCombined := ckg.Allocate()
	ckgCombined.Seed = seed

	for _, pi := range P {
		pi.ckgShare = ckg.Allocate()
	}

	elapsedCKGParty = runTimedParty(func() {
		for _, pi := range P {
			/* #nosec G601 -- Implicit memory aliasing in for loop acknowledged */
			if err := ckg.Gen(pi.sk, seed, pi.ckgShare); err != nil {
				panic(fmt.Errorf("ckgphase -> Gen: %w", err))
			}
		}
	}, len(P))

	pk = rlwe.NewPublicKey(params)

	elapsedCKGCloud = runTimed(func() {

		for _, pi := range P {
			if err := ckg.Aggregate(ckgCombined, pi.ckgShare, ckgCombined); err != nil {
				panic(fmt.Errorf("ckgphase -> Aggregate: %w", err))
			}
		}

		if err := ckg.Finalize(ckgCombined, pk); err != nil {
			panic(fmt.Errorf("ckgphase -> Finalize: %w", err))
		}
	})

	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedCKGCloud, elapsedCKGParty)

	return
}

func rkgphase(params heint.Parameters, pk *rlwe.PublicKey, P []*party) (rlk *rlwe.RelinearizationKey) {
	l := log.New(os.Stderr, "", 0)

	l.Println("> RelinearizationKeyGen Phase")

	rkg := mhe.NewRelinearizationKeyProtocol(params) // Relineariation key generation

	rkgCombined := rkg.Allocate()

	for _, pi := range P {
		pi.rkgShare = rkg.Allocate()
	}

	elapsedRKGParty = runTimedParty(func() {
		for _, pi := range P {
			/* #nosec G601 -- Implicit memory aliasing in for loop acknowledged */
			if err := rkg.Gen(pi.sk, pk, pi.rkgShare); err != nil {
				panic(fmt.Errorf("rkgphase -> Gen: %w", err))
			}
		}
	}, len(P))

	rlk = rlwe.NewRelinearizationKey(params)
	elapsedRKGCloud += runTimed(func() {

		for _, pi := range P {
			/* #nosec G601 -- Implicit memory aliasing in for loop acknowledged */
			if err := rkg.Aggregate(rkgCombined, pi.rkgShare, rkgCombined); err != nil {
				panic(fmt.Errorf("rkgphase -> Aggregate: %w", err))
			}
		}

		if err := rkg.Finalize(rkgCombined, rlk); err != nil {
			panic(fmt.Errorf("rkgphase -> Finalize: %w", err))
		}
	})

	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedRKGCloud, elapsedRKGParty)

	return
}
