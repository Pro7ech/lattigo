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
	gkgShare *mhe.GaloisKeyShare
	ksShare  *mhe.KeySwitchingShare

	input []uint64
}

type maskTask struct {
	query           *rlwe.Ciphertext
	mask            *rlwe.Plaintext
	row             *rlwe.Ciphertext
	res             *rlwe.Ciphertext
	elapsedmaskTask time.Duration
}

var elapsedCKGCloud time.Duration
var elapsedCKGParty time.Duration
var elapsedRKGCloud time.Duration
var elapsedRKGParty time.Duration
var elapsedGKGCloud time.Duration
var elapsedGKGParty time.Duration
var elapsedCKSCloud time.Duration
var elapsedPCKSParty time.Duration
var elapsedRequestParty time.Duration
var elapsedRequestCloud time.Duration
var elapsedRequestCloudCPU time.Duration

func main() {

	// This example simulates a SMC instance of a private information retrieval (PIR) problem.
	// The problem statement is as follows: a cloud stores data of several parties
	// encrypted under a shared public-key. An external party wants to retrieve
	// the plaintext content of one of the ciphertexts while ensuring the following
	// security property: no information other than the fact that a request was made must
	// be disclosed to the cloud, to the owners of the shared public-key or to anyone else.
	//
	// For more details see
	//    Multiparty Homomorphic Encryption: From Theory to Practice (<https://eprint.iacr.org/2020/304>)

	l := log.New(os.Stderr, "", 0)

	// $go run main.go arg1 arg2
	// arg1: number of parties
	// arg2: number of Go routines
	// MinDelta number of parties for n=8192: 512 parties (this is a memory intensive process)

	N := 3 // Default number of parties
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

	// Index of the ciphertext to retrieve.
	queryIndex := 2

	// Creating encryption parameters
	// LogN = 13 & LogQP = 218
	params, err := heint.NewParametersFromLiteral(heint.ParametersLiteral{
		LogN: 13,
		LogQ: []int{54, 54, 54},
		LogP: []int{55},
		T:    0x10001,
		R:    1,
	})
	if err != nil {
		panic(err)
	}

	// Instantiation of each of the protocols needed for the PIR example

	// Create each party, and allocate the memory for all the shares that the protocols will need
	P := genparties(params, N)

	// 1) Collective public key generation
	pk := ckgphase(params, sampling.NewSeed(), P)

	// 2) Collective RelinearizationKey generation
	rlk := rkgphase(params, pk, P)

	// 3) Collective GaloisKeys generation
	gks := gkgphase(params, sampling.NewSeed(), P)

	// Instantiates EvaluationKeySet
	evk := rlwe.NewMemEvaluationKeySet(rlk, gks...)

	l.Printf("\tSetup done (cloud: %s, party: %s)\n",
		elapsedCKGCloud+elapsedRKGCloud+elapsedGKGCloud,
		elapsedCKGParty+elapsedRKGParty+elapsedGKGParty)

	// Pre-loading memory
	encoder := heint.NewEncoder(params)
	l.Println("> Memory alloc Phase")
	encInputs := make([]*rlwe.Ciphertext, N)
	plainMask := make([]*rlwe.Plaintext, N)

	// Ciphertexts to be retrieved
	for i := range encInputs {
		encInputs[i] = heint.NewCiphertext(params, 1, params.MaxLevel())
	}

	// Plaintext masks: plainmask[i] = encode([0, ..., 0, 1_i, 0, ..., 0])
	// (zero with a 1 at the i-th position).
	for i := range plainMask {
		maskCoeffs := make([]uint64, params.N())
		maskCoeffs[i] = 1
		plainMask[i] = heint.NewPlaintext(params, params.MaxLevel())
		if err := encoder.Encode(maskCoeffs, plainMask[i]); err != nil {
			panic(err)
		}
	}

	// Ciphertexts encrypted under collective public key and stored in the cloud
	l.Println("> Encrypt Phase")
	encryptor := rlwe.NewEncryptor(params, pk)
	pt := heint.NewPlaintext(params, params.MaxLevel())
	elapsedEncryptParty := runTimedParty(func() {
		for i, pi := range P {
			if err := encoder.Encode(pi.input, pt); err != nil {
				panic(err)
			}
			if err := encryptor.Encrypt(pt, encInputs[i]); err != nil {
				panic(err)
			}
		}
	}, N)

	elapsedEncryptCloud := time.Duration(0)
	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedEncryptCloud, elapsedEncryptParty)

	// Request phase
	encQuery, err := genquery(params, queryIndex, encoder, encryptor)

	if err != nil {
		panic(err)
	}

	result := requestphase(params, queryIndex, NGoRoutine, encQuery, encInputs, plainMask, evk)

	// Collective (partial) decryption (key switch)
	encOut, err := cksphase(params, P, result)

	if err != nil {
		panic(err)
	}

	l.Println("> ResulPlaintextModulus:")

	// Decryption by the external party
	decryptor := rlwe.NewDecryptor(params, P[0].sk)
	ptres := heint.NewPlaintext(params, params.MaxLevel())
	elapsedDecParty := runTimed(func() {
		decryptor.Decrypt(encOut, ptres)
	})

	res := make([]uint64, params.MaxSlots())
	if err := encoder.Decode(ptres, res); err != nil {
		panic(err)
	}

	l.Printf("\t%v...%v\n", res[:8], res[params.N()-8:])
	l.Printf("> Finished (total cloud: %s, total party: %s)\n",
		elapsedCKGCloud+elapsedRKGCloud+elapsedGKGCloud+elapsedEncryptCloud+elapsedRequestCloudCPU+elapsedCKSCloud,
		elapsedCKGParty+elapsedRKGParty+elapsedGKGParty+elapsedEncryptParty+elapsedRequestParty+elapsedPCKSParty+elapsedDecParty)
}

func cksphase(params heint.Parameters, P []*party, result *rlwe.Ciphertext) (encOut *rlwe.Ciphertext, err error) {
	l := log.New(os.Stderr, "", 0)

	l.Println("> KeySwitch Phase")

	cks := mhe.NewKeySwitchingProtocol[rlwe.SecretKey](params) // Collective public-key re-encryption

	for _, pi := range P {
		pi.ksShare = cks.Allocate(params.MaxLevel())
	}

	noise := float64(1 << 30)

	zero := rlwe.NewSecretKey(params)
	cksCombined := cks.Allocate(params.MaxLevel())
	elapsedPCKSParty = runTimedParty(func() {
		for _, pi := range P[1:] {
			/* #nosec G601 -- Implicit memory aliasing in for loop acknowledged */
			if err = cks.Gen(pi.sk, zero, noise, result, pi.ksShare); err != nil {
				return
			}
		}
	}, len(P)-1)

	encOut = result.Clone()
	elapsedCKSCloud = runTimed(func() {
		for _, pi := range P {
			if err = cks.Aggregate(pi.ksShare, cksCombined, cksCombined); err != nil {
				return
			}
		}
		if err = cks.Finalize(encOut, cksCombined, encOut); err != nil {
			return
		}
	})
	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedCKSCloud, elapsedPCKSParty)

	return
}

func genparties(params heint.Parameters, N int) []*party {

	P := make([]*party, N)

	kgen := rlwe.NewKeyGenerator(params)

	for i := range P {
		pi := &party{}
		pi.sk = kgen.GenSecretKeyNew()

		pi.input = make([]uint64, params.N())
		for j := range pi.input {
			pi.input[j] = uint64(i)
		}

		P[i] = pi
	}

	return P
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

func gkgphase(params heint.Parameters, seed [32]byte, P []*party) (galKeys []*rlwe.GaloisKey) {

	l := log.New(os.Stderr, "", 0)

	l.Println("> GKG Phase")

	gkg := mhe.NewGaloisKeyProtocol(params) // Rotation keys generation

	for _, pi := range P {
		pi.gkgShare = gkg.Allocate()
	}

	galEls := append(params.GaloisElementsForInnerSum(1, params.N()>>1), params.GaloisElementForRowRotation())
	galKeys = make([]*rlwe.GaloisKey, len(galEls))

	gkgShareCombined := gkg.Allocate()

	source := sampling.NewSource(seed)

	for i, galEl := range galEls {

		seedi := source.NewSeed()

		gkgShareCombined.Seed = seedi

		gkgShareCombined.GaloisElement = galEl

		elapsedGKGParty += runTimedParty(func() {
			for _, pi := range P {
				/* #nosec G601 -- Implicit memory aliasing in for loop acknowledged */
				if err := gkg.Gen(pi.sk, galEl, seedi, pi.gkgShare); err != nil {
					panic(fmt.Errorf("gkgphase -> Gen: %w", err))
				}
			}

		}, len(P))

		elapsedGKGCloud += runTimed(func() {

			if err := gkg.Aggregate(P[0].gkgShare, P[1].gkgShare, gkgShareCombined); err != nil {
				panic(err)
			}

			for _, pi := range P[2:] {
				if err := gkg.Aggregate(gkgShareCombined, pi.gkgShare, gkgShareCombined); err != nil {
					panic(fmt.Errorf("gkgphase -> Gen: %w", err))
				}
			}

			galKeys[i] = rlwe.NewGaloisKey(params)

			if err := gkg.Finalize(gkgShareCombined, galKeys[i]); err != nil {
				panic(fmt.Errorf("gkgphase -> Finalize: %w", err))
			}
		})
	}

	l.Printf("\tdone (cloud: %s, party %s)\n", elapsedGKGCloud, elapsedGKGParty)

	return
}

func genquery(params heint.Parameters, queryIndex int, encoder *heint.Encoder, encryptor *rlwe.Encryptor) (encQuery *rlwe.Ciphertext, err error) {
	// Query ciphertext
	queryCoeffs := make([]uint64, params.N())
	queryCoeffs[queryIndex] = 1
	query := heint.NewPlaintext(params, params.MaxLevel())
	elapsedRequestParty += runTimed(func() {
		var err error
		if err = encoder.Encode(queryCoeffs, query); err != nil {
			return
		}

		encQuery = heint.NewCiphertext(params, 1, params.MaxLevel())

		if err = encryptor.Encrypt(query, encQuery); err != nil {
			return
		}
	})

	return
}

func requestphase(params heint.Parameters, queryIndex, NGoRoutine int, encQuery *rlwe.Ciphertext, encInputs []*rlwe.Ciphertext, plainMask []*rlwe.Plaintext, evk rlwe.EvaluationKeySet) *rlwe.Ciphertext {

	l := log.New(os.Stderr, "", 0)

	l.Println("> Request Phase")

	// Buffer for the intermediate computation done by the cloud
	encPartial := make([]*rlwe.Ciphertext, len(encInputs))
	for i := range encPartial {
		encPartial[i] = heint.NewCiphertext(params, 2, params.MaxLevel())
	}

	evaluator := heint.NewEvaluator(params, evk)

	// Split the task among the Go routines
	tasks := make(chan *maskTask)
	workers := &sync.WaitGroup{}
	workers.Add(NGoRoutine)
	for i := 1; i <= NGoRoutine; i++ {
		go func(i int) {
			evaluator := evaluator.ShallowCopy() // creates a shallow evaluator copy for this goroutine
			tmp := heint.NewCiphertext(params, 1, params.MaxLevel())
			buf := evaluator.NewHoistingBuffer(tmp.Level(), params.MaxLevelP())
			for task := range tasks {
				task.elapsedmaskTask = runTimed(func() {
					// 1) Multiplication BFV-style of the query with the plaintext mask
					if err := evaluator.MulScaleInvariant(task.query, task.mask, tmp); err != nil {
						panic(err)
					}

					// 2) Inner sum (populate all the slots with the sum of all the slots)
					if err := evaluator.InnerSum(tmp, 1, params.N()>>1, buf, tmp); err != nil {
						panic(err)
					}

					if tmpRot, err := evaluator.RotateRowsNew(tmp); err != nil {

					} else {
						if err := evaluator.Add(tmp, tmpRot, tmp); err != nil {
							panic(err)
						}
					}

					// 3) Multiplication of 2) with the i-th ciphertext stored in the cloud
					if err := evaluator.Mul(tmp, task.row, task.res); err != nil {
						panic(err)
					}
				})
			}
			//l.Println("\t evaluator", i, "down")
			workers.Done()
		}(i)
		//l.Println("\t evaluator", i, "started")
	}

	taskList := make([]*maskTask, 0)

	elapsedRequestCloud += runTimed(func() {
		for i := range encInputs {
			task := &maskTask{
				query: encQuery,
				mask:  plainMask[i],
				row:   encInputs[i],
				res:   encPartial[i],
			}
			taskList = append(taskList, task)
			tasks <- task
		}
		close(tasks)
		workers.Wait()
	})

	for _, t := range taskList {
		elapsedRequestCloudCPU += t.elapsedmaskTask
	}

	resultDeg2 := heint.NewCiphertext(params, 2, params.MaxLevel())
	result := heint.NewCiphertext(params, 1, params.MaxLevel())

	// Summation of all the partial result among the different Go routines
	finalAddDuration := runTimed(func() {
		for i := 0; i < len(encInputs); i++ {
			if err := evaluator.Add(resultDeg2, encPartial[i], resultDeg2); err != nil {
				panic(err)
			}
		}
		if err := evaluator.Relinearize(resultDeg2, result); err != nil {
			panic(err)
		}
	})

	elapsedRequestCloud += finalAddDuration
	elapsedRequestCloudCPU += finalAddDuration

	l.Printf("\tdone (cloud: %s/%s, party: %s)\n",
		elapsedRequestCloud, elapsedRequestCloudCPU, elapsedRequestParty)

	return result
}
