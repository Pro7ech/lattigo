# Changelog
All notable changes to this library are documented in this file.

## [0.0.1] - 24.06.2024

Changes affecting the entire library:
- Extensive refactoring of the `Ring` object (see much below for details).
- Refactored how polynomials and their derivative structs (e.g. ciphertexts and keys) are instantiated. 
  They now all have the following methods:
    - `.FromBuffer` which allow to assign a new backing array to the receiver from an `[]uint64` slice
    - `.BufferSize` which returns the minimum size of the `[]uint64` slice to provide to `.FromBuffer`
- Calling `New<Something>` will internally call the two here above methods 
- Removed the package `ring/ringqp`: all instances of `RingQP` have been replaced
  by separate calls to `RingQ` and `RingP`. New associated structs have been designed
  to replace the old `ringqp.Poly` (see changes to the `ring` package)
- Refactored all sampling (see changes to `utils/sampling`), improves related performance by a speedup factor of up to 2x
- Replaced most instances of `[]*<object>` by `[]<object>`, for example `[]*big.Float -> []big.Float`
- Optimized the buffers and their size of many objects. 

- `he`:
  - Linear Transformations:
    - Generalized implementation of linear transformation such that package specific code (e.g. `heint` or `hefloat`) is not necessary anymore.
    - Significantly improved the search for the best giant step size, which is not anymore constrained to a power of two:
      - Added `OptimalLinearTransformationGiantStep` which replaces `FindBestBSGSRatio` and returns much more optimal values (not constrained to be a power of two anymore) that properly minimize the number of Galois elements.
    - `LinearTransformationParameters`:
      - Removed the `LogBSGSRatio` field.
      - Removed the `Naive` field.
      - Added the `GiantStep` field.
      - Added `.GaloisElements(*)`: returns the set of Galois elements necessary to evaluate the diagonalized matrix.
    - `LinearTransformation`:
      - Removed the ` LogBabyStepGianStepRatio` field.
      - Removed the `N1` field.
      - Added the `GiantStep` field.
    - `Diagonals` (diagonalized matrix):
      - Added `Add`: add two diagonalized matrices together.
      - Added `Mul`: multiply ttwo diagonalized matrices together.
      - Added `Indexes`: returns the indexes of the non-zero diagonals of the diagonalized matrix.
      - Added `GaloisElements`: returns the set of Galois elements necessary to evaluate the diagonalized matrix.
      - Added `At`: returns a specific diagonal of the diagonalized matrix.
      - Added `Evaluate`: evaluates the diagonalized matrix on a vector.
    - `Permutation` (permutation matrix):
      - Added `Indexes`: returns the indexes of the non-zero diagonals of the permutation.
      - Added `Diagonals`: returns the diagonalized matrix of the permutation.
      - Added `GaloisElements`: returns the set of Galois elements necessary to evaluate the permutation.
  - **Polynomial Evaluation**:
    - Improved relinearization patterns when evaluating a polynomial with the flag `lazy=true`.
    - The output of polynomial evaluation is not rescaled anymore, enabling more optimal noise management.
    - Added `EncodedPolynomial` type, a pre-encoded `VectorPolynomial` into `rlwe.Plaintext` and associated methods for evaluation.
    - `PolynomialVector`:
      - Simplified the field `Mapping` which now takes a single slices as mapping, instead of a map of slices.
      - Added `Evaluate` method.

- `heint`:
  - Added support for prime power plaintext modulus:
    - Removed `PlaintextModlus` as it wasn't specific enough to distinguish between the base plaintext modulus and its powers. 
    - Added `T` which is the base plaintext modulus.
    - Added `R` wich is the base plaintext modulus power.
    - Field names `T` and `R` will be subject to change in the next release if better names can be found.
  - Merged `schemes/bgv/` into `heint`.
  - Removed package specific code for linear transformations (this functionality now solely depends on the `he` package).

- `hefloat`:
  - Bootstrapping:
    - Added [EvalRound+](https://eprint.iacr.org/2024/1379).
    - Reworked `Parameters` and `ParametersLiteral`.
    - Fixed wrong returned `MinimumInputLevel`.
    - Added API to estimate the failure probability:
      - `FailureProbability` returns $$\text{PR}[||I(X)|| > K]$$.
      - `FindSuitableK` returns the smallest K satisfying $$\text{PR}[||I(X)|| > K] <= 2^{\text{logfailure}}$$.
      - `ModifiedIrwinHall` estimates $$\text{PR}[||I(X)|| > K]$$.
    - Improved serialization support for `ParametersLiteral`.
  - `Evaluator`:
    - Added `MatchScalesForMul` which enables to match the scales of two ciphertext such that after multiplication and rescaling the scaling factor is the one desired.
  - `InverseEvaluator`:
    - Changed `log2Min` and `log2Max` to `Min` and `Max` respectively. This enables a more human friendly parameterization.
    - Added `InvSqrt`, which returns 1/sqrt(x) by Newton iterations. Contrary to the GoldschmidtDivision algorithm, it can be used to refine a value already close to the ideal value, enabling composition with polynomial approximation.
    - `GoldschmidtDivision` takes as operand the number of iterations instead of automatically estimating them.
    - `IntervalNormalization` uses one less level per iteration (2 instead of 3), and use one less bootstrapping per iteration if using the Conjugate Invariant ring.
  - Added affine transformation for EvalMod1.
  - Merged `schemes/ckks` into `hefloat`.
  - Removed package specific code for linear transformations (this functionality now solely depends on the `he` package).
  - Improved statistics, which now also display the standard deviation as well as the error statistics.

- `mhe`:
  - General rework, uniformization and simplification of the API of all protocols. All protocols now comply to the similar interface `Gen`, `Aggregate`, `Finalize`.
  - Greatly reduced code and code complexity of all protocols:
    - Protocols use the `rlwe.Encryptor` instead of re-implementing encryption routines.
    - Shares are now standardized using the new structs defined in the `ring` package.
  - New single-round protocols which enable a fully single-round setup for `heint`, `hefloat` and `hebin`:
    - `mhe.CircularCiphertextProtocol`: single-round generation of `RLWE(ms)`.
    - `mhe.CircularGadgetCiphertextProtocol`: single-round generation of `GRLWE(ms)`.
    - An single-round setup example can be found [here](https://github.com/Pro7ech/lattigo/blob/master/examples/multi_party/setup/one_round/main.go).
  - Improved the interactive relinearization key gen protocol from [Homomorphic Encryption for Multiple Users with Less Communications](https://eprint.iacr.org/2021/1085).
  - Added full support for deterministic share generation.

- `core`:
  - Removed the `core` package (which was empty after the changes).

- `rlwe`:
  - Moved out of `core`.
  - Expanded the API of the `Encryptor` to support full deterministic encryption and be able to perform key-switching.
  - Added support for signed digit decomposition via the struct `DigitDecomposition`.
  - Parameters can be specified with any combination of (`Q`, `LogQ`) and (`P`, `LogP`).
  - Added `NoiseCiphertext`, which returns the base 2 logarithm of the standard deviation of the residual noise in an `rlwe.Ciphertext`.
  - Removed field `nbPi` in `DecomposeNTT`.
  - Added [Optimizing HE operations via Level-aware Key-switching Framework](https://eprint.iacr.org/2023/1328).

- `rgsw`:
  - Moved out of `core`.
  - Added support for `RGSWxRGSW` product.
  - Added `.FromGadgetCiphertext` which produces an `rgsw.Ciphertext` from an `rlwe.GadgetCiphertext`.
  - Added support for signed digit decomposition.

- `schemes`:
  - `bfv`: removed.
  - `bgv`: merged into `he/heint`.
  - `ckks`: merged into `he/hefloat`.

- `examples`:
  - Refactored all examples.

- `ring`:
  - `Ring`:
    - Renamed `Ring` to `RNSRing` and `SubRing` to `Ring`.
    - Renamed `Poly` to `RNSPoly` which is now a slice of `Poly` and added type `Poly`, a slice of `[]uint64`.
    - Greatly simplified struct `RNSRing` which is now simply `[]*Ring`.
    - Updated vectorized operations to accept slices that are not multiples of 8 (and not trigger buffer overflows).
    - Added `Modulus` which returns the modulus of the ring (`.AtLevel(level).Modulus()` replaces `.ModulusAtLevel[level]`).
    - Added `RescaleConstants` which returns the rescaling constant for a given level (`.RescaleConstants(level)` replaces `RescaleConstants[level]`).
    - Added `Concat` which returns the concatenation of two rings.
    - Added `AddModuli` which returns an instance of a ring with additional moduli.
  - `BasisExtender`:
    - Removed and replaced by methods on the `RNSRing` type. Constants are now computed on the fly.
  - Refactored the samplers which now take a `sampling.Source` as random coins generator.
  - `ring.Poly` is now a reslice of an 1D `[]uint64` backing array instead of
    a collection of independently allocated 1D arrays.
  - Added `Point`, `Vector` and `Matrix` structs with many associated methods.
  - Added the `Stats` method which returns log2(std) and mean of a Poly.

- `utils`:
  - Removed many slices utilities, which are now available through the native package `slice`.
  - Removed `Min` and `Max` which now have native supported in Go as `min` and `max`.
  - `structs`:
    - Added `Copyer` interface and support (TODO review copy/clone).
  - `sampling`:
    - Replaced the blake2b based XOF (`sampling.PRNG`) by the `math/rand/v2` ChaCha8-based CSPRNG (`sampling.Source`). 
    - The `sampling.Source` struct is now used for all sampling the library.
  - `bignum`:
    - Refactored and fixed many bugs in the multi-interval Remez minimax polynomial approximation algorithm which now properly works when doing multi-interval approximations.
    - Added `Log2ErfC` which returns the base 2 logarithm of the complementary error function.
    - Added `Stats([]big.Int, prec)`, which returns the base 2 logarithm of the standard deviation and the mean
    - Added `ToComplexSlice` to cast a numerical slice to a `[]bignum.Complex`.
  - `concurrency`:
    - New package providing basic support for concurrency.

Others:
- Improved issue template

## [0.0.0] - 12.06.2024

- Fork of Lattigo v5.0.2