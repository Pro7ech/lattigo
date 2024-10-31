// Package he implements scheme agnostic functionalities for RLWE-based Homomorphic Encryption schemes implemented in lattigo.
package he

import (
	"github.com/Pro7ech/lattigo/rlwe"
)

// Encoder defines a set of common and scheme agnostic method provided by an Encoder struct.
type Encoder interface {
	Embed(values interface{}, metaData *rlwe.MetaData, output interface{}) (err error)
}

// Evaluator defines a set of common and scheme agnostic method provided by an Evaluator struct.
type Evaluator interface {
	rlwe.ParameterProvider
	Add(op0 *rlwe.Ciphertext, op1 rlwe.Operand, opOut *rlwe.Ciphertext) (err error)
	AddNew(op0 *rlwe.Ciphertext, op1 rlwe.Operand) (opOut *rlwe.Ciphertext, err error)
	Sub(op0 *rlwe.Ciphertext, op1 rlwe.Operand, opOut *rlwe.Ciphertext) (err error)
	SubNew(op0 *rlwe.Ciphertext, op1 rlwe.Operand) (opOut *rlwe.Ciphertext, err error)
	Mul(op0 *rlwe.Ciphertext, op1 rlwe.Operand, opOut *rlwe.Ciphertext) (err error)
	MulNew(op0 *rlwe.Ciphertext, op1 rlwe.Operand) (opOut *rlwe.Ciphertext, err error)
	MulRelin(op0 *rlwe.Ciphertext, op1 rlwe.Operand, opOut *rlwe.Ciphertext) (err error)
	MulRelinNew(op0 *rlwe.Ciphertext, op1 rlwe.Operand) (opOut *rlwe.Ciphertext, err error)
	MulThenAdd(op0 *rlwe.Ciphertext, op1 rlwe.Operand, opOut *rlwe.Ciphertext) (err error)
	Relinearize(op0, op1 *rlwe.Ciphertext) (err error)
	Rescale(op0, op1 *rlwe.Ciphertext) (err error)
	GetEvaluatorBuffer() *rlwe.EvaluatorBuffers // TODO extract
	DropLevel(op0 *rlwe.Ciphertext, Level int)
	LevelsConsumedPerRescaling() int
}
