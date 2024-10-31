package rlwe

import (
	"github.com/Pro7ech/lattigo/ring"
)

type Element interface {
	N() int
	LogN() int
	Degree() int
	Level() int
	LevelQ() int
	LevelP() int
	AsPoint() *ring.Point
	AsVector() *ring.Vector
	AsPlaintext() *Plaintext
	AsCiphertext() *Ciphertext
}
