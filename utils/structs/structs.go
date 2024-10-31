// Package structs implements helpers to generalize vectors and matrices of structs, as well as their serialization.
package structs

type Equatable[T any] interface {
	Equal(*T) bool
}

type Cloner[V any] interface {
	Clone() *V
}

type Copyer[V any] interface {
	Copy(*V)
}

type ShallowCopyer[V any] interface {
	ShallowCopy() *V
}

type BinarySizer interface {
	BinarySize() int
}
