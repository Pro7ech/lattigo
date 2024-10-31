// Package concurrency implements a simple channel based ressource manager for concurrent operations.
package concurrency

import (
	"sync"
)

// ResourceManager is a struct storing a channel of some given ressource (e.g. an [rlwe.Evaluator])
// meant to be used concurrently and a channel for errors.
type ResourceManager[T any] struct {
	sync.WaitGroup
	Ressources chan T
	Errors     chan error
}

// NewRessourceManager instantiates a new [RessourceManager].
func NewRessourceManager[T any](ressources []T) *ResourceManager[T] {
	Ressources := make(chan T, len(ressources))
	for i := range ressources {
		Ressources <- ressources[i]
	}
	return &ResourceManager[T]{
		Ressources: Ressources,
		Errors:     make(chan error, len(ressources)),
	}
}

// Task is an abstract templates for a function taking as input
// a ressource of any kind that can be used concurrently.
type Task[T any] func(ressource T) (err error)

// Run runs a [Task] concurrently.
// If the internal error channel is not empty, does nothing.
// Adds any error returned by [Task] to the internal error channel.
func (r *ResourceManager[T]) Run(f Task[T]) {
	r.Add(1)
	go func() {
		defer r.Done()
		if len(r.Errors) != 0 {
			return
		}
		ressource := <-r.Ressources
		if err := f(ressource); err != nil {
			if len(r.Errors) < cap(r.Errors) {
				r.Errors <- err
			}
		}
		r.Ressources <- ressource
	}()
}

// Wait waits until all concurrent [Task] have finished and returns
// the first encountered error, if any.
func (r *ResourceManager[T]) Wait() (err error) {
	if len(r.Errors) == 0 {
		r.WaitGroup.Wait()
	} else {
		return <-r.Errors
	}

	if len(r.Errors) != 0 {
		return <-r.Errors
	}

	return
}
