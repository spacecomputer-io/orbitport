package utils

import "sync"

type Locked[T any] struct {
	mu sync.RWMutex
	v  T
}

func NewLocked[T any](v T) *Locked[T] {
	return &Locked[T]{
		v: v,
	}
}

func (l *Locked[T]) Get() T {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.v
}

func (l *Locked[T]) Set(v T) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.v = v
}
