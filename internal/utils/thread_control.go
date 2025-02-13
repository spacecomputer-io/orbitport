package utils

import (
	"context"
	"sync"
)

var _ ThreadControl = &threadControl{}

// ThreadControl is a helper for managing a group of goroutines.
type ThreadControl interface {
	// Go starts a goroutine and tracks the lifetime of the goroutine.
	Go(fn func(context.Context))
	// GoCtx starts a goroutine with a given context and tracks the lifetime of the goroutine.
	GoCtx(ctx context.Context, fn func(context.Context))
	// Close cancels the goroutines and waits for all of them to exit.
	Close()
}

func NewThreadControl() *threadControl {
	tc := &threadControl{
		stop: make(chan struct{}),
	}

	return tc
}

type threadControl struct {
	threadsWG sync.WaitGroup
	stop      stopChan
}

func (tc *threadControl) Go(fn func(context.Context)) {
	tc.threadsWG.Add(1)
	go func() {
		defer tc.threadsWG.Done()
		ctx, cancel := tc.stop.NewCtx()
		defer cancel()
		fn(ctx)
	}()
}

func (tc *threadControl) GoCtx(ctx context.Context, fn func(context.Context)) {
	tc.threadsWG.Add(1)
	go func() {
		defer tc.threadsWG.Done()
		// Create a new context that is cancelled when either parent context is cancelled or stop is closed.
		ctx2, cancel := tc.stop.Ctx(ctx)
		defer cancel()
		fn(ctx2)
	}()
}

func (tc *threadControl) Close() {
	close(tc.stop)
	tc.threadsWG.Wait()
}

// A stopChan signals when some work should stop.
type stopChan chan struct{}

// NewCtx returns a background [context.Context] that is cancelled when StopChan is closed.
func (s stopChan) NewCtx() (context.Context, context.CancelFunc) {
	return stopRChan((<-chan struct{})(s)).NewCtx()
}

// Ctx cancels a [context.Context] when StopChan is closed.
func (s stopChan) Ctx(ctx context.Context) (context.Context, context.CancelFunc) {
	return stopRChan((<-chan struct{})(s)).Ctx(ctx)
}

// CtxCancel cancels a [context.Context] when StopChan is closed.
// Returns ctx and cancel unmodified, for convenience.
func (s stopChan) CtxCancel(ctx context.Context, cancel context.CancelFunc) (context.Context, context.CancelFunc) {
	return stopRChan((<-chan struct{})(s)).CtxCancel(ctx, cancel)
}

// A stopRChan signals when some work should stop.
// This version is receive-only.
type stopRChan <-chan struct{}

// NewCtx returns a background [context.Context] that is cancelled when StopChan is closed.
func (s stopRChan) NewCtx() (context.Context, context.CancelFunc) {
	return s.Ctx(context.Background())
}

// Ctx cancels a [context.Context] when StopChan is closed.
func (s stopRChan) Ctx(ctx context.Context) (context.Context, context.CancelFunc) {
	return s.CtxCancel(context.WithCancel(ctx))
}

// CtxCancel cancels a [context.Context] when StopChan is closed.
// Returns ctx and cancel unmodified, for convenience.
func (s stopRChan) CtxCancel(ctx context.Context, cancel context.CancelFunc) (context.Context, context.CancelFunc) {
	go func() {
		select {
		case <-s:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}
