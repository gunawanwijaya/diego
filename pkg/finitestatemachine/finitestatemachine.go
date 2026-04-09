package finitestatemachine

import (
	"context"
	"sync"

	"github.com/gunawanwijaya/diego/pkg"
)

type fsm[T comparable] struct {
	mu *sync.Mutex

	currentState  T
	transitionMap TransitionMap[T]
	onTransition  OnTransition[T]
}

type FiniteStateMachine[T comparable] interface {
	CurrentState() T
	Next(ctx context.Context, action T) (nextState T, err error)
}

type TransitionMap[T comparable] map[[2]T]T

type OnTransition[T comparable] func(ctx context.Context, state, action, nextState T) error

func New[T comparable](initState T, transitionMap TransitionMap[T], onTransition OnTransition[T]) (FiniteStateMachine[T], error) {
	if onTransition == nil {
		onTransition = func(ctx context.Context, state, action, nextState T) error { return nil }
	}
	{
		valid := false
		for sa, ns := range transitionMap {
			if initState == sa[0] || initState == ns {
				valid = true
				break
			}
		}
		if !valid {
			return nil, pkg.Errorf("unmapped initial state: %v", initState)
		}
	}
	fsm := &fsm[T]{
		mu:            &sync.Mutex{},
		currentState:  initState,
		transitionMap: transitionMap,
		onTransition:  onTransition,
	}
	return fsm, nil
}

func (x *fsm[T]) CurrentState() T { return x.currentState }

func (x *fsm[T]) Next(ctx context.Context, action T) (nextState T, err error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	var ok bool
	var zero T
	if nextState, ok = x.transitionMap[[2]T{x.CurrentState(), action}]; !ok {
		return zero, pkg.ErrUnimplemented
	}
	if err = x.onTransition(ctx, x.CurrentState(), action, nextState); err != nil {
		return zero, err
	}
	x.currentState = nextState
	return nextState, nil
}
