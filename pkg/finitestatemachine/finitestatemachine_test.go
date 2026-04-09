//go:generate stringer -type=enum
package finitestatemachine_test

import (
	"context"
	"testing"

	"github.com/gunawanwijaya/diego/pkg"
	"github.com/gunawanwijaya/diego/pkg/finitestatemachine"
	"github.com/stretchr/testify/require"
)

type enum int

const (
	STATUS_IDLE enum = (iota + 1)
	STATUS_READY
)

const (
	ACTION_STARTUP enum = -(iota + 1)
	ACTION_SHUTDOWN
)

func TestFiniteStateMachine(t *testing.T) {
	tmap := finitestatemachine.TransitionMap[enum]{
		{STATUS_IDLE, ACTION_STARTUP}:   STATUS_READY,
		{STATUS_READY, ACTION_SHUTDOWN}: STATUS_IDLE,
	}
	hook := finitestatemachine.OnTransition[enum](func(ctx context.Context, state, action, nextState enum) error {
		t.Logf("%s > %s > %s", (state), (action), (nextState))
		return nil
	})
	ctx, err := context.Background(), error(nil)
	fsm := pkg.Must1(finitestatemachine.New(STATUS_IDLE, tmap, nil))
	require.Equal(t, pkg.Must1(fsm.Next(ctx, ACTION_STARTUP)), STATUS_READY)

	_, err = finitestatemachine.New(999, tmap, nil)
	require.Error(t, err)

	fsm = pkg.Must1(finitestatemachine.New(STATUS_IDLE, tmap, hook))

	require.Equal(t, pkg.Must1(fsm.Next(ctx, ACTION_STARTUP)), STATUS_READY)
	require.Equal(t, pkg.Must1(fsm.Next(ctx, ACTION_SHUTDOWN)), STATUS_IDLE)
	require.Equal(t, pkg.Must1(fsm.Next(ctx, ACTION_STARTUP)), STATUS_READY)
	require.Equal(t, pkg.Must1(fsm.Next(ctx, ACTION_SHUTDOWN)), STATUS_IDLE)

	_, err = fsm.Next(ctx, ACTION_SHUTDOWN)
	require.ErrorIs(t, err, pkg.ErrUnimplemented)
	require.Equal(t, fsm.CurrentState(), STATUS_IDLE)

	_, err = fsm.Next(ctx, 999)
	require.Error(t, err)
	require.Equal(t, fsm.CurrentState(), STATUS_IDLE)

	hook = func(ctx context.Context, state, action, nextState enum) error { return pkg.ErrUnimplemented }
	fsm = pkg.Must1(finitestatemachine.New(STATUS_IDLE, tmap, hook))

	_, err = fsm.Next(ctx, ACTION_STARTUP)
	require.ErrorIs(t, err, pkg.ErrUnimplemented)
	require.Equal(t, fsm.CurrentState(), STATUS_IDLE)
}
