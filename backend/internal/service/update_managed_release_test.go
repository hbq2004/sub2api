package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCustomReleaseRejectsInPlaceUpdateAndRollback(t *testing.T) {
	// Missing clients deliberately prove rejection precedes any network/file work.
	s := NewUpdateService(nil, nil, "0.2.13-custom", "release")
	require.ErrorIs(t, s.PerformUpdate(context.Background()), ErrManagedReleaseUpdate)
	require.ErrorIs(t, s.Rollback(), ErrManagedReleaseUpdate)
	require.ErrorIs(t, s.RollbackToVersion(context.Background(), "0.2.12"), ErrManagedReleaseUpdate)
}
