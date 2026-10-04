//go:build unit

package repository

import (
	"context"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestRevokedTokenFamilyRejectsInFlightRefresh(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	cache := NewRefreshTokenCache(client)
	ctx := context.Background()
	data := &service.RefreshTokenData{UserID: 1, FamilyID: "family-one", ExpiresAt: time.Now().Add(time.Hour)}
	require.NoError(t, cache.StoreRefreshToken(ctx, "old-hash", data, time.Hour))
	require.NoError(t, cache.AddToUserTokenSet(ctx, 1, "old-hash", time.Hour))
	require.NoError(t, cache.AddToFamilyTokenSet(ctx, data.FamilyID, "old-hash", time.Hour))
	require.NoError(t, cache.DeleteTokenFamily(ctx, data.FamilyID))

	// A refresh already in progress must not recreate the family after logout.
	require.ErrorIs(t, cache.AddToFamilyTokenSet(ctx, data.FamilyID, "inflight-hash", time.Hour), service.ErrTokenRevoked)
	active, err := cache.IsTokenFamilyActive(ctx, data.FamilyID)
	require.NoError(t, err)
	require.False(t, active)
	require.NoError(t, cache.AddToFamilyTokenSet(ctx, "other-device", "other-hash", time.Hour))
	active, err = cache.IsTokenFamilyActive(ctx, "other-device")
	require.NoError(t, err)
	require.True(t, active)
}
