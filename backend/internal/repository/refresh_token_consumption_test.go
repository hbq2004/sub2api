//go:build unit

package repository

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestRefreshTokenConsumptionAllowsOneConcurrentClaim(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	cache := NewRefreshTokenCache(client)
	ctx := context.Background()
	require.NoError(t, cache.StoreRefreshToken(ctx, "audit-hash", &service.RefreshTokenData{UserID: 71, FamilyID: "audit-family", ExpiresAt: time.Now().Add(time.Hour)}, time.Hour))
	var winners atomic.Int64
	var group sync.WaitGroup
	errors := make(chan error, 32)
	for i := 0; i < 32; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			consumed, err := cache.ConsumeRefreshToken(ctx, "audit-hash")
			if err != nil {
				errors <- err
			}
			if consumed {
				winners.Add(1)
			}
		}()
	}
	group.Wait()
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
	require.EqualValues(t, 1, winners.Load())
	_, err := cache.GetRefreshToken(ctx, "audit-hash")
	require.ErrorIs(t, err, service.ErrRefreshTokenNotFound)
}
