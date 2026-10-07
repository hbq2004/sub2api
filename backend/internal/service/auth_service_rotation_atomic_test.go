//go:build unit

package service_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

type rotationAuditCache struct {
	*emailBindRefreshTokenCacheStub
	targetHash string
	ready      chan struct{}
	release    chan struct{}
	arrivals   atomic.Int32
	fail       bool
}

func (c *rotationAuditCache) waitForRotation(hash string) {
	if hash != c.targetHash || c.ready == nil {
		return
	}
	if c.arrivals.Add(1) == 2 {
		close(c.ready)
	}
	<-c.release
}

func (c *rotationAuditCache) DeleteRefreshToken(ctx context.Context, hash string) error {
	c.waitForRotation(hash)
	if c.fail && hash == c.targetHash {
		return errors.New("synthetic cache unavailable")
	}
	return c.emailBindRefreshTokenCacheStub.DeleteRefreshToken(ctx, hash)
}

func (c *rotationAuditCache) ConsumeRefreshToken(_ context.Context, hash string) (bool, error) {
	c.waitForRotation(hash)
	if c.fail && hash == c.targetHash {
		return false, errors.New("synthetic cache unavailable")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, present := c.tokens[hash]; !present {
		return false, nil
	}
	delete(c.tokens, hash)
	return true, nil
}

func newRotationAuditFixture(t *testing.T) (*service.AuthService, *rotationAuditCache, string) {
	t.Helper()
	user := &service.User{ID: 71, Email: "rotation-audit@example.invalid", PasswordHash: "synthetic-password-hash", Role: service.RoleUser, Status: service.StatusActive}
	userRepo := newEmailBindUserRepoStub(user)
	cache := &rotationAuditCache{emailBindRefreshTokenCacheStub: newEmailBindRefreshTokenCacheStub()}
	cfg := &config.Config{JWT: config.JWTConfig{Secret: strings.Repeat("audit", 8), ExpireHour: 1, AccessTokenExpireMinutes: 60, RefreshTokenExpireDays: 7}}
	auth := service.NewAuthService(nil, userRepo, nil, cache, cfg, nil, nil, nil, nil, nil, nil, nil, nil)
	pair, err := auth.GenerateTokenPair(context.Background(), user, "")
	require.NoError(t, err)
	digest := sha256.Sum256([]byte(pair.RefreshToken))
	cache.targetHash = hex.EncodeToString(digest[:])
	return auth, cache, pair.RefreshToken
}

func TestAuthServiceRefreshTokenPairConcurrentConsumption(t *testing.T) {
	auth, cache, oldToken := newRotationAuditFixture(t)
	cache.ready, cache.release = make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(cache.release) }) }
	t.Cleanup(release)
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			_, err := auth.RefreshTokenPair(context.Background(), oldToken)
			results <- err
		}()
	}
	select {
	case <-cache.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("both refresh requests did not reach the rotation boundary")
	}
	release()
	succeeded, rejected := 0, 0
	for i := 0; i < 2; i++ {
		select {
		case err := <-results:
			if err == nil {
				succeeded++
			} else if errors.Is(err, service.ErrRefreshTokenInvalid) {
				rejected++
			} else {
				t.Fatalf("unexpected refresh error: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("refresh request did not finish")
		}
	}
	require.Equal(t, 1, succeeded, "a single refresh token must issue exactly one successor")
	require.Equal(t, 1, rejected, "concurrent replay must be rejected")
}

func TestAuthServiceRefreshTokenPairConsumptionFailure(t *testing.T) {
	auth, cache, oldToken := newRotationAuditFixture(t)
	cache.fail = true
	pair, err := auth.RefreshTokenPair(context.Background(), oldToken)
	require.ErrorIs(t, err, service.ErrServiceUnavailable)
	require.True(t, pair == nil, "cache failure must not issue a new token pair")
}

func TestAuthServiceRefreshTokenPairSerialReplay(t *testing.T) {
	auth, _, oldToken := newRotationAuditFixture(t)
	_, err := auth.RefreshTokenPair(context.Background(), oldToken)
	require.NoError(t, err)
	_, err = auth.RefreshTokenPair(context.Background(), oldToken)
	require.ErrorIs(t, err, service.ErrRefreshTokenInvalid)
}
