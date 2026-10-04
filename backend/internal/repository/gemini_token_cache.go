package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/credentialcrypto"
	"github.com/Wei-Shaw/sub2api/internal/service"

	"github.com/redis/go-redis/v9"
)

const (
	oauthTokenKeyPrefix       = "oauth:token:"
	oauthRefreshLockKeyPrefix = "oauth:refresh_lock:"
)

type geminiTokenCache struct {
	rdb       *redis.Client
	protector *credentialcrypto.Protector
}

func NewGeminiTokenCache(rdb *redis.Client) service.GeminiTokenCache {
	return &geminiTokenCache{rdb: rdb}
}

func ProvideProtectedGeminiTokenCache(rdb *redis.Client, protector *credentialcrypto.Protector) service.GeminiTokenCache {
	return &geminiTokenCache{rdb: rdb, protector: protector}
}

func (c *geminiTokenCache) GetAccessToken(ctx context.Context, cacheKey string) (string, error) {
	key := fmt.Sprintf("%s%s", oauthTokenKeyPrefix, cacheKey)
	value, err := c.rdb.Get(ctx, key).Result()
	if err != nil {
		return "", err
	}
	plain, err := c.protector.OpenCache(key, value)
	if errors.Is(err, credentialcrypto.ErrLegacy) {
		return "", redis.Nil
	}
	return plain, err
}

func (c *geminiTokenCache) SetAccessToken(ctx context.Context, cacheKey string, token string, ttl time.Duration) error {
	key := fmt.Sprintf("%s%s", oauthTokenKeyPrefix, cacheKey)
	value, err := c.protector.SealCache(key, token)
	if err != nil {
		return err
	}
	return c.rdb.Set(ctx, key, value, ttl).Err()
}

func (c *geminiTokenCache) DeleteAccessToken(ctx context.Context, cacheKey string) error {
	key := fmt.Sprintf("%s%s", oauthTokenKeyPrefix, cacheKey)
	return c.rdb.Del(ctx, key).Err()
}

func (c *geminiTokenCache) AcquireRefreshLock(ctx context.Context, cacheKey string, ttl time.Duration) (bool, error) {
	key := fmt.Sprintf("%s%s", oauthRefreshLockKeyPrefix, cacheKey)
	return c.rdb.SetNX(ctx, key, 1, ttl).Result()
}

func (c *geminiTokenCache) ReleaseRefreshLock(ctx context.Context, cacheKey string) error {
	key := fmt.Sprintf("%s%s", oauthRefreshLockKeyPrefix, cacheKey)
	return c.rdb.Del(ctx, key).Err()
}
