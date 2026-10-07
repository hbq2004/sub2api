package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/redis/go-redis/v9"
)

const (
	refreshTokenKeyPrefix    = "refresh_token:"
	userRefreshTokensPrefix  = "user_refresh_tokens:"
	tokenFamilyPrefix        = "token_family:"
	revokedTokenFamilyPrefix = "revoked_token_family:"
)

// refreshTokenKey generates the Redis key for a refresh token.
func refreshTokenKey(tokenHash string) string {
	return refreshTokenKeyPrefix + tokenHash
}

// userRefreshTokensKey generates the Redis key for user's token set.
func userRefreshTokensKey(userID int64) string {
	return fmt.Sprintf("%s%d", userRefreshTokensPrefix, userID)
}

// tokenFamilyKey generates the Redis key for token family set.
func tokenFamilyKey(familyID string) string {
	return tokenFamilyPrefix + familyID
}

type refreshTokenCache struct {
	rdb *redis.Client
}

// NewRefreshTokenCache creates a new RefreshTokenCache implementation.
func NewRefreshTokenCache(rdb *redis.Client) service.RefreshTokenCache {
	return &refreshTokenCache{rdb: rdb}
}

func (c *refreshTokenCache) StoreRefreshToken(ctx context.Context, tokenHash string, data *service.RefreshTokenData, ttl time.Duration) error {
	key := refreshTokenKey(tokenHash)
	val, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal refresh token data: %w", err)
	}
	return c.rdb.Set(ctx, key, val, ttl).Err()
}

func (c *refreshTokenCache) GetRefreshToken(ctx context.Context, tokenHash string) (*service.RefreshTokenData, error) {
	key := refreshTokenKey(tokenHash)
	val, err := c.rdb.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, service.ErrRefreshTokenNotFound
		}
		return nil, err
	}
	var data service.RefreshTokenData
	if err := json.Unmarshal([]byte(val), &data); err != nil {
		return nil, fmt.Errorf("unmarshal refresh token data: %w", err)
	}
	return &data, nil
}

func (c *refreshTokenCache) DeleteRefreshToken(ctx context.Context, tokenHash string) error {
	key := refreshTokenKey(tokenHash)
	return c.rdb.Del(ctx, key).Err()
}

func (c *refreshTokenCache) ConsumeRefreshToken(ctx context.Context, tokenHash string) (bool, error) {
	removed, err := c.rdb.Del(ctx, refreshTokenKey(tokenHash)).Result()
	return removed == 1, err
}

func (c *refreshTokenCache) DeleteUserRefreshTokens(ctx context.Context, userID int64) error {
	// Get all token hashes for this user
	tokenHashes, err := c.GetUserTokenHashes(ctx, userID)
	if err != nil && err != redis.Nil {
		return fmt.Errorf("get user token hashes: %w", err)
	}

	if len(tokenHashes) == 0 {
		return nil
	}

	// Build keys to delete
	keys := make([]string, 0, len(tokenHashes)+1)
	families := make(map[string]struct{})
	for _, hash := range tokenHashes {
		keys = append(keys, refreshTokenKey(hash))
		data, err := c.GetRefreshToken(ctx, hash)
		if err != nil && !errors.Is(err, service.ErrRefreshTokenNotFound) {
			return fmt.Errorf("get refresh session: %w", err)
		}
		if data != nil && data.FamilyID != "" {
			families[data.FamilyID] = struct{}{}
		}
	}
	for familyID := range families {
		if err := c.DeleteTokenFamily(ctx, familyID); err != nil {
			return err
		}
	}
	keys = append(keys, userRefreshTokensKey(userID))

	// Delete all keys in a pipeline
	pipe := c.rdb.Pipeline()
	for _, key := range keys {
		pipe.Del(ctx, key)
	}
	_, err = pipe.Exec(ctx)
	return err
}

func (c *refreshTokenCache) DeleteTokenFamily(ctx context.Context, familyID string) error {
	// Keep a tombstone while in-flight refreshes could still recreate this family.
	const script = `
local ttl = math.max(redis.call('PTTL', KEYS[1]), redis.call('PTTL', KEYS[2]), 60000)
redis.call('PSETEX', KEYS[2], ttl, '1')
local hashes = redis.call('SMEMBERS', KEYS[1])
for _, hash in ipairs(hashes) do redis.call('DEL', ARGV[1] .. hash) end
redis.call('DEL', KEYS[1])
return 1`
	return c.rdb.Eval(ctx, script, []string{tokenFamilyKey(familyID), revokedTokenFamilyPrefix + familyID}, refreshTokenKeyPrefix).Err()
}

func (c *refreshTokenCache) AddToUserTokenSet(ctx context.Context, userID int64, tokenHash string, ttl time.Duration) error {
	key := userRefreshTokensKey(userID)
	pipe := c.rdb.Pipeline()
	pipe.SAdd(ctx, key, tokenHash)
	pipe.Expire(ctx, key, ttl)
	_, err := pipe.Exec(ctx)
	return err
}

func (c *refreshTokenCache) AddToFamilyTokenSet(ctx context.Context, familyID string, tokenHash string, ttl time.Duration) error {
	const script = `
if redis.call('EXISTS', KEYS[2]) == 1 then return 0 end
redis.call('SADD', KEYS[1], ARGV[1])
redis.call('PEXPIRE', KEYS[1], ARGV[2])
return 1`
	result, err := c.rdb.Eval(ctx, script, []string{tokenFamilyKey(familyID), revokedTokenFamilyPrefix + familyID}, tokenHash, ttl.Milliseconds()).Int()
	if err != nil {
		return err
	}
	if result == 0 {
		return service.ErrTokenRevoked
	}
	return nil
}

func (c *refreshTokenCache) GetUserTokenHashes(ctx context.Context, userID int64) ([]string, error) {
	key := userRefreshTokensKey(userID)
	return c.rdb.SMembers(ctx, key).Result()
}

func (c *refreshTokenCache) GetFamilyTokenHashes(ctx context.Context, familyID string) ([]string, error) {
	key := tokenFamilyKey(familyID)
	return c.rdb.SMembers(ctx, key).Result()
}

func (c *refreshTokenCache) IsTokenInFamily(ctx context.Context, familyID string, tokenHash string) (bool, error) {
	key := tokenFamilyKey(familyID)
	return c.rdb.SIsMember(ctx, key, tokenHash).Result()
}

func (c *refreshTokenCache) IsTokenFamilyActive(ctx context.Context, familyID string) (bool, error) {
	const script = `
if redis.call('EXISTS', KEYS[2]) == 1 then return 0 end
return redis.call('EXISTS', KEYS[1])`
	active, err := c.rdb.Eval(ctx, script, []string{tokenFamilyKey(familyID), revokedTokenFamilyPrefix + familyID}).Int()
	return active == 1, err
}
