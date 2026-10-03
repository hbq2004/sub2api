package repository

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Wei-Shaw/sub2api/internal/pkg/credentialcrypto"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func syntheticCredentialProtector(t *testing.T, active string, allowLegacy bool) *credentialcrypto.Protector {
	t.Helper()
	data, err := json.Marshal(map[string]any{"active_key_id": active, "encryption_keys": map[string]string{"v1": strings.Repeat("01", 32), "v2": strings.Repeat("03", 32)}, "lookup_key": strings.Repeat("02", 32)})
	require.NoError(t, err)
	p, err := credentialcrypto.Load(strings.NewReader(string(data)), allowLegacy)
	require.NoError(t, err)
	return p
}

func TestProtectedKeyringRejectsNormalizedRedemptionRoots(t *testing.T) {
	t.Setenv("REDEEM_CODE_ENCRYPTION_KEY", " "+strings.Repeat("01", 32)+" ")
	t.Setenv("REDEEM_CODE_HMAC_KEY", "\t"+strings.Repeat("03", 32)+"\n")
	_, err := newRedeemCodeProtectorFromEnv()
	require.NoError(t, err, "redemption keys accept surrounding whitespace")
	data, err := json.Marshal(map[string]any{"active_key_id": "v1", "encryption_keys": map[string]string{"v1": strings.Repeat("01", 32)}, "lookup_key": strings.Repeat("02", 32)})
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "synthetic-keyring.json")
	require.NoError(t, os.WriteFile(path, data, 0600))
	t.Setenv("ACCOUNT_CREDENTIAL_KEYRING_FILE", path)
	t.Setenv("ACCOUNT_CREDENTIAL_ENCRYPTION_REQUIRED", "true")
	t.Setenv("ACCOUNT_CREDENTIAL_ALLOW_LEGACY", "false")
	_, err = ProvideAccountCredentialProtector(nil)
	require.ErrorContains(t, err, "must not reuse")
}

func TestProtectedCredentialSnapshotPreservesCASAndHidesBindings(t *testing.T) {
	p := syntheticCredentialProtector(t, "v1", true)
	old := map[string]any{"access_token": "synthetic-access", "refresh_token": "synthetic-refresh"}
	stored, err := p.Encrypt(17, old)
	require.NoError(t, err)
	encoded, err := json.Marshal(stored)
	require.NoError(t, err)
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	repo := &accountRepository{sql: db, protector: p}
	for _, expected := range []map[string]any{old, {"access_token": "synthetic-stale", "refresh_token": "synthetic-refresh"}} {
		mock.ExpectQuery(regexp.QuoteMeta("SELECT credentials FROM accounts WHERE id = $1 AND deleted_at IS NULL")).WithArgs(int64(17)).WillReturnRows(sqlmock.NewRows([]string{"credentials"}).AddRow(encoded))
		actual, err := repo.credentialSnapshotJSON(context.Background(), db, 17, expected)
		require.NoError(t, err)
		require.NotContains(t, string(actual), "synthetic-access")
		require.NotContains(t, string(actual), "synthetic-stale")
		if expected["access_token"] == old["access_token"] {
			require.JSONEq(t, string(encoded), string(actual))
		} else {
			require.NotEqual(t, string(encoded), string(actual))
		}
	}
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestProtectedSchedulerAndOAuthCacheRoundtrip(t *testing.T) {
	server := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { rdb.Close() })
	p := syntheticCredentialProtector(t, "v1", true)
	cache := NewSchedulerCache(rdb).(*schedulerCache)
	cache.protector = p
	ctx := context.Background()
	account := &service.Account{ID: 17, Platform: service.PlatformOpenAI, Type: service.AccountTypeOAuth, Credentials: map[string]any{"api_key": "synthetic-api", "access_token": "synthetic-access", "refresh_token": "synthetic-refresh", "model_mapping": map[string]any{"test": "test"}}}
	require.NoError(t, cache.SetAccount(ctx, account))
	for _, key := range []string{schedulerAccountKey("17"), schedulerAccountMetaKey("17")} {
		stored, err := rdb.Get(ctx, key).Result()
		require.NoError(t, err)
		for _, secret := range []string{"synthetic-api", "synthetic-access", "synthetic-refresh"} {
			require.NotContains(t, stored, secret)
		}
	}
	loaded, err := cache.GetAccount(ctx, 17)
	require.NoError(t, err)
	require.Equal(t, account.Credentials, loaded.Credentials)
	bucket := service.SchedulerBucket{GroupID: 1, Platform: service.PlatformOpenAI, Mode: "standard"}
	writeToken, err := cache.CaptureBucketWriteToken(ctx, bucket)
	require.NoError(t, err)
	require.NoError(t, cache.SetSnapshot(ctx, bucket, writeToken, []service.Account{*account}))
	snapshot, hit, err := cache.GetSnapshot(ctx, bucket)
	require.NoError(t, err)
	require.True(t, hit)
	require.Len(t, snapshot, 1)
	require.Equal(t, "synthetic-api", snapshot[0].Credentials["api_key"])
	unprotectedCache := NewSchedulerCache(rdb)
	_, err = unprotectedCache.GetAccount(ctx, 17)
	require.ErrorIs(t, err, credentialcrypto.ErrKeyRequired)
	legacy, err := json.Marshal(account)
	require.NoError(t, err)
	require.NoError(t, rdb.Set(ctx, schedulerAccountKey("17"), legacy, 0).Err())
	loaded, err = cache.GetAccount(ctx, 17)
	require.NoError(t, err)
	require.Nil(t, loaded, "legacy cache must be a miss so the database is hydrated")
	tokens := ProvideProtectedGeminiTokenCache(rdb, p)
	require.NoError(t, tokens.SetAccessToken(ctx, "synthetic-subject", "synthetic-token", time.Minute))
	stored, err := rdb.Get(ctx, oauthTokenKeyPrefix+"synthetic-subject").Result()
	require.NoError(t, err)
	require.NotContains(t, stored, "synthetic-token")
	value, err := tokens.GetAccessToken(ctx, "synthetic-subject")
	require.NoError(t, err)
	require.Equal(t, "synthetic-token", value)
	require.NoError(t, rdb.Set(ctx, oauthTokenKeyPrefix+"synthetic-subject", "legacy-token", time.Minute).Err())
	_, err = tokens.GetAccessToken(ctx, "synthetic-subject")
	require.ErrorIs(t, err, redis.Nil)
	require.Equal(t, "synthetic-access", account.Credentials["access_token"], "cache writes must not mutate callers")
}

func TestProtectedCachesRejectTamperingAndRelocation(t *testing.T) {
	server := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { rdb.Close() })
	p := syntheticCredentialProtector(t, "v1", false)
	cache := NewSchedulerCache(rdb).(*schedulerCache)
	cache.protector = p
	ctx := context.Background()
	account := &service.Account{ID: 17, Credentials: map[string]any{"api_key": "synthetic-cached-api", "access_token": "synthetic-cached-access"}}
	require.NoError(t, cache.SetAccount(ctx, account))
	full, err := rdb.Get(ctx, schedulerAccountKey("17")).Result()
	require.NoError(t, err)
	require.NoError(t, rdb.Set(ctx, schedulerAccountKey("18"), full, 0).Err())
	_, err = cache.GetAccount(ctx, 18)
	require.ErrorIs(t, err, credentialcrypto.ErrProtection)
	var relocated service.Account
	require.NoError(t, json.Unmarshal([]byte(full), &relocated))
	relocated.ID = 18
	payload, err := json.Marshal(relocated)
	require.NoError(t, err)
	require.NoError(t, rdb.Set(ctx, schedulerAccountKey("18"), payload, 0).Err())
	_, err = cache.GetAccount(ctx, 18)
	require.ErrorIs(t, err, credentialcrypto.ErrProtection)
	var corrupt service.Account
	require.NoError(t, json.Unmarshal([]byte(full), &corrupt))
	corrupt.Credentials[credentialcrypto.EnvelopeKey].(map[string]any)["ciphertext"] = "broken"
	payload, err = json.Marshal(corrupt)
	require.NoError(t, err)
	require.NoError(t, rdb.Set(ctx, schedulerAccountKey("17"), payload, 0).Err())
	_, err = cache.GetAccount(ctx, 17)
	require.ErrorIs(t, err, credentialcrypto.ErrProtection)
	tokens := ProvideProtectedGeminiTokenCache(rdb, p)
	require.NoError(t, tokens.SetAccessToken(ctx, "synthetic-origin", "synthetic-cached-token", time.Minute))
	sealed, err := rdb.Get(ctx, oauthTokenKeyPrefix+"synthetic-origin").Result()
	require.NoError(t, err)
	require.NoError(t, rdb.Set(ctx, oauthTokenKeyPrefix+"synthetic-target", sealed, time.Minute).Err())
	_, err = tokens.GetAccessToken(ctx, "synthetic-target")
	require.ErrorIs(t, err, credentialcrypto.ErrProtection)
}
