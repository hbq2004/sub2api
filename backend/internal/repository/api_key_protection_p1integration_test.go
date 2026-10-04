//go:build p1integration

package repository

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	dbent "github.com/Wei-Shaw/sub2api/ent"
	_ "github.com/Wei-Shaw/sub2api/ent/runtime"
	"github.com/Wei-Shaw/sub2api/internal/pkg/credentialcrypto"
	"github.com/Wei-Shaw/sub2api/internal/pkg/pagination"
	"github.com/Wei-Shaw/sub2api/internal/service"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func TestDownstreamKeyRealDatabaseMigrationAndRevocation(t *testing.T) {
	dsn := os.Getenv("P1_TEST_DATABASE_DSN")
	require.NotEmpty(t, dsn, "use a dedicated synthetic database")
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	defer db.Close()
	ctx := context.Background()
	require.NoError(t, ApplyMigrations(ctx, db))
	client := dbent.NewClient(dbent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	defer client.Close()
	u, err := client.User.Create().SetEmail("p1-synthetic@example.invalid").SetPasswordHash("synthetic-password-hash").Save(ctx)
	require.NoError(t, err)
	raw := "synthetic-api-key-retained-through-protection-migration"
	legacy := newAPIKeyRepositoryWithSQL(client, db)
	k := &service.APIKey{UserID: u.ID, Key: raw, Name: "legacy-migration", Status: service.StatusActive, Quota: 2, QuotaUsed: 0.25, RateLimit1d: 1}
	require.NoError(t, legacy.Create(ctx, k))
	p := syntheticCredentialProtector(t, "v1", false)
	count, err := MigrateDownstreamAPIKeys(ctx, db, p, false)
	require.NoError(t, err)
	require.Equal(t, 1, count)
	repo := newAPIKeyRepositoryWithSQL(client, db)
	repo.protector = p
	var stored, ciphertext, hint string
	require.NoError(t, db.QueryRow("SELECT key,key_ciphertext,key_hint FROM api_keys WHERE id=$1", k.ID).Scan(&stored, &ciphertext, &hint))
	require.Equal(t, p.LookupDownstream(raw), stored)
	require.NotContains(t, ciphertext, raw)
	require.Equal(t, service.MaskAPIKey(raw), hint)
	got, err := repo.GetByKey(ctx, raw)
	require.NoError(t, err)
	require.Equal(t, k.ID, got.ID)
	require.Equal(t, 0.25, got.QuotaUsed)
	require.Equal(t, 1.0, got.RateLimit1d)
	_, err = repo.GetByKeyForAuth(ctx, stored)
	require.ErrorIs(t, err, service.ErrAPIKeyNotFound)
	got, err = repo.GetByKeyForAuth(ctx, raw)
	require.NoError(t, err)
	require.Equal(t, k.ID, got.ID)
	require.Empty(t, got.Key, "auth snapshot never stores bearer material")
	ownerKey, owner, err := repo.GetKeyAndOwnerID(ctx, k.ID)
	require.NoError(t, err)
	require.Equal(t, raw, ownerKey)
	require.Equal(t, u.ID, owner)
	keys, _, err := repo.ListByUserID(ctx, u.ID, pagination.PaginationParams{Page: 1, PageSize: 10}, service.APIKeyListFilters{})
	require.NoError(t, err)
	require.Equal(t, raw, keys[0].Key)
	stringsForInvalidation, err := repo.ListKeysByUserID(ctx, u.ID)
	require.NoError(t, err)
	require.Equal(t, []string{raw}, stringsForInvalidation)
	count, err = MigrateDownstreamAPIKeys(ctx, db, p, false)
	require.NoError(t, err)
	require.Zero(t, count)
	_, err = MigrateDownstreamAPIKeys(ctx, db, nil, true)
	require.ErrorIs(t, err, credentialcrypto.ErrKeyRequired)
	state, err := repo.IncrementQuotaUsedAndGetState(ctx, k.ID, 2)
	require.NoError(t, err)
	require.Equal(t, raw, state.Key, "quota exhaustion invalidates the same auth identity")
	require.Equal(t, service.StatusAPIKeyQuotaExhausted, state.Status)
	fresh := &service.APIKey{UserID: u.ID, Key: "synthetic-new-downstream-protected-key", Name: "protected-create", Status: service.StatusActive}
	require.NoError(t, repo.Create(ctx, fresh))
	require.NoError(t, db.QueryRow("SELECT key_ciphertext FROM api_keys WHERE id=$1", fresh.ID).Scan(&ciphertext))
	require.NotContains(t, ciphertext, fresh.Key)
	require.NoError(t, repo.DeleteWithAudit(ctx, fresh.ID))
	_, err = repo.GetByKey(ctx, fresh.Key)
	require.ErrorIs(t, err, service.ErrAPIKeyNotFound)
	require.NoError(t, db.QueryRow("SELECT key_ciphertext FROM api_keys WHERE id=$1", fresh.ID).Scan(&ciphertext))
	require.Empty(t, ciphertext, "revocation erases recoverable bearer")

	// A later corrupt row must roll back the entire migration, including earlier legacy rows.
	_, err = db.Exec("UPDATE api_keys SET key=$1,key_ciphertext='' WHERE id=$2", raw, k.ID)
	require.NoError(t, err)
	bad := &service.APIKey{UserID: u.ID, Key: "synthetic-corrupt-envelope-row", Name: "tamper", Status: service.StatusActive}
	require.NoError(t, repo.Create(ctx, bad))
	_, err = db.Exec("UPDATE api_keys SET key_ciphertext='invalid' WHERE id=$1", bad.ID)
	require.NoError(t, err)
	_, err = MigrateDownstreamAPIKeys(ctx, db, p, false)
	require.Error(t, err)
	require.NoError(t, db.QueryRow("SELECT key FROM api_keys WHERE id=$1", k.ID).Scan(&stored))
	require.Equal(t, raw, stored, "failed migration leaves no partial updates")
	_, err = db.Exec("INSERT INTO idempotency_records(scope,idempotency_key_hash,request_fingerprint,status,response_body,expires_at) VALUES('user.api_keys.create','synthetic-hash','synthetic-fingerprint','succeeded',$1,$2)", `{"key":"synthetic-old-replayed-key","id":1}`, time.Now().Add(time.Hour))
	require.NoError(t, err)
	migration, err := os.ReadFile("../../migrations/242_downstream_api_key_protection.sql")
	require.NoError(t, err)
	_, err = db.Exec(string(migration))
	require.NoError(t, err)
	var response string
	require.NoError(t, db.QueryRow("SELECT response_body FROM idempotency_records WHERE scope='user.api_keys.create'").Scan(&response))
	require.NotContains(t, response, "synthetic-old-replayed-key")
}
