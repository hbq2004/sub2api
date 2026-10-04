//go:build integration

package repository

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/pkg/credentialcrypto"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func isolatedCredentialDatabase(t *testing.T) (*sql.DB, *dbent.Client) {
	t.Helper()
	name := fmt.Sprintf("credential_test_%d", time.Now().UnixNano())
	_, err := integrationDB.Exec("CREATE DATABASE " + pq.QuoteIdentifier(name))
	require.NoError(t, err)
	parsed, err := url.Parse(integrationDSN)
	require.NoError(t, err)
	parsed.Path = "/" + name
	db, err := sql.Open("postgres", parsed.String())
	require.NoError(t, err)
	require.NoError(t, ApplyMigrations(context.Background(), db))
	client := dbent.NewClient(dbent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	t.Cleanup(func() {
		client.Close()
		db.Close()
		_, err := integrationDB.Exec("DROP DATABASE " + pq.QuoteIdentifier(name) + " WITH (FORCE)")
		require.NoError(t, err)
	})
	return db, client
}

func createSyntheticCredentialAccount(t *testing.T, repo *accountRepository, name, platform, kind string, credentials map[string]any) *service.Account {
	t.Helper()
	account := &service.Account{Name: name, Platform: platform, Type: kind, Status: service.StatusActive, Schedulable: true, Concurrency: 1, Priority: 1, Credentials: credentials, Extra: map[string]any{}}
	require.NoError(t, repo.Create(context.Background(), account))
	return account
}

func storedCredentialJSON(t *testing.T, db *sql.DB, id int64) string {
	t.Helper()
	var raw string
	require.NoError(t, db.QueryRow("SELECT credentials::text FROM accounts WHERE id = $1", id).Scan(&raw))
	return raw
}

func TestAccountCredentialProtectionIntegration(t *testing.T) {
	db, client := isolatedCredentialDatabase(t)
	p := syntheticCredentialProtector(t, "v1", true)
	repo := newAccountRepositoryWithSQL(client, db, nil)
	repo.protector = p
	ctx := context.Background()

	t.Run("create-edit-bulk-refresh-candidates", func(t *testing.T) {
		account := createSyntheticCredentialAccount(t, repo, "protected-oauth", service.PlatformOpenAI, service.AccountTypeOAuth, map[string]any{"access_token": "synthetic-access", "refresh_token": "synthetic-refresh", "expires_at": "2099-01-01T00:00:00Z", "model_mapping": map[string]any{"test": "test"}})
		original := storedCredentialJSON(t, db, account.ID)
		require.NotContains(t, original, "synthetic-access")
		require.NotContains(t, original, "synthetic-refresh")
		loaded, err := repo.GetByID(ctx, account.ID)
		require.NoError(t, err)
		require.Equal(t, account.Credentials, loaded.Credentials)
		loaded.Name = "protected-oauth-renamed"
		require.NoError(t, repo.Update(ctx, loaded))
		require.JSONEq(t, original, storedCredentialJSON(t, db, account.ID), "metadata edits reuse ciphertext when the credential document is unchanged")
		page, err := repo.ListOAuthRefreshCandidatePage(ctx, service.OAuthRefreshPageOptions{Platforms: []string{service.PlatformOpenAI}, ActiveOnly: true, RequireRefreshToken: true, Limit: 20})
		require.NoError(t, err)
		require.Len(t, page.Accounts, 1)
		require.Equal(t, "synthetic-refresh", page.Accounts[0].Credentials["refresh_token"])
		count, err := repo.BulkUpdate(ctx, []int64{account.ID}, service.AccountBulkUpdate{Credentials: map[string]any{"access_token": "synthetic-bulk"}})
		require.NoError(t, err)
		require.Equal(t, int64(1), count)
		loaded, err = repo.GetByID(ctx, account.ID)
		require.NoError(t, err)
		require.Equal(t, "synthetic-bulk", loaded.Credentials["access_token"])
		require.Equal(t, "synthetic-refresh", loaded.Credentials["refresh_token"])
		require.NotContains(t, storedCredentialJSON(t, db, account.ID), "synthetic-bulk")
		empty := createSyntheticCredentialAccount(t, repo, "empty-refresh", service.PlatformOpenAI, service.AccountTypeOAuth, map[string]any{"access_token": "synthetic-only", "refresh_token": "  "})
		page, err = repo.ListOAuthRefreshCandidatePage(ctx, service.OAuthRefreshPageOptions{Platforms: []string{service.PlatformOpenAI}, ActiveOnly: true, RequireRefreshToken: true, Limit: 20})
		require.NoError(t, err)
		for _, candidate := range page.Accounts {
			require.NotEqual(t, empty.ID, candidate.ID)
		}
		copies, err := repo.GetByIDs(ctx, []int64{account.ID, empty.ID})
		require.NoError(t, err)
		require.Len(t, copies, 2)
		require.Equal(t, "synthetic-bulk", copies[0].Credentials["access_token"])
		duplicate := &service.Account{Name: "protected-copy", Platform: service.PlatformOpenAI, Type: service.AccountTypeOAuth, Status: service.StatusDisabled, Credentials: loaded.Credentials, Extra: map[string]any{}, Concurrency: 1}
		require.NoError(t, repo.CreateWithAccountGroups(ctx, duplicate, nil))
		copy, err := repo.GetByID(ctx, duplicate.ID)
		require.NoError(t, err)
		require.Equal(t, loaded.Credentials, copy.Credentials)
	})

	t.Run("refresh-CAS-one-winner-and-stale-error-rejection", func(t *testing.T) {
		credentials := map[string]any{"access_token": "synthetic-old-access", "refresh_token": "synthetic-old-refresh"}
		account := createSyntheticCredentialAccount(t, repo, "protected-grok", service.PlatformGrok, service.AccountTypeOAuth, credentials)
		var winners atomic.Int32
		var workers sync.WaitGroup
		for i := range 16 {
			workers.Add(1)
			go func(index int) {
				defer workers.Done()
				updated, err := repo.UpdateGrokOAuthCredentialsIfUnchanged(ctx, account.ID, credentials, nil, map[string]any{"access_token": fmt.Sprintf("synthetic-rotated-%d", index), "refresh_token": "synthetic-new-refresh"})
				if err != nil {
					t.Error(err)
					return
				}
				if updated {
					winners.Add(1)
				}
			}(i)
		}
		workers.Wait()
		require.Equal(t, int32(1), winners.Load())
		changed, err := repo.SetGrokOAuthRefreshErrorIfCredentialsUnchanged(ctx, account.ID, credentials, nil, "synthetic-stale-error")
		require.NoError(t, err)
		require.False(t, changed)
		loaded, err := repo.GetByID(ctx, account.ID)
		require.NoError(t, err)
		require.Equal(t, service.StatusActive, loaded.Status)
		require.Equal(t, "synthetic-new-refresh", loaded.Credentials["refresh_token"])
		require.NotContains(t, storedCredentialJSON(t, db, account.ID), "synthetic-new-refresh")
	})

	t.Run("concurrent-bulk-merges-retain-every-field", func(t *testing.T) {
		account := createSyntheticCredentialAccount(t, repo, "bulk-concurrency", service.PlatformOpenAI, service.AccountTypeOAuth, map[string]any{"refresh_token": "synthetic-retained"})
		var workers sync.WaitGroup
		for i := range 12 {
			workers.Add(1)
			go func(index int) {
				defer workers.Done()
				_, err := repo.BulkUpdate(ctx, []int64{account.ID}, service.AccountBulkUpdate{Credentials: map[string]any{fmt.Sprintf("synthetic_field_%d", index): "synthetic-value"}})
				if err != nil {
					t.Error(err)
				}
			}(i)
		}
		workers.Wait()
		loaded, err := repo.GetByID(ctx, account.ID)
		require.NoError(t, err)
		require.Len(t, loaded.Credentials, 13)
		require.NotContains(t, storedCredentialJSON(t, db, account.ID), "synthetic-value")
	})

	t.Run("legacy-upgrade-preserves-usage-state", func(t *testing.T) {
		legacyRepo := newAccountRepositoryWithSQL(client, db, nil)
		account := createSyntheticCredentialAccount(t, legacyRepo, "legacy-upgrade", service.PlatformOpenAI, service.AccountTypeAPIKey, map[string]any{"api_key": "synthetic-legacy", "base_url": "https://ollama.com/v1"})
		account.Extra = map[string]any{service.UpstreamBillingProbeExtraKey: map[string]any{"status": "ok"}, service.OllamaCloudUsageAutoRefreshExtraKey: true, service.OllamaCloudUsageSessionExtraKey: "synthetic-existing-encrypted-session"}
		extraJSON, err := json.Marshal(account.Extra)
		require.NoError(t, err)
		_, err = db.Exec("UPDATE accounts SET extra = $1::jsonb WHERE id = $2", string(extraJSON), account.ID)
		require.NoError(t, err)
		before, err := legacyRepo.GetByID(ctx, account.ID)
		require.NoError(t, err)
		require.NoError(t, repo.UpdateCredentials(ctx, account.ID, account.Credentials))
		loaded, err := repo.GetByID(ctx, account.ID)
		require.NoError(t, err)
		require.Equal(t, before.Extra, loaded.Extra)
		require.Equal(t, true, loaded.Extra[service.OllamaCloudUsageAutoRefreshExtraKey])
		require.Equal(t, "synthetic-existing-encrypted-session", loaded.Extra[service.OllamaCloudUsageSessionExtraKey])
		require.NotContains(t, storedCredentialJSON(t, db, account.ID), "synthetic-legacy")
	})

	t.Run("shared-api-key-grouping-and-billing-CAS", func(t *testing.T) {
		for _, provider := range []struct{ name, baseURL string }{{"ollama", "https://ollama.com/v1"}, {"opencode", "https://opencode.ai/zen/go/v1"}} {
			t.Run(provider.name, func(t *testing.T) {
				first := createSyntheticCredentialAccount(t, repo, provider.name+"-1", service.PlatformOpenAI, service.AccountTypeAPIKey, map[string]any{"api_key": "synthetic-shared-" + provider.name, "base_url": provider.baseURL})
				second := createSyntheticCredentialAccount(t, repo, provider.name+"-2", service.PlatformAnthropic, service.AccountTypeAPIKey, first.Credentials)
				var siblings []service.Account
				var err error
				if provider.name == "ollama" {
					siblings, err = repo.ListOllamaCloudUsageGroupAccounts(ctx, []*service.Account{first})
					require.NoError(t, err)
					require.Len(t, siblings, 2)
					require.NoError(t, repo.SaveOllamaCloudUsageSession(ctx, first, "synthetic-already-encrypted-session", true))
					due, err := repo.ListDueOllamaCloudUsageAccounts(ctx, time.Now(), time.Minute, time.Hour, 100)
					require.NoError(t, err)
					matches := 0
					for _, candidate := range due {
						if candidate.Credentials["api_key"] == first.Credentials["api_key"] {
							matches++
						}
					}
					require.Equal(t, 1, matches)
				} else {
					siblings, err = repo.ListOpenCodeGoUsageGroupAccounts(ctx, []*service.Account{first})
					require.NoError(t, err)
					require.Len(t, siblings, 2)
					require.NoError(t, repo.SetOpenCodeGoUsageAutoRefresh(ctx, first, true))
					due, err := repo.ListDueOpenCodeGoUsageAccounts(ctx, time.Now(), time.Minute, time.Hour, 100)
					require.NoError(t, err)
					require.Len(t, due, 1)
				}
				loaded, err := repo.GetByID(ctx, first.ID)
				require.NoError(t, err)
				require.NoError(t, repo.UpdateUpstreamBillingProbeSnapshot(ctx, loaded, &service.UpstreamBillingProbeSnapshot{Status: service.UpstreamBillingProbeStatusOK}, nil))
				loaded, err = repo.GetByID(ctx, second.ID)
				require.NoError(t, err)
				if provider.name == "opencode" {
					require.Equal(t, true, loaded.Extra[service.OpenCodeGoUsageAutoRefreshExtraKey])
				}
				require.Equal(t, first.Credentials, loaded.Credentials)
			})
		}
	})

	t.Run("missing-and-wrong-key-startup-and-independent-key-recovery", func(t *testing.T) {
		_, err := ProvideAccountRepository(client, db, nil, nil)
		require.ErrorIs(t, err, credentialcrypto.ErrKeyRequired)
		wrongJSON, err := json.Marshal(map[string]any{"active_key_id": "v1", "encryption_keys": map[string]string{"v1": strings.Repeat("04", 32)}, "lookup_key": strings.Repeat("02", 32)})
		require.NoError(t, err)
		wrong, err := credentialcrypto.Load(strings.NewReader(string(wrongJSON)), true)
		require.NoError(t, err)
		_, err = ProvideAccountRepository(client, db, nil, wrong)
		require.ErrorIs(t, err, credentialcrypto.ErrProtection)
		_, err = ProvideAccountRepository(client, db, nil, syntheticCredentialProtector(t, "v2", false))
		require.NoError(t, err, "a recovered keyring retaining old versions must decrypt historical rows")
		strictRepo := newAccountRepositoryWithSQL(client, db, nil)
		strictRepo.protector = syntheticCredentialProtector(t, "v2", false)
		metadata, err := strictRepo.ListOpsAccountsForStats(ctx, "", nil)
		require.NoError(t, err)
		require.NotEmpty(t, metadata)
		for _, account := range metadata {
			require.Nil(t, account.Credentials)
		}
	})
}

func TestAccountCredentialMigrationIntegration(t *testing.T) {
	db, client := isolatedCredentialDatabase(t)
	ctx := context.Background()
	p := syntheticCredentialProtector(t, "v1", true)
	legacyRepo := newAccountRepositoryWithSQL(client, db, nil)
	first := createSyntheticCredentialAccount(t, legacyRepo, "migration-first", service.PlatformOpenAI, service.AccountTypeOAuth, map[string]any{"access_token": "synthetic-migration", "refresh_token": "synthetic-migration-refresh"})
	second := createSyntheticCredentialAccount(t, legacyRepo, "migration-history", service.PlatformOpenAI, service.AccountTypeAPIKey, map[string]any{"api_key": "synthetic-history"})
	original := storedCredentialJSON(t, db, first.ID)
	_, err := db.Exec("UPDATE accounts SET deleted_at = NOW() WHERE id = $1", second.ID)
	require.NoError(t, err)
	report, err := MigrateAccountCredentials(ctx, db, p, "verify", false)
	require.NoError(t, err)
	require.Equal(t, int64(2), report.Legacy)
	require.JSONEq(t, original, storedCredentialJSON(t, db, first.ID))
	// The second row fails after the first rewrite, proving transaction rollback.
	invalid, err := p.Encrypt(second.ID+1, second.Credentials)
	require.NoError(t, err)
	invalidJSON, err := json.Marshal(invalid)
	require.NoError(t, err)
	_, err = db.Exec("UPDATE accounts SET credentials = $1::jsonb WHERE id = $2", string(invalidJSON), second.ID)
	require.NoError(t, err)
	_, err = MigrateAccountCredentials(ctx, db, p, "encrypt", false)
	require.ErrorIs(t, err, credentialcrypto.ErrProtection)
	require.JSONEq(t, original, storedCredentialJSON(t, db, first.ID))
	secondPlain, err := json.Marshal(second.Credentials)
	require.NoError(t, err)
	_, err = db.Exec("UPDATE accounts SET credentials = $1::jsonb WHERE id = $2", string(secondPlain), second.ID)
	require.NoError(t, err)
	report, err = MigrateAccountCredentials(ctx, db, p, "encrypt", false)
	require.NoError(t, err)
	require.Equal(t, int64(2), report.Rewritten)
	require.NotContains(t, storedCredentialJSON(t, db, first.ID), "synthetic-migration")
	require.NotContains(t, storedCredentialJSON(t, db, second.ID), "synthetic-history")
	report, err = MigrateAccountCredentials(ctx, db, p, "encrypt", false)
	require.NoError(t, err)
	require.Zero(t, report.Rewritten)
	rotated := syntheticCredentialProtector(t, "v2", false)
	report, err = MigrateAccountCredentials(ctx, db, rotated, "reencrypt", false)
	require.NoError(t, err)
	require.Equal(t, int64(2), report.Rewritten)
	var document map[string]any
	require.NoError(t, json.Unmarshal([]byte(storedCredentialJSON(t, db, first.ID)), &document))
	require.Equal(t, "v2", rotated.KeyID(document))
	_, err = MigrateAccountCredentials(ctx, db, rotated, "decrypt", false)
	require.Error(t, err)
	report, err = MigrateAccountCredentials(ctx, db, rotated, "decrypt", true)
	require.NoError(t, err)
	require.Equal(t, int64(2), report.Rewritten)
	require.JSONEq(t, original, storedCredentialJSON(t, db, first.ID))
	report, err = MigrateAccountCredentials(ctx, db, rotated, "decrypt", true)
	require.NoError(t, err, "an explicit rollback must be retryable after a post-commit cache purge failure")
	require.Zero(t, report.Rewritten)
	_, err = MigrateAccountCredentials(ctx, db, rotated, "verify", false)
	require.ErrorIs(t, err, credentialcrypto.ErrLegacy)
}

func TestAccountCredentialProtectionUsageMetadataIntegration(t *testing.T) {
	db, client := isolatedCredentialDatabase(t)
	repo := newAccountRepositoryWithSQL(client, db, nil)
	repo.protector = syntheticCredentialProtector(t, "v1", false)
	ctx := context.Background()
	for _, provider := range []struct {
		name, baseURL, eligibility string
		list                       func(context.Context, []*service.Account) ([]service.Account, error)
	}{
		{"ollama", " https://ollama.com/v1 ", ollamaCloudUsageEligibleSQL, repo.ListOllamaCloudUsageGroupAccounts},
		{"opencode", " HTTPS://OPENCODE.AI:443/ZeN/Go/V1/ ", opencodeGoUsageEligibleSQL, repo.ListOpenCodeGoUsageGroupAccounts},
	} {
		t.Run(provider.name, func(t *testing.T) {
			credentials := map[string]any{"api_key": "synthetic-padded-" + provider.name, "base_url": provider.baseURL}
			first := createSyntheticCredentialAccount(t, repo, provider.name+"-padded-1", service.PlatformOpenAI, service.AccountTypeAPIKey, credentials)
			second := createSyntheticCredentialAccount(t, repo, provider.name+"-padded-2", service.PlatformAnthropic, service.AccountTypeAPIKey, credentials)
			members, err := provider.list(ctx, []*service.Account{first})
			require.NoError(t, err)
			require.Len(t, members, 2)
			for _, account := range []*service.Account{first, second} {
				var eligible bool
				require.NoError(t, db.QueryRow("SELECT ("+provider.eligibility+") FROM accounts WHERE id = $1", account.ID).Scan(&eligible))
				require.True(t, eligible)
			}
		})
	}
	zen := createSyntheticCredentialAccount(t, repo, "padded-zen", service.PlatformOpenCodeGo, service.AccountTypeAPIKey, map[string]any{"api_key": "synthetic-zen", "account_mode": " zen "})
	var eligible bool
	require.NoError(t, db.QueryRow("SELECT ("+opencodeGoUsageEligibleSQL+") FROM accounts WHERE id = $1", zen.ID).Scan(&eligible))
	require.False(t, eligible, "a Zen account must not become a Go usage account after protection")
	loaded, err := repo.GetByID(ctx, zen.ID)
	require.NoError(t, err)
	require.Equal(t, zen.Credentials, loaded.Credentials)
}

func TestAccountCredentialMigrationUpgradesOldFormatIntegration(t *testing.T) {
	db, client := isolatedCredentialDatabase(t)
	ctx := context.Background()
	p := syntheticCredentialProtector(t, "v1", false)
	repo := newAccountRepositoryWithSQL(client, db, nil)
	repo.protector = p
	account := createSyntheticCredentialAccount(t, repo, "historical-format", service.PlatformOpenAI, service.AccountTypeOAuth, map[string]any{"access_token": "synthetic-format-one"})
	// Construct the previously shipped v1 format independently of the protector.
	block, err := aes.NewCipher([]byte(strings.Repeat("\x01", 32)))
	require.NoError(t, err)
	aead, err := cipher.NewGCMWithRandomNonce(block)
	require.NoError(t, err)
	plain, err := json.Marshal(account.Credentials)
	require.NoError(t, err)
	aad := []byte(fmt.Sprintf("sub2api/accounts/%d/credentials/v1/v1\x00{}", account.ID))
	old, err := json.Marshal(map[string]any{credentialcrypto.EnvelopeKey: map[string]any{
		"version": 1, "key_id": "v1", "ciphertext": base64.RawStdEncoding.EncodeToString(aead.Seal(nil, nil, plain, aad)),
	}})
	require.NoError(t, err)
	_, err = db.Exec("UPDATE accounts SET credentials = $1::jsonb WHERE id = $2", string(old), account.ID)
	require.NoError(t, err)
	_, err = ProvideAccountRepository(client, db, nil, p)
	require.NoError(t, err, "startup must continue to verify historical ciphertext")
	report, err := MigrateAccountCredentials(ctx, db, p, "reencrypt", false)
	require.NoError(t, err)
	require.Equal(t, int64(1), report.Rewritten, "the same AES key may still require a format upgrade")
	var stored map[string]any
	require.NoError(t, json.Unmarshal([]byte(storedCredentialJSON(t, db, account.ID)), &stored))
	require.True(t, p.IsCurrent(stored))
	loaded, err := repo.GetByID(ctx, account.ID)
	require.NoError(t, err)
	require.Equal(t, account.Credentials, loaded.Credentials)
	report, err = MigrateAccountCredentials(ctx, db, p, "reencrypt", false)
	require.NoError(t, err)
	require.Zero(t, report.Rewritten)
}

func TestAccountCredentialProtectionRestoreIntegration(t *testing.T) {
	sourceDB, sourceClient := isolatedCredentialDatabase(t)
	p := syntheticCredentialProtector(t, "v1", true)
	repo := newAccountRepositoryWithSQL(sourceClient, sourceDB, nil)
	repo.protector = p
	account := createSyntheticCredentialAccount(t, repo, "synthetic-backup-source", service.PlatformOpenAI, service.AccountTypeOAuth, map[string]any{"access_token": "synthetic-restore-access", "refresh_token": "synthetic-restore-refresh"})
	backup := storedCredentialJSON(t, sourceDB, account.ID)
	restoreDB, restoreClient := isolatedCredentialDatabase(t)
	_, err := restoreDB.Exec("INSERT INTO accounts(id, name, platform, type, credentials, extra, concurrency, priority, status) VALUES ($1, $2, $3, $4, $5::jsonb, '{}'::jsonb, 1, 1, 'active')", account.ID, "synthetic-restored", service.PlatformOpenAI, service.AccountTypeOAuth, backup)
	require.NoError(t, err)
	_, err = ProvideAccountRepository(restoreClient, restoreDB, nil, nil)
	require.ErrorIs(t, err, credentialcrypto.ErrKeyRequired)
	// This is a separately loaded recovery keyring, not the original object.
	recovered, err := ProvideAccountRepository(restoreClient, restoreDB, nil, syntheticCredentialProtector(t, "v2", false))
	require.NoError(t, err)
	loaded, err := recovered.GetByID(context.Background(), account.ID)
	require.NoError(t, err)
	require.Equal(t, account.Credentials, loaded.Credentials)
}

func TestAccountCredentialProtectionFailureAndStressIntegration(t *testing.T) {
	db, client := isolatedCredentialDatabase(t)
	repo := newAccountRepositoryWithSQL(client, db, nil)
	repo.protector = syntheticCredentialProtector(t, "v1", false)
	ctx := context.Background()
	t.Run("bulk-outbox-failure-rolls-back-every-row", func(t *testing.T) {
		first := createSyntheticCredentialAccount(t, repo, "fault-first", service.PlatformOpenAI, service.AccountTypeOAuth, map[string]any{"access_token": "synthetic-fault-first"})
		second := createSyntheticCredentialAccount(t, repo, "fault-second", service.PlatformOpenAI, service.AccountTypeOAuth, map[string]any{"access_token": "synthetic-fault-second"})
		before := []string{storedCredentialJSON(t, db, first.ID), storedCredentialJSON(t, db, second.ID)}
		var events int64
		require.NoError(t, db.QueryRow("SELECT count(*) FROM scheduler_outbox").Scan(&events))
		_, err := db.Exec(`CREATE FUNCTION credential_audit_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic credential outbox failure'; END $$`)
		require.NoError(t, err)
		_, err = db.Exec(fmt.Sprintf("CREATE TRIGGER credential_audit_fault BEFORE INSERT ON scheduler_outbox FOR EACH ROW WHEN (NEW.account_id = %d) EXECUTE FUNCTION credential_audit_fault()", second.ID))
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err := db.Exec("DROP TRIGGER IF EXISTS credential_audit_fault ON scheduler_outbox")
			require.NoError(t, err)
			_, err = db.Exec("DROP FUNCTION credential_audit_fault()")
			require.NoError(t, err)
		})
		_, err = repo.BulkUpdate(ctx, []int64{second.ID, first.ID}, service.AccountBulkUpdate{Credentials: map[string]any{"access_token": "synthetic-fault-new"}})
		require.Error(t, err)
		for i, account := range []*service.Account{first, second} {
			require.JSONEq(t, before[i], storedCredentialJSON(t, db, account.ID))
		}
		var after int64
		require.NoError(t, db.QueryRow("SELECT count(*) FROM scheduler_outbox").Scan(&after))
		require.Equal(t, events, after)
	})
	t.Run("reverse-order-concurrent-bulk-has-no-deadlocks-or-lost-fields", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		ids := make([]int64, 3)
		for i := range ids {
			account := createSyntheticCredentialAccount(t, repo, fmt.Sprintf("stress-%d", i), service.PlatformOpenAI, service.AccountTypeOAuth, map[string]any{"access_token": "synthetic-stress"})
			ids[i] = account.ID
		}
		var workers sync.WaitGroup
		for i := range 24 {
			workers.Add(1)
			go func(index int) {
				defer workers.Done()
				order := append([]int64(nil), ids...)
				if index%2 == 0 {
					order[0], order[2] = order[2], order[0]
				}
				count, err := repo.BulkUpdate(ctx, order, service.AccountBulkUpdate{Credentials: map[string]any{fmt.Sprintf("synthetic_stress_%d", index): "synthetic-value"}})
				if err != nil || count != 3 {
					t.Errorf("bulk update failed: count=%d error=%v", count, err)
				}
			}(i)
		}
		workers.Wait()
		for _, id := range ids {
			account, err := repo.GetByID(ctx, id)
			require.NoError(t, err)
			require.Len(t, account.Credentials, 25)
			require.NotContains(t, storedCredentialJSON(t, db, id), "synthetic-value")
		}
	})
}
