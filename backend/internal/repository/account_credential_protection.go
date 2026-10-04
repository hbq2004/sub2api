package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"time"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/credentialcrypto"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/lib/pq"
)

func ProvideAccountCredentialProtector(cfg *config.Config) (*credentialcrypto.Protector, error) {
	forbidden := []string{os.Getenv("REDEEM_CODE_ENCRYPTION_KEY"), os.Getenv("REDEEM_CODE_HMAC_KEY")}
	if cfg != nil {
		forbidden = append(forbidden, cfg.Totp.EncryptionKey, cfg.JWT.Secret)
	}
	return credentialcrypto.LoadFromEnv(forbidden...)
}

func ProvideAccountRepository(client *dbent.Client, db *sql.DB, cache service.SchedulerCache, protector *credentialcrypto.Protector) (service.AccountRepository, error) {
	repo := newAccountRepositoryWithSQL(client, db, cache)
	repo.protector = protector
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	// Check every historical row too, before any background writer can start.
	if _, err := MigrateAccountCredentials(ctx, db, protector, "verify", false); err != nil {
		return nil, err
	}
	return repo, nil
}

func ProvideAdminAccountRepository(client *dbent.Client, db *sql.DB, cache service.SchedulerCache, protector *credentialcrypto.Protector) service.AdminAccountRepository {
	repo := newAccountRepositoryWithSQL(client, db, cache)
	repo.protector = protector
	return repo
}

func (r *accountRepository) accountToService(m *dbent.Account) (*service.Account, error) {
	out := accountEntityToService(m)
	if out == nil || m.Credentials == nil {
		// Metadata-only Ent projections deliberately omit the credential column.
		return out, nil
	}
	credentials, err := r.protector.Decrypt(m.ID, m.Credentials)
	if err != nil {
		return nil, err
	}
	out.Credentials = credentials
	return out, nil
}

func (r *accountRepository) createProtectedAccount(ctx context.Context, account *service.Account) error {
	client := clientFromContext(ctx, r.client)
	var tx *dbent.Tx
	if dbent.TxFromContext(ctx) == nil {
		var err error
		tx, err = client.Tx(ctx)
		if err != nil && !errors.Is(err, dbent.ErrTxStarted) {
			return err
		}
		if tx != nil {
			defer func() { _ = tx.Rollback() }()
			ctx = dbent.NewTxContext(ctx, tx)
			client = tx.Client()
		}
	}
	if err := r.createAccountRecord(ctx, client, account); err != nil {
		return err
	}
	if err := enqueueSchedulerOutbox(ctx, client, service.SchedulerOutboxEventAccountChanged, &account.ID, nil, buildSchedulerGroupPayload(account.GroupIDs)); err != nil {
		return err
	}
	if tx != nil {
		return tx.Commit()
	}
	return nil
}

// Resolve a plaintext expectation to the exact stored ciphertext. Re-encrypting
// an expectation would invalidate JSONB CAS because GCM uses random nonces.
// The final SQL equality still rejects changes occurring after this read.
func (r *accountRepository) credentialSnapshot(ctx context.Context, q sqlQueryer, id int64, expected map[string]any) (map[string]any, error) {
	if r.protector == nil {
		return r.protector.Encrypt(id, expected)
	}
	var raw []byte
	err := scanSingleRow(ctx, q, "SELECT credentials FROM accounts WHERE id = $1 AND deleted_at IS NULL", []any{id}, &raw)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if err == nil {
		var stored map[string]any
		if json.Unmarshal(raw, &stored) != nil {
			return nil, credentialcrypto.ErrProtection
		}
		plain, err := r.protector.Decrypt(id, stored)
		if err != nil {
			return nil, err
		}
		actualJSON, _ := json.Marshal(plain)
		expectedJSON, err := json.Marshal(normalizeJSONMap(expected))
		if err != nil {
			return nil, credentialcrypto.ErrProtection
		}
		if bytes.Equal(actualJSON, expectedJSON) {
			return stored, nil
		}
	}
	return r.protector.Encrypt(id, expected)
}

func (r *accountRepository) credentialSnapshotJSON(ctx context.Context, q sqlQueryer, id int64, expected map[string]any) ([]byte, error) {
	stored, err := r.credentialSnapshot(ctx, q, id, expected)
	if err != nil {
		return nil, err
	}
	return json.Marshal(stored)
}

// Upgrade a legacy row under the edit's transaction lock so SQL compares HMAC
// identities consistently and does not discard unchanged usage state.
func (r *accountRepository) ensureProtectedCredentialRow(ctx context.Context, client *dbent.Client, id int64) error {
	if r.protector == nil {
		return nil
	}
	var raw []byte
	if err := scanSingleRow(ctx, client, "SELECT credentials FROM accounts WHERE id = $1 AND deleted_at IS NULL FOR NO KEY UPDATE", []any{id}, &raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return service.ErrAccountNotFound
		}
		return err
	}
	var stored map[string]any
	if json.Unmarshal(raw, &stored) != nil {
		return credentialcrypto.ErrProtection
	}
	plain, err := r.protector.Decrypt(id, stored)
	if err != nil {
		return err
	}
	if credentialcrypto.IsProtected(stored) {
		return nil
	}
	protected, err := r.protector.Encrypt(id, plain)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(protected)
	if err != nil {
		return credentialcrypto.ErrProtection
	}
	_, err = client.ExecContext(ctx, "UPDATE accounts SET credentials = $1::jsonb WHERE id = $2 AND deleted_at IS NULL", string(encoded), id)
	return err
}

func (r *accountRepository) grokSnapshotJSON(ctx context.Context, id int64, raw string) (string, error) {
	if r.protector == nil {
		return raw, nil
	}
	var expected map[string]any
	if json.Unmarshal([]byte(raw), &expected) != nil {
		return "", credentialcrypto.ErrProtection
	}
	stored, err := r.credentialSnapshotJSON(ctx, r.sql, id, expected)
	return string(stored), err
}

func (r *accountRepository) apiKeyMatchSQL(expression, placeholder string) string {
	if r.protector == nil {
		return expression + " = " + placeholder
	}
	return expression + " = ANY(" + placeholder + ")"
}

func (r *accountRepository) apiKeyMatchArg(key string) any {
	if r.protector == nil {
		return key
	}
	return pq.Array(r.protector.LookupCandidates(key))
}

// Protected documents must be merged under row locks, not by JSONB ||, which
// would leave the sealed document stale and could expose the incoming token.
func (r *accountRepository) bulkUpdateProtectedCredentials(ctx context.Context, ids []int64, updates service.AccountBulkUpdate) (int64, error) {
	baseCtx := ctx
	contextTx := dbent.TxFromContext(ctx)
	client := clientFromContext(ctx, r.client)
	var tx *dbent.Tx
	if contextTx == nil {
		var err error
		tx, err = client.Tx(ctx)
		if err != nil && !errors.Is(err, dbent.ErrTxStarted) {
			return 0, err
		}
		if tx != nil {
			defer func() { _ = tx.Rollback() }()
			ctx = dbent.NewTxContext(ctx, tx)
			client = tx.Client()
		}
	}
	rows, err := client.QueryContext(ctx, "SELECT id, type, credentials FROM accounts WHERE id = ANY($1) AND deleted_at IS NULL ORDER BY id FOR NO KEY UPDATE", pq.Array(ids))
	if err != nil {
		return 0, err
	}
	type document struct {
		id          int64
		kind        string
		credentials map[string]any
	}
	documents := make([]document, 0, len(ids))
	for rows.Next() {
		var d document
		var raw []byte
		if err := rows.Scan(&d.id, &d.kind, &raw); err != nil {
			_ = rows.Close()
			return 0, err
		}
		if json.Unmarshal(raw, &d.credentials) != nil {
			_ = rows.Close()
			return 0, credentialcrypto.ErrProtection
		}
		documents = append(documents, d)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return 0, err
	}
	for _, d := range documents {
		if updates.ProbeEnabled != nil && d.kind != service.AccountTypeAPIKey {
			return 0, service.ErrUpstreamBillingProbeAccountInvalid
		}
		plain, err := r.protector.Decrypt(d.id, d.credentials)
		if err != nil {
			return 0, err
		}
		for key, value := range updates.Credentials {
			plain[key] = value
		}
		if err := r.UpdateCredentials(ctx, d.id, plain); err != nil {
			return 0, err
		}
	}
	updates.Credentials = nil
	if _, err := r.BulkUpdate(ctx, ids, updates); err != nil {
		return 0, err
	}
	if tx != nil {
		if err := tx.Commit(); err != nil {
			return 0, err
		}
	}
	if contextTx == nil && tx != nil {
		for _, d := range documents {
			r.syncSchedulerAccountSnapshotDetached(baseCtx, d.id)
		}
	}
	return int64(len(documents)), nil
}
