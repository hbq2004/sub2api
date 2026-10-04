package repository

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"fmt"
	"strings"
	"time"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/ent/apikey"
	"github.com/Wei-Shaw/sub2api/internal/pkg/credentialcrypto"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

const downstreamKeyPrefix = "hmac-sha256:downstream:v1:"

func downstreamKeySubject(id int64) string { return fmt.Sprintf("downstream-api-key/%d", id) }

func ProvideProtectedAPIKeyRepository(client *dbent.Client, db *sql.DB, protector *credentialcrypto.Protector) (service.APIKeyRepository, error) {
	repo := newAPIKeyRepositoryWithSQL(client, db)
	repo.protector = protector
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if _, err := MigrateDownstreamAPIKeys(ctx, db, protector, false); err != nil {
		return nil, err
	}
	return repo, nil
}

// Migration verifies every envelope and changes only key material, atomically.
// Existing consumers keep the same bearer, balances, quotas, IDs and expiry.
func MigrateDownstreamAPIKeys(ctx context.Context, db *sql.DB, p *credentialcrypto.Protector, verifyOnly bool) (int, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(24220261004)"); err != nil {
		return 0, err
	}
	rows, err := tx.QueryContext(ctx, "SELECT id, key, key_ciphertext, deleted_at IS NOT NULL FROM api_keys ORDER BY id FOR UPDATE")
	if err != nil {
		return 0, err
	}
	type item struct {
		id              int64
		key, ciphertext string
		deleted         bool
	}
	var items []item
	for rows.Next() {
		var v item
		if err = rows.Scan(&v.id, &v.key, &v.ciphertext, &v.deleted); err != nil {
			_ = rows.Close()
			return 0, err
		}
		items = append(items, v)
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return 0, err
	}
	if err = rows.Close(); err != nil {
		return 0, err
	}
	changed := 0
	for _, v := range items {
		if v.deleted { // Erase recoverable material for revoked/soft-deleted identities.
			if p != nil && (!strings.HasPrefix(v.key, "deleted-") || v.ciphertext != "") {
				if _, err = tx.ExecContext(ctx, "UPDATE api_keys SET key=$1, key_ciphertext='', key_hint='' WHERE id=$2", fmt.Sprintf("deleted-protected-%d", v.id), v.id); err != nil {
					return 0, err
				}
			}
			continue
		}
		if strings.HasPrefix(v.key, downstreamKeyPrefix) {
			if p == nil {
				return 0, credentialcrypto.ErrKeyRequired
			}
			plain, openErr := p.OpenCache(downstreamKeySubject(v.id), v.ciphertext)
			if openErr != nil || !hmac.Equal([]byte(p.LookupDownstream(plain)), []byte(v.key)) {
				return 0, credentialcrypto.ErrProtection
			}
			continue
		}
		if p == nil {
			continue
		}
		if verifyOnly {
			return 0, credentialcrypto.ErrLegacy
		}
		if v.key == "" || v.ciphertext != "" {
			return 0, credentialcrypto.ErrProtection
		}
		ciphertext, sealErr := p.SealCache(downstreamKeySubject(v.id), v.key)
		if sealErr != nil {
			return 0, sealErr
		}
		if _, err = tx.ExecContext(ctx, "UPDATE api_keys SET key=$1, key_ciphertext=$2, key_hint=$3 WHERE id=$4", p.LookupDownstream(v.key), ciphertext, service.MaskAPIKey(v.key), v.id); err != nil {
			return 0, err
		}
		changed++
	}
	if verifyOnly {
		return 0, nil
	}
	return changed, tx.Commit()
}

func (r *apiKeyRepository) lookupIdentity(raw string) string {
	if r.protector == nil {
		return raw
	}
	return r.protector.LookupDownstream(raw)
}

func (r *apiKeyRepository) openKey(ctx context.Context, id int64, stored string) (string, error) {
	if !strings.HasPrefix(stored, downstreamKeyPrefix) {
		if r.protector != nil {
			return "", credentialcrypto.ErrLegacy
		}
		return stored, nil
	}
	if r.protector == nil {
		return "", credentialcrypto.ErrKeyRequired
	}
	var ciphertext string
	if err := scanSingleRow(ctx, clientFromContext(ctx, r.client), "SELECT key_ciphertext FROM api_keys WHERE id=$1 AND deleted_at IS NULL", []any{id}, &ciphertext); err != nil {
		return "", err
	}
	raw, err := r.protector.OpenCache(downstreamKeySubject(id), ciphertext)
	if err != nil || !hmac.Equal([]byte(r.protector.LookupDownstream(raw)), []byte(stored)) {
		return "", credentialcrypto.ErrProtection
	}
	return raw, nil
}

func (r *apiKeyRepository) protectedEntityToService(ctx context.Context, m *dbent.APIKey) (*service.APIKey, error) {
	result := apiKeyEntityToService(m)
	if m.Key == "" {
		return result, nil
	} // Auth projections deliberately omit key material.
	raw, err := r.openKey(ctx, m.ID, m.Key)
	if err != nil {
		return nil, err
	}
	result.Key = raw
	return result, nil
}

func (r *apiKeyRepository) createProtectedKey(ctx context.Context, key *service.APIKey) error {
	client := clientFromContext(ctx, r.client)
	var tx *dbent.Tx
	if dbent.TxFromContext(ctx) == nil {
		var err error
		tx, err = client.Tx(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		ctx = dbent.NewTxContext(ctx, tx)
		client = tx.Client()
	}
	raw := key.Key
	key.Key = r.lookupIdentity(raw)
	err := r.createRecord(ctx, key)
	key.Key = raw
	if err != nil {
		return err
	}
	ciphertext, err := r.protector.SealCache(downstreamKeySubject(key.ID), raw)
	if err != nil {
		return err
	}
	if _, err = client.ExecContext(ctx, "UPDATE api_keys SET key_ciphertext=$1, key_hint=$2 WHERE id=$3", ciphertext, service.MaskAPIKey(raw), key.ID); err != nil {
		return err
	}
	if tx != nil {
		return tx.Commit()
	}
	return nil
}

func (r *apiKeyRepository) keyStrings(ctx context.Context, q *dbent.APIKeyQuery) ([]string, error) {
	records, err := q.Select(apikey.FieldID, apikey.FieldKey).All(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(records))
	for _, record := range records {
		raw, err := r.openKey(ctx, record.ID, record.Key)
		if err != nil {
			return nil, err
		}
		result = append(result, raw)
	}
	return result, nil
}
