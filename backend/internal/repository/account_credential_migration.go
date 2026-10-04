package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/Wei-Shaw/sub2api/internal/pkg/credentialcrypto"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

// AccountCredentialMigrationReport contains counts only, never documents.
type AccountCredentialMigrationReport struct {
	Mode      string `json:"mode"`
	Rows      int64  `json:"rows"`
	Protected int64  `json:"protected"`
	Legacy    int64  `json:"legacy"`
	Rewritten int64  `json:"rewritten"`
}

// MigrateAccountCredentials verifies all rows, including soft-deleted accounts.
// Mutations run in one transaction with ordered locks and durable cache events.
// Application writers must be stopped before invoking a mutation mode.
func MigrateAccountCredentials(ctx context.Context, db *sql.DB, protector *credentialcrypto.Protector, mode string, allowPlaintextRollback bool) (AccountCredentialMigrationReport, error) {
	report := AccountCredentialMigrationReport{Mode: mode}
	switch mode {
	case "verify":
	case "encrypt", "reencrypt":
		if protector == nil {
			return report, credentialcrypto.ErrKeyRequired
		}
	case "decrypt":
		if protector == nil || !allowPlaintextRollback {
			return report, errors.New("plaintext rollback requires the keyring and explicit authorization")
		}
	default:
		return report, errors.New("unknown upstream credential migration mode")
	}
	if db == nil {
		return report, errors.New("upstream credential database is not configured")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: mode == "verify"})
	if err != nil {
		return report, err
	}
	defer func() { _ = tx.Rollback() }()
	query := "SELECT id, credentials FROM accounts ORDER BY id"
	if mode != "verify" {
		query += " FOR NO KEY UPDATE"
	}
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return report, err
	}
	type document struct {
		id     int64
		stored map[string]any
	}
	documents := make([]document, 0)
	for rows.Next() {
		var d document
		var raw []byte
		if err := rows.Scan(&d.id, &raw); err != nil {
			_ = rows.Close()
			return report, err
		}
		if json.Unmarshal(raw, &d.stored) != nil {
			_ = rows.Close()
			return report, credentialcrypto.ErrProtection
		}
		report.Rows++
		if credentialcrypto.IsProtected(d.stored) {
			report.Protected++
		} else {
			report.Legacy++
		}
		if mode == "verify" {
			if _, err := protector.Decrypt(d.id, d.stored); err != nil {
				_ = rows.Close()
				return report, err
			}
		} else {
			documents = append(documents, d)
		}
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return report, err
	}
	for _, d := range documents {
		protected := credentialcrypto.IsProtected(d.stored)
		reader := protector
		if mode == "decrypt" && !protected {
			// Explicit rollback retries may see plaintext after SQL committed.
			reader = nil
		}
		plain, err := reader.Decrypt(d.id, d.stored)
		if err != nil {
			return report, err
		}
		if (mode == "encrypt" && protected) || (mode == "reencrypt" && protector.IsCurrent(d.stored)) || (mode == "decrypt" && !protected) {
			continue
		}
		stored := plain
		if mode != "decrypt" {
			stored, err = protector.Encrypt(d.id, plain)
			if err != nil {
				return report, err
			}
		}
		encoded, err := json.Marshal(stored)
		if err != nil {
			return report, credentialcrypto.ErrProtection
		}
		if _, err := tx.ExecContext(ctx, "UPDATE accounts SET credentials = $1::jsonb, updated_at = NOW() WHERE id = $2", string(encoded), d.id); err != nil {
			return report, err
		}
		if err := enqueueSchedulerOutbox(ctx, tx, service.SchedulerOutboxEventAccountChanged, &d.id, nil, nil); err != nil {
			return report, err
		}
		report.Rewritten++
	}
	if err := tx.Commit(); err != nil {
		return report, err
	}
	return report, nil
}
