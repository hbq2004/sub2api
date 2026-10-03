package repository

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"errors"
	"strings"
	"time"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/ent/redeemcode"
	"github.com/Wei-Shaw/sub2api/ent/user"
	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/pagination"
	"github.com/Wei-Shaw/sub2api/internal/service"

	entsql "entgo.io/ent/dialect/sql"
)

type redeemCodeRepository struct {
	client    *dbent.Client
	protector *redeemCodeProtector
}

func NewRedeemCodeRepository(client *dbent.Client) service.RedeemCodeRepository {
	return &redeemCodeRepository{client: client}
}

func ProvideRedeemCodeRepository(client *dbent.Client, cfg *config.Config) (service.RedeemCodeRepository, error) {
	protector, err := newRedeemCodeProtectorFromEnv()
	if err != nil {
		return nil, err
	}
	if cfg != nil {
		totpKey, err := decodeRedeemCodeKey(cfg.Totp.EncryptionKey, "TOTP_ENCRYPTION_KEY")
		if err != nil {
			return nil, err
		}
		if hmac.Equal(protector.hmacKey, totpKey) || hmac.Equal(protector.encryptionKey, totpKey) {
			return nil, errors.New("redeem code protection keys must not reuse the TOTP encryption key")
		}
	}
	repo := &redeemCodeRepository{client: client, protector: protector}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := repo.verifyProtectedCodes(ctx); err != nil {
		return nil, err
	}
	if err := repo.backfillLegacyCodes(ctx); err != nil {
		return nil, err
	}
	return repo, nil
}

func (r *redeemCodeRepository) Create(ctx context.Context, code *service.RedeemCode) error {
	if r.protector != nil {
		storedCode, err := r.protector.encrypt(code.Code)
		if err != nil {
			return err
		}
		client := clientFromContext(ctx, r.client)
		rows, err := client.QueryContext(ctx, `INSERT INTO redeem_codes (code, code_hash, code_key_version, type, value, status, notes, validity_days, expires_at, used_by, used_at, group_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING id, created_at`, storedCode, r.protector.digest(code.Code), redeemCodeProtectionKeyVersion, code.Type, code.Value, code.Status, code.Notes, code.ValidityDays, code.ExpiresAt, code.UsedBy, code.UsedAt, code.GroupID)
		if err != nil {
			return err
		}
		defer rows.Close()
		if !rows.Next() {
			if err := rows.Err(); err != nil {
				return err
			}
			return sql.ErrNoRows
		}
		return rows.Scan(&code.ID, &code.CreatedAt)
	}
	created, err := r.client.RedeemCode.Create().
		SetCode(code.Code).
		SetType(code.Type).
		SetValue(code.Value).
		SetStatus(code.Status).
		SetNotes(code.Notes).
		SetValidityDays(code.ValidityDays).
		SetNillableExpiresAt(code.ExpiresAt).
		SetNillableUsedBy(code.UsedBy).
		SetNillableUsedAt(code.UsedAt).
		SetNillableGroupID(code.GroupID).
		Save(ctx)
	if err == nil {
		code.ID = created.ID
		code.CreatedAt = created.CreatedAt
	}
	return err
}

func (r *redeemCodeRepository) CreateBatch(ctx context.Context, codes []service.RedeemCode) error {
	if len(codes) == 0 {
		return nil
	}
	if r.protector != nil {
		if dbent.TxFromContext(ctx) != nil {
			for i := range codes {
				if err := r.Create(ctx, &codes[i]); err != nil {
					return err
				}
			}
			return nil
		}
		tx, err := r.client.Tx(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		txCtx := dbent.NewTxContext(ctx, tx)
		for i := range codes {
			if err := r.Create(txCtx, &codes[i]); err != nil {
				return err
			}
		}
		return tx.Commit()
	}

	builders := make([]*dbent.RedeemCodeCreate, 0, len(codes))
	for i := range codes {
		c := &codes[i]
		b := r.client.RedeemCode.Create().
			SetCode(c.Code).
			SetType(c.Type).
			SetValue(c.Value).
			SetStatus(c.Status).
			SetNotes(c.Notes).
			SetValidityDays(c.ValidityDays).
			SetNillableExpiresAt(c.ExpiresAt).
			SetNillableUsedBy(c.UsedBy).
			SetNillableUsedAt(c.UsedAt).
			SetNillableGroupID(c.GroupID)
		builders = append(builders, b)
	}

	return r.client.RedeemCode.CreateBulk(builders...).Exec(ctx)
}

func (r *redeemCodeRepository) GetByID(ctx context.Context, id int64) (*service.RedeemCode, error) {
	client := clientFromContext(ctx, r.client)
	m, err := client.RedeemCode.Query().
		Where(redeemcode.IDEQ(id)).
		Only(ctx)
	if err != nil {
		if dbent.IsNotFound(err) {
			return nil, service.ErrRedeemCodeNotFound
		}
		return nil, err
	}
	code, err := r.entityToService(ctx, m)
	return code, err
}

func (r *redeemCodeRepository) GetByCode(ctx context.Context, code string) (*service.RedeemCode, error) {
	if r.protector != nil {
		id, err := r.idByHash(ctx, code)
		if err == sql.ErrNoRows {
			return nil, service.ErrRedeemCodeNotFound
		}
		if err != nil {
			return nil, err
		}
		return r.GetByID(ctx, id)
	}
	m, err := r.client.RedeemCode.Query().
		Where(redeemcode.CodeEQ(code)).
		Only(ctx)
	if err != nil {
		if dbent.IsNotFound(err) {
			return nil, service.ErrRedeemCodeNotFound
		}
		return nil, err
	}
	return r.entityToService(ctx, m)
}

func (r *redeemCodeRepository) idByHash(ctx context.Context, code string) (int64, error) {
	client := clientFromContext(ctx, r.client)
	rows, err := client.QueryContext(ctx, `SELECT id FROM redeem_codes WHERE code_hash = $1`, r.protector.digest(code))
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return 0, err
		}
		return 0, sql.ErrNoRows
	}
	var id int64
	err = rows.Scan(&id)
	return id, err
}

func (r *redeemCodeRepository) Delete(ctx context.Context, id int64) error {
	_, err := r.client.RedeemCode.Delete().Where(redeemcode.IDEQ(id)).Exec(ctx)
	return err
}

func (r *redeemCodeRepository) List(ctx context.Context, params pagination.PaginationParams) ([]service.RedeemCode, *pagination.PaginationResult, error) {
	return r.ListWithFilters(ctx, params, "", "", "")
}

func (r *redeemCodeRepository) ListWithFilters(ctx context.Context, params pagination.PaginationParams, codeType, status, search string) ([]service.RedeemCode, *pagination.PaginationResult, error) {
	q := r.client.RedeemCode.Query()

	if codeType != "" {
		q = q.Where(redeemcode.TypeEQ(codeType))
	}
	if status != "" {
		now := time.Now()
		switch status {
		case service.StatusExpired:
			q = q.Where(redeemcode.Or(
				redeemcode.StatusEQ(service.StatusExpired),
				redeemcode.And(
					redeemcode.StatusEQ(service.StatusUnused),
					redeemcode.ExpiresAtNotNil(),
					redeemcode.ExpiresAtLTE(now),
				),
			))
		case service.StatusUnused:
			q = q.Where(
				redeemcode.StatusEQ(service.StatusUnused),
				redeemcode.Or(
					redeemcode.ExpiresAtIsNil(),
					redeemcode.ExpiresAtGT(now),
				),
			)
		default:
			q = q.Where(redeemcode.StatusEQ(status))
		}
	}
	if search != "" {
		if r.protector != nil {
			id, err := r.idByHash(ctx, search)
			if err != nil && err != sql.ErrNoRows {
				return nil, nil, err
			}
			if err == sql.ErrNoRows {
				q = q.Where(redeemcode.HasUserWith(user.EmailContainsFold(search)))
			} else {
				q = q.Where(redeemcode.Or(
					redeemcode.IDEQ(id),
					redeemcode.HasUserWith(user.EmailContainsFold(search)),
				))
			}
		} else {
			q = q.Where(redeemcode.Or(
				redeemcode.CodeContainsFold(search),
				redeemcode.HasUserWith(user.EmailContainsFold(search)),
			))
		}
	}

	total, err := q.Count(ctx)
	if err != nil {
		return nil, nil, err
	}

	codesQuery := q.
		WithUser().
		WithGroup().
		Offset(params.Offset()).
		Limit(params.Limit())
	for _, order := range redeemCodeListOrder(params) {
		codesQuery = codesQuery.Order(order)
	}

	codes, err := codesQuery.All(ctx)
	if err != nil {
		return nil, nil, err
	}

	outCodes, err := r.entitiesToService(ctx, codes)
	if err != nil {
		return nil, nil, err
	}

	return outCodes, paginationResultFromTotal(int64(total), params), nil
}

func redeemCodeListOrder(params pagination.PaginationParams) []func(*entsql.Selector) {
	sortBy := strings.ToLower(strings.TrimSpace(params.SortBy))
	sortOrder := params.NormalizedSortOrder(pagination.SortOrderDesc)

	var field string
	switch sortBy {
	case "type":
		field = redeemcode.FieldType
	case "value":
		field = redeemcode.FieldValue
	case "status":
		field = redeemcode.FieldStatus
	case "used_at":
		field = redeemcode.FieldUsedAt
	case "created_at":
		field = redeemcode.FieldCreatedAt
	case "expires_at":
		field = redeemcode.FieldExpiresAt
	case "code":
		field = redeemcode.FieldID
	default:
		field = redeemcode.FieldID
	}

	if sortOrder == pagination.SortOrderAsc {
		return []func(*entsql.Selector){dbent.Asc(field), dbent.Asc(redeemcode.FieldID)}
	}
	return []func(*entsql.Selector){dbent.Desc(field), dbent.Desc(redeemcode.FieldID)}
}

func (r *redeemCodeRepository) Update(ctx context.Context, code *service.RedeemCode) error {
	client := clientFromContext(ctx, r.client)
	up := client.RedeemCode.UpdateOneID(code.ID).
		SetType(code.Type).
		SetValue(code.Value).
		SetStatus(code.Status).
		SetNotes(code.Notes).
		SetValidityDays(code.ValidityDays)

	if code.UsedBy != nil {
		up.SetUsedBy(*code.UsedBy)
	} else {
		up.ClearUsedBy()
	}
	if code.UsedAt != nil {
		up.SetUsedAt(*code.UsedAt)
	} else {
		up.ClearUsedAt()
	}
	if code.GroupID != nil {
		up.SetGroupID(*code.GroupID)
	} else {
		up.ClearGroupID()
	}
	if code.ExpiresAt != nil {
		up.SetExpiresAt(*code.ExpiresAt)
	} else {
		up.ClearExpiresAt()
	}

	updated, err := up.Save(ctx)
	if err != nil {
		if dbent.IsNotFound(err) {
			return service.ErrRedeemCodeNotFound
		}
		return err
	}
	code.CreatedAt = updated.CreatedAt
	return nil
}

func (r *redeemCodeRepository) BatchUpdate(ctx context.Context, ids []int64, fields service.RedeemCodeBatchUpdateFields) (int64, error) {
	uniqueIDs := make([]int64, 0, len(ids))
	seen := make(map[int64]struct{}, len(ids))
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		uniqueIDs = append(uniqueIDs, id)
	}
	if len(uniqueIDs) == 0 {
		return 0, nil
	}

	if tx := dbent.TxFromContext(ctx); tx != nil {
		return r.batchUpdate(ctx, tx.Client(), uniqueIDs, fields)
	}

	tx, err := r.client.Tx(ctx)
	if err != nil {
		return 0, err
	}
	txCtx := dbent.NewTxContext(ctx, tx)
	defer func() { _ = tx.Rollback() }()

	updated, err := r.batchUpdate(txCtx, tx.Client(), uniqueIDs, fields)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return updated, nil
}

func (r *redeemCodeRepository) batchUpdate(ctx context.Context, client *dbent.Client, ids []int64, fields service.RedeemCodeBatchUpdateFields) (int64, error) {
	existing, err := client.RedeemCode.Query().
		Where(redeemcode.IDIn(ids...)).
		All(ctx)
	if err != nil {
		return 0, err
	}
	if len(existing) != len(ids) {
		return 0, service.ErrRedeemCodeNotFound
	}
	if fields.TouchesUsedSensitiveFields() {
		for _, code := range existing {
			if code.Status == service.StatusUsed {
				return 0, service.ErrRedeemCodeUsed
			}
		}
	}

	up := client.RedeemCode.Update().Where(redeemcode.IDIn(ids...))
	if fields.Status != nil {
		up.SetStatus(*fields.Status)
	}
	if fields.Notes != nil {
		up.SetNotes(*fields.Notes)
	}
	if fields.ExpiresAt.Set {
		if fields.ExpiresAt.Value != nil {
			up.SetExpiresAt(*fields.ExpiresAt.Value)
		} else {
			up.ClearExpiresAt()
		}
	}
	if fields.GroupID.Set {
		if fields.GroupID.Value != nil {
			up.SetGroupID(*fields.GroupID.Value)
		} else {
			up.ClearGroupID()
		}
	}

	affected, err := up.Save(ctx)
	if err != nil {
		return 0, err
	}
	if affected != len(ids) {
		return 0, service.ErrRedeemCodeNotFound
	}
	return int64(affected), nil
}

func (r *redeemCodeRepository) Use(ctx context.Context, id, userID int64) error {
	now := time.Now()
	client := clientFromContext(ctx, r.client)
	affected, err := client.RedeemCode.Update().
		Where(redeemcode.IDEQ(id), redeemcode.StatusEQ(service.StatusUnused)).
		SetStatus(service.StatusUsed).
		SetUsedBy(userID).
		SetUsedAt(now).
		Save(ctx)
	if err != nil {
		return err
	}
	if affected == 0 {
		return service.ErrRedeemCodeUsed
	}
	return nil
}

func (r *redeemCodeRepository) ListByUser(ctx context.Context, userID int64, limit int) ([]service.RedeemCode, error) {
	if limit <= 0 {
		limit = 10
	}

	codes, err := r.client.RedeemCode.Query().
		Where(redeemcode.UsedByEQ(userID)).
		WithGroup().
		Order(dbent.Desc(redeemcode.FieldUsedAt), dbent.Desc(redeemcode.FieldID)).
		Limit(limit).
		All(ctx)
	if err != nil {
		return nil, err
	}

	return r.entitiesToService(ctx, codes)
}

// ListByUserPaginated returns paginated balance/concurrency history for a user.
// Supports optional type filter (e.g. "balance", "admin_balance", "concurrency", "admin_concurrency", "subscription").
func (r *redeemCodeRepository) ListByUserPaginated(ctx context.Context, userID int64, params pagination.PaginationParams, codeType string) ([]service.RedeemCode, *pagination.PaginationResult, error) {
	q := r.client.RedeemCode.Query().
		Where(redeemcode.UsedByEQ(userID))

	// Optional type filter
	if codeType != "" {
		q = q.Where(redeemcode.TypeEQ(codeType))
	}

	total, err := q.Count(ctx)
	if err != nil {
		return nil, nil, err
	}

	codes, err := q.
		WithGroup().
		Offset(params.Offset()).
		Limit(params.Limit()).
		Order(dbent.Desc(redeemcode.FieldUsedAt), dbent.Desc(redeemcode.FieldID)).
		All(ctx)
	if err != nil {
		return nil, nil, err
	}

	converted, err := r.entitiesToService(ctx, codes)
	if err != nil {
		return nil, nil, err
	}
	return converted, paginationResultFromTotal(int64(total), params), nil
}

// SumPositiveBalanceByUser returns total recharged amount (sum of value > 0 where type is balance/admin_balance).
func (r *redeemCodeRepository) SumPositiveBalanceByUser(ctx context.Context, userID int64) (float64, error) {
	var result []struct {
		Sum float64 `json:"sum"`
	}
	err := r.client.RedeemCode.Query().
		Where(
			redeemcode.UsedByEQ(userID),
			redeemcode.ValueGT(0),
			redeemcode.TypeIn("balance", "admin_balance"),
		).
		Aggregate(dbent.As(dbent.Sum(redeemcode.FieldValue), "sum")).
		Scan(ctx, &result)
	if err != nil {
		return 0, err
	}
	if len(result) == 0 {
		return 0, nil
	}
	return result[0].Sum, nil
}

func redeemCodeEntityToService(m *dbent.RedeemCode) *service.RedeemCode {
	if m == nil {
		return nil
	}
	out := &service.RedeemCode{
		ID:           m.ID,
		Code:         m.Code,
		Type:         m.Type,
		Value:        m.Value,
		Status:       m.Status,
		UsedBy:       m.UsedBy,
		UsedAt:       m.UsedAt,
		Notes:        derefString(m.Notes),
		CreatedAt:    m.CreatedAt,
		ExpiresAt:    m.ExpiresAt,
		GroupID:      m.GroupID,
		ValidityDays: m.ValidityDays,
	}
	if m.Edges.User != nil {
		out.User = userEntityToService(m.Edges.User)
	}
	if m.Edges.Group != nil {
		out.Group = groupEntityToService(m.Edges.Group)
	}
	return out
}

func (r *redeemCodeRepository) entityToService(ctx context.Context, model *dbent.RedeemCode) (*service.RedeemCode, error) {
	code := redeemCodeEntityToService(model)
	if code == nil || r.protector == nil {
		return code, nil
	}
	plain, err := r.plaintextCode(ctx, model.ID, model.Code)
	if err != nil {
		return nil, err
	}
	code.Code = plain
	return code, nil
}

func (r *redeemCodeRepository) entitiesToService(ctx context.Context, models []*dbent.RedeemCode) ([]service.RedeemCode, error) {
	out := make([]service.RedeemCode, 0, len(models))
	for i := range models {
		if s, err := r.entityToService(ctx, models[i]); err != nil {
			return nil, err
		} else if s != nil {
			out = append(out, *s)
		}
	}
	return out, nil
}

func (r *redeemCodeRepository) plaintextCode(ctx context.Context, id int64, stored string) (string, error) {
	client := clientFromContext(ctx, r.client)
	rows, err := client.QueryContext(ctx, `SELECT code_hash, code_key_version FROM redeem_codes WHERE id = $1`, id)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return "", err
		}
		return "", sql.ErrNoRows
	}
	var hash sql.NullString
	var version int
	if err := rows.Scan(&hash, &version); err != nil {
		return "", err
	}
	if err := rows.Close(); err != nil {
		return "", err
	}
	if version == redeemCodeProtectionKeyVersion && hash.Valid {
		return r.protector.decrypt(stored)
	}
	if version != 0 || hash.Valid {
		return "", errors.New("inconsistent redeem code protection metadata")
	}
	if err := r.protectLegacyCode(ctx, id, stored); err != nil {
		return "", err
	}
	return stored, nil
}

func (r *redeemCodeRepository) protectLegacyCode(ctx context.Context, id int64, plaintext string) error {
	if r.protector == nil {
		return nil
	}
	ciphertext, err := r.protector.encrypt(plaintext)
	if err != nil {
		return err
	}
	client := clientFromContext(ctx, r.client)
	result, err := client.ExecContext(ctx, `UPDATE redeem_codes SET code = $1, code_hash = $2, code_key_version = $3 WHERE id = $4 AND code_key_version = 0 AND code_hash IS NULL AND code = $5`, ciphertext, r.protector.digest(plaintext), redeemCodeProtectionKeyVersion, id, plaintext)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return errors.New("redeem code changed during legacy migration")
	}
	return nil
}

func (r *redeemCodeRepository) backfillLegacyCodes(ctx context.Context) error {
	if r.protector == nil {
		return nil
	}
	rows, err := r.client.QueryContext(ctx, `SELECT id, code, code_hash, code_key_version FROM redeem_codes WHERE code_key_version = 0 OR code_hash IS NULL`)
	if err != nil {
		return err
	}
	type legacyCode struct {
		id   int64
		code string
	}
	legacy := make([]legacyCode, 0)
	for rows.Next() {
		var id int64
		var plaintext string
		var hash sql.NullString
		var version int
		if err := rows.Scan(&id, &plaintext, &hash, &version); err != nil {
			_ = rows.Close()
			return err
		}
		if version != 0 || hash.Valid {
			_ = rows.Close()
			return errors.New("inconsistent redeem code protection metadata")
		}
		legacy = append(legacy, legacyCode{id: id, code: plaintext})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, item := range legacy {
		if err := r.protectLegacyCode(ctx, item.id, item.code); err != nil {
			return err
		}
	}
	return nil
}

func (r *redeemCodeRepository) verifyProtectedCodes(ctx context.Context) error {
	rows, err := r.client.QueryContext(ctx, `SELECT code, code_hash, code_key_version FROM redeem_codes WHERE code_key_version > 0`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var ciphertext, digest string
		var version int
		if err := rows.Scan(&ciphertext, &digest, &version); err != nil {
			return err
		}
		if version != redeemCodeProtectionKeyVersion {
			return errors.New("unsupported redeem code key version")
		}
		plaintext, err := r.protector.decrypt(ciphertext)
		if err != nil || !hmac.Equal([]byte(digest), []byte(r.protector.digest(plaintext))) {
			return errors.New("redeem code protection key mismatch or corrupted record")
		}
	}
	return rows.Err()
}
