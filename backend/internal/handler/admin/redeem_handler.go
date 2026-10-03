package admin

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/handler/dto"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"

	"github.com/gin-gonic/gin"
)

// RedeemHandler handles admin redeem code management
type RedeemHandler struct {
	adminService  service.AdminService
	redeemService *service.RedeemService
}

// NewRedeemHandler creates a new admin redeem handler
func NewRedeemHandler(adminService service.AdminService, redeemService *service.RedeemService) *RedeemHandler {
	return &RedeemHandler{
		adminService:  adminService,
		redeemService: redeemService,
	}
}

// GenerateRedeemCodesRequest represents generate redeem codes request
type GenerateRedeemCodesRequest struct {
	Count         int        `json:"count" binding:"required,min=1,max=100"`
	Type          string     `json:"type" binding:"required,oneof=balance concurrency subscription invitation"`
	Value         float64    `json:"value"`
	GroupID       *int64     `json:"group_id"`      // 订阅类型必填
	ValidityDays  int        `json:"validity_days"` // 订阅类型使用，正数增加/负数退款扣减
	ExpiresAt     *time.Time `json:"expires_at"`
	ExpiresInDays *int       `json:"expires_in_days" binding:"omitempty,min=1,max=3650"`
}

// CreateAndRedeemCodeRequest represents creating a fixed code and redeeming it for a target user.
// Type 为 omitempty 而非 required 是为了向后兼容旧版调用方（不传 type 时默认 balance）。
type CreateAndRedeemCodeRequest struct {
	Code          string     `json:"code" binding:"required,min=3,max=128"`
	Type          string     `json:"type" binding:"omitempty,oneof=balance concurrency subscription invitation"` // 不传时默认 balance（向后兼容）
	Value         float64    `json:"value" binding:"required"`
	UserID        int64      `json:"user_id" binding:"required,gt=0"`
	GroupID       *int64     `json:"group_id"`      // subscription 类型必填
	ValidityDays  int        `json:"validity_days"` // subscription 类型：正数增加，负数退款扣减
	Notes         string     `json:"notes"`
	ExpiresAt     *time.Time `json:"expires_at"`
	ExpiresInDays *int       `json:"expires_in_days" binding:"omitempty,min=1,max=3650"`
}

func resolveRedeemCodeExpiresAt(expiresAt *time.Time, expiresInDays *int) (*time.Time, error) {
	if expiresAt != nil && expiresInDays != nil {
		return nil, infraerrors.BadRequest("REDEEM_CODE_EXPIRY_CONFLICT", "expires_at and expires_in_days cannot both be set")
	}

	now := time.Now().UTC()
	if expiresInDays != nil {
		if *expiresInDays <= 0 {
			return nil, infraerrors.BadRequest("REDEEM_CODE_EXPIRES_IN_DAYS_INVALID", "expires_in_days must be greater than zero")
		}
		expires := now.AddDate(0, 0, *expiresInDays)
		return &expires, nil
	}
	if expiresAt == nil {
		return nil, nil
	}

	expires := expiresAt.UTC()
	if !expires.After(now) {
		return nil, infraerrors.BadRequest("REDEEM_CODE_EXPIRES_AT_INVALID", "expires_at must be in the future")
	}
	return &expires, nil
}

// List handles listing all redeem codes with pagination
// GET /api/v1/admin/redeem-codes
func (h *RedeemHandler) List(c *gin.Context) {
	page, pageSize := response.ParsePagination(c)
	codeType := c.Query("type")
	status := c.Query("status")
	search := c.Query("search")
	sortBy := c.DefaultQuery("sort_by", "id")
	sortOrder := c.DefaultQuery("sort_order", "desc")
	// 标准化和验证 search 参数
	search = strings.TrimSpace(search)
	if len(search) > 100 {
		search = search[:100]
	}

	codes, total, err := h.adminService.ListRedeemCodes(c.Request.Context(), page, pageSize, codeType, status, search, sortBy, sortOrder)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	out := make([]dto.AdminRedeemCode, 0, len(codes))
	for i := range codes {
		out = append(out, *dto.RedeemCodeFromServiceAdmin(&codes[i]))
	}
	response.Paginated(c, out, total, page, pageSize)
}

// GetByID handles getting a redeem code by ID
// GET /api/v1/admin/redeem-codes/:id
func (h *RedeemHandler) GetByID(c *gin.Context) {
	codeID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "Invalid redeem code ID")
		return
	}

	code, err := h.adminService.GetRedeemCode(c.Request.Context(), codeID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	response.Success(c, dto.RedeemCodeFromServiceAdmin(code))
}

// Generate handles generating new redeem codes
// POST /api/v1/admin/redeem-codes/generate
func (h *RedeemHandler) Generate(c *gin.Context) {
	c.Header("Cache-Control", "private, no-store")
	c.Header("Pragma", "no-cache")
	var req GenerateRedeemCodesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}

	expiresAt, err := resolveRedeemCodeExpiresAt(req.ExpiresAt, req.ExpiresInDays)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	var generated []dto.AdminRedeemCode
	result, err := executeAdminIdempotent(c, "admin.redeem_codes.generate", req, service.DefaultWriteIdempotencyTTL(), func(ctx context.Context) (any, error) {
		codes, execErr := h.adminService.GenerateRedeemCodes(ctx, &service.GenerateRedeemCodesInput{
			Count:        req.Count,
			Type:         req.Type,
			Value:        req.Value,
			GroupID:      req.GroupID,
			ValidityDays: req.ValidityDays,
			ExpiresAt:    expiresAt,
		})
		if execErr != nil {
			return nil, execErr
		}

		out := make([]dto.AdminRedeemCode, 0, len(codes))
		generated = make([]dto.AdminRedeemCode, 0, len(codes))
		for i := range codes {
			out = append(out, *dto.RedeemCodeFromServiceAdmin(&codes[i]))
			generated = append(generated, *dto.RedeemCodeFromServiceAdminGenerated(&codes[i]))
		}
		return out, nil
	})
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if result != nil && result.Replayed {
		c.Header("X-Idempotency-Replayed", "true")
		response.ErrorFrom(c, infraerrors.Conflict("REDEEM_CODE_ALREADY_GENERATED", "codes were already generated; plaintext cannot be shown again"))
		return
	}
	response.Success(c, generated)
}

// CreateAndRedeem creates a fixed redeem code and redeems it for a target user in one step.
// POST /api/v1/admin/redeem-codes/create-and-redeem
func (h *RedeemHandler) CreateAndRedeem(c *gin.Context) {
	if h.redeemService == nil {
		response.InternalError(c, "redeem service not configured")
		return
	}

	var req CreateAndRedeemCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}
	req.Code = strings.TrimSpace(req.Code)
	// 向后兼容：旧版调用方（如 Sub2ApiPay）不传 type 字段，默认当作 balance 充值处理。
	// 请勿删除此默认值逻辑，否则会导致旧版调用方 400 报错。
	if req.Type == "" {
		req.Type = "balance"
	}

	if req.Type == "subscription" {
		if req.GroupID == nil {
			response.BadRequest(c, "group_id is required for subscription type")
			return
		}
		if req.ValidityDays == 0 {
			response.BadRequest(c, "validity_days must not be zero for subscription type")
			return
		}
	}

	expiresAt, err := resolveRedeemCodeExpiresAt(req.ExpiresAt, req.ExpiresInDays)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	executeAdminIdempotentJSON(c, "admin.redeem_codes.create_and_redeem", req, service.DefaultWriteIdempotencyTTL(), func(ctx context.Context) (any, error) {
		existing, err := h.redeemService.GetByCode(ctx, req.Code)
		if err == nil {
			return h.resolveCreateAndRedeemExisting(ctx, existing, req.UserID)
		}
		if !errors.Is(err, service.ErrRedeemCodeNotFound) {
			return nil, err
		}

		createErr := h.redeemService.CreateCode(ctx, &service.RedeemCode{
			Code:         req.Code,
			Type:         req.Type,
			Value:        req.Value,
			Status:       service.StatusUnused,
			Notes:        req.Notes,
			GroupID:      req.GroupID,
			ValidityDays: req.ValidityDays,
			ExpiresAt:    expiresAt,
		})
		if createErr != nil {
			// Unique code race: if code now exists, use idempotent semantics by used_by.
			existingAfterCreateErr, getErr := h.redeemService.GetByCode(ctx, req.Code)
			if getErr == nil {
				return h.resolveCreateAndRedeemExisting(ctx, existingAfterCreateErr, req.UserID)
			}
			return nil, createErr
		}

		redeemed, redeemErr := h.redeemService.RedeemForAdminFulfillment(ctx, req.UserID, req.Code)
		if redeemErr != nil {
			return nil, redeemErr
		}
		return gin.H{"redeem_code": dto.RedeemCodeFromServiceAdmin(redeemed)}, nil
	})
}

func (h *RedeemHandler) resolveCreateAndRedeemExisting(ctx context.Context, existing *service.RedeemCode, userID int64) (any, error) {
	if existing == nil {
		return nil, infraerrors.Conflict("REDEEM_CODE_CONFLICT", "redeem code conflict")
	}

	// If previous run created the code but crashed before redeem, redeem it now.
	if existing.IsExpired() {
		return nil, service.ErrRedeemCodeExpired
	}
	if existing.CanUse() {
		redeemed, err := h.redeemService.RedeemForAdminFulfillment(ctx, userID, existing.Code)
		if err == nil {
			return gin.H{"redeem_code": dto.RedeemCodeFromServiceAdmin(redeemed)}, nil
		}
		if !errors.Is(err, service.ErrRedeemCodeUsed) {
			return nil, err
		}
		latest, getErr := h.redeemService.GetByCode(ctx, existing.Code)
		if getErr == nil {
			existing = latest
		}
	}

	if existing.UsedBy != nil && *existing.UsedBy == userID {
		return gin.H{"redeem_code": dto.RedeemCodeFromServiceAdmin(existing)}, nil
	}

	return nil, infraerrors.Conflict("REDEEM_CODE_CONFLICT", "redeem code already used by another user")
}

// Delete handles deleting a redeem code
// DELETE /api/v1/admin/redeem-codes/:id
func (h *RedeemHandler) Delete(c *gin.Context) {
	codeID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "Invalid redeem code ID")
		return
	}

	err = h.adminService.DeleteRedeemCode(c.Request.Context(), codeID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	response.Success(c, gin.H{"message": "Redeem code deleted successfully"})
}

// BatchDelete handles batch deleting redeem codes
// POST /api/v1/admin/redeem-codes/batch-delete
func (h *RedeemHandler) BatchDelete(c *gin.Context) {
	var req struct {
		IDs []int64 `json:"ids" binding:"required,min=1"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}

	deleted, err := h.adminService.BatchDeleteRedeemCodes(c.Request.Context(), req.IDs)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	response.Success(c, gin.H{
		"deleted": deleted,
		"message": "Redeem codes deleted successfully",
	})
}

// BatchUpdate handles batch updating redeem codes
// POST /api/v1/admin/redeem-codes/batch-update
func (h *RedeemHandler) BatchUpdate(c *gin.Context) {
	if h.redeemService == nil {
		response.InternalError(c, "redeem service not configured")
		return
	}

	var req dto.BatchUpdateRedeemCodesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}

	result, err := h.redeemService.BatchUpdate(c.Request.Context(), &service.RedeemCodeBatchUpdateInput{
		IDs:    req.IDs,
		Fields: redeemBatchUpdateFieldsFromDTO(req.Fields),
	})
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	response.Success(c, gin.H{
		"updated": result.Updated,
		"message": "Redeem codes updated successfully",
	})
}

func redeemBatchUpdateFieldsFromDTO(in dto.BatchUpdateRedeemCodeFields) service.RedeemCodeBatchUpdateFields {
	out := service.RedeemCodeBatchUpdateFields{
		Status: in.Status,
		Notes:  in.Notes,
		Type:   in.Type,
		Value:  in.Value,
	}
	if in.ExpiresAt.Set {
		out.ExpiresAt = service.NullableTimeUpdate{Set: true, Value: in.ExpiresAt.Value}
	}
	if in.GroupID.Set {
		out.GroupID = service.NullableInt64Update{Set: true, Value: in.GroupID.Value}
	}
	return out
}

// Expire handles expiring a redeem code
// POST /api/v1/admin/redeem-codes/:id/expire
func (h *RedeemHandler) Expire(c *gin.Context) {
	codeID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "Invalid redeem code ID")
		return
	}

	code, err := h.adminService.ExpireRedeemCode(c.Request.Context(), codeID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	response.Success(c, dto.RedeemCodeFromServiceAdmin(code))
}

// GetStats handles getting redeem code statistics
// GET /api/v1/admin/redeem-codes/stats
func (h *RedeemHandler) GetStats(c *gin.Context) {
	// Return mock data for now
	response.Success(c, gin.H{
		"total_codes":             0,
		"active_codes":            0,
		"used_codes":              0,
		"expired_codes":           0,
		"total_value_distributed": 0.0,
		"by_type": gin.H{
			"balance":     0,
			"concurrency": 0,
			"trial":       0,
		},
	})
}

// Export rejects bulk plaintext exports. Codes are shown only in the immediate
// response to generation, where administrators can transfer them to fulfillment.
// GET /api/v1/admin/redeem-codes/export
func (h *RedeemHandler) Export(c *gin.Context) {
	response.ErrorFrom(c, infraerrors.New(http.StatusForbidden, "REDEEM_CODE_EXPORT_DISABLED", "plaintext redeem-code export is disabled"))
}
