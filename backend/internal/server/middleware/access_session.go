package middleware

import (
	"errors"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

func enforceAccessSession(c *gin.Context, authService *service.AuthService, claims *service.JWTClaims) bool {
	if err := authService.ValidateAccessSession(c.Request.Context(), claims); err != nil {
		if errors.Is(err, service.ErrServiceUnavailable) {
			AbortWithError(c, 503, "SERVICE_UNAVAILABLE", "Unable to verify session")
		} else {
			AbortWithError(c, 401, "TOKEN_REVOKED", "Session has been revoked")
		}
		return false
	}
	return true
}
