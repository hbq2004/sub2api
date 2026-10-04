package routes

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/handler"
	"github.com/Wei-Shaw/sub2api/internal/handler/admin"
	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestAdminSensitiveRoutesRunStepUpBeforeAnySideEffect(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &handler.Handlers{Admin: &handler.AdminHandlers{
		Setting: &admin.SettingHandler{}, System: &admin.SystemHandler{},
	}}
	gate := middleware.StepUpAuthMiddleware(func(c *gin.Context) {
		middleware.AbortWithError(c, http.StatusForbidden, "STEP_UP_REQUIRED", "Recent verification required")
	})
	g := r.Group("/admin")
	registerSettingsRoutes(g, h, gate)
	registerSystemRoutes(g, h, gate)
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/admin/settings/admin-api-key/regenerate"},
		{http.MethodDelete, "/admin/settings/admin-api-key"},
		{http.MethodPost, "/admin/system/update"},
		{http.MethodPost, "/admin/system/rollback"},
		{http.MethodPost, "/admin/system/restart"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
			require.Equal(t, http.StatusForbidden, rec.Code)
			require.Contains(t, rec.Body.String(), "STEP_UP_REQUIRED")
		})
	}
}
