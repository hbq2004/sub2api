package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestAPIKeyIdempotencyKeepsOneTimeBearerOutOfStorageAndReplay(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := newUserMemoryIdempotencyRepoStub()
	service.SetDefaultIdempotencyCoordinator(service.NewIdempotencyCoordinator(repo, service.DefaultIdempotencyConfig()))
	t.Cleanup(func() { service.SetDefaultIdempotencyCoordinator(nil) })
	raw := "synthetic-one-time-created-api-key"
	router := gin.New()
	router.Use(withUserSubject(3))
	router.POST("/key", func(c *gin.Context) {
		executeUserIdempotentJSONWithResponse(c, "user.api_keys.create", gin.H{"name": "test"}, time.Minute,
			func(context.Context) (any, error) { return gin.H{"key": service.MaskAPIKey(raw)}, nil },
			func(data any) any { data.(gin.H)["key"] = raw; return data })
	})
	request := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/key", nil)
		r.Header.Set("Idempotency-Key", "synthetic-idempotency")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	first := request()
	require.Equal(t, http.StatusOK, first.Code)
	require.Contains(t, first.Body.String(), raw)
	replay := request()
	require.Equal(t, http.StatusOK, replay.Code)
	require.Equal(t, "true", replay.Header().Get("X-Idempotency-Replayed"))
	require.NotContains(t, replay.Body.String(), raw)
}
