//go:build unit

package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/repository"
	servermiddleware "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

type sessionUserRepo struct {
	service.UserRepository
	user *service.User
}

func (r *sessionUserRepo) GetByID(context.Context, int64) (*service.User, error) {
	return r.user, nil
}

func (r *sessionUserRepo) GetUserAvatar(context.Context, int64) (*service.UserAvatar, error) {
	return nil, nil
}

func (r *sessionUserRepo) UpdateUserLastActiveAt(context.Context, int64, time.Time) error {
	return nil
}

func TestAccessSessionLogoutRevokesOnlyCurrentDevice(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = client.Close() })
	cache := repository.NewRefreshTokenCache(client)
	user := &service.User{ID: 1, Email: "session@example.com", Role: service.RoleAdmin, Status: service.StatusActive, TokenVersion: 7, TokenVersionResolved: true}
	repo := &sessionUserRepo{user: user}
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "test-only-session-secret", ExpireHour: 1, RefreshTokenExpireDays: 7}}
	svc := service.NewAuthService(nil, repo, nil, cache, cfg, nil, nil, nil, nil, nil, nil, nil, nil)
	userSvc := service.NewUserService(repo, nil, nil, nil)
	router := gin.New()
	router.GET("/user", gin.HandlerFunc(servermiddleware.NewJWTAuthMiddleware(svc, userSvc, nil, nil)), func(c *gin.Context) { c.Status(200) })
	router.GET("/admin", gin.HandlerFunc(servermiddleware.NewAdminAuthMiddleware(svc, userSvc, nil, nil)), func(c *gin.Context) { c.Status(200) })
	first, err := svc.GenerateTokenPair(context.Background(), user, "")
	require.NoError(t, err)
	second, err := svc.GenerateTokenPair(context.Background(), user, "")
	require.NoError(t, err)
	status := func(path, token string) int {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		return response.Code
	}
	require.Equal(t, 200, status("/user", first.AccessToken))
	require.Equal(t, 200, status("/admin", first.AccessToken))
	require.NoError(t, svc.RevokeRefreshToken(context.Background(), first.RefreshToken))
	require.Equal(t, 401, status("/user", first.AccessToken))
	require.Equal(t, 401, status("/admin", first.AccessToken))
	require.Equal(t, 200, status("/user", second.AccessToken))
	require.Equal(t, 200, status("/admin", second.AccessToken))
	require.NoError(t, svc.RevokeAllUserSessions(context.Background(), user.ID))
	require.Equal(t, 401, status("/user", second.AccessToken))

	third, err := svc.GenerateTokenPair(context.Background(), user, "")
	require.NoError(t, err)
	server.Close()
	require.Equal(t, 503, status("/user", third.AccessToken))
}
