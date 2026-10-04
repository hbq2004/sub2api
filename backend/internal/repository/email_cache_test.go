//go:build unit

package repository

import (
	"context"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestDeleteVerificationCodeIfMatchPreservesNewerCode(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	cache := NewEmailCache(client)
	ctx := context.Background()
	email := "user@example.com"
	require.NoError(t, cache.SetVerificationCode(ctx, email, &service.VerificationCodeData{Code: "654321"}, time.Minute))
	require.NoError(t, cache.DeleteVerificationCodeIfMatch(ctx, email, "123456"))
	data, err := cache.GetVerificationCode(ctx, email)
	require.NoError(t, err)
	require.Equal(t, "654321", data.Code)
	require.NoError(t, cache.DeleteVerificationCodeIfMatch(ctx, email, "654321"))
	_, err = cache.GetVerificationCode(ctx, email)
	require.ErrorIs(t, err, redis.Nil)
}

func TestVerifyCodeKey(t *testing.T) {
	tests := []struct {
		name     string
		email    string
		expected string
	}{
		{
			name:     "normal_email",
			email:    "user@example.com",
			expected: "verify_code:user@example.com",
		},
		{
			name:     "empty_email",
			email:    "",
			expected: "verify_code:",
		},
		{
			name:     "email_with_plus",
			email:    "user+tag@example.com",
			expected: "verify_code:user+tag@example.com",
		},
		{
			name:     "email_with_special_chars",
			email:    "user.name+tag@sub.domain.com",
			expected: "verify_code:user.name+tag@sub.domain.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := verifyCodeKey(tc.email)
			require.Equal(t, tc.expected, got)
		})
	}
}
