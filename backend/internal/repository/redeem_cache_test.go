//go:build unit

package repository

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRedeemRateLimitKey(t *testing.T) {
	tests := []struct {
		name     string
		userID   int64
		expected string
	}{
		{
			name:     "normal_user_id",
			userID:   123,
			expected: "redeem:ratelimit:v2:123",
		},
		{
			name:     "zero_user_id",
			userID:   0,
			expected: "redeem:ratelimit:v2:0",
		},
		{
			name:     "negative_user_id",
			userID:   -1,
			expected: "redeem:ratelimit:v2:-1",
		},
		{
			name:     "max_int64",
			userID:   math.MaxInt64,
			expected: "redeem:ratelimit:v2:9223372036854775807",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := redeemRateLimitKey(tc.userID)
			require.Equal(t, tc.expected, got)
		})
	}
}

func TestRedeemLockKey(t *testing.T) {
	tests := []struct {
		name     string
		code     string
		expected string
	}{
		{
			name:     "normal_code",
			code:     "ABC123",
			expected: "redeem:lock:ABC123",
		},
		{
			name:     "empty_code",
			code:     "",
			expected: "redeem:lock:",
		},
		{
			name:     "code_with_special_chars",
			code:     "CODE-2024:test",
			expected: "redeem:lock:CODE-2024:test",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := redeemLockKey(tc.code)
			digest := sha256.Sum256([]byte(tc.code))
			require.Equal(t, redeemLockKeyPrefix+hex.EncodeToString(digest[:]), got)
			if tc.code != "" {
				require.NotContains(t, got, tc.code)
			}
		})
	}
}
