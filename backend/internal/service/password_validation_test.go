//go:build unit

package service

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/stretchr/testify/require"
)

type passwordValidationEmailCache struct {
	emailCacheStub
	verifyReads  int
	resetReads   int
	resetDeletes int
}

func (c *passwordValidationEmailCache) GetVerificationCode(context.Context, string) (*VerificationCodeData, error) {
	c.verifyReads++
	return &VerificationCodeData{Code: "123456", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}, nil
}

func (c *passwordValidationEmailCache) GetPasswordResetToken(context.Context, string) (*PasswordResetTokenData, error) {
	c.resetReads++
	return &PasswordResetTokenData{Token: strings.Repeat("a", 64), CreatedAt: time.Now()}, nil
}

func (c *passwordValidationEmailCache) DeletePasswordResetToken(context.Context, string) error {
	c.resetDeletes++
	return nil
}

func TestPasswordLengthUsesUTF8Bytes(t *testing.T) {
	for _, password := range []string{strings.Repeat("a", 72), strings.Repeat("\u4e2d", 24)} {
		_, err := (&AuthService{}).HashPassword(password)
		require.NoError(t, err)
	}
	for _, password := range []string{strings.Repeat("a", 73), strings.Repeat("\u4e2d", 25)} {
		_, err := (&AuthService{}).HashPassword(password)
		status, data := infraerrors.ToHTTP(err)
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "PASSWORD_TOO_LONG", data.Reason)
	}
}

func TestRegisterLongPasswordDoesNotConsumeEmailVerification(t *testing.T) {
	cache := &passwordValidationEmailCache{}
	svc := newAuthService(&userRepoStub{}, map[string]string{
		SettingKeyRegistrationEnabled: "true", SettingKeyEmailVerifyEnabled: "true",
	}, cache, nil)
	_, _, err := svc.RegisterWithVerification(context.Background(), "user@example.com", strings.Repeat("a", 73), "123456", "", "", "")
	status, data := infraerrors.ToHTTP(err)
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, "PASSWORD_TOO_LONG", data.Reason)
	require.Zero(t, cache.verifyReads)
}

func TestResetLongPasswordDoesNotConsumeResetToken(t *testing.T) {
	cache := &passwordValidationEmailCache{}
	svc := newAuthService(&userRepoStub{}, map[string]string{
		SettingKeyEmailVerifyEnabled: "true", SettingKeyPasswordResetEnabled: "true",
		SettingKeySMTPHost: "localhost", SettingKeySMTPUsername: "qa", SettingKeySMTPPassword: "synthetic-only", SettingKeySMTPFrom: "qa@example.com",
	}, cache, nil)
	err := svc.ResetPassword(context.Background(), "user@example.com", strings.Repeat("a", 64), strings.Repeat("a", 73))
	status, data := infraerrors.ToHTTP(err)
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, "PASSWORD_TOO_LONG", data.Reason)
	require.Zero(t, cache.resetReads)
	require.Zero(t, cache.resetDeletes)
}

func TestOAuthAndBindingLongPasswordPreserveVerificationCode(t *testing.T) {
	cache := &passwordValidationEmailCache{}
	svc := newAuthService(&userRepoStub{}, map[string]string{SettingKeyRegistrationEnabled: "true"}, cache, nil)
	_, _, err := svc.RegisterOAuthEmailAccount(context.Background(), "user@example.com", strings.Repeat("a", 73), "123456", "", "github")
	require.ErrorIs(t, err, ErrPasswordTooLong)
	_, err = svc.BindEmailIdentity(context.Background(), 1, "user@example.com", "123456", strings.Repeat("a", 73))
	require.ErrorIs(t, err, ErrPasswordTooLong)
	require.Zero(t, cache.verifyReads)
}

type revocationFailureUserRepo struct{ UserRepository }

func (revocationFailureUserRepo) GetByID(context.Context, int64) (*User, error) {
	return &User{ID: 1}, nil
}

type revocationFailureCache struct{ RefreshTokenCache }

func (revocationFailureCache) DeleteUserRefreshTokens(context.Context, int64) error {
	return errors.New("synthetic cache outage")
}

func TestRevokeAllSessionsReportsCacheFailure(t *testing.T) {
	svc := &AuthService{userRepo: revocationFailureUserRepo{}, refreshTokenCache: revocationFailureCache{}}
	require.ErrorIs(t, svc.RevokeAllUserTokens(context.Background(), 1), ErrServiceUnavailable)
}
