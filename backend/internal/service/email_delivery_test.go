//go:build unit

package service

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type deliveryEmailCache struct {
	emailCacheStub
	deleted bool
}

func (c *deliveryEmailCache) SetVerificationCode(_ context.Context, _ string, data *VerificationCodeData, _ time.Duration) error {
	c.data = data
	return nil
}

func (c *deliveryEmailCache) DeleteVerificationCodeIfMatch(ctx context.Context, _, code string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.data != nil && c.data.Code == code {
		c.data = nil
		c.deleted = true
	}
	return nil
}

func TestVerificationDeliveryFailureAllowsImmediateRetry(t *testing.T) {
	cache := &deliveryEmailCache{}
	settings := &settingRepoStub{values: map[string]string{}}
	svc := NewEmailService(settings, cache)

	err := svc.SendVerifyCode(context.Background(), "user@example.com", "Sub2API")
	require.ErrorIs(t, err, ErrEmailNotConfigured)
	require.True(t, cache.deleted)
	require.Nil(t, cache.data)

	_, port := startFakeSMTPServer(t, false, false)
	settings.values[SettingKeySMTPHost] = "127.0.0.1"
	settings.values[SettingKeySMTPPort] = strconv.Itoa(port)
	settings.values[SettingKeySMTPFrom] = "sender@example.com"

	require.NoError(t, svc.SendVerifyCode(context.Background(), "user@example.com", "Sub2API"))
	require.NotNil(t, cache.data)
	require.ErrorIs(t, svc.SendVerifyCode(context.Background(), "user@example.com", "Sub2API"), ErrVerifyCodeTooFrequent)
}

func TestVerificationDeliveryCleanupSurvivesRequestCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cache := &deliveryEmailCache{}
	svc := NewEmailService(&settingRepoStub{values: map[string]string{}}, cache)
	require.Error(t, svc.SendVerifyCode(ctx, "user@example.com", "Sub2API"))
	require.True(t, cache.deleted)
	require.Nil(t, cache.data)
}

func TestSendVerifyCodeResultRejectsMissingSMTP(t *testing.T) {
	svc := newAuthService(&userRepoStub{}, map[string]string{
		SettingKeyRegistrationEnabled: "true",
	}, &deliveryEmailCache{}, nil)
	result, err := svc.SendVerifyCodeWithResult(context.Background(), "user@example.com")
	require.Nil(t, result)
	require.True(t, errors.Is(err, ErrEmailNotConfigured))
}

func TestSendVerifyCodeResultWaitsForSMTPAcceptance(t *testing.T) {
	srv, port := startFakeSMTPServer(t, false, false)
	cache := &deliveryEmailCache{}
	svc := newAuthService(&userRepoStub{}, map[string]string{
		SettingKeyRegistrationEnabled: "true",
		SettingKeySMTPHost:            "127.0.0.1",
		SettingKeySMTPPort:            strconv.Itoa(port),
		SettingKeySMTPFrom:            "sender@example.com",
	}, cache, nil)
	result, err := svc.SendVerifyCodeWithResult(context.Background(), "user@example.com")
	require.NoError(t, err)
	require.Equal(t, 60, result.Countdown)
	require.True(t, srv.sawCommand("DATA"))
	require.NotNil(t, cache.data)
}
