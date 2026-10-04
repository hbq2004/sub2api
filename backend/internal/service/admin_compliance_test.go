package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

type adminComplianceRepoStub struct {
	values map[string]string
}

func (r *adminComplianceRepoStub) Get(ctx context.Context, key string) (*Setting, error) {
	if value, ok := r.values[key]; ok {
		return &Setting{Key: key, Value: value}, nil
	}
	return nil, ErrSettingNotFound
}

func (r *adminComplianceRepoStub) GetValue(ctx context.Context, key string) (string, error) {
	setting, err := r.Get(ctx, key)
	if err != nil {
		return "", err
	}
	return setting.Value, nil
}

func (r *adminComplianceRepoStub) Set(ctx context.Context, key, value string) error {
	if r.values == nil {
		r.values = map[string]string{}
	}
	r.values[key] = value
	return nil
}

func (r *adminComplianceRepoStub) GetMultiple(ctx context.Context, keys []string) (map[string]string, error) {
	return map[string]string{}, nil
}

func (r *adminComplianceRepoStub) SetMultiple(ctx context.Context, settings map[string]string) error {
	return nil
}

func (r *adminComplianceRepoStub) GetAll(ctx context.Context) (map[string]string, error) {
	return map[string]string{}, nil
}

func (r *adminComplianceRepoStub) Delete(ctx context.Context, key string) error {
	delete(r.values, key)
	return nil
}

func TestAdminComplianceStatusRequiresAckWhenMissing(t *testing.T) {
	svc := NewSettingService(&adminComplianceRepoStub{}, &config.Config{})

	status, err := svc.GetAdminComplianceStatus(context.Background(), 1)
	require.NoError(t, err)
	require.True(t, status.Required)
	require.Equal(t, AdminComplianceVersion, status.Version)
	require.Equal(t, AdminComplianceAckPhraseZH, status.AckPhraseZH)
	require.Equal(t, AdminComplianceDocumentPathZH, status.DocumentPathZH)
}

func TestAcceptAdminComplianceRejectsWrongPhrase(t *testing.T) {
	svc := NewSettingService(&adminComplianceRepoStub{}, &config.Config{})

	_, err := svc.AcceptAdminCompliance(context.Background(), AdminComplianceAcceptInput{
		AdminUserID: 1,
		Language:    "zh",
		Phrase:      "我同意",
	})
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrAdminComplianceInvalidPhrase))
}

func TestAdminComplianceUsesConfiguredSiteNameAndRequiresExactInput(t *testing.T) {
	const siteName = "智驿 AI"
	for _, language := range []string{"zh-CN", "en"} {
		t.Run(language, func(t *testing.T) {
			repo := &adminComplianceRepoStub{values: map[string]string{SettingKeySiteName: siteName}}
			svc := NewSettingService(repo, &config.Config{})
			status, err := svc.GetAdminComplianceStatus(context.Background(), 42)
			require.NoError(t, err)
			require.Contains(t, status.AckPhraseZH, siteName)
			require.Contains(t, status.AckPhraseEN, siteName)
			require.True(t, status.Required)

			legacyPhrase := strings.ReplaceAll(expectedAdminCompliancePhrase(language), defaultSiteName, "Sub2API")
			for _, phrase := range []string{"", "我同意", legacyPhrase} {
				_, err = svc.AcceptAdminCompliance(context.Background(), AdminComplianceAcceptInput{
					AdminUserID: 42, Language: language, Phrase: phrase,
				})
				require.ErrorIs(t, err, ErrAdminComplianceInvalidPhrase)
				require.Empty(t, repo.values[adminComplianceAcknowledgementKey(42)])
			}

			phrase := status.AckPhraseEN
			if language == "zh-CN" {
				phrase = status.AckPhraseZH
			}
			accepted, err := svc.AcceptAdminCompliance(context.Background(), AdminComplianceAcceptInput{
				AdminUserID: 42, Language: language, Phrase: phrase,
			})
			require.NoError(t, err)
			require.False(t, accepted.Required)
			require.NotEmpty(t, repo.values[adminComplianceAcknowledgementKey(42)])
		})
	}
}

func TestAcceptAdminCompliancePersistsCurrentVersion(t *testing.T) {
	repo := &adminComplianceRepoStub{}
	svc := NewSettingService(repo, &config.Config{})

	status, err := svc.AcceptAdminCompliance(context.Background(), AdminComplianceAcceptInput{
		AdminUserID: 42,
		Language:    "zh-CN",
		Phrase:      AdminComplianceAckPhraseZH,
		IPAddress:   "203.0.113.10",
		UserAgent:   "test-agent",
	})
	require.NoError(t, err)
	require.False(t, status.Required)
	require.NotNil(t, status.Acknowledgement)
	require.Equal(t, int64(42), status.Acknowledgement.AdminUserID)
	require.Equal(t, "203.0.113.10", status.Acknowledgement.IPAddress)

	var stored AdminComplianceAcknowledgement
	require.NoError(t, json.Unmarshal([]byte(repo.values[adminComplianceAcknowledgementKey(42)]), &stored))
	require.Equal(t, AdminComplianceVersion, stored.Version)
	require.Equal(t, AdminComplianceDocumentPathZH, stored.DocumentZH)
}

func TestAdminComplianceStatusRequiresAckOnOldVersion(t *testing.T) {
	old, err := json.Marshal(AdminComplianceAcknowledgement{Version: "v2026.01.01"})
	require.NoError(t, err)
	svc := NewSettingService(&adminComplianceRepoStub{
		values: map[string]string{adminComplianceAcknowledgementKey(1): string(old)},
	}, &config.Config{})

	status, err := svc.GetAdminComplianceStatus(context.Background(), 1)
	require.NoError(t, err)
	require.True(t, status.Required)
	require.Nil(t, status.Acknowledgement)
}

func TestAdminComplianceStatusIsPerAdminUser(t *testing.T) {
	current, err := json.Marshal(AdminComplianceAcknowledgement{
		Version:     AdminComplianceVersion,
		AdminUserID: 1,
	})
	require.NoError(t, err)
	svc := NewSettingService(&adminComplianceRepoStub{
		values: map[string]string{adminComplianceAcknowledgementKey(1): string(current)},
	}, &config.Config{})

	statusForUserOne, err := svc.GetAdminComplianceStatus(context.Background(), 1)
	require.NoError(t, err)
	require.False(t, statusForUserOne.Required)

	statusForUserTwo, err := svc.GetAdminComplianceStatus(context.Background(), 2)
	require.NoError(t, err)
	require.True(t, statusForUserTwo.Required)
}
