package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/ent/authidentity"
	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
)

func TestEmailOAuthFragmentDecodedOnceByBrowser(t *testing.T) {
	values := url.Values{
		"access_token":      {"test-token+/%=value"},
		"refresh_token":     {"test-refresh+/%=value"},
		"redirect":          {"/keys?filter=a%2Fb&label=two words#details"},
		"error_description": {"Access denied & retry / 100%"},
	}
	for _, callback := range []string{"/auth/oauth/callback", "https://app.example/auth/oauth/callback?lang=en"} {
		t.Run(callback, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
			redirectWithFragment(c, callback, values)

			_, fragment, found := strings.Cut(recorder.Header().Get("Location"), "#")
			require.True(t, found)
			decoded, err := url.ParseQuery(fragment)
			require.NoError(t, err)
			require.Equal(t, values, decoded, "the browser decodes location.hash only once")
			require.Equal(t, "no-store", recorder.Header().Get("Cache-Control"))
		})
	}
}

func TestGitHubOAuthMockProviderCallbackPreservesDestinationAndClearsCookies(t *testing.T) {
	requests := make(chan string, 3)
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			_ = r.ParseForm()
			if r.Form.Get("code") != "test-provider-code" || r.Form.Get("client_secret") != "test-client-secret" {
				http.Error(w, "unexpected token request", http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"test-provider-token","token_type":"bearer"}`))
		case "/user":
			if r.Header.Get("Authorization") != "Bearer test-provider-token" {
				http.Error(w, "missing authorization", http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"id":123,"login":"octo","email":null}`))
		case "/emails":
			_, _ = w.Write([]byte(`[{"email":"unverified@example.com","primary":false,"verified":false},{"email":"verified@example.com","primary":true,"verified":true}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(provider.Close)
	handler, client := newOAuthPendingFlowTestHandler(t, false)
	_, err := client.User.Create().SetEmail("verified@example.com").SetUsername("existing").
		SetPasswordHash("test-hash").SetRole(service.RoleUser).SetStatus(service.StatusActive).Save(context.Background())
	require.NoError(t, err)
	handler.settingSvc = service.NewSettingService(&oauthPendingFlowSettingRepoStub{values: map[string]string{
		service.SettingKeyGitHubOAuthEnabled: "true",
	}}, &config.Config{GitHubOAuth: config.EmailOAuthProviderConfig{
		Enabled: true, ClientID: "test-client", ClientSecret: "test-client-secret",
		AuthorizeURL: provider.URL + "/authorize", TokenURL: provider.URL + "/token",
		UserInfoURL: provider.URL + "/user", EmailsURL: provider.URL + "/emails",
		RedirectURL: "https://app.example/api/v1/auth/oauth/github/callback",
	}})
	start := httptest.NewRecorder()
	startCtx, _ := gin.CreateTestContext(start)
	destination := "/keys?filter=test%2Fkey"
	startCtx.Request = httptest.NewRequest(http.MethodGet, "/api/v1/auth/oauth/github/start?redirect="+url.QueryEscape(destination), nil)
	handler.GitHubOAuthStart(startCtx)
	require.Equal(t, http.StatusFound, start.Code)
	authorizeURL, err := url.Parse(start.Header().Get("Location"))
	require.NoError(t, err)

	callback := httptest.NewRecorder()
	callbackCtx, _ := gin.CreateTestContext(callback)
	callbackCtx.Request = httptest.NewRequest(http.MethodGet, "/api/v1/auth/oauth/github/callback?code=test-provider-code&state="+url.QueryEscape(authorizeURL.Query().Get("state")), nil)
	for _, cookie := range start.Result().Cookies() {
		if cookie.MaxAge >= 0 {
			callbackCtx.Request.AddCookie(cookie)
		}
	}
	handler.GitHubOAuthCallback(callbackCtx)
	require.Equal(t, http.StatusFound, callback.Code)
	_, fragment, _ := strings.Cut(callback.Header().Get("Location"), "#")
	values, err := url.ParseQuery(fragment)
	require.NoError(t, err)
	require.True(t, values.Get("access_token") != "")
	require.Equal(t, destination, values.Get("redirect"))
	require.Equal(t, 3, len(requests))
	for _, name := range []string{emailOAuthStateCookieName, emailOAuthRedirectCookie, emailOAuthProviderCookie, emailOAuthAffiliateCookie, oauthPromoCodeCookieName} {
		requireCookieCleared(t, callback, name)
	}
}

func TestEmailOAuthFailedCallbackClearsTransientCookies(t *testing.T) {
	for _, provider := range []string{"github", "google"} {
		for _, query := range []string{"?error=access_denied", "", "?code=test-code&state=wrong-state"} {
			t.Run(provider+query, func(t *testing.T) {
				cfg := config.EmailOAuthProviderConfig{
					Enabled: true, ClientID: "test-client", ClientSecret: "test-secret",
					RedirectURL: "https://app.example/api/v1/auth/oauth/" + provider + "/callback",
				}
				handler, _ := newOAuthPendingFlowTestHandler(t, false)
				handler.settingSvc = service.NewSettingService(&oauthPendingFlowSettingRepoStub{values: map[string]string{
					service.SettingKeyGitHubOAuthEnabled: "true", service.SettingKeyGoogleOAuthEnabled: "true",
				}}, &config.Config{
					GitHubOAuth: cfg, GoogleOAuth: cfg,
				})
				recorder := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(recorder)
				c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/auth/oauth/"+provider+"/callback"+query, nil)
				handler.emailOAuthCallback(c, provider)
				require.Equal(t, http.StatusFound, recorder.Code)

				for _, name := range []string{emailOAuthStateCookieName, emailOAuthRedirectCookie, emailOAuthProviderCookie, emailOAuthAffiliateCookie, oauthPromoCodeCookieName} {
					requireCookieCleared(t, recorder, name)
				}
			})
		}
	}
}

func TestEmailOAuthRejectsUnavailableTotpAndDisabledRegistration(t *testing.T) {
	for _, blocked := range []string{"totp_unavailable", "registration_disabled", "inactive_user"} {
		t.Run(blocked, func(t *testing.T) {
			handler, client := newOAuthPendingFlowTestHandlerWithDependencies(t, oauthPendingFlowTestHandlerOptions{
				settingValues: map[string]string{
					service.SettingKeyTotpEnabled: "true", service.SettingKeyRegistrationEnabled: "false",
				},
			})
			if blocked != "registration_disabled" {
				status := service.StatusActive
				if blocked == "inactive_user" {
					status = service.StatusDisabled
				}
				_, err := client.User.Create().SetEmail("blocked@example.com").SetPasswordHash("test-hash").
					SetRole(service.RoleUser).SetStatus(status).SetTotpEnabled(true).Save(context.Background())
				require.NoError(t, err)
			}
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/auth/oauth/github/callback", nil)
			handler.emailOAuthCallbackWithProfile(c, "github", config.EmailOAuthProviderConfig{}, "/auth/oauth/callback", "/keys", &emailOAuthProfile{
				Subject: "blocked-subject", Email: "blocked@example.com", EmailVerified: true,
			})
			values := parseOAuthRedirectFragment(t, recorder.Header().Get("Location"))
			require.NotEmpty(t, values.Get("error"))
			require.Empty(t, values.Get("access_token"))
			count, err := client.AuthIdentity.Query().Count(context.Background())
			require.NoError(t, err)
			require.Zero(t, count)
			count, err = client.PendingAuthSession.Query().Count(context.Background())
			require.NoError(t, err)
			require.Zero(t, count)
		})
	}
}

func TestEmailOAuthTotpBeforeTokenIssueAndIdentityBinding(t *testing.T) {
	for _, provider := range []string{"github", "google"} {
		t.Run(provider, func(t *testing.T) {
			cache := &oauthPendingFlowTotpCacheStub{}
			handler, client := newOAuthPendingFlowTestHandlerWithDependencies(t, oauthPendingFlowTestHandlerOptions{
				settingValues: map[string]string{service.SettingKeyTotpEnabled: "true"},
				totpCache:     cache, totpEncryptor: oauthPendingFlowTotpEncryptorStub{},
			})
			ctx := context.Background()
			secret := "JBSWY3DPEHPK3PXP"
			user, err := client.User.Create().SetEmail("owner@example.com").SetUsername("owner").
				SetPasswordHash("test-hash").SetRole(service.RoleUser).SetStatus(service.StatusActive).
				SetTotpEnabled(true).SetTotpSecretEncrypted(secret).SetTotpEnabledAt(time.Now().Add(-time.Hour)).Save(ctx)
			require.NoError(t, err)
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/auth/oauth/"+provider+"/callback", nil)
			handler.emailOAuthCallbackWithProfile(c, provider, config.EmailOAuthProviderConfig{}, "/auth/oauth/callback", "/keys", &emailOAuthProfile{
				Subject: "test-subject", Email: user.Email, EmailVerified: true, Username: "provider-user",
			})

			require.Equal(t, http.StatusFound, recorder.Code)
			require.NotContains(t, recorder.Header().Get("Location"), "access_token=")
			count, err := client.AuthIdentity.Query().Count(ctx)
			require.NoError(t, err)
			require.Zero(t, count)
			session, err := client.PendingAuthSession.Query().Only(ctx)
			require.NoError(t, err)
			require.Equal(t, user.ID, *session.TargetUserID)
			payload, ok := readCompletionResponse(session.LocalFlowState)
			require.True(t, ok)
			require.Equal(t, true, payload["requires_2fa"])
			tempToken, ok := payload["temp_token"].(string)
			require.True(t, ok)
			loginSession, err := cache.GetLoginSession(ctx, tempToken)
			require.NoError(t, err)
			require.Equal(t, session.SessionToken, loginSession.PendingOAuthBind.PendingSessionToken)

			exchangeRecorder := httptest.NewRecorder()
			exchangeCtx, _ := gin.CreateTestContext(exchangeRecorder)
			exchangeCtx.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/pending/exchange", strings.NewReader(`{}`))
			exchangeCtx.Request.Header.Set("Content-Type", "application/json")
			for _, cookie := range recorder.Result().Cookies() {
				if cookie.MaxAge >= 0 {
					exchangeCtx.Request.AddCookie(cookie)
				}
			}
			handler.ExchangePendingOAuthCompletion(exchangeCtx)
			require.Equal(t, http.StatusOK, exchangeRecorder.Code)
			require.NotContains(t, exchangeRecorder.Body.String(), "access_token")
			require.Equal(t, true, decodeJSONResponseData(t, exchangeRecorder)["requires_2fa"])

			for _, valid := range []bool{false, true} {
				code := "invalid"
				if valid {
					code, err = totp.GenerateCode(secret, time.Now())
					require.NoError(t, err)
				}
				loginRecorder := httptest.NewRecorder()
				loginCtx, _ := gin.CreateTestContext(loginRecorder)
				loginCtx.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/2fa", strings.NewReader(`{"temp_token":"`+tempToken+`","totp_code":"`+code+`"}`))
				loginCtx.Request.Header.Set("Content-Type", "application/json")
				handler.Login2FA(loginCtx)
				if !valid {
					require.NotEqual(t, http.StatusOK, loginRecorder.Code)
					require.NotContains(t, loginRecorder.Body.String(), "access_token")
					continue
				}
				require.Equal(t, http.StatusOK, loginRecorder.Code)
				require.Contains(t, loginRecorder.Body.String(), "access_token")
			}
			identity, err := client.AuthIdentity.Query().Where(authidentity.ProviderTypeEQ(provider)).Only(ctx)
			require.NoError(t, err)
			require.Equal(t, user.ID, identity.UserID)
			stored, err := client.PendingAuthSession.Get(ctx, session.ID)
			require.NoError(t, err)
			require.NotNil(t, stored.ConsumedAt)
		})
	}
}
