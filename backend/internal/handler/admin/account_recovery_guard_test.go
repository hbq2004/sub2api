package admin

import (
	"net/http"
	"testing"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

func TestRejectManualRevokedOAuthRecovery(t *testing.T) {
	tests := []struct {
		name    string
		account *service.Account
		blocked bool
	}{
		{"revoked code", &service.Account{Platform: service.PlatformOpenAI,
			Type: service.AccountTypeOAuth, Status: service.StatusError,
			ErrorMessage: `Authentication failed (401): {"code":"token_revoked"}`}, true},
		{"invalidated message", &service.Account{Platform: service.PlatformOpenAI,
			Type: service.AccountTypeOAuth, Status: service.StatusError,
			ErrorMessage: "Token revoked (401): Encountered invalidated oauth token"}, true},
		{"deactivated code", &service.Account{Platform: service.PlatformOpenAI,
			Type: service.AccountTypeOAuth, Status: service.StatusError,
			ErrorMessage: "account_deactivated"}, true},
		{"temporary error", &service.Account{Platform: service.PlatformOpenAI,
			Type: service.AccountTypeOAuth, Status: service.StatusError,
			ErrorMessage: "upstream timeout"}, false},
		{"other platform", &service.Account{Platform: service.PlatformGemini,
			Type: service.AccountTypeOAuth, Status: service.StatusError,
			ErrorMessage: "token_revoked"}, false},
		{"already active", &service.Account{Platform: service.PlatformOpenAI,
			Type: service.AccountTypeOAuth, Status: service.StatusActive,
			ErrorMessage: "token_revoked"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := rejectManualRevokedOAuthRecovery(tt.account)
			if tt.blocked {
				if err == nil || infraerrors.Code(err) != http.StatusConflict {
					t.Fatalf("expected conflict, got %v", err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
