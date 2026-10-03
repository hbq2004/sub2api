package dto

import (
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

func TestRedeemCodeResponsesOnlyRevealNewlyGeneratedCode(t *testing.T) {
	const code = "ABCD1234EFGH5678"
	record := &service.RedeemCode{ID: 1, Code: code, Type: service.RedeemTypeBalance}
	for _, result := range []string{
		RedeemCodeFromService(record).Code,
		RedeemCodeFromServiceAdmin(record).Code,
	} {
		if result == code || result != "ABCD...5678" {
			t.Fatalf("existing code was not masked: %q", result)
		}
	}
	if got := RedeemCodeFromServiceAdminGenerated(record).Code; got != code {
		t.Fatalf("newly generated code not returned once: %q", got)
	}
}
