package repository

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
)

func testRedeemCodeProtector(t *testing.T) *redeemCodeProtector {
	t.Helper()
	key := strings.Repeat("42", 32)
	decoded, err := hex.DecodeString(key)
	if err != nil {
		t.Fatal(err)
	}
	return &redeemCodeProtector{hmacKey: decoded, encryptionKey: decoded}
}

func TestRedeemCodeProtectorRoundTrip(t *testing.T) {
	p := testRedeemCodeProtector(t)
	ciphertext, err := p.encrypt("ABCD-1234")
	if err != nil {
		t.Fatal(err)
	}
	if ciphertext == "ABCD-1234" || ciphertext == "" {
		t.Fatalf("expected ciphertext, got %q", ciphertext)
	}
	plaintext, err := p.decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if plaintext != "ABCD-1234" {
		t.Fatalf("plaintext mismatch: %q", plaintext)
	}
}

func TestRedeemCodeProtectorUsesDeterministicKeyedDigestAndRandomCiphertext(t *testing.T) {
	p := testRedeemCodeProtector(t)
	if p.digest(" ABCD-1234 ") != p.digest("ABCD-1234") {
		t.Fatal("digest should normalize surrounding whitespace")
	}
	first, err := p.encrypt("ABCD-1234")
	if err != nil {
		t.Fatal(err)
	}
	second, err := p.encrypt("ABCD-1234")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("AES-GCM ciphertext must use a fresh nonce")
	}
}

func TestRedeemCodeProtectorRejectsWrongKey(t *testing.T) {
	p := testRedeemCodeProtector(t)
	ciphertext, err := p.encrypt("ABCD-1234")
	if err != nil {
		t.Fatal(err)
	}
	wrong := &redeemCodeProtector{hmacKey: []byte(strings.Repeat("b", 32)), encryptionKey: []byte(strings.Repeat("c", 32))}
	if _, err := wrong.decrypt(ciphertext); err == nil {
		t.Fatal("wrong encryption key unexpectedly decrypted code")
	}
}

func TestRedeemCodeProtectorRequiresTwoIndependentKeys(t *testing.T) {
	t.Setenv("REDEEM_CODE_HMAC_KEY", strings.Repeat("42", 32))
	t.Setenv("REDEEM_CODE_ENCRYPTION_KEY", strings.Repeat("42", 32))
	if _, err := newRedeemCodeProtectorFromEnv(); err == nil {
		t.Fatal("identical keys must be rejected")
	}
	t.Setenv("REDEEM_CODE_ENCRYPTION_KEY", strings.Repeat("43", 32))
	if _, err := newRedeemCodeProtectorFromEnv(); err != nil {
		t.Fatalf("independent keys rejected: %v", err)
	}
}

func TestRedeemCodeRepositoryRejectsTOTPKeyReuse(t *testing.T) {
	hmacKey := strings.Repeat("42", 32)
	t.Setenv("REDEEM_CODE_HMAC_KEY", hmacKey)
	t.Setenv("REDEEM_CODE_ENCRYPTION_KEY", strings.Repeat("43", 32))
	_, err := ProvideRedeemCodeRepository(nil, &config.Config{Totp: config.TotpConfig{EncryptionKey: hmacKey}})
	if err == nil {
		t.Fatal("TOTP key reuse must be rejected before database access")
	}
}
