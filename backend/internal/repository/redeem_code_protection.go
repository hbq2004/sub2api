package repository

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const redeemCodeProtectionKeyVersion = 1

// redeemCodeProtector keeps lookup and recovery keys separate. The lookup
// digest is deterministic; the stored code ciphertext remains randomized.
type redeemCodeProtector struct {
	hmacKey       []byte
	encryptionKey []byte
}

func newRedeemCodeProtectorFromEnv() (*redeemCodeProtector, error) {
	hmacHex := strings.TrimSpace(os.Getenv("REDEEM_CODE_HMAC_KEY"))
	encryptionHex := strings.TrimSpace(os.Getenv("REDEEM_CODE_ENCRYPTION_KEY"))
	if hmacHex == "" && encryptionHex == "" {
		return nil, errors.New("redeem code protection keys are not configured")
	}
	if hmacHex == "" || encryptionHex == "" {
		return nil, errors.New("both REDEEM_CODE_HMAC_KEY and REDEEM_CODE_ENCRYPTION_KEY are required")
	}
	hmacKey, err := decodeRedeemCodeKey(hmacHex, "REDEEM_CODE_HMAC_KEY")
	if err != nil {
		return nil, err
	}
	encryptionKey, err := decodeRedeemCodeKey(encryptionHex, "REDEEM_CODE_ENCRYPTION_KEY")
	if err != nil {
		return nil, err
	}
	if hmac.Equal(hmacKey, encryptionKey) {
		return nil, errors.New("redeem code HMAC and encryption keys must be different")
	}
	return &redeemCodeProtector{hmacKey: hmacKey, encryptionKey: encryptionKey}, nil
}

func decodeRedeemCodeKey(value, name string) ([]byte, error) {
	key, err := hex.DecodeString(value)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("%s must be 64 hexadecimal characters", name)
	}
	return key, nil
}

func (p *redeemCodeProtector) digest(code string) string {
	mac := hmac.New(sha256.New, p.hmacKey)
	_, _ = mac.Write([]byte(strings.TrimSpace(code)))
	return hex.EncodeToString(mac.Sum(nil))
}

func (p *redeemCodeProtector) encrypt(code string) (string, error) {
	block, err := aes.NewCipher(p.encryptionKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(strings.TrimSpace(code)), nil)
	return base64.RawStdEncoding.EncodeToString(sealed), nil
}

func (p *redeemCodeProtector) decrypt(ciphertext string) (string, error) {
	data, err := base64.RawStdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(p.encryptionKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(data) < gcm.NonceSize() {
		return "", errors.New("redeem code ciphertext is too short")
	}
	plain, err := gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
