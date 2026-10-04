package service

import "strings"

// MaskAPIKey never returns an authenticatable bearer or a database lookup identity.
func MaskAPIKey(key string) string {
	if key == "" {
		return ""
	}
	if strings.HasPrefix(key, "hmac-sha256:") || len(key) <= 12 {
		return "***"
	}
	return key[:6] + "********" + key[len(key)-4:]
}
