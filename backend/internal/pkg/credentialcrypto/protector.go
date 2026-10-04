// Package credentialcrypto protects upstream credentials outside the database.
package credentialcrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

const (
	EnvelopeKey    = "__sub2api_credentials"
	currentVersion = 2
)

var (
	ErrProtection  = errors.New("upstream credential protection failed")
	ErrKeyRequired = errors.New("upstream credential encryption keyring is required")
	ErrLegacy      = errors.New("legacy plaintext upstream credentials are not permitted")
	keyIDPattern   = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)
)

type keyringFile struct {
	ActiveKeyID string            `json:"active_key_id"`
	Keys        map[string]string `json:"encryption_keys"`
	LookupKey   string            `json:"lookup_key"`
}

type envelope struct {
	Version    int    `json:"version"`
	KeyID      string `json:"key_id"`
	Ciphertext string `json:"ciphertext"`
}

// Protector is immutable. The lookup key remains stable during AES key rotation.
type Protector struct {
	active      string
	keys        map[string]cipher.AEAD
	lookupKey   []byte
	allowLegacy bool
}

func LoadFromEnv(forbiddenKeys ...string) (*Protector, error) {
	path := strings.TrimSpace(os.Getenv("ACCOUNT_CREDENTIAL_KEYRING_FILE"))
	required, err := envBool("ACCOUNT_CREDENTIAL_ENCRYPTION_REQUIRED", false)
	if err != nil {
		return nil, err
	}
	if path == "" {
		if required {
			return nil, ErrKeyRequired
		}
		return nil, nil
	}
	allowLegacy, err := envBool("ACCOUNT_CREDENTIAL_ALLOW_LEGACY", true)
	if err != nil {
		return nil, err
	}
	original, err := os.Lstat(path)
	if err != nil || !original.Mode().IsRegular() {
		return nil, errors.New("upstream credential keyring must be a regular file")
	}
	// #nosec G703 -- only administrator environment configuration selects this path; file identity and owner-only permissions are checked.
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open upstream credential keyring file")
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(original, info) {
		return nil, errors.New("upstream credential keyring must be a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("upstream credential keyring permissions must be owner-only")
	}
	return Load(file, allowLegacy, forbiddenKeys...)
}

func envBool(name string, fallback bool) (bool, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	flag, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean", name)
	}
	return flag, nil
}

func Load(reader io.Reader, allowLegacy bool, forbiddenKeys ...string) (*Protector, error) {
	data, err := io.ReadAll(io.LimitReader(reader, 65537))
	if err != nil || len(data) > 65536 {
		return nil, errors.New("invalid upstream credential keyring file")
	}
	var config keyringFile
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("invalid upstream credential keyring JSON")
	}
	if !keyIDPattern.MatchString(config.ActiveKeyID) || len(config.Keys) == 0 || len(config.Keys) > 32 {
		return nil, errors.New("invalid upstream credential keyring configuration")
	}
	lookup, err := decodeKey(config.LookupKey)
	if err != nil {
		return nil, err
	}
	allKeys := [][]byte{lookup}
	p := &Protector{active: config.ActiveKeyID, keys: make(map[string]cipher.AEAD), lookupKey: lookup, allowLegacy: allowLegacy}
	for id, value := range config.Keys {
		if !keyIDPattern.MatchString(id) {
			return nil, errors.New("invalid upstream credential key ID")
		}
		key, err := decodeKey(value)
		if err != nil {
			return nil, err
		}
		for _, other := range allKeys {
			if hmac.Equal(key, other) {
				return nil, errors.New("upstream credential encryption and lookup keys must be distinct")
			}
		}
		allKeys = append(allKeys, key)
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, ErrProtection
		}
		aead, err := cipher.NewGCMWithRandomNonce(block)
		if err != nil {
			return nil, ErrProtection
		}
		p.keys[id] = aead
	}
	if p.keys[p.active] == nil {
		return nil, errors.New("active upstream credential encryption key is absent")
	}
	for _, forbidden := range forbiddenKeys {
		if forbidden == "" {
			continue
		}
		candidates := [][]byte{[]byte(forbidden)}
		if decoded, err := hex.DecodeString(strings.TrimSpace(forbidden)); err == nil {
			candidates = append(candidates, decoded)
		}
		for _, key := range allKeys {
			for _, candidate := range candidates {
				if hmac.Equal(key, candidate) {
					return nil, errors.New("upstream credential keys must not reuse authentication or redemption roots")
				}
			}
		}
	}
	return p, nil
}

func decodeKey(value string) ([]byte, error) {
	key, err := hex.DecodeString(value)
	if err != nil || len(key) != 32 {
		return nil, errors.New("upstream credential keys must be 64 hexadecimal characters")
	}
	return key, nil
}

func IsProtected(credentials map[string]any) bool {
	_, exists := credentials[EnvelopeKey]
	return exists
}

func (p *Protector) ActiveKeyID() string { return p.active }

func (p *Protector) KeyID(credentials map[string]any) string {
	e, err := parseEnvelope(credentials[EnvelopeKey])
	if err != nil {
		return ""
	}
	return e.KeyID
}

func (p *Protector) IsCurrent(credentials map[string]any) bool {
	e, err := parseEnvelope(credentials[EnvelopeKey])
	return p != nil && err == nil && e.Version == currentVersion && e.KeyID == p.active
}

func (p *Protector) Lookup(apiKey string) string {
	if p == nil || apiKey == "" {
		return apiKey
	}
	mac := hmac.New(sha256.New, p.lookupKey)
	_, _ = mac.Write([]byte("sub2api/upstream-api-key/v1\x00"))
	_, _ = mac.Write([]byte(apiKey))
	return "hmac-sha256:v1:" + hex.EncodeToString(mac.Sum(nil))
}

func (p *Protector) LookupCandidates(apiKey string) []string {
	if p == nil {
		return []string{apiKey}
	}
	keys := []string{p.Lookup(apiKey)}
	if p.allowLegacy {
		keys = append(keys, apiKey)
	}
	return keys
}

func normalize(credentials map[string]any) (map[string]any, []byte, error) {
	if credentials == nil {
		credentials = map[string]any{}
	}
	for key := range credentials {
		if strings.HasPrefix(key, "__sub2api_") {
			return nil, nil, ErrProtection
		}
	}
	encoded, err := json.Marshal(credentials)
	if err != nil {
		return nil, nil, ErrProtection
	}
	var normalized map[string]any
	if json.Unmarshal(encoded, &normalized) != nil {
		return nil, nil, ErrProtection
	}
	return normalized, encoded, nil
}

// Only SQL routing metadata is exposed. Unknown fields are encrypted too.
func (p *Protector) projection(credentials map[string]any, version int) map[string]any {
	out := make(map[string]any)
	if raw, ok := credentials["base_url"].(string); ok {
		if version >= 2 {
			raw = strings.TrimSpace(raw)
		}
		parsed, err := url.Parse(raw)
		if err == nil && isPublicUsageBaseURL(parsed) && (version == 1 || (isCanonicalUsageURL(parsed) && !strings.ContainsAny(raw, "?#"))) {
			out["base_url"] = raw
		}
	}
	if mode, ok := credentials["account_mode"]; ok {
		if raw, ok := mode.(string); ok && version >= 2 {
			mode = strings.TrimSpace(raw)
		}
		if mode == nil || mode == "" || mode == "go" || mode == "zen" {
			out["account_mode"] = mode
		}
	}
	if key, ok := credentials["api_key"].(string); ok {
		out["api_key"] = p.Lookup(key)
	}
	if token, ok := credentials["refresh_token"].(string); ok && strings.TrimSpace(token) != "" {
		out["refresh_token"] = "protected"
	}
	return out
}

func isCanonicalUsageURL(parsed *url.URL) bool {
	authority := strings.ToLower(parsed.Host)
	hostname := strings.ToLower(parsed.Hostname())
	return parsed.Opaque == "" && !parsed.ForceQuery && parsed.RawPath == "" &&
		(authority == hostname || authority == hostname+":443")
}

func isPublicUsageBaseURL(parsed *url.URL) bool {
	if parsed.Scheme != "https" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Port() != "" && parsed.Port() != "443") {
		return false
	}
	path := strings.ToLower(strings.TrimSuffix(parsed.Path, "/"))
	switch strings.ToLower(parsed.Hostname()) {
	case "ollama.com", "www.ollama.com":
		return path == "" || path == "/v1"
	case "opencode.ai":
		return path == "/zen/go" || path == "/zen/go/v1"
	}
	return false
}

func credentialAAD(id int64, keyID string, version int, projection map[string]any) ([]byte, error) {
	encoded, err := json.Marshal(projection)
	if err != nil || id < 0 {
		return nil, ErrProtection
	}
	return append([]byte(fmt.Sprintf("sub2api/accounts/%d/credentials/v%d/%s\x00", id, version, keyID)), encoded...), nil
}

func (p *Protector) Encrypt(id int64, credentials map[string]any) (map[string]any, error) {
	if p != nil && id <= 0 {
		return nil, ErrProtection
	}
	return p.encrypt(id, credentials, currentVersion)
}

// Pending documents exist only inside the account creation transaction. They
// are resealed with the database-assigned ID before that transaction commits.
func (p *Protector) EncryptPending(credentials map[string]any) (map[string]any, error) {
	return p.encrypt(0, credentials, currentVersion)
}

func (p *Protector) encrypt(id int64, credentials map[string]any, version int) (map[string]any, error) {
	normalized, encoded, err := normalize(credentials)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return normalized, nil
	}
	out := p.projection(normalized, version)
	aad, err := credentialAAD(id, p.active, version, out)
	if err != nil {
		return nil, err
	}
	sealed := p.keys[p.active].Seal(nil, nil, encoded, aad)
	out[EnvelopeKey] = envelope{Version: version, KeyID: p.active, Ciphertext: base64.RawStdEncoding.EncodeToString(sealed)}
	return out, nil
}

func parseEnvelope(value any) (envelope, error) {
	var e envelope
	encoded, err := json.Marshal(value)
	if err != nil {
		return e, ErrProtection
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&e) != nil || (e.Version != 1 && e.Version != currentVersion) || !keyIDPattern.MatchString(e.KeyID) || e.Ciphertext == "" {
		return e, ErrProtection
	}
	return e, nil
}

func (p *Protector) Decrypt(id int64, credentials map[string]any) (map[string]any, error) {
	if !IsProtected(credentials) {
		if p != nil && !p.allowLegacy {
			return nil, ErrLegacy
		}
		normalized, _, err := normalize(credentials)
		return normalized, err
	}
	if p == nil {
		return nil, ErrKeyRequired
	}
	if id <= 0 {
		return nil, ErrProtection
	}
	e, err := parseEnvelope(credentials[EnvelopeKey])
	if err != nil || p.keys[e.KeyID] == nil {
		return nil, ErrProtection
	}
	projection := make(map[string]any, len(credentials)-1)
	for key, value := range credentials {
		if key != EnvelopeKey {
			projection[key] = value
		}
	}
	aad, err := credentialAAD(id, e.KeyID, e.Version, projection)
	if err != nil {
		return nil, err
	}
	sealed, err := base64.RawStdEncoding.DecodeString(e.Ciphertext)
	if err != nil {
		return nil, ErrProtection
	}
	plain, err := p.keys[e.KeyID].Open(nil, nil, sealed, aad)
	if err != nil {
		return nil, ErrProtection
	}
	var decoded map[string]any
	if json.Unmarshal(plain, &decoded) != nil || decoded == nil {
		return nil, ErrProtection
	}
	normalized, _, err := normalize(decoded)
	if err != nil {
		return nil, err
	}
	// Historical projections are part of the authenticated format contract.
	expected, _ := json.Marshal(p.projection(normalized, e.Version))
	actual, _ := json.Marshal(projection)
	if !bytes.Equal(expected, actual) {
		return nil, ErrProtection
	}
	return normalized, nil
}

// Cache tokens authenticate both their namespace and their lookup identity.
func (p *Protector) SealCache(subject, token string) (string, error) {
	if p == nil {
		return token, nil
	}
	sealed := p.keys[p.active].Seal(nil, nil, []byte(token), []byte("sub2api/oauth-cache/v1/"+p.active+"/"+subject))
	encoded, err := json.Marshal(envelope{Version: 1, KeyID: p.active, Ciphertext: base64.RawStdEncoding.EncodeToString(sealed)})
	if err != nil {
		return "", ErrProtection
	}
	return "sub2api-credential:v1:" + string(encoded), nil
}

func (p *Protector) OpenCache(subject, value string) (string, error) {
	const prefix = "sub2api-credential:v1:"
	if !strings.HasPrefix(value, prefix) {
		if p != nil {
			return "", ErrLegacy
		}
		return value, nil
	}
	if p == nil {
		return "", ErrKeyRequired
	}
	var raw any
	if json.Unmarshal([]byte(strings.TrimPrefix(value, prefix)), &raw) != nil {
		return "", ErrProtection
	}
	e, err := parseEnvelope(raw)
	if err != nil || e.Version != 1 || p.keys[e.KeyID] == nil {
		return "", ErrProtection
	}
	sealed, err := base64.RawStdEncoding.DecodeString(e.Ciphertext)
	if err != nil {
		return "", ErrProtection
	}
	plain, err := p.keys[e.KeyID].Open(nil, nil, sealed, []byte("sub2api/oauth-cache/v1/"+e.KeyID+"/"+subject))
	if err != nil {
		return "", ErrProtection
	}
	return string(plain), nil
}
