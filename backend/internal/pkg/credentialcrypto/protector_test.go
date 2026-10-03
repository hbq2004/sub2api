package credentialcrypto

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func testProtector(t testing.TB, active string, allowLegacy bool) *Protector {
	t.Helper()
	data, err := json.Marshal(keyringFile{ActiveKeyID: active, Keys: map[string]string{"v1": strings.Repeat("01", 32), "v2": strings.Repeat("03", 32)}, LookupKey: strings.Repeat("02", 32)})
	require.NoError(t, err)
	p, err := Load(strings.NewReader(string(data)), allowLegacy)
	require.NoError(t, err)
	return p
}

func cloneDocument(t *testing.T, document map[string]any) map[string]any {
	t.Helper()
	data, err := json.Marshal(document)
	require.NoError(t, err)
	var result map[string]any
	require.NoError(t, json.Unmarshal(data, &result))
	return result
}

func TestProtectorEncryptsUnknownFieldsAndAuthenticatesIdentity(t *testing.T) {
	p := testProtector(t, "v1", true)
	plain := map[string]any{"access_token": "synthetic-access", "refresh_token": "synthetic-refresh", "api_key": "synthetic-api", "unknown_secret": map[string]any{"nested": "synthetic-nested"}, "base_url": "https://ollama.com/v1", "expires_at": float64(1900000000)}
	first, err := p.Encrypt(17, plain)
	require.NoError(t, err)
	second, err := p.Encrypt(17, plain)
	require.NoError(t, err)
	require.NotEqual(t, first[EnvelopeKey], second[EnvelopeKey])
	encoded, err := json.Marshal(first)
	require.NoError(t, err)
	for _, secret := range []string{"synthetic-access", "synthetic-refresh", "synthetic-api", "synthetic-nested"} {
		require.NotContains(t, string(encoded), secret)
	}
	require.Equal(t, first["api_key"], second["api_key"])
	require.Equal(t, "protected", first["refresh_token"])
	restored, err := p.Decrypt(17, first)
	require.NoError(t, err)
	require.Equal(t, plain, restored)
	_, err = p.Decrypt(18, first)
	require.ErrorIs(t, err, ErrProtection)
	_, err = (*Protector)(nil).Decrypt(17, first)
	require.ErrorIs(t, err, ErrKeyRequired)
	for _, field := range []string{"base_url", "api_key", "refresh_token"} {
		tampered := cloneDocument(t, first)
		tampered[field] = "tampered"
		_, err := p.Decrypt(17, tampered)
		require.ErrorIs(t, err, ErrProtection)
	}
	tampered := cloneDocument(t, first)
	tampered[EnvelopeKey].(map[string]any)["ciphertext"] = "broken"
	_, err = p.Decrypt(17, tampered)
	require.ErrorIs(t, err, ErrProtection)
	_, err = p.Encrypt(17, first)
	require.ErrorIs(t, err, ErrProtection)
}

func TestProtectorLegacyRefreshPresenceAndPrivateURLs(t *testing.T) {
	p := testProtector(t, "v1", true)
	strict := testProtector(t, "v1", false)
	_, err := strict.Decrypt(9, map[string]any{"api_key": "synthetic"})
	require.ErrorIs(t, err, ErrLegacy)
	for _, value := range []any{nil, "", "  "} {
		stored, err := p.Encrypt(9, map[string]any{"refresh_token": value})
		require.NoError(t, err)
		_, exists := stored["refresh_token"]
		require.False(t, exists)
	}
	for _, raw := range []string{"https://user:synthetic-password@example.test", "https://example.test?api_key=synthetic-query", "https://example.test#synthetic-fragment"} {
		stored, err := p.Encrypt(9, map[string]any{"base_url": raw})
		require.NoError(t, err)
		_, exists := stored["base_url"]
		require.False(t, exists)
		decoded, err := p.Decrypt(9, stored)
		require.NoError(t, err)
		require.Equal(t, raw, decoded["base_url"])
	}
	pending, err := p.EncryptPending(map[string]any{"access_token": "synthetic"})
	require.NoError(t, err)
	_, err = p.Decrypt(0, pending)
	require.ErrorIs(t, err, ErrProtection)
	_, err = p.Decrypt(9, pending)
	require.ErrorIs(t, err, ErrProtection)
}

func TestProtectorRotationRecoveryAndWrongKeys(t *testing.T) {
	old := testProtector(t, "v1", true)
	rotated := testProtector(t, "v2", true)
	stored, err := old.Encrypt(4, map[string]any{"api_key": "synthetic-recovery"})
	require.NoError(t, err)
	decoded, err := rotated.Decrypt(4, stored)
	require.NoError(t, err)
	require.Equal(t, "synthetic-recovery", decoded["api_key"])
	require.Equal(t, old.Lookup("synthetic-recovery"), rotated.Lookup("synthetic-recovery"))
	for _, wrong := range []keyringFile{
		{ActiveKeyID: "v2", Keys: map[string]string{"v2": strings.Repeat("03", 32)}, LookupKey: strings.Repeat("02", 32)},
		{ActiveKeyID: "v1", Keys: map[string]string{"v1": strings.Repeat("04", 32)}, LookupKey: strings.Repeat("02", 32)},
		{ActiveKeyID: "v1", Keys: map[string]string{"v1": strings.Repeat("01", 32)}, LookupKey: strings.Repeat("04", 32)},
	} {
		data, err := json.Marshal(wrong)
		require.NoError(t, err)
		p, err := Load(strings.NewReader(string(data)), true)
		require.NoError(t, err)
		_, err = p.Decrypt(4, stored)
		require.ErrorIs(t, err, ErrProtection)
	}
}

func TestProtectorRejectsInvalidOrReusedRoots(t *testing.T) {
	config := keyringFile{ActiveKeyID: "v1", Keys: map[string]string{"v1": strings.Repeat("01", 32)}, LookupKey: strings.Repeat("02", 32)}
	data, err := json.Marshal(config)
	require.NoError(t, err)
	_, err = Load(strings.NewReader(string(data)), true, strings.Repeat("01", 32))
	require.ErrorContains(t, err, "must not reuse")
	for _, raw := range []string{`{}`, `{"active_key_id":"v1","lookup_key":"bad"}`, string(data) + `{}`, strings.Replace(string(data), strings.Repeat("02", 32), strings.Repeat("01", 32), 1)} {
		_, err := Load(strings.NewReader(raw), true)
		require.Error(t, err)
	}
	t.Setenv("ACCOUNT_CREDENTIAL_KEYRING_FILE", "")
	t.Setenv("ACCOUNT_CREDENTIAL_ENCRYPTION_REQUIRED", "true")
	_, err = LoadFromEnv()
	require.ErrorIs(t, err, ErrKeyRequired)
}

func TestProtectorRejectsWhitespaceWrappedForbiddenRoots(t *testing.T) {
	config := keyringFile{ActiveKeyID: "v1", Keys: map[string]string{"v1": strings.Repeat("01", 32)}, LookupKey: strings.Repeat("02", 32)}
	data, err := json.Marshal(config)
	require.NoError(t, err)
	for _, test := range []struct{ name, forbidden string }{
		{"encryption-root", " " + config.Keys["v1"] + " "},
		{"lookup-root", "\t" + config.LookupKey + "\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := Load(strings.NewReader(string(data)), false, test.forbidden)
			require.ErrorContains(t, err, "must not reuse")
		})
	}
}

func FuzzProtectorDocument(f *testing.F) {
	p := testProtector(f, "v1", false)
	expected := map[string]any{"access_token": "synthetic-fuzz-access", "api_key": "synthetic-fuzz-api"}
	for _, version := range []int{1, 2} {
		stored, err := p.encrypt(17, expected, version)
		require.NoError(f, err)
		encoded, err := json.Marshal(stored)
		require.NoError(f, err)
		f.Add(int64(17), encoded)
	}
	for _, raw := range []string{"{}", "null", `{"__sub2api_credentials":null}`, `{"__sub2api_credentials":{"version":2,"key_id":"v1","ciphertext":"broken"}}`} {
		f.Add(int64(17), []byte(raw))
	}
	f.Fuzz(func(t *testing.T, id int64, raw []byte) {
		var stored map[string]any
		if json.Unmarshal(raw, &stored) != nil {
			return
		}
		plain, err := p.Decrypt(id, stored)
		if err == nil {
			require.Equal(t, int64(17), id)
			require.Equal(t, expected, plain)
			require.True(t, IsProtected(stored))
		}
	})
}

func FuzzProtectorOAuthCache(f *testing.F) {
	p := testProtector(f, "v1", false)
	const subject = "oauth:token:synthetic-fuzz"
	sealed, err := p.SealCache(subject, "synthetic-fuzz-token")
	require.NoError(f, err)
	f.Add(subject, sealed)
	f.Add(subject, "legacy")
	f.Add(subject, "sub2api-credential:v1:{}")
	f.Add("oauth:token:synthetic-other", sealed)
	f.Fuzz(func(t *testing.T, identity, value string) {
		plain, err := p.OpenCache(identity, value)
		if err == nil {
			require.Equal(t, subject, identity)
			require.Equal(t, "synthetic-fuzz-token", plain)
		}
	})
}

func TestProtectorCacheDomainsAndConcurrentUse(t *testing.T) {
	p := testProtector(t, "v1", true)
	sealed, err := p.SealCache("oauth:token:synthetic-1", "synthetic-access")
	require.NoError(t, err)
	require.NotContains(t, sealed, "synthetic-access")
	_, err = p.OpenCache("oauth:token:synthetic-2", sealed)
	require.ErrorIs(t, err, ErrProtection)
	_, err = p.OpenCache("oauth:token:synthetic-1", "legacy")
	require.ErrorIs(t, err, ErrLegacy)
	_, err = (*Protector)(nil).OpenCache("oauth:token:synthetic-1", sealed)
	require.ErrorIs(t, err, ErrKeyRequired)
	var group sync.WaitGroup
	for i := range 64 {
		group.Add(1)
		go func(id int64) {
			defer group.Done()
			stored, err := p.Encrypt(id, map[string]any{"access_token": "synthetic-concurrent"})
			if err != nil {
				t.Error(err)
				return
			}
			decoded, err := p.Decrypt(id, stored)
			if err != nil || decoded["access_token"] != "synthetic-concurrent" {
				t.Error("concurrent credential roundtrip failed")
			}
		}(int64(i + 1))
	}
	group.Wait()
}

func TestProtectorPreservesUsageMetadataSemantics(t *testing.T) {
	p := testProtector(t, "v1", false)
	for _, raw := range []string{" https://ollama.com/v1 ", " HTTPS://OPENCODE.AI:443/ZeN/Go/V1/ "} {
		t.Run(raw, func(t *testing.T) {
			plain := map[string]any{"api_key": "synthetic-usage", "base_url": raw}
			stored, err := p.Encrypt(17, plain)
			require.NoError(t, err)
			require.Equal(t, strings.TrimSpace(raw), stored["base_url"])
			restored, err := p.Decrypt(17, stored)
			require.NoError(t, err)
			require.Equal(t, plain, restored, "normalizing SQL metadata must preserve the original credentials")
		})
	}
	for _, mode := range []string{" zen ", "\tzen\n", " go "} {
		plain := map[string]any{"account_mode": mode}
		stored, err := p.Encrypt(17, plain)
		require.NoError(t, err)
		require.Equal(t, strings.TrimSpace(mode), stored["account_mode"])
		restored, err := p.Decrypt(17, stored)
		require.NoError(t, err)
		require.Equal(t, plain, restored)
	}
	for _, raw := range []string{"https://ollama.com?", "https://ollama.com/%76%31", "https://ollama.com:", "https://opencode.ai/zen/go#", "https://synthetic:password@opencode.ai/zen/go"} {
		stored, err := p.Encrypt(17, map[string]any{"base_url": raw})
		require.NoError(t, err)
		require.NotContains(t, stored, "base_url", "noncanonical and credential-bearing URLs remain encrypted")
	}
}

func TestProtectorVersionOneCompatibilityAndUpgrade(t *testing.T) {
	p := testProtector(t, "v1", false)
	plain := map[string]any{"api_key": "synthetic-history", "base_url": " https://opencode.ai/zen/go ", "account_mode": " zen "}
	old, err := p.encrypt(17, plain, 1)
	require.NoError(t, err)
	require.NotContains(t, old, "base_url")
	require.NotContains(t, old, "account_mode")
	require.False(t, p.IsCurrent(old))
	restored, err := p.Decrypt(17, old)
	require.NoError(t, err)
	require.Equal(t, plain, restored)
	upgraded, err := p.Encrypt(17, restored)
	require.NoError(t, err)
	require.True(t, p.IsCurrent(upgraded))
	require.Equal(t, "zen", upgraded["account_mode"])
	require.Equal(t, "https://opencode.ai/zen/go", upgraded["base_url"])
	restored, err = p.Decrypt(17, upgraded)
	require.NoError(t, err)
	require.Equal(t, plain, restored)
	tampered := cloneDocument(t, upgraded)
	tampered[EnvelopeKey].(map[string]any)["version"] = float64(1)
	_, err = p.Decrypt(17, tampered)
	require.ErrorIs(t, err, ErrProtection)
	rotated := testProtector(t, "v2", false)
	require.False(t, rotated.IsCurrent(upgraded))
}
