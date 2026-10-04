package repository

import (
	"net/http"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

func TestHTTPUpstreamRequestHostUsesConfiguredAllowlist(t *testing.T) {
	cfg := &config.Config{Security: config.SecurityConfig{URLAllowlist: config.URLAllowlistConfig{
		Enabled:           true,
		UpstreamHosts:     []string{"api.example.test"},
		AllowPrivateHosts: true, // avoid DNS resolution in this unit test
	}}}
	svc, ok := NewHTTPUpstream(cfg).(*httpUpstreamService)
	require.True(t, ok)

	req, err := http.NewRequest(http.MethodGet, "https://unapproved.example.test/v1", nil)
	require.NoError(t, err)
	require.Error(t, svc.validateRequestHost(req))

	req, err = http.NewRequest(http.MethodGet, "https://api.example.test/v1", nil)
	require.NoError(t, err)
	require.NoError(t, svc.validateRequestHost(req))
}

func TestHTTPUpstreamRequestHostRejectsHTTPWhenPolicyEnabled(t *testing.T) {
	cfg := &config.Config{Security: config.SecurityConfig{URLAllowlist: config.URLAllowlistConfig{
		Enabled:           true,
		UpstreamHosts:     []string{"api.example.test"},
		AllowPrivateHosts: true,
		AllowInsecureHTTP: true, // enabled policy still requires HTTPS
	}}}
	svc, ok := NewHTTPUpstream(cfg).(*httpUpstreamService)
	require.True(t, ok)
	req, err := http.NewRequest(http.MethodGet, "http://api.example.test/v1", nil)
	require.NoError(t, err)
	require.Error(t, svc.validateRequestHost(req))
}
