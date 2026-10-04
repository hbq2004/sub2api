package repository

import (
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestDownstreamKeyProtectionDomainsAndRowBinding(t *testing.T) {
	p := syntheticCredentialProtector(t, "v1", false)
	raw := "synthetic-downstream-bearer-for-security-test"
	require.NotEqual(t, raw, p.LookupDownstream(raw))
	require.NotEqual(t, p.Lookup(raw), p.LookupDownstream(raw))
	require.NotEqual(t, p.LookupDownstream(raw), p.LookupDownstream(p.LookupDownstream(raw)))
	a, err := p.SealCache(downstreamKeySubject(1), raw)
	require.NoError(t, err)
	b, err := p.SealCache(downstreamKeySubject(1), raw)
	require.NoError(t, err)
	require.NotEqual(t, a, b)
	require.NotContains(t, a, raw)
	opened, err := p.OpenCache(downstreamKeySubject(1), a)
	require.NoError(t, err)
	require.Equal(t, raw, opened)
	_, err = p.OpenCache(downstreamKeySubject(2), a)
	require.Error(t, err)
	_, err = p.OpenCache("oauth-account/1", a)
	require.Error(t, err)
	require.NotContains(t, service.MaskAPIKey(raw), raw)
	require.Equal(t, "***", service.MaskAPIKey(p.LookupDownstream(raw)))
	require.Equal(t, "***", service.MaskAPIKey(strings.Repeat("a", 8)))
}
