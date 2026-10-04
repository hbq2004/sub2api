package urlvalidator

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPublicDialPinsVettedIP(t *testing.T) {
	lookups := 0
	address := ""
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		lookups++
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
	}
	dial := func(_ context.Context, _ string, target string) (net.Conn, error) { address = target; return a, nil }
	conn, err := dialPublic(context.Background(), "tcp", "provider.example:443", dial, lookup)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.Equal(t, 1, lookups)
	require.Equal(t, "93.184.216.34:443", address)
}

func TestPublicDialRejectsPrivateDNSWithoutConnecting(t *testing.T) {
	called := false
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}, {IP: net.ParseIP("127.0.0.1")}}, nil
	}
	dial := func(context.Context, string, string) (net.Conn, error) { called = true; return nil, nil }
	_, err := dialPublic(context.Background(), "tcp", "provider.example:443", dial, lookup)
	require.Error(t, err)
	require.False(t, called)
}
