package main

import (
	"context"
	"flag"
	"io"
	"os"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestPurgeCredentialCacheKeepsOtherNamespaces(t *testing.T) {
	server := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	ctx := context.Background()
	for _, key := range []string{"sched:acc:17", "sched:meta:17", "oauth:token:17", "oauth:refresh_lock:17", "auth:session:17", "billing:17", "sched:ready:17"} {
		require.NoError(t, rdb.Set(ctx, key, "synthetic", 0).Err())
	}
	require.NoError(t, purgeCredentialCache(ctx, rdb))
	for _, key := range []string{"sched:acc:17", "sched:meta:17", "oauth:token:17"} {
		require.False(t, server.Exists(key))
	}
	for _, key := range []string{"oauth:refresh_lock:17", "auth:session:17", "billing:17", "sched:ready:17"} {
		require.True(t, server.Exists(key))
	}
}

func TestMigrationRejectsUnsafeOptionsBeforeConnecting(t *testing.T) {
	originalArgs, originalFlags := os.Args, flag.CommandLine
	t.Cleanup(func() { os.Args, flag.CommandLine = originalArgs, originalFlags })
	t.Setenv("ACCOUNT_CREDENTIAL_MIGRATION_DSN", "")
	for _, test := range []struct {
		name      string
		args      []string
		errorText string
	}{
		{"unknown-mode", []string{"--mode=invalid"}, "mode must be"},
		{"encrypt-with-live-writers", []string{"--mode=encrypt", "--apply", "--purge-cache"}, "writers must be stopped"},
		{"reencrypt-with-live-writers", []string{"--mode=reencrypt", "--apply", "--purge-cache"}, "writers must be stopped"},
		{"decrypt-with-live-writers", []string{"--mode=decrypt", "--apply", "--purge-cache", "--allow-plaintext-rollback"}, "writers must be stopped"},
		{"mutation-without-purge", []string{"--mode=encrypt", "--apply", "--writers-stopped"}, "cache purge is required"},
		{"purge-without-apply", []string{"--purge-cache"}, "cache purge requires apply"},
		{"verify-purge-with-live-writers", []string{"--mode=verify", "--apply", "--purge-cache"}, "writers must be stopped"},
	} {
		t.Run(test.name, func(t *testing.T) {
			os.Args = append([]string{"credential-migrate"}, test.args...)
			flag.CommandLine = flag.NewFlagSet("credential-migrate", flag.ContinueOnError)
			flag.CommandLine.SetOutput(io.Discard)
			require.ErrorContains(t, run(), test.errorText)
		})
	}
}
