// credential-migrate is an offline, explicitly invoked credential migration.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/credentialcrypto"
	"github.com/Wei-Shaw/sub2api/internal/repository"
	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"
)

func main() {
	if err := run(); err != nil {
		// Driver errors may echo connection strings or bind arguments.
		fmt.Fprintln(os.Stderr, "upstream credential migration failed; keep writers stopped")
		os.Exit(1)
	}
}

func run() error {
	mode := flag.String("mode", "verify", "verify, encrypt, reencrypt, or decrypt")
	apply := flag.Bool("apply", false, "commit an explicitly selected migration")
	writersStopped := flag.Bool("writers-stopped", false, "confirm all application writers are stopped")
	allowRollback := flag.Bool("allow-plaintext-rollback", false, "explicitly allow restoring plaintext storage")
	purgeCache := flag.Bool("purge-cache", false, "remove only upstream OAuth and scheduler credential cache entries")
	flag.Parse()
	switch *mode {
	case "verify", "encrypt", "reencrypt", "decrypt":
	default:
		return errors.New("mode must be verify, encrypt, reencrypt, or decrypt")
	}
	if *apply && (*mode != "verify" || *purgeCache) && !*writersStopped {
		return errors.New("writers must be stopped")
	}
	if *apply && *mode != "verify" && !*purgeCache {
		return errors.New("upstream credential cache purge is required")
	}
	if *purgeCache && !*apply {
		return errors.New("cache purge requires apply")
	}
	dsn := os.Getenv("ACCOUNT_CREDENTIAL_MIGRATION_DSN")
	if dsn == "" {
		return errors.New("migration database connection is required")
	}
	protector, err := credentialcrypto.LoadFromEnv(os.Getenv("TOTP_ENCRYPTION_KEY"), os.Getenv("JWT_SECRET"), os.Getenv("REDEEM_CODE_ENCRYPTION_KEY"), os.Getenv("REDEEM_CODE_HMAC_KEY"))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	selectedMode := *mode
	if !*apply {
		selectedMode = "verify"
	}
	var rdb *redis.Client
	if *purgeCache {
		addr := os.Getenv("ACCOUNT_CREDENTIAL_MIGRATION_REDIS_ADDR")
		if addr == "" {
			return errors.New("migration Redis connection is required")
		}
		dbIndex := 0
		if value := os.Getenv("ACCOUNT_CREDENTIAL_MIGRATION_REDIS_DB"); value != "" {
			var err error
			dbIndex, err = strconv.Atoi(value)
			if err != nil || dbIndex < 0 {
				return errors.New("migration Redis database index must be a nonnegative integer")
			}
		}
		rdb = redis.NewClient(&redis.Options{Addr: addr, DB: dbIndex, Username: os.Getenv("ACCOUNT_CREDENTIAL_MIGRATION_REDIS_USERNAME"), Password: os.Getenv("ACCOUNT_CREDENTIAL_MIGRATION_REDIS_PASSWORD")})
		defer func() { _ = rdb.Close() }()
		if err := rdb.Ping(ctx).Err(); err != nil {
			return err
		}
	}
	report, err := repository.MigrateAccountCredentials(ctx, db, protector, selectedMode, *allowRollback)
	if err != nil {
		return err
	}
	if rdb != nil {
		if err := purgeCredentialCache(ctx, rdb); err != nil {
			fmt.Fprintln(os.Stderr, "database migration committed; cache purge failed; keep writers stopped and retry the purge")
			return err
		}
	}
	return json.NewEncoder(os.Stdout).Encode(report)
}

func purgeCredentialCache(ctx context.Context, rdb *redis.Client) error {
	for _, pattern := range []string{"sched:acc:*", "sched:meta:*", "oauth:token:*"} {
		var cursor uint64
		for {
			keys, next, err := rdb.Scan(ctx, cursor, pattern, 256).Result()
			if err != nil {
				return err
			}
			if len(keys) > 0 {
				if err := rdb.Del(ctx, keys...).Err(); err != nil {
					return err
				}
			}
			cursor = next
			if cursor == 0 {
				break
			}
		}
	}
	return nil
}
