# Redeem-code protection rollout

## Tokyo deployment status (2026-10-02 CST)

The Tokyo application is running `sub2api:redeem-protection-v2-20261002`.
Migration `241_redeem_code_protection.sql` is recorded as applied. A count-only
query confirmed all 7 existing redeem-code rows have a hash and key version 1,
with 0 legacy rows remaining. All 7 stored `code` values have the ciphertext
length/shape expected after migration. The application container is healthy and
the public `/health` endpoint returned 200. The active upstream account count
remained 46; this deployment did not change account credential storage.

The post-migration encrypted archive `20261001T222635Z.p7m` was downloaded to
the Git-ignored `private-backups/` directory, decrypted, checksum-verified, and
restored in isolated local containers (100 PostgreSQL tables, 1224 Redis keys).
The two dedicated redeem-code keys are present in the server's private `.env`
and a local Git-ignored `private-keys/` recovery file, separate from the backup
archive directory. Preserve an independently protected copy
of these keys: the database backup alone cannot recover the codes. An earlier
build was rejected because its protected repository wiring was absent; the
previous image was restored before the corrected image was built and deployed.

This verification covers storage shape, startup, health, and isolated data
restore. It does not include a production redemption using a real code or a
second-machine restore. Historical backups, exports, subscription notes, and
other systems' inventories remain separate cleanup and access-control scopes.

The application stores a keyed SHA-256 digest for exact lookup and randomized
AES-256-GCM ciphertext for recovery. The existing `redeem_codes.code` column
becomes the ciphertext carrier after migration. The plaintext is returned only
in the immediate response to code generation. Admin and user list/detail/history
responses show a mask; bulk CSV export is disabled.

## Before rollout

1. Preserve a verified encrypted PostgreSQL backup and a working restore path.
   Verify the latest `.p7m` hash and an isolated restore before changing the
   application. The old backup contains plaintext codes; keep it private and
   follow the normal retention policy.
2. Generate two **different** 32-byte random keys. Set the 64-character hex
   values in the server's private environment as `REDEEM_CODE_HMAC_KEY` and
   `REDEEM_CODE_ENCRYPTION_KEY`. Do not put values in Git, chat, scripts, logs,
   Docker command arguments, or the TOTP key. Back up both keys separately from
   the database. Startup rejects either key if it equals the TOTP key. Losing
   either key makes protected codes unusable.
3. Deploy the binary, `241_redeem_code_protection.sql`, and the two environment
   variables together. Do not run the new binary without both keys. A missing,
   malformed, equal, or incorrect key causes startup to fail closed.

## Cutover and verification

1. Start one application instance. Migration 241 widens `code` and adds
   `code_hash` plus `code_key_version` and clears historical idempotency
   responses that may contain plaintext codes. Startup then verifies existing
   protected records and replaces legacy plaintext rows with ciphertext and
   HMAC digests.
   Keep other writers stopped during this one-time backfill.
2. Inspect counts only: no rows should remain with `code_hash IS NULL` or
   `code_key_version = 0`; all protected records must be version 1. Do not
   print codes, hashes, ciphertext, or key values.
3. In an isolated environment, use a synthetic code to verify generation,
   one-time display, exact lookup, redemption, repeat-use rejection, masked
   list/history, and rejected CSV export. Verify password/OAuth invitation
   redemption separately if enabled.
4. Confirm public health and normal application logs after restart. Re-run the
   encrypted backup and isolated restore with both keys available in the
   recovery environment.

The schema change and backfill are forward-only. Rolling back the application
binary alone will not restore plaintext lookup. Restore the pre-cutover
encrypted database backup into an isolated environment with the previous
binary, or roll forward with the protected-code binary and preserved keys.

This implementation does not encrypt another system's inventory: codes
transferred to CatFK or another seller are stored according to that provider's
own controls. Existing plaintext copies in previous backups or exports need
their own retention and access review.

`payment_orders.recharge_code` is a separate internal payment-fulfillment
identifier and remains in that table in plaintext. The checkout/payment
subsystem requires its own migration before making a whole-database
"no plaintext codes" claim.

Older subscription notes may also contain codes that were already redeemed.
They are not lookup authorities, but require a separate scoped cleanup before
claiming all historical plaintext references have been removed.
