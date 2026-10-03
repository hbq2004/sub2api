-- Redeem codes are migrated by the application because the HMAC and AES keys
-- must never be placed in a SQL migration or database.
ALTER TABLE redeem_codes ALTER COLUMN code TYPE TEXT;
ALTER TABLE redeem_codes ADD COLUMN IF NOT EXISTS code_hash VARCHAR(64);
ALTER TABLE redeem_codes ADD COLUMN IF NOT EXISTS code_key_version INT NOT NULL DEFAULT 0;
CREATE UNIQUE INDEX IF NOT EXISTS idx_redeem_codes_code_hash
    ON redeem_codes(code_hash)
    WHERE code_hash IS NOT NULL;

-- Older successful responses may contain full codes. They cannot be replayed
-- after the one-time-display policy takes effect.
UPDATE idempotency_records
SET response_body = NULL
WHERE scope IN ('admin.redeem_codes.generate', 'admin.redeem_codes.create_and_redeem')
  AND response_body IS NOT NULL;
