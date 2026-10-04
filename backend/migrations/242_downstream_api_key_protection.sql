-- The indexed identity is an HMAC. Recovery material uses the existing external keyring.
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS key_ciphertext TEXT NOT NULL DEFAULT '';
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS key_hint VARCHAR(128) NOT NULL DEFAULT '';

-- Older create responses can contain the original bearer; retain replay metadata only.
UPDATE idempotency_records
SET response_body = jsonb_set(response_body::jsonb, '{key}', '"***"'::jsonb)::text
WHERE scope LIKE '%api_keys.create%' AND response_body IS NOT NULL
  AND response_body::jsonb ? 'key';
