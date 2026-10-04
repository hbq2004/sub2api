# Administrator emergency recovery

This is a procedure, not a record of a real lost-device drill. Verified from
the current code and deployment on 2026-10-02 (China Standard Time).

## Before an incident

- Keep the administrator password, a second TOTP method/recovery material, and
  the Tencent Cloud account recovery methods outside the Sub2API database and
  separate from encrypted backup archives. Do not put any values here.
- Keep an enrolled Passkey. A Passkey can sign in, but administrator sensitive
  operations and Passkey changes still require a fresh TOTP step-up grant.
- Retain the latest verified encrypted archive and the independent encrypted
  recovery-key copy. The archive and key-copy folders must remain unshared.

## TOTP device lost while Passkey and password remain available

1. Sign in to `https://api.zynexus.top` with the existing Passkey. Confirm the
   expected origin before touching account settings.
2. Use the administrator's own TOTP disable flow. The service checks the
   current administrator password; it does not accept the Passkey as step-up.
   This creates a temporary period when sensitive operations are unavailable.
3. Immediately enroll a new TOTP device through the normal setup and verify a
   fresh login plus a sensitive-operation step-up. Confirm `totp_enabled` and
   `step_up_enabled` remain true and the Passkey still works.
4. Use the normal revoke-all-sessions command before finishing recovery, then
   sign in again with the recovered factors. Rebinding TOTP alone does not
   invalidate existing access or refresh sessions. Review recent administrator
   audit events; record only event IDs, timestamps, and outcome.

If the password or Passkey is also unavailable, do not change production
database fields by hand. Use Tencent Cloud's existing account recovery path and
the verified encrypted backup in an isolated environment. Restore service only
after identifying the affected identity, preserving a fresh recoverable copy,
and checking the application encryption key and WebAuthn origin.

The logged-in Tencent Cloud main account showed virtual MFA bound, login and
operation protection enabled, plus WeChat and safety-phone methods. This is
configuration evidence, not proof that a person can complete emergency login
after losing the MFA device.

## Independent recovery acceptance, 2026-10-02

The current production image was restored on the independent Windows Docker
host, using the encrypted database archive, independently recovered keyring,
encrypted deployment configuration and pinned image bundle. A disposable
administrator and Chromium virtual authenticator completed actual WebAuthn
registration and signature validation, lost-TOTP password recovery, new TOTP
enrollment, a new password/TOTP login and sensitive-operation step-up. Explicit
session revocation rejected both old access and refresh tokens. The real
production administrator and its enrolled devices were not changed. This
proves the isolated application workflow, not physical-device or cloud-account
recovery. See the full launch acceptance evidence in sub2api-security.
