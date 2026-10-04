# Lightweight security tasks 6-10

Evidence checked 2026-10-02 (China Standard Time). Only metadata and test
results are recorded. No credential values, OAuth payloads, private keys, or
plaintext backup contents were printed or committed.

## 6. Automatic encrypted backup

- Tokyo `sub2api-backup.timer` is active and persistent. Its last 04:00 run
  exited with status 0 and created `20260930T200001Z.p7m`. The next run was
  scheduled for 2026-10-02 04:00 CST when inspected.
- Windows `Sub2API-PullEncryptedBackup` and
  `Sub2API-CheckEncryptedBackup` last returned 0. Their next scheduled times
  were 06:30 and 07:00 CST. A reboot was not performed; the timer and task
  registrations were checked, but post-reboot execution remains to observe.
- The downloaded 775905-byte archive decrypted, its internal SHA-256 manifest
  passed, and the encrypted archive SHA-256 was
  `B2B7105A4AAA4796C63CCD207E946CAD9EC7DE50FA2A2749EEE7FFC3EED94729`.

## 7. Off-host copy and restore

- The existing Google Drive folder `Sub2API encrypted backups` contains the
  latest encrypted archive and manifest. It is not shared. The independently
  stored encrypted recovery-key copy is in a separate unshared folder. The
  plaintext PEM, SMTP credential, and recovery passphrase were not uploaded.
- A fresh download of the Drive archive matched the local encrypted archive
  byte-for-byte by SHA-256. The temporary browser download was removed after
  verification.
- Recovery from that Drive copy succeeded in isolated Docker containers:
  PostgreSQL 100 tables, Redis 1220 keys, Sub2API health OK, and Passkey
  begin-login OK. No production containers or ports were changed. A physical
  second-machine restore was not performed.

## 8. Administrator emergency recovery

- The isolated application/Passkey restore succeeded. Focused Go tests for
  administrator Passkey and step-up guards passed.
- Current code requires TOTP for sensitive administrator step-up; Passkey login
  is not a replacement. Administrator TOTP disable requires the administrator
  password, followed by immediate re-enrollment in a lost-device recovery.
- Tencent Cloud account protection and alternate methods were inspected in an
  authenticated console session. A real lost-device or cloud account recovery
  was not performed on the sole production administrator. See
  `ADMIN_EMERGENCY_RECOVERY.md`.

## 9. Leak outlets

- Account and proxy exports set `Cache-Control: private, no-store`; audit logs
  record sensitive reads and recursively redact credential-shaped keys.
- Recent application log high-risk literal count: 0. Recent audit request-body
  high-risk literal count: 0. The checks were counts only; no matching values
  were displayed. Unauthenticated export and backup-download endpoints both
  returned HTTP 401.
- Local backup validation removed plaintext staging. Recovery drills removed
  their temporary containers and directories. Private backup/tools and sync
  state paths are Git-ignored.
- Sync CLI and read-only audit failure messages were narrowed to fixed status
  text, preventing upstream error bodies from being echoed in terminals.
  Twenty-five sync tests passed. This audit cannot prove every historical log
  or every provider error is free of secrets.

## 10. Git leak prevention

- The shallow commit graph was completed to 7260 commits. A later object audit
  found 28723 missing historical blobs; a filtered refetch recovered all but
  one 62 MB compiled Go test binary at `backend/repository.test`. The entire
  remaining source/document/config history was scanned offline with that one
  binary path explicitly excluded. The binary itself was not scanned.
- The history scan returned 107 locations: 64 test/fixture/example, six docs,
  and 37 other source/config locations. Rules: 76 generic API key, 26 business
  root material, three private key, and two JWT. These locations require
  individual review; historical `config.yaml` paths in particular cannot be
  assumed safe or current without checking exposure and rotation evidence.
- Existing working-tree scan is blocked. A focused backend scan found 54
  findings: 47 in test/fixture paths and seven in ordinary source files.
  These are unreviewed locations, not accepted false positives or evidence of
  live credential compromise.
- Pinned Gitleaks 8.30.1 now scans staged commit differences with only
  rule/location output through `.githooks/pre-commit`; the hook is enabled in
  this checkout via local `core.hooksPath`. A corresponding GitHub Actions job
  was added to block new findings in push/PR ranges after the workflow is
  committed to the remote repository. The workflow does not suppress or
  baseline the 107 historical findings; it checks only new changes while
  historical review proceeds. Branch protection and a remote runner result
  have not yet been verified.
- A synthetic generated API key in a disposable Git repository was rejected by
  the staged scanner. The temporary repository was removed. The current
  checkout's pre-commit hook passed against its empty index.
- A focused draft PR, `https://github.com/hbq2004/sub2api/pull/1`, contains the
  gate files without the dirty local checkout or its 11 unpublished commits.
  Its first push and PR `secret-gate` jobs passed. A pre-existing
  `frontend-security` failure was traced to Axios 1.18.1; PR commit
  `16780bb9d` upgrades only Axios and its lock entry to 1.20.0. Local
  production audit now reports zero high/critical Axios advisories. The
  current PR `Security Scan` workflow completed successfully with all three
  jobs green: `secret-gate`, `backend-security`, and `frontend-security`.

## Scope decisions recorded after the 1-5 review

- On 2026-10-02 the owner chose to leave groups 2, 4, 5, 8, and 11 without new
  daily, weekly, monthly, or RPM values. The hourly aggregate usage alert is
  the interim control; it is not a provider-cost ceiling.
- On 2026-10-02 the owner chose a synthetic revoke/cache-clear regression only.
  No active upstream account was paused, revoked, or re-authorized, and no
  provider-side revoke was claimed.
- The existing focused tests cover revoked-token classification and failover to
  a healthy account without contacting an upstream provider. A real revoke
  drill remains pending a disposable identity.
