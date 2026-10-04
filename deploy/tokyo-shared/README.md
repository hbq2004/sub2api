# Tokyo shared server

`api.zynexus.top` runs Sub2API on the same Tokyo host as `shop.zynexus.top` and
`zynexus.top`. The shop's Caddy is the only public listener on ports 80/443.
Sub2API is bound to `127.0.0.1:8080` and also joins the private `zynexus-edge`
Docker network. PostgreSQL and Redis have no published ports.

The server directories are `/home/ubuntu/sub2api` and
`/home/ubuntu/ai-daichong-shop`. The latter's `Caddyfile` and `compose.yaml`
were copied into this directory at deployment time. Preserve later changes
to those live files when updating either service.

Sub2API uses `docker-compose.local.yml` plus `sub2api.override.yaml` with
images pinned to the digests used for the migration. Its `.env`, `data/`,
`postgres_data/`, and `redis_data/` are private runtime state and are not in
Git. The cloud account proxy bindings were cleared because the migrated
`host.docker.internal:7890` proxy only exists on the Windows machine.

Check the deployment:

```sh
sudo docker compose --project-directory /home/ubuntu/sub2api \
  --env-file /home/ubuntu/sub2api/.env \
  -f /home/ubuntu/sub2api/docker-compose.local.yml \
  -f /home/ubuntu/sub2api/sub2api.override.yaml ps
curl -fsS https://api.zynexus.top/health
curl -fsS https://shop.zynexus.top/health
```

`sub2api-backup.timer` runs daily at 04:00 server time, after the shop's
03:30 backup. It writes an encrypted CMS archive containing the PostgreSQL
dump, Redis snapshot, application state, and SHA-256 manifest under
`/home/ubuntu/sub2api/backups/daily/`. The script validates the database
dump and Redis snapshot before encryption. The timer executes a root-owned
copy of the script at `/usr/local/sbin/sub2api-backup`. Encrypted copies
of the migration and deployment-day backups are in the Git-ignored
`private-backups/` directory. Keep copying new backups off-host as data
changes.

## Backup encryption and SSH access

### Cloud security monitoring (2026-10-04)

The production account pool is cloud-primary; local production accounts are
disabled and the local application stays stopped for manual debugging.
The cloud security monitor and its independent heartbeat watchdog run through
enabled systemd timers every five minutes, with Persistent=true. See
[CLOUD_MONITOR_CN.md](CLOUD_MONITOR_CN.md) for thresholds, status and recovery.
The cloud SMTP TLS test was accepted and the user confirmed actual mail receipt.
The Windows encrypted backup download and backup verification tasks continue.


The recovery key and public certificate were generated with
`New-BackupRecipient.ps1` under the Git-ignored
`private-backups/` directory. Keep another secure copy of the private key:
without it, encrypted backups cannot be restored. Copy only the public
`backup-recipient.pem` to `/etc/sub2api/backup-recipient.pem` on the server.
The backup service writes an AES-256-CBC CMS database archive and a separate
AES-256-CBC CMS credential-keyring archive per run. The database payload carries
only a checksum manifest for the matching keyring archive; it never embeds the
keyring. Plaintext intermediate files stay under `/run` and are removed when
the script exits. Configure the server-side keyring recipient certificate at
`/etc/sub2api/credential-keyring-recipient.pem` before enabling the timer.
Create the separate recipient pair with `New-KeyringBackupRecipient.ps1` and
keep its private key in a recovery domain separate from the database recipient.
Download the matching pair and run
`Test-EncryptedBackup.ps1 -Archive <path> -KeyringArchive <path>` to verify
decryption, checksums and the keyring pairing without printing credentials.
Historical migration archives created before the paired keyring manifest must
use `-AllowLegacyWithoutKeyring` only when the separately supplied keyring
capsule is independently verified.

On the Windows backup machine, the `Sub2API-PullEncryptedBackup` task runs at
06:30 with a private PowerShell 7 installation under `private-tools/powershell`.
Both `private-tools/` and `private-backups/` are excluded from Git. After a
runtime update, test the task and confirm `LastTaskResult` is `0`.
`Check-BackupStatus.ps1` checks the verified archive marker, its age, and its
current hash. It returns an error for a missing, stale, or changed archive.
An email sender must be configured separately before this becomes an external
notification.

The 07:00 `Sub2API-CheckEncryptedBackup` task runs
`Invoke-BackupHealthCheck.ps1`. It checks that the 06:30 download completed
verification after its scheduled time and that the archive remains fresh
and unchanged. On failure it calls `Send-BackupAlert.ps1` with a fixed reason;
the mail contains no backup contents or credentials. Configure
`private-backups/mail-settings.json` with QQ sender and recipient addresses,
then run `Set-BackupMailCredential.ps1 -SendTest` interactively under the same
Windows account as the scheduled task. Enter a QQ Mail SMTP authorization code,
not the QQ account password. The encrypted credential file is bound to that
Windows user and excluded from Git. Re-run the helper when the authorization
code changes. QQ Mail SMTP service must be enabled for the sender account.

`New-EncryptedBackupManifest.ps1` creates a no-secret manifest for the `.p7m`
archives. Upload that manifest beside the archives when using Google Drive and
verify the listed SHA-256 values after a future download.

`Protect-RecoveryKeyForOffsite.ps1` creates an AES-256-GCM encrypted copy of the
recovery private key after an interactive passphrase entry. The passphrase is
never written to the file, command line, chat, or Git. `Restore-OffsiteRecoveryKey.ps1`
can restore it to a new path after the passphrase is supplied. The encrypted copy
is stored separately from the backup archives in the Drive folder `Sub2API
recovery key (encrypted)`; the original PEM key is not uploaded.

`UPSTREAM_ACCOUNT_INVENTORY.md` is a value-free snapshot of account metadata and
the remaining budget/revocation fields. `BACKUP_ALERT_TEST.md` records the
simulated failure notification evidence. Neither file contains OAuth tokens,
passwords, private keys, or SMTP credentials.

Use `Restore-EncryptedBackup.ps1 -Archive <path> -KeyringArchive <path>` for a
local database and Redis recovery drill. Add
`-TestApplication -AppImage <compatible-image> -CredentialKeyring <recovered-path>` to also restore application state and
check Sub2API startup; `-TestPasskeys` additionally validates the production
WebAuthn origin configuration. The application drill uses an internal-only
Docker network with no published ports. All modes remove temporary containers,
networks, and plaintext staging. This does not prove recovery on another machine.
Application tests require an explicit compatible `-AppImage`. The generic
script rejects databases containing protected upstream credential envelopes;
those require an independently recovered keyring and credential-aware restore.
Do not use the old migration or Passkey image as an implicit default.

As of 2026-10-02, cloud upstream credential encryption is active in strict
mode. After the Zhiyi AI branding and logo releases, the current image is pinned to
`sha256:b3c82104f4ddfd8dec0dabf452a7cdb63a08afdcaf86580016de26c91365c42c`.
It derives from the protected credential image
`sha256:c6dde38d376e9bbe52f30f5efc35bd1195b704764c6d91afb2ac2fd030a656ea`
and retains its offline migration tool unchanged. The application replaces
only branding defaults and the embedded frontend using the saved OAuth
source snapshot; credential and authentication implementations are retained. The
existing two-file Compose command still applies, with the protected keyring
secret and read-only root filesystem in the live `sub2api.override.yaml`.

The tracked `sub2api.override.yaml` is an older topology snapshot. Do not
overwrite the protected live override with it. Application releases must
preserve the live secrets, strict encryption settings and read-only filesystem.
The branding release record is `output/zhiyi-ui-20261002/README.md`; the latest
logo release record and rollback instructions are in
`output/zhiyi-logo-20261002/README.md`. Its rollback configuration is
`/home/ubuntu/sub2api/sub2api.override.before-zhiyi-logo-20261002.json`; it restores
the previous protected branding image without reverting encrypted account data.

The keyring is `/etc/sub2api/upstream-credential-keyring.json` on the server,
owned by UID 1000 with mode 0400. Its separate encrypted recovery capsule,
database backups and encrypted deployment configuration are in the restricted
local business directory `deploy/private-credentials/cloud-upstream-20261002/`.
The capsule uses the existing business backup certificate and must remain
separate from the database archives. Existing authentication and CDK roots
were preserved. Routine database backups do not include the keyring; retain
the matching capsule for every backup that uses this key version.

An offline archive containing both compatible application images is at
`output/cloud-credential-release-20261002/recovery-images.tar.gz`. It was
loaded successfully into local Docker. Full pre- and post-migration backup
restores and explicit plaintext rollback were tested on an internal-only
cloud Docker network, with temporary plaintext removed afterward. These
checks do not measure recovery on a replacement host or establish RPO/RTO.
The task's full evidence and recovery procedure are in
`D:/Desktop/sub2api-security/docs/sub2api/cloud-credential-rollout-2026-10-02.md`.

Install `00-sub2api-hardening.conf` as
`/etc/ssh/sshd_config.d/00-sub2api-hardening.conf` after confirming key-based
login for `ubuntu`. Validate with `sshd -t`, reload SSH, and confirm a new
key-based session before closing the current session.

As of 2026-09-30, password and root SSH logins are disabled, and a fresh
`ubuntu` public-key login was verified. The online Sub2API administrator
enrolled in TOTP; the system TOTP and sensitive-operation step-up switches
are enabled. Existing online upstream accounts remain in place so GPT model
access continues. Local and online configurations still do not sync.
