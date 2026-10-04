# Local to cloud configuration sync

## Operating convention

Create upstream accounts and their groups in the local administrator UI first.
After checking the local records, sync the selected accounts and their required
groups to the cloud. The local installation is the source for these records;
cloud-only records are left in place unless reviewed separately. Sync is an
explicit operation, not an automatic background task.

## Local Web button

Open the local administrator account page at `http://127.0.0.1:8080/admin/accounts`
using the Sub2API one-click launcher. Select one or more local upstream account
rows and click **Sync to Cloud**. Enter the cloud administrator email, password,
and current TOTP code. If local account export requests step-up verification,
enter the local administrator TOTP code too. Preview the planned group and
account changes. The Web preview treats differences limited to account model
mapping, group bindings, and automatic credit reset settings as updates from the
local source. It shows changed model mapping entries, reset settings, and both
group memberships before confirmation, without exposing OAuth tokens or usage
snapshots. Confirming an update replaces the cloud account's group bindings with
the local bindings, including removal of cloud-only groups. Other account
credential differences and group configuration conflicts still cancel the entire
Web sync before writing. The server re-reads the cloud before writing and the page verifies
the resulting cloud records before showing completion. The cloud password and
TOTP codes are cleared from the dialog after preview. The local sync service
holds a short-lived cloud administrator session in process memory for the
confirmation step; it does not persist the password, TOTP codes, or session.
The preview expires after ten minutes and cannot be reused. It is bound to the
local and cloud record IDs as well as the configuration, so replacing a record
invalidates the preview. A failed apply restores attempted updates to existing
records, removes newly created cloud records, and verifies the restored state.
Restoration re-reads cloud OAuth tokens and runtime data. If an administrator
changed a record independently, rollback stops and reports that it needs attention
instead of overwriting that edit or deleting its dependencies. This action never
copies personal API keys. Clearing account notes, expiry, or load factor uses the
API's explicit clearing values rather than null pointers.

The button is shown only on the local `:8080` Web UI. The companion sync
service listens on `127.0.0.1:8769`, accepts requests only from that UI, and
verifies the current local administrator token on every request. The one-click
launcher starts this companion service alongside the local Docker deployment.

Personal API clients on this Windows PC use the local base URL
`http://127.0.0.1:8080/v1` and a key issued by the local installation. The
cloud endpoint `https://api.zynexus.top/v1` serves clients intentionally using
the cloud installation. Keep personal local API keys on the local instance: the
account-ID selection commands below sync upstream accounts and groups without
copying API keys. Loopback binding means the local URL is reachable only from
this PC.

For newly added OAuth upstream accounts, preview the selected local IDs before
applying the sync:

```powershell
node deploy/sync-local-to-cloud.mjs --include-oauth --only-account-ids 9,10,11
node deploy/sync-local-to-cloud.mjs --include-oauth --only-account-ids 9,10,11 --apply
```

Replace the example IDs with the actual local account IDs. Check the preview
for cloud conflicts and verify cloud group bindings after applying. A cloud
account can have different token refresh and proxy requirements from its local
counterpart, so verify cloud usability separately when it matters.

## Signed-in browser workflow

For a small set of new OAuth accounts, use the existing administrator sessions
in the local and cloud web UIs. Select only accounts missing from the cloud,
then use Accounts > More actions > Export selected. Turn off proxy export for
machine-specific local proxies. Import the resulting JSON in the cloud UI,
then bind the imported accounts to the matching cloud group with bulk edit.
Refresh the cloud account and group pages to verify names, counts, and group
bindings. The UI asks for a fresh 2FA code only when step-up is required; it
does not require another email/password login while the sessions are valid.
The exported JSON contains upstream credentials: keep it private, retain an
encrypted recovery copy if needed, and remove temporary plaintext copies.

The UI import creates accounts without group bindings and does not perform
deduplication. Verify the selection against current cloud accounts before
export, and do not import the same file twice.

## Command-line workflow

Run from this repository on the Windows PC with Node.js 20+:

```powershell
node deploy/sync-local-to-cloud.mjs
node deploy/sync-local-to-cloud.mjs --apply
node deploy/sync-local-to-cloud.mjs --include-oauth --only-account-id 8
node deploy/sync-local-to-cloud.mjs --include-oauth --only-account-id 8 --apply
node deploy/sync-local-to-cloud.mjs --include-oauth --only-account-ids 9,10,11 --apply
```

The first command previews changes. The second applies them after an interactive
administrator login to each instance. The last two commands preview and apply
only local account ID 8 and its required groups; they do not sync API keys or
other accounts. Use `--only-account-ids` for several IDs in one login. The
command refuses cloud login without TOTP and checks, before and after syncing,
that the cloud administrator has
TOTP enabled, the global TOTP and sensitive-operation step-up switches are on,
and the TOTP encryption key is configured. It does not copy local users, passwords,
TOTP secrets, or security settings to the cloud. Passwords and 2FA codes stay in
process memory. Account export requires a fresh step-up code. The cloud
connection must use HTTPS; the local connection must use a
loopback address. No key or upstream credential is printed.

The command syncs groups, API-key-type upstream accounts, and API keys owned by
the logged-in local administrator to the logged-in cloud administrator. Use
`--include-oauth` to include OAuth upstream accounts. OAuth access/refresh/ID
tokens, token expiry, and observed subscription state can change independently
on each instance; they are ignored when comparing existing accounts and cloud
tokens are retained on updates. Codex usage, credits, reset windows, and other
runtime snapshots are also ignored. The Web preview lists changed configuration
fields and safe settings without showing credential secrets. An explicit
`auto_reset_credit_enabled=false` and thresholds of `1` compare equal to the
same unset defaults in the cloud. It does not sync runtime observations such as
`privacy_mode`; the cloud checks privacy independently
after creating OAuth accounts. The completed dialog reports that cloud result
separately, and the ignored sync state records aggregate counts only. It does not sync
users, balances, quota usage, rate-window usage, probe snapshots, logs, subscriptions, proxies,
or deletions. Local proxy bindings are ignored because local proxy addresses
are usually invalid on the server. Existing cloud proxy bindings are left alone.
Accounts with machine-specific proxy dependencies must be checked on the cloud.

Records match by group platform/name, upstream platform/type/name, and exact
API key value. Renaming a group or upstream account creates a new cloud record;
the old cloud record is not removed. Groups containing fallback group IDs,
model-routing account IDs, or pinned Codex manifest account IDs stop preflight
until those references can be mapped.
The upstream account export omits Spark shadow accounts; these are reported as
skipped. Group sort order and composite routes are not included.

On a first run, an existing cloud record with different configuration is a
conflict in the CLI. Once a matching state has been applied, an ignored local
state file records cloud configuration fingerprints. Later cloud edits trigger a
CLI conflict instead of silent overwrite. In the Web UI, differences limited to
the local-owned account fields named above are previewed as updates even without
a baseline; other conflicts still block the sync. `--take-local` remains disabled
in the CLI. Cloud usage and balances remain cloud-owned.

The command re-reads cloud configuration after applying changes and saves sync
state only when every selected record matches. A partial failure can leave
earlier records applied; rerun the preview before retrying. Existing cloud
backups should be kept before the first apply.
