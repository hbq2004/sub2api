# Lightweight security work: 1-5 acceptance record

Verified 2026-10-02 (China Standard Time). All live checks were metadata-only;
no API key, OAuth token, password, TOTP secret, or private key was exported.

## 1. Online baseline

- `https://api.zynexus.top/health`, `https://shop.zynexus.top/health`, and
  `https://zynexus.top/` returned HTTP 200.
- Caddy is the public listener on ports 80/443. Sub2API is bound to
  `127.0.0.1:8080`; PostgreSQL and Redis have no published host ports.
- The live container set is healthy for Sub2API and PostgreSQL; Redis is up.
- Effective SSH policy is public-key only: password and keyboard-interactive
  authentication are disabled and root login is disabled.
- Tencent Cloud Lighthouse firewall allows TCP 22 only from the fixed `/32`
  management address shown in the console; TCP 80/443 remain public. The
  current rule is documented as the Codex SSH fixed IP rule.
- Administrator aggregate state shows TOTP enabled, step-up enabled, and one
  enrolled passkey. Cloud-provider security-group SSH allowlisting was not
  was read from the logged-in Tencent Cloud console; no firewall rule was
  changed.

## 2. Downstream keys

The three active keys remain active and have the verified rolling limits of USD
20 / 30 / 150 for 5 hours / 1 day / 7 days. The key values are not stored here.
Thirty-day metadata shows key 3 has 42.22 USD and 1,084 requests, key 1 has
0.02 USD and 14 requests, and key 2 has 0 USD and 55 requests.

## 3. Upstream accounts

The live database still contains 46 active top-level accounts (45 OAuth and one
API key). Recent metadata confirms real traffic is concentrated in accounts 3,
5, 6, and 7; the remaining active rows had no recorded usage in the checked
30-day window. This does not establish that those rows are unused or safe to
disable. No account was paused or revoked. Consumer, loss ceiling,
anomaly signal, and provider revocation evidence remain pending per account.

## 4. Upstream groups

Groups 2, 4, 5, 8, and 11 have bound accounts but all currently have null daily,
weekly, and monthly limits and RPM 0 (unlimited). A safe numeric budget cannot
be inferred from traffic: the group fields limit subscription usage, not total
provider spend. Only group 2 has an active subscription at present. Group RPM
is likewise a per-user control. Set values only after the owner supplies
per-group budgets and accepts the impact on existing subscriptions.

Owner decision on 2026-10-02: keep the five groups unchanged for now and use
the aggregate usage monitor as the interim control. No daily, weekly, monthly,
or RPM value was written in this batch. This is an accepted temporary exposure,
not a claim that the groups have a hard provider-cost ceiling.

## 5. Alerts and revocation

The existing backup failure email path is verified. A new local monitor checks
hourly aggregate usage and 15-minute login/2FA failures, with cooldown and no
credential reads. Synthetic trigger and no-trigger tests pass; the live read-only
sample was below both thresholds, and the first scheduled run returned `0`.
The SMTP self-test succeeded on retry after one transient failure; continued
mail delivery needs observation.
A disposable upstream identity was not
available, so provider-side revoke and cache-clear were not performed. Do not
revoke any of the 46 active accounts as part of this batch.

Owner decision on 2026-10-02: perform only the synthetic revoke/cache-clear
regression for this batch. A real provider revoke remains intentionally
deferred until a disposable upstream identity and its provider procedure are
available.

## Remaining inputs

1. Per-group daily/weekly/monthly budgets (and optional RPM) for groups 2, 4, 5,
   8, and 11, if the owner later chooses to impose subscription limits.
2. One disposable upstream identity plus its provider-side revoke procedure for
   a real revoke drill.
3. Cloud-provider SSH security-group allowlist evidence.
