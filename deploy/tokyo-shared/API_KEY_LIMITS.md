# Downstream API key limits

Verified 2026-10-02 (China Standard Time) through the administrator console and
a metadata-only readback from the production database. No API key values are
stored here.

The three active downstream keys were set to the same rolling limits:

- 5-hour limit: USD 20
- 1-day limit: USD 30
- 7-day limit: USD 150
- Lifetime quota: unchanged (unlimited)

Affected key names: `日抛号测试`, `bai 国模测试`, and `Personal Unified`.
Database readback confirmed all three values on key IDs 3, 2, and 1
respectively; all remained `active` and had zero lifetime quota usage at the
time of verification.

These limits apply to requests made with the downstream keys. They do not make
the upstream OAuth tokens field-encrypted and do not establish a hard provider
cost ceiling for every upstream account. The five upstream-bound groups still
need separate account exposure and revocation review.
