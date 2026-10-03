# Tokyo upstream account inventory (no credential values)

Observed 2026-10-01 from the live Sub2API database using a metadata-only query.
This is an operational checklist, not a credential export. The cloud instance is
the formal source. All 46 top-level accounts were `active`: 45 OAuth and one
upstream API key. No account was paused or changed during this inventory.

Current group limit check: the five groups with bound accounts have no daily,
weekly, or monthly USD limit configured; their `rpm_limit` is also `0` (unlimited).
This is a confirmed gap, not an assumed budget. Do not treat the current setup as
ready for customer traffic until each group has an approved hard ceiling or the
account set and exposure are reduced enough to make the loss limit acceptable.

For every row, the actual consumer, acceptable loss ceiling, anomaly threshold,
and provider-side revocation procedure remain **unverified**. A group binding
shows potential routing, not proof that a customer or bot used the account.
Before declaring a row ready, record those four facts through authorized,
no-value evidence and test revocation using a disposable identity. Do not put
passwords, bearer tokens, private keys, or OAuth payloads in this file.

| ID | Platform / type | Group | Schedulable | Consumer | Loss ceiling | Anomaly signal | Provider revocation |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | gemini / oauth | Personal Unified | no | pending | pending | pending | pending |
| 2 | antigravity / oauth | Personal Unified | no | pending | pending | pending | pending |
| 3 | openai / oauth | Personal Unified | yes | pending | pending | pending | pending |
| 4 | openai / apikey | 国模 | no | pending | pending | pending | pending |
| 5 | openai / oauth | 日抛号 | no | pending | pending | pending | pending |
| 6 | openai / oauth | 日抛号 | yes | pending | pending | pending | pending |
| 7 | openai / oauth | 日抛号 | yes | pending | pending | pending | pending |
| 8 | openai / oauth | 日抛号 | yes | pending | pending | pending | pending |
| 9 | openai / oauth | Plus 独享分组 - 速度更快 | yes | pending | pending | pending | pending |
| 10 | openai / oauth | Plus 独享分组 - 速度更快 | yes | pending | pending | pending | pending |
| 11 | openai / oauth | Plus 独享分组 - 速度更快 | yes | pending | pending | pending | pending |
| 12 | openai / oauth | Plus 独享分组 - 速度更快 | yes | pending | pending | pending | pending |
| 13 | openai / oauth | Plus 独享分组 - 速度更快 | yes | pending | pending | pending | pending |
| 14 | openai / oauth | Plus 独享分组 - 速度更快 | yes | pending | pending | pending | pending |
| 75 | openai / oauth | GO - 支持 5.6 Terra | yes | pending | pending | pending | pending |
| 76 | openai / oauth | GO - 支持 5.6 Terra | yes | pending | pending | pending | pending |
| 77 | openai / oauth | GO - 支持 5.6 Terra | yes | pending | pending | pending | pending |
| 78 | openai / oauth | GO - 支持 5.6 Terra | yes | pending | pending | pending | pending |
| 79 | openai / oauth | GO - 支持 5.6 Terra | yes | pending | pending | pending | pending |
| 80 | openai / oauth | GO - 支持 5.6 Terra | yes | pending | pending | pending | pending |
| 81 | openai / oauth | GO - 支持 5.6 Terra | yes | pending | pending | pending | pending |
| 82 | openai / oauth | GO - 支持 5.6 Terra | yes | pending | pending | pending | pending |
| 83 | openai / oauth | GO - 支持 5.6 Terra | yes | pending | pending | pending | pending |
| 84 | openai / oauth | GO - 支持 5.6 Terra | yes | pending | pending | pending | pending |
| 85 | openai / oauth | GO - 支持 5.6 Terra | yes | pending | pending | pending | pending |
| 86 | openai / oauth | GO - 支持 5.6 Terra | yes | pending | pending | pending | pending |
| 87 | openai / oauth | GO - 支持 5.6 Terra | yes | pending | pending | pending | pending |
| 88 | openai / oauth | GO - 支持 5.6 Terra | yes | pending | pending | pending | pending |
| 89 | openai / oauth | GO - 支持 5.6 Terra | yes | pending | pending | pending | pending |
| 90 | openai / oauth | GO - 支持 5.6 Terra | yes | pending | pending | pending | pending |
| 91 | openai / oauth | GO - 支持 5.6 Terra | yes | pending | pending | pending | pending |
| 92 | openai / oauth | GO - 支持 5.6 Terra | yes | pending | pending | pending | pending |
| 93 | openai / oauth | GO - 支持 5.6 Terra | yes | pending | pending | pending | pending |
| 94 | openai / oauth | GO - 支持 5.6 Terra | yes | pending | pending | pending | pending |
| 95 | openai / oauth | GO - 支持 5.6 Terra | yes | pending | pending | pending | pending |
| 96 | openai / oauth | GO - 支持 5.6 Terra | yes | pending | pending | pending | pending |
| 97 | openai / oauth | GO - 支持 5.6 Terra | yes | pending | pending | pending | pending |
| 98 | openai / oauth | GO - 支持 5.6 Terra | yes | pending | pending | pending | pending |
| 99 | openai / oauth | GO - 支持 5.6 Terra | yes | pending | pending | pending | pending |
| 100 | openai / oauth | GO - 支持 5.6 Terra | yes | pending | pending | pending | pending |
| 101 | openai / oauth | GO - 支持 5.6 Terra | yes | pending | pending | pending | pending |
| 102 | openai / oauth | GO - 支持 5.6 Terra | yes | pending | pending | pending | pending |
| 103 | openai / oauth | GO - 支持 5.6 Terra | yes | pending | pending | pending | pending |
| 104 | openai / oauth | GO - 支持 5.6 Terra | yes | pending | pending | pending | pending |
| 105 | openai / oauth | Plus 独享分组 - 速度更快 | yes | pending | pending | pending | pending |
| 106 | openai / oauth | Plus 独享分组 - 速度更快 | yes | pending | pending | pending | pending |

## Incident sequence

1. Record only the affected account ID, group, time, and anomaly category.
2. Disable that Sub2API account and verify new scheduling stops; preserve logs.
3. Revoke the grant or key at the provider's independent control surface.
4. Clear the account's cached authorization state and verify old credentials
   cannot be used. Do not merely clear the error or re-enable scheduling.
5. Re-authorize through the normal provider flow, test with an authorized
   low-impact request, then restore only the intended group and limits.

The sequence above is a procedure, not evidence that a live grant was revoked.
