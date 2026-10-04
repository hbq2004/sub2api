# Backup alert test record

Date: 2026-10-01 (China Standard Time)

- Normal backup download task: last result `0`.
- Normal backup health task: last result `0`.
- Simulated failure: an empty test directory was used; no production archive,
  database, Redis data, or upstream account was changed.
- The health check returned failure as expected and classified the alert path as
  `check_failed_mail_sent`.
- The user confirmed receipt of the QQ Mail message titled
  `Sub2API backup alert: daily encrypted backup download or verification failed`.

This proves the backup failure notification path. It does not prove usage-spike,
upstream-login-failure, or provider-side OAuth revocation alerts; those controls
were added locally on 2026-10-02. Provider-side OAuth revocation remains untested.

## Security signal monitor

`Monitor-SecuritySignals.ps1` was run against the live Tokyo database on
2026-10-02 (China Standard Time) in read-only mode. It returned zero USD of
usage in the previous hour and zero 4xx authentication events in the previous
15 minutes. Synthetic inputs also verified both alert branches and the empty
branch without sending mail.
The hourly scheduled task completed its first live run with result `0`.
An SMTP self-test initially failed despite TCP/587 connectivity; one retry
succeeded. Delivery should be treated as intermittent until a later scheduled
alert or test is observed. No authentication material was logged.

The monitor checks hourly aggregate usage (default alert at USD 5) and recent
login/2FA failures (default alert at five events in 15 minutes). It keeps a
local cooldown marker so one incident does not send repeated messages. It never
reads credential columns and does not revoke or pause an account.
