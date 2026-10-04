# P1 Key protection and release acceptance

This release starts at the deployed custom revision `d8930b7a5fff7ea199b151c5f2e80b7f1729fde9`.

The `api_keys.key` index now holds a domain-separated HMAC. Recoverable material is sealed by the existing AES-GCM keyring and authenticated against the API key ID. Startup migrates and verifies all active rows in one transaction. A missing keyring or damaged protected row blocks startup. Consumers retain their original bearer, quotas, expiry, IDs and accounting. Deleted rows lose recoverable material. The existing lookup root remains stable; no encryption, JWT, TOTP or consumer key rotation is required.

Key lists, usage DTOs and persistent create-replay responses are masked. The first create response is shown once with `Cache-Control: no-store`. Viewing or copying an existing key requires the owner's JWT session and recent TOTP; another user's administrator session cannot reveal it. Enable TOTP in Profile before using this recovery action. Existing configured clients continue to authenticate normally.

Database migration 242 adds ciphertext and display-hint columns. Keep a paired encrypted pre-release database/keyring backup and the previous image before deployment. Rolling back to an image without this feature requires restoring the matching pre-migration database; an old image cannot authenticate HMAC identities. Rehearse this rollback with blocked egress. Restoring an older database loses changes after its snapshot, so prefer forward recovery for a live accounting system.

Cloud publication checks the exact image revision against the owned GitHub fork and requires successful checks from that revision plus enforced strict branch protection. Missing commits, failed or skipped required checks, stale labels and unavailable GitHub evidence block publication before image transfer.

The selected recovery targets are RPO at most one hour and RTO at most two hours. Cloud snapshots run every thirty minutes; the existing independent Windows host retrieves them every fifteen minutes and checks both snapshot age and verification age. This computer must remain powered and connected to maintain that off-host interval. A two-minute public HTTPS observer runs under the existing user with S4U/Limited and retries outage and recovery notifications through existing protected mail settings.

These controls reduce database and backup disclosure risk. Application-host compromise can still expose running decryption keys. A Windows observer is not an independently hosted service when the computer is off. Full replacement-OS, public TLS/DNS cutover, cloud-account recovery, physical authenticator recovery and issuer-side evidence for HSR-019/037/038 require their own acceptance evidence. Synthetic fixtures and SMTP acceptance do not establish those results.
