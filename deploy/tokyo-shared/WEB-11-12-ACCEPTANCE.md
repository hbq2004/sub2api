# Public entry and personal vault acceptance

Verified 2026-10-02 (China Standard Time). No credentials, tokens, private
keys, or password-vault contents were read or recorded.

## 11. Public path acceptance

- `https://zynexus.top/` returned HTTP 200. The public page visibly links to
  `shop.zynexus.top` and `api.zynexus.top`.
- `https://shop.zynexus.top/` and `/health` returned HTTP 200. The shop page
  currently reports that products are being prepared; this is not an enabled
  sales catalog or payment acceptance claim.
- `https://api.zynexus.top/` and `/health` returned HTTP 200.
- `https://api.zynexus.top/admin/login` returned HTTP 200 and is reachable
  without exposing an authenticated session.
- LinuxDo and OIDC callback probes returned the explicit `OAUTH_DISABLED`
  response. The routes are handled, but OAuth login is intentionally disabled.
- The live Caddyfile and Compose file SHA-256 values match the local
  `deploy/tokyo-shared` and `D:\Desktop\总站` production snapshots. The portal
  `index.html`, `styles.css`, and `favicon.svg` also match the live files under
  `/home/ubuntu/ai-daichong-shop/portal`.
- Live containers are running: Sub2API and PostgreSQL report healthy; Redis,
  Caddy, shop, and shop Redis are up. No production redeploy was needed because
  the live files already match the reviewed release snapshot.

## 12. Personal password vault

- KeePassXC 2.7.12 was prepared from the official Windows release. The empty
  KDBX exists under the planned `C:\Users\hbq\Documents\PersonalVault` area;
  no vault contents were inspected.
- The owner must complete the remaining handoff personally in KeePassXC:
  replace the old master password, close and reopen with the new password,
  enable idle and system-lock auto-lock, add only a synthetic entry/attachment,
  and open an independent encrypted backup copy to verify recovery.
- The master password, recovery material, KDBX contents, and any plaintext
  export must not be entered into chat, Git, project documents, or browser
  forms. Browser integration and automatic fill remain disabled until the
  single-machine recovery test passes.

## Launch decision

The ZyNexus static portal and API public entry are formally online and passed
the public-path checks. The customer-facing shop remains in preparation mode;
formal commercial launch still requires approved products, payment acceptance,
and a real small-value lifecycle test. No payment or product activation was
performed in this acceptance pass.
