# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [1.3.0] — unreleased

### Added
- **Certificates and deploy targets (drivers).** One certificate (name, ACME CA,
  DNS provider) is issued once and deployed to any number of targets, each
  handled by a driver with its own settings schema and `preflight / probe /
  deploy / activate / verify / snapshot / rollback`. Fleet rows are targets; a
  target can be added to an existing certificate from Settings. (#16, #19)
- **Generic SSH/SCP driver**: SFTP upload to configured paths (atomic rename,
  key mode 600, optional full-chain file), an optional activation command,
  served-serial verification on `host:port`, and a probe that checks the
  remote directories are writable and sudo permits the command. (#22)
- **Per-certificate run lock** shared by the scheduler and the web UI
  (`fcntl.flock` under `/config/locks`, released by the kernel if the holder
  dies). The dashboard shows a cron run as *working* and refuses to start a
  second run; `renew-all` skips a locked certificate; the CLI exits 3 with the
  holder's pid, start time and actor. (#5)
- **CSRF protection** on every non-GET route (token tied to the `csrf` cookie,
  403 otherwise), `SameSite=Strict` session cookie, **login lockout** after five
  failed sign-ins per user and address for 15 minutes, logged. (#6)
- **Scheduler-aware health**: `/healthz` returns 503 when no scheduled pass
  finished within twice the cron interval; the entrypoint exits when either
  the web UI or supercronic dies so `restart: unless-stopped` recovers the
  container. The System page shows the scheduler state and active runs. (#11)
- **Rollback policy**: snapshots record their CA environment; a failed
  production activation never silently restores a staging or lab certificate
  (per-target `allow_cross_env_rollback`, off by default); the server page
  shows the rollback target. (#8)
- **Renewal window from the certificate's own lifetime**: renew once a third
  remains (30 days of 90, 15 of 45, 2 of 6); `RENEW_WINDOW_DAYS` overrides
  with an absolute window; the lifetime meter uses `notBefore`/`notAfter`;
  Lego is not run when nothing is due; ARI stays on unless the certificate on
  disk came from another environment. (#9)
- **Actor and source** on every run (`scheduler · cron`, `alice · web`,
  `root · cli`), in history, on the pages, in `/api/history` and alerts. (#14)
- **Backup and restore**: `python -m app.cli backup|restore` (config, certs,
  SSH material, visible lab CA state; logs excluded; offline root opt-in;
  optional AES-256-GCM encryption; restore refuses a newer `servers.json`
  without `--force` and runs preflight) and `./setup.sh --backup|--restore`
  on the host, which also sees the lab CA online state. (#13)
- **DNS provider passthrough**: `dns.env` variables (stored and redacted like
  other inline secrets) are passed to Lego for any provider; the form has a
  provider field and a variables editor. (#12)
- **ARI** (RFC 9773): scheduled runs ask the CA for the certificate's
  suggested renewal window first and renew once it opens (this is how
  Let's Encrypt requests early renewal after an incident, and in-window
  renewals are exempt from rate limits); the lifetime rule is the fallback.
  A `replaces` link the CA rejects (certificate from another account) is
  retried once without ARI.
- `python -m app.cli probe <target>` (alias `ssh-test`), `--source` /
  `--actor` on `renew`, `redeploy`, `renew-all`.

- **Published, verifiable images.** A `v*` tag runs `.github/workflows/release.yml`: version
  consistency check (`scripts/check-version.py`), the full CI, a multi-arch build
  (linux/amd64, linux/arm64) pushed to `ghcr.io/robertsonc/orchestrator-acme-cert-manager:<version>`
  with SBOM, provenance and a signed attestation, and a GitHub Release from this file.
  No `:latest` tag. `docker compose up -d` pulls the pinned image and only builds when
  the tag is unpublished (#10).

### Changed
- **The container runs unprivileged** (uid/gid 10001 by default).
  `docker-compose.yml` takes `OACM_UID`/`OACM_GID` from `.env`; `setup.sh`
  writes your own ids there so the bind mounts need no chown. Preflight names
  the exact fix when the service user cannot write `config/` or `data/`;
  `upgrade-check.sh` blocks until the keys exist. (#7)
- `servers.json` is written in the `version: 2` shape (`certificates` with
  `targets`). A pre-1.3 `servers` file is read as one certificate with one
  Orchestrator target per entry (same id for both) and rewritten in the new
  shape only when something is saved. `upgrade-check.sh` reads both shapes.
- Step messages show the **last** non-empty line of stderr (the `service`
  wrapper prints `Redirecting to ...` first). Activation commands that use the
  `service` wrapper, lack `sudo` or lack `--no-block` are flagged. (#15)
- TLS verification failures against the Orchestrator API are their own kind
  (`tls`), explained (staging / self-signed certificate; turn off `verify_ssl`
  or set `ca_bundle`) and never retried; preflight and the server page warn
  when `verify_ssl` is on while a staging or self-signed certificate is in
  play. (#15)
- The settings list groups targets under their certificate; "Delete" removes
  a target, and the certificate with its last target.
- Logout is a POST.
- Lego 5.5.2 (from 5.3.1; no CLI changes), verified against the release's
  checksum file; the Dockerfile downloads the asset for the build
  architecture (amd64 / arm64).
- Lego runs with an allow-listed environment (basics, `LEGO_*`, the
  certificate's DNS variables, Cloudflare's for Cloudflare certificates):
  the container's own API keys never reach a DNS provider script.
- Certificates with a lifetime of 10 days or less renew at half the lifetime.

- The compose service image is `ghcr.io/robertsonc/orchestrator-acme-cert-manager:<version>`;
  `setup.sh --start` pulls it (`--build` builds locally). CI pins actions by commit SHA.

- Dependencies moved to current releases: Flask 3.1.3, requests 2.34.2, paramiko 5.0.1,
  cryptography 50.0.2, certifi 2026.10.19 (every advisory on the previous pins cleared);
  pip installs wheels only. supercronic 0.2.51. **paramiko 5 no longer speaks SHA-1 SSH
  algorithms** (ssh-rsa host-key signatures, diffie-hellman-*-sha1, DSS keys): RSA keys still
  work through rsa-sha2-256/512, which every OpenSSH since 7.2 offers, and the SSH test
  explains the failure when a server offers nothing else.
- Validation answered with HTTP 401/403 is reported as an API-key problem (`auth`), not as a
  rejected payload; a redirect names the host it pointed to and never stores its query string.
- Alerts name the targets of the run; a history write failure no longer suppresses the alert.
- `logout` revokes by generation, so a login in the same second as the logout cannot survive it.
- A `scheduler.json` whose top level is not an object is discarded instead of aborting the run.

- Review round two: a scheduled run no longer re-deploys to a target that already serves the issued
  certificate (hex/int serial mismatch), a failing or monitor-only target no longer blocks the
  targets after it, the SSH driver creates the private key private before writing it, swaps files
  atomically after staging all of them, sends the certificate's name as SNI and bounds SFTP; the
  Orchestrator driver keeps one snapshot per target; ClearPass records API errors and lost PUT
  responses per node (and rolls back), reads nodes by their real uuid and honours the callback
  lifetime; ARI retries only on real CA wording; restore skips read-only mounts instead of dying
  half-way, backups never nest, `restore` reads `BACKUP_PASSPHRASE`; deleting a target removes only
  its own emptied certificate; the web UI replaces a foreign `csrf` cookie, refuses a duplicate
  domain on edit too, keeps the primary target's name, accepts suffixed secret variable names,
  invalidates the served-certificate cache on save and shows custom CA URLs with the right
  environment; the cron job's exit status reaches supercronic; `TARGETARCH` comes from BuildKit so
  the arm64 image gets arm64 binaries (CI now cross-builds it).

### Fixed
- A scheduled renewal and a Force renew/deploy from the UI could run on the
  same server at once. (#5)

## [1.2.0] — 2026-10-20
- Upgrade guide, host readiness check (`upgrade-check.sh`), System page and
  CLI-dependency indicators.

## [1.1.0] — 2026-10-20
- Bundled lab CA (step-ca) with name constraints, DNS-01 ACME and a CRL.
- Hardened deployment: guided SSH setup, persistent configuration, deploy
  diagnostics; dark-first ops console.

## [1.0.0] — 2026-08
- Initial release: Let's Encrypt issuance over Cloudflare DNS-01, deployment
  through the Orchestrator `httpsCertificate` API, SSH activation with
  served-certificate verification and rollback, web dashboard, scheduler.
