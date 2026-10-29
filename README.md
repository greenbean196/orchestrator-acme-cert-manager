# Orchestrator ACME Certificate Manager

Automated TLS certificate lifecycle management for **HPE Aruba Networking EdgeConnect SD‑WAN Orchestrator**.

This tool issues, deploys, activates, and renews a publicly trusted HTTPS certificate for an Orchestrator appliance, and, since 1.3, for anything else a **deploy-target driver** knows how to reach. It obtains certificates from [Let's Encrypt](https://letsencrypt.org/) (or the bundled lab CA) over the ACME protocol using a DNS‑01 challenge, uploads them through the target's API or over SSH, activates them, and **verifies the target is actually serving the new certificate**, rolling back to the last known good certificate if anything goes wrong. Everything runs in a single unprivileged Docker container and is managed from a browser dashboard.

It started as the Orchestrator counterpart to the [ClearPass ACME Certificate Manager](https://github.com/sinemad/cppm-acme-cert-manager); that tool's deploy path is now a driver here (see [Deploy targets and drivers](#deploy-targets-and-drivers)).

> **Scope / status:** built and validated in a lab against Let's Encrypt staging and production. It is intended for internal/lab use behind a trusted network boundary. Read the [Security Considerations](#security-considerations) before running it anywhere less private.

---

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Directory Structure](#directory-structure)
- [Initial Setup](#initial-setup)
- [Configure SSH key authentication](#configure-ssh-key-authentication)
- [Configuration persistence](#configuration-persistence)
- [How It Works](#how-it-works)
- [Staging to production](#staging-to-production)
- [Deploy targets and drivers](#deploy-targets-and-drivers)
- [Bundled lab CA](#bundled-lab-ca)
- [Configuration Reference](#configuration-reference)
- [Web UI](#web-ui)
- [CLI](#cli)
- [Maintenance](#maintenance)
- [Upgrading](#upgrading)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)
- [Orchestrator API Reference](#orchestrator-api-reference)
- [Development](#development)
- [License](#license)

---

## Features

- **Full lifecycle, unattended**: issue once → deploy + activate on every target, on a schedule (twice daily by default) or on demand. A certificate is renewed when a third of its own lifetime remains (30 days of 90), so shorter Let's Encrypt lifetimes need no retuning.
- **Deploy targets with drivers**: one certificate, any number of targets. Drivers for **EdgeConnect Orchestrator** (REST + SSH activation), **generic SSH/SCP** (copy files, run a command, verify on host:port), **ClearPass Policy Manager** (REST, per cluster node) and **EdgeConnect appliances via Orchestrator** (read-only until confirmed on hardware). Each driver owns its settings, preflight, probe, deploy, activation, verification and rollback.
- **DNS‑01 via Cloudflare**: works for appliances with no public inbound reachability; supports private hosts.
- **Verified activation**: after reloading the web service, the tool reads the certificate the appliance is *actually serving* and confirms its serial matches what was installed. "Port is up" is not treated as success.
- **Automatic rollback**: if activation can't be verified, the previous working certificate is re‑deployed and re‑verified, so a bad renewal never takes the appliance offline. The snapshot records which CA issued it; a failed production activation never silently restores a staging or lab certificate (per-target policy).
- **One run per certificate at a time**: the scheduler and the dashboard share a lock, so a cron pass and a Force renew cannot collide; the dashboard shows a cron run as *working* and says who holds the lock. Every run records who started it and from where (`scheduler · cron`, `alice · web`).
- **Rate‑limit‑safe re‑deploy**: a **Force deploy** action re‑pushes the certificate already on disk without contacting the CA, so you can recover a deployment without spending a Let's Encrypt issuance.
- **Bundled lab CA (optional)**: a name-constrained `step-ca` in the same Compose stack issues browser-trustable certificates for every management interface in the lab over ACME (DNS-01 via Cloudflare), with a CRL and a root you distribute once. Picked per server like staging or production.
- **Guided host setup**: `setup.sh` installs Docker if needed, generates a dedicated SSH key, pins the Orchestrator host key, installs the public key, checks the `sudo` rule, and verifies the whole SSH path before the container ever starts.
- **Preflight checks**: the container refuses to start on a configuration that would silently lose changes; SSH settings are validated when saved and before every activation; a **Test SSH** button verifies authentication and `sudo` authorization without restarting anything.
- **Deployment diagnostics**: every API failure records the phase (validation / install), HTTP status, attempt count, elapsed time and a redacted response excerpt; transient `502/503/504` answers to the validation call are retried with backoff, without ever re‑issuing.
- **Lifecycle visibility**: the dashboard shows the **issued** certificate (local), the **served** certificate (what clients get on `:443`), whether each is **staging** or **production**, and an **activation** state (live / pending / unknown).
- **Ops-console dashboard**: a fleet overview with a per-server health roll-up and a detail page per Orchestrator (pipeline timeline, diagnostics, SSH/API state, history); dark-first with a light theme; live refresh without a build step or external assets.
- **Per‑server secrets with env fallback**: the Cloudflare token and Orchestrator API key can be stored per server (never echoed back to the browser) or supplied via environment variables.
- **Authentication**: a first‑run Setup flow and a login gate protect the dashboard and settings; every button carries a CSRF token, sign-in locks after repeated failures, the container runs unprivileged.
- **Failure alerts**: a webhook (email, Slack, etc.) fires when a renewal fails.
- **Backup and restore**: one command for config, certificates, SSH material and the lab CA state; restore refuses to overwrite a newer configuration and runs preflight.
- **Health that means something**: `/healthz` turns unhealthy when scheduled runs stop happening, and the container restarts when either of its processes dies.

---

## Prerequisites

- A **Linux host** (Ubuntu/Debian or a RHEL‑family distribution) that can reach the internet and the Orchestrator. `setup.sh` installs **Docker Engine + Compose plugin** from Docker's official repository if they are missing.
- A **domain in Cloudflare** for the appliance's hostname, plus a **Cloudflare API token** scoped to *Edit zone DNS* for that zone.
- For an **EdgeConnect Orchestrator** target:
  - a **Read‑Write API key** (Orchestrator → *Users & Authentication → API Keys*), and
  - an account you can **SSH into with a public key**, with passwordless `sudo` scoped to the service restart and the `nginx` reload (see [Configure SSH key authentication](#configure-ssh-key-authentication)).
- A **DNS A record** for the appliance hostname pointing at the Orchestrator (DNS‑only, not proxied).
- Recommended: run the container on a host that reaches the Orchestrator over its management address, and reach the web UI over an **SSH tunnel** (the UI binds to localhost by default).

---

## Directory Structure

```
orchestrator-acme-cert-manager/
├── app/
│   ├── cli.py                 # CLI: list / check / probe / issue / deploy / restart / renew / redeploy / backup / restore
│   ├── config.py              # load/save servers.json (v1 migrated in memory, v2 written); secrets (inline → env)
│   ├── models.py              # Certificate, Target, ServerConfig (legacy view), StepResult, RenewalRecord
│   ├── drivers/               # deploy-target drivers behind one contract (base.py)
│   │   ├── orchestrator.py    #   EdgeConnect Orchestrator: deploy.py + restart.py + sshcheck.py, unchanged
│   │   ├── ssh.py             #   generic SSH/SCP: SFTP upload, activation command, verify on host:port
│   │   ├── clearpass.py       #   ClearPass: OAuth2, per-node PUT of a PKCS#12 served by a callback listener
│   │   └── edgeconnect.py     #   EdgeConnect appliance via Orchestrator: read-only + experimental passthrough
│   ├── preflight.py           # startup checks: config persistence, permissions, per-target driver preflight
│   ├── sshcheck.py            # SSH settings validation, pinned-host-key client, sudo authorization probe
│   ├── issue.py               # stage 1 — Lego ACME issuance (DNS-01); renewal window from the cert's lifetime
│   ├── deploy.py              # Orchestrator httpsCertificate API upload (retries, diagnostics)
│   ├── restart.py             # Orchestrator SSH restart + served-cert verify + rollback (environment guard)
│   ├── renew.py               # issue once, then deploy + activate per target; locks; history; alerts
│   ├── locks.py               # per-certificate flock shared by the scheduler and the web UI
│   ├── certs.py               # certificate parsing, served-cert probe, renewal-window rule
│   ├── backup.py              # backup / restore archives (optionally encrypted)
│   ├── store.py               # renewal history (history.json) and scheduler state (scheduler.json)
│   ├── notify.py              # webhook failure alerts
│   ├── sysinfo.py             # System page data: environment, scheduler, SSH material, lab CA
│   ├── entrypoint.sh          # preflight, then the web server and supercronic, supervised
│   └── webui/
│       ├── server.py          # Flask app: fleet + server pages, live fragments, settings CRUD, Test SSH, auth
│       ├── auth.py            # PBKDF2 login + HMAC-signed sessions
│       ├── templates/         # base, index/_fleet, server/_server, settings, server_form, login, setup
│       └── static/            # style.css (dark-first tokens), app.js (theme + live refresh)
├── config/                    # PERSISTENT, bind-mounted at /config (gitignored contents)
│   ├── crontab                # supercronic schedule (02:00 / 14:00)
│   ├── servers.example.json   # template for servers.json
│   ├── servers.json           # the live server list (created by setup.sh or the web UI)
│   ├── history.json           # renewal history
│   ├── scheduler.json         # last scheduled pass (read by /healthz)
│   ├── locks/                 # per-certificate run locks
│   ├── admin.json             # web UI admin credential
│   └── session.secret         # cookie signing key
├── data/                      # runtime state (gitignored)
│   ├── certs/<domain>/        # issued certs, Lego account, rollback snapshot
│   ├── logs/
│   └── ssh/                   # orch_restart (private key), orch_restart.pub, known_hosts
├── pki/
│   ├── lab-ca-init.sh         # one-time step-ca init (run inside the step-ca image by setup.sh --with-ca)
│   ├── intermediate.tpl       # name-constrained issuing-CA template
│   └── leaf.tpl               # serverAuth-only leaf template with the CRL distribution point
├── data/pki/                  # lab CA ONLINE state (gitignored): certs/, secrets/ (intermediate key only), config/, db/
├── data/pki-root/             # lab CA OFFLINE root key + password (gitignored; move off the host)
├── tests/                     # pytest suite
├── Dockerfile
├── docker-compose.yml
├── docker-compose.override.yml.example
├── .env.example               # copy → .env (setup.sh does this)
├── requirements.txt / requirements-dev.txt
├── setup.sh                   # host preparation (Docker, key, host key, sudo check, lab CA init, backup/restore)
├── upgrade-check.sh           # read-only host readiness report before an upgrade or lab CA enablement
├── CHANGELOG.md
└── UPGRADING.md               # version-to-version upgrade steps and lab CA enablement on an existing host
```

`config/` and `data/` are **bind‑mounted** into the container so state survives rebuilds. `config/` must be mounted as a **directory** (not a single file) and must be **writable**; the web UI writes `servers.json` there. See [Configuration persistence](#configuration-persistence).

---

## Initial Setup

### 1. Clone the repository

```bash
git clone https://github.com/<you>/orchestrator-acme-cert-manager.git
cd orchestrator-acme-cert-manager
```

### 2. Run the setup script

```bash
./setup.sh --host orchestrator.example.com --ssh-user admin --email you@example.com
```

The script is idempotent and safe to re‑run. In order it:

| Step | What it does | Touches the Orchestrator? |
|---|---|---|
| Docker | Installs Docker Engine + the Compose plugin from Docker's official repository if `docker compose` is missing (Ubuntu/Debian/RHEL‑family), enables the service, adds you to the `docker` group. | No |
| Directories | Creates `data/{certs,logs,ssh}` and `config/` with restrictive permissions. | No |
| SSH key | Generates `data/ssh/orch_restart` (RSA‑4096, no passphrase) if absent. | No |
| `.env` / `servers.json` | Creates both from the examples with your host, user, port and email. The CA starts as **staging**. Writes `OACM_UID`/`OACM_GID` (your own ids) so the unprivileged container can write `config/` and `data/`. | No |
| Host key | Runs `ssh-keyscan`, **shows the fingerprints and asks you to confirm** them against a trusted reference, then pins them in `data/ssh/known_hosts`. | Read only |
| Public key | If key auth does not work yet, offers to install the public key via `ssh-copy-id` (the appliance prompts for the account password once). | Appends one line to `~/.ssh/authorized_keys` |
| `sudo` rule | Probes `sudo -n -l` for both activation commands. If not permitted, prints the exact `sudoers` line an administrator must add. With `--install-sudoers` it offers to write that drop‑in itself, after confirmation and `visudo` validation. | Only with `--install-sudoers` |
| Final test | Key authentication + `sudo -n -l` for both commands. Nothing is restarted. | Read only |

Useful flags: `--non-interactive` (no prompts; anything that needs a human is reported and skipped), `--trust-host-key` (pin without the prompt, only after you verified the fingerprint), `--skip-docker`, `--skip-remote` (print the manual steps instead), `--start` (run `docker compose up -d` at the end; add `--build` to build the image from the checkout), `--ssh-port`, `--server-id`, `--key-type ed25519`. Run `./setup.sh --help` for the full list. Every option also has an environment variable (`ORCH_HOST`, `ORCH_SSH_USER`, `ACME_EMAIL`, …) for scripted use.

If you prefer to do the SSH steps by hand, follow [Configure SSH key authentication](#configure-ssh-key-authentication) and run `./setup.sh --skip-remote`.

### 3. Add the secrets

Edit `.env` and set `CF_DNS_API_TOKEN` and `ORCH_API_KEY`, **or** leave them blank and enter them per server in the web UI later (the inline value wins; the env var is the fallback). Keep values unquoted; if you edited the file on Windows, strip carriage returns with `sed -i 's/\r$//' .env`.

### 4. Start

```bash
docker compose up -d            # pulls ghcr.io/robertsonc/orchestrator-acme-cert-manager:<version>
docker compose logs --tail 50
```

Every tagged release publishes a multi-arch image (linux/amd64, linux/arm64) to GHCR; `docker-compose.yml` pins the exact version, never `:latest`. If that tag is not published (you are running an unreleased checkout) Compose builds the image from the checkout instead; `docker compose up -d --build` always builds locally. See [Releases and the published image](#releases-and-the-published-image) to verify an image before running it.

The container runs a **preflight** on start and exits with an explanation if the configuration path is not persistently mounted or a legacy `/data/servers.json` would be ignored (see [Configuration persistence](#configuration-persistence)). Confirm the checks and the SSH path from inside the container:

```bash
docker compose exec -T orchestrator-acme-cert-manager python -m app.cli check
docker compose exec -T orchestrator-acme-cert-manager python -m app.cli ssh-test <server-id>
```

Expected from `ssh-test`:

```text
<server-id> ssh-test: OK — SSH key authentication to admin@orchestrator.example.com succeeded and sudo permits the activation commands without a password.
  [ok ] sudo /bin/systemctl restart --no-block gms.service
  [ok ] sudo /bin/systemctl reload nginx
```

### 5. Create the admin account

The web UI binds to `127.0.0.1:8090`. Open an SSH tunnel from your workstation:

```bash
ssh -L 8090:localhost:8090 <user>@<docker-host>
```

Browse to **http://localhost:8090**. On first run you'll be sent to a **Setup** page — create the single administrator account (password ≥ 8 characters).

### 6. Staging run, then production

On the dashboard click **Force renew** with the CA set to **staging** (the default written by `setup.sh`). Watch the card: the run must reach **Activation: live** with the **Served** serial equal to the **Issued** serial. Then open **Settings → Edit → CA → Let's Encrypt (production)**, save, and **Force renew** again. See [Staging to production](#staging-to-production) for what each state means and how to recover.

---

## Configure SSH key authentication

`setup.sh` automates this section. Read it to understand what the script does, or to do it by hand on an appliance where the script cannot be used.

### Purpose

The certificate manager uses SSH to activate an uploaded TLS certificate on Orchestrator. After uploading the certificate through the REST API, it connects to the appliance and runs:

```bash
sudo /bin/systemctl restart --no-block gms.service
sudo /bin/systemctl reload nginx
```

The restart is non‑blocking so the SSH command returns while GMS restarts. The application then verifies the certificate served on TCP/443. SSH must use **public‑key authentication**; there is no interactive password prompt. The connection uses Paramiko with a **strict host‑key policy**: unknown or changed host keys are rejected.

### Step 1 — Generate a dedicated key

On the Docker host, from the repository directory:

```bash
mkdir -p data/ssh && chmod 700 data/ssh
ssh-keygen -t rsa -b 4096 -f data/ssh/orch_restart -C "orchestrator-acme-cert-manager" -N ""
chmod 600 data/ssh/orch_restart
chmod 644 data/ssh/orch_restart.pub
```

RSA‑4096 was used successfully in the tested environment; the tested Orchestrator did not accept an Ed25519 key. Use a dedicated key for this application and protect the private key: it has no passphrase because the unattended service must use it without a prompt.

### Step 2 — Install the public key on Orchestrator

Log in to Orchestrator as the account the tool will use (for example `admin`) and append the contents of `data/ssh/orch_restart.pub` to that account's `~/.ssh/authorized_keys`:

```bash
umask 077; mkdir -p ~/.ssh
echo '<contents of data/ssh/orch_restart.pub>' >> ~/.ssh/authorized_keys
chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys
```

Only the public key belongs on the appliance. If the appliance restricts shell‑level SSH configuration, use the supported administrative method for that Orchestrator version.

### Step 3 — Configure restricted passwordless `sudo`

The SSH account must run exactly the two activation commands without a password. An administrator adds a scoped rule with `visudo` (for example as `/etc/sudoers.d/orchestrator-acme-cert-manager`, mode `0440`):

```sudoers
admin ALL=(root) NOPASSWD: /bin/systemctl restart --no-block gms.service, /bin/systemctl reload nginx
```

Verify the `systemctl` path on the appliance (`command -v systemctl`) and adjust if it differs. Do not grant unrestricted passwordless `sudo`. Check authorization without restarting anything:

```bash
sudo -n -l /bin/systemctl restart --no-block gms.service
sudo -n -l /bin/systemctl reload nginx
```

Each prints the fully qualified command when permitted and exits non‑zero otherwise.

### Step 4 — Pin the Orchestrator host key

```bash
ssh-keyscan -t rsa,ecdsa,ed25519 orchestrator.example.com > data/ssh/known_hosts
ssh-keygen -lf data/ssh/known_hosts      # show the fingerprints
chmod 644 data/ssh/known_hosts
```

**Security requirement:** `ssh-keyscan` retrieves keys but does not authenticate the server. Compare the fingerprints with a reference obtained from the Orchestrator console or an administrator before trusting them. The entry must match the exact hostname (or address) the tool connects to; for a non‑default port use `ssh-keyscan -p <port>`, which writes the `[host]:port` form the tool expects. Never disable host‑key verification to work around a mismatch.

### Step 5 — Test from the Docker host

```bash
ssh -i data/ssh/orch_restart -o BatchMode=yes -o IdentitiesOnly=yes \
    -o UserKnownHostsFile=data/ssh/known_hosts -o StrictHostKeyChecking=yes \
    admin@orchestrator.example.com 'sudo -n -l /bin/systemctl reload nginx'
```

Expected output: `/bin/systemctl reload nginx`. This proves key authentication and `sudo` authorization without a password prompt.

### Step 6 — Configure the certificate manager

In `config/servers.json` or the web UI:

```json
"ssh": {
  "user": "admin",
  "key_path": "/data/ssh/orch_restart",
  "known_hosts": "/data/ssh/known_hosts",
  "port": 22,
  "restart_command": "sudo /bin/systemctl restart --no-block gms.service",
  "nginx_reload_command": "sudo /bin/systemctl reload nginx"
}
```

These paths are **inside the container**. `docker-compose.yml` mounts `./data/ssh` read‑only at `/data/ssh`. The web UI validates the key (exists, readable, parseable, no passphrase) and the `known_hosts` entry when you save, and the activation step re‑validates them before connecting.

### Step 7 — Verify from inside the container

```bash
docker compose exec -T orchestrator-acme-cert-manager python -m app.cli check
docker compose exec -T orchestrator-acme-cert-manager python -m app.cli ssh-test <server-id>
```

or press **Test SSH** on the Settings page. Both authenticate and run `sudo -n -l` for each command; neither restarts a service.

### Step 8 — Validate activation

After a deployment, the dashboard compares the **Issued** and **Served** serials. To check by hand:

```bash
echo | openssl s_client -connect orchestrator.example.com:443 -servername orchestrator.example.com 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -serial
```

The serial must match `data/certs/<domain>/<domain>.cer`. A successful API upload alone does not mean the certificate is active.

---

## Configuration persistence

The server list, the admin credential, the cookie‑signing secret and the renewal history all live in **`/config`** inside the container, which `docker-compose.yml` bind‑mounts from `./config`. `SERVERS_FILE=/config/servers.json` is set explicitly in the Compose file and in the image, so a missing `.env` entry can no longer redirect the application to an unmounted path.

On start the preflight:

- logs the active configuration path (also shown on the dashboard's **System** panel and `/api/status`);
- **refuses to start** if that path is not on a mount (the container would silently lose UI changes), or if a server list exists only at the legacy `/data/servers.json`;
- **warns** if both `/data/servers.json` and `/config/servers.json` exist and differ (only `/config` is used).

Set `STRICT_STARTUP=false` to downgrade the fatal findings to warnings for one‑off recovery work.

### Migrating from `/data/servers.json`

Releases before 1.1 defaulted to `/data/servers.json` when `SERVERS_FILE` was not set. That path is **not** covered by the documented bind mounts, so the running container may hold a server list (with inline secrets) that exists nowhere on the host. Do **not** recreate the container before you have copied it out.

```bash
# 1. Copy the active config out of the running container (the container must still exist).
docker compose exec -T orchestrator-acme-cert-manager sh -c 'cat /data/servers.json' > config/servers.from-container.json
docker compose exec -T orchestrator-acme-cert-manager sh -c 'cat /data/history.json 2>/dev/null' > config/history.from-container.json

# 2. Compare with whatever is already in config/ — both may contain different secrets or newer settings.
diff <(python3 -m json.tool config/servers.from-container.json) <(python3 -m json.tool config/servers.json)

# 3. Merge by hand into config/servers.json, then lock it down.
chmod 600 config/servers.json
rm config/servers.from-container.json

# 4. Recreate with the new image (the preflight now verifies the path is persistent).
docker compose down && docker compose up -d
docker compose exec -T orchestrator-acme-cert-manager python -m app.cli check
```

Acceptance: a server added in the UI appears in `config/servers.json` on the host; settings survive `docker compose down && up`; `python -m app.cli check` reports no `legacy-*` findings.

---

## How It Works

### The pipeline

Each renewal runs three stages in order and **stops on the first failure**, so a half‑finished renewal never reaches the appliance:

1. **Issue** (`issue.py`) — runs the [Lego](https://go-acme.github.io/lego/) ACME client: `lego run` with a Cloudflare DNS‑01 challenge against Let's Encrypt. The tool injects the resolved Cloudflare token into Lego's environment, requests (or renews) the certificate, and flattens Lego's output into three canonical files: `<domain>.cer` (leaf), `<domain>.key` (private key), and `ca.cer` (issuer chain). `--ari-disable` is passed to avoid a renewal‑info mismatch when a certificate from the *other* environment is present on disk.
2. **Deploy** (`deploy.py`) — uploads the certificate to the Orchestrator `httpsCertificate` REST API as a base64 data‑URI JSON payload, authenticating with the API key (`X-Auth-Token`): first a **validation** call, then the **install**.
   - The validation call is idempotent and is retried up to `DEPLOY_VALIDATION_ATTEMPTS` (default 3) times with exponential backoff (`DEPLOY_RETRY_BACKOFF`, default 5 s) on transport errors and on HTTP **502/503/504**, which the appliance's reverse proxy returns while the GMS backend is restarting.
   - The install call is **never** retried automatically: the appliance may have applied it even if the response was lost. The recorded message says so and points at **Force deploy**.
   - A 4xx is a rejection and is not retried. Every failure records phase, kind (`transient` / `rejected` / `http` / `transport`), status, attempt, elapsed time, endpoint, and a redacted response excerpt; the dashboard shows them under **Diagnostics**. Key material, PEM blocks, data URIs and credential‑looking fields are stripped before anything is stored.
   - Nothing in this stage talks to the ACME CA, so retries never consume an issuance.
3. **Activate + verify** (`restart.py`) — validates the SSH settings (`sshcheck.validate`), connects with the pinned host key, runs the restart and `nginx` reload, then polls the appliance on `:443` and compares the **served certificate's serial** to the one just deployed. On success the certificate is snapshotted as the new known‑good; on failure the tool re‑deploys the previous known‑good certificate and re‑verifies.

`renew.py` coordinates the stages: **issue once per certificate**, then **deploy → activate for each of its targets** in order, stopping at the first failure. Every run is recorded (with the failed step's full diagnostic detail, the target it failed on, and who started it) and a failure alert is sent. **Force deploy** runs deploy → activate for one target from the certificate already on disk. The stages above describe the Orchestrator driver; other drivers implement the same steps their own way (see [Deploy targets and drivers](#deploy-targets-and-drivers)).

A run holds the certificate's **lock** (`config/locks/<id>.lock`, an `flock` the kernel releases if the process dies) for its whole duration. The scheduler skips a locked certificate and says so; the dashboard refuses to start a second run and shows who holds the lock; the CLI exits 3.

### Scheduled renewal

`supercronic` reads `config/crontab` and triggers a renewal at **02:00 and 14:00**. Each scheduled run only renews a certificate that is due: by default when **a third of the certificate's own lifetime** remains (30 days for a 90-day certificate, 15 for 45, 2 for 6). Set `RENEW_WINDOW_DAYS` for an absolute window instead. When nothing is due, Lego is not run at all. Each pass records its outcome in `config/scheduler.json`; `/healthz` reports 503 once no pass has finished within twice the cron interval, and the System page shows the same.

### Authentication

The web UI uses a single admin account. Passwords are hashed with PBKDF2‑SHA256; sessions are HMAC‑signed cookies with an 8‑hour lifetime. The credential and signing key are written `chmod 600` into `/config`.

### Certificate files

For each server, under `data/certs/<domain>/`:

| File            | Contents                                           |
|-----------------|----------------------------------------------------|
| `<domain>.cer`  | leaf (end‑entity) certificate                      |
| `<domain>.key`  | private key (`chmod 600`)                          |
| `ca.cer`        | issuer chain (intermediate + root)                 |
| `certificates/` | Lego's own working directory and ACME account      |
| `rollback/`     | last known‑good snapshot used by the rollback path |

---

## Staging to production

The dashboard tracks three things separately, because they fail separately:

| Field | Meaning |
|---|---|
| **Issued** | the certificate stored locally in `data/certs/<domain>/`, with a **staging** / **production** badge derived from its issuer |
| **Served** | the certificate the appliance presents on TCP/443 right now (read live, cached for 60 s) |
| **Activation** | `live` when Served = Issued; `pending` when they differ; `unknown` when `:443` could not be read; `none` before the first issuance |

A typical transition: staging run green (`live`, staging badge) → CA switched to production → **Force renew**. If issuance succeeds but deployment or activation fails, the card shows:

```text
Production certificate issued (serial …). Orchestrator is still serving staging certificate (serial …).
Deployment or activation is pending — use Force deploy (no CA contact).
```

and the run is recorded as **failed**, never as a successful renewal. **Force deploy** re‑runs deploy → activate with the production certificate already on disk, so recovering from a transient `502` or an SSH problem costs no production issuance. The **Force renew** button is for a new issuance only.

If the Issued badge says **staging** while the server is configured for production (or vice versa), the card says so; run **Force renew** to issue from the configured CA.

**Rollback never crosses environments by default.** The last-known-good snapshot records which CA issued it. If a *production* activation fails and the only snapshot is a *staging* (or lab) certificate, the run fails with that reason and the appliance keeps whatever it serves, instead of quietly going back to a browser-untrusted certificate. Tick **Allow rollback across CA environments** on the target to change that; the result then says a cross-environment rollback happened. The server page shows the rollback target (serial, environment, when it was taken).

---

## Deploy targets and drivers

Since 1.3 the unit of configuration is a **certificate** (name, ACME CA, DNS provider) with one or more **targets**. A target is a driver plus its settings; the driver owns everything product-specific:

| Step | What the driver does |
|---|---|
| `preflight` | static checks of the settings and credentials, no side effects (Settings form, `cli check`, System page) |
| `probe` | live, non-disruptive connectivity and authorization test (the **Test SSH / Test API** button, `cli probe`) |
| `deploy` | put the certificate where the product takes it; safe to repeat |
| `activate` | the disruptive step (service restart, PUT that restarts a service) |
| `verify` | what clients actually get: the served certificate on host:port, or the certificate the product's API reports |
| `snapshot` / `rollback` | last-known-good handling with the environment guard above |

A pre-1.3 `servers.json` entry becomes one certificate with one Orchestrator target of the same id, automatically; the file is rewritten in the new shape when something is saved. Fleet rows are targets; a certificate shared by several targets shows the same **Issued** certificate on each row with its own **Served** and **Activation** state. **Force renew** issues once and deploys to every target of that certificate; **Force deploy** re-pushes to the one target. Add a target to an existing certificate from **Settings → + Target**.

### EdgeConnect Orchestrator

What this tool has always done: REST validate/install, SSH restart + nginx reload, served-serial check on :443, rollback. Settings and behaviour are unchanged; see the sections above.

### Generic SSH/SCP

For anything with an SSH management plane and no product API. Settings: host, SSH user/port/key/known_hosts (the same pinned-host-key client as the Orchestrator driver), remote paths for the certificate, private key (written mode 600) and optionally the chain, a **full-chain** switch for daemons that want leaf + chain in one file, an optional **activation command** (`sudo /bin/systemctl reload nginx`), and the host:port whose served certificate is verified. Files are uploaded over SFTP to a temporary name and renamed into place. **Test SSH** checks authentication, that the remote directories are writable, and `sudo -n -l` for the activation command.

### ClearPass Policy Manager

Ported from the ClearPass ACME tool and rebuilt on what the API documents (identical in 6.11, 6.12 and 6.14): `PUT /api/server-cert/name/{server_uuid}/{service_name}` with a **PKCS#12 URL and passphrase**. ClearPass fetches the file itself, so the driver runs a short-lived **callback listener** on `callback_host:callback_port` (publish the port on the cert manager service: `ports: ["8765:8765"]` in `docker-compose.override.yml`, reachable from every node) that serves one random path to the cluster's addresses only and stops when the run ends. Authentication is OAuth2 client credentials (`POST /api/oauth`; create the API client under *Administration → API Services → API Clients* with an operator profile that has API access and Certificates read/write, plus Server Manager read for the node list; the secret can come from `CPPM_CLIENT_SECRET`).

Nodes come from `GET /api/cluster/server` (all, or a list); subscribers are updated first and the entry node last, one at a time, each verified (API-reported certificate, and the certificate served on the node's :443 with the certificate name as SNI) before the next. Installing *is* the activation: ClearPass restarts the service on that node when the PUT lands (web UI/guest portal for HTTPS, RADIUS for RADIUS/RadSec). If a node fails, the nodes already updated in that run are rolled back from the snapshot.

**Slots and key types.** ClearPass 6.10+ has two HTTPS slots, **HTTPS(RSA)** and **HTTPS(ECC)**; ECC-capable clients get the ECC certificate when that slot is enabled, and the ECC slot rejects RSA keys. A target selects its slots (HTTPS(RSA), HTTPS(ECC), RADIUS, RadSec). This tool issues one key type per certificate, so to serve both slots create **two certificates** (one `rsa2048`, one `ec256`) each with its own ClearPass target. When only one HTTPS slot is in scope and the other is enabled with a different certificate, the default policy **blocks** the run and explains why; `warn` and `ignore` are available.

Confirm on your cluster before the first production run: that the nodes can reach the callback port, that an `http://` callback is accepted on your release, and the PUT timing (the driver reports each in its diagnostics). Trust-list management (adding the issuing CA to *Certificates → Trust List*) is not automated yet.

### EdgeConnect appliance via Orchestrator

What is documented: Orchestrator reports an appliance's certificate (`GET /gms/rest/httpsCertificate?nePk=`) and proxies appliance REST calls (`/gms/rest/appliance/rest?nePk=&url=`). The appliance's own install endpoint "must restart nodejs manually" and HPE documents direct uploads as overwritten by Orchestrator synchronization; the supported paths are the **HTTPS Certificate template** (schema not public) or **EST end-entity profiles** (9.4.3+, the appliance generates its own key). So this driver ships the read-only parts for real (version, appliance state, reachability, the reported certificate; **Test Orchestrator API**) and keeps the write path behind an explicit **experimental passthrough write** switch with a configurable process to restart. Enable it only after confirming on a lab appliance; until then the target is monitor-only.

---

## Bundled lab CA

Public CAs will happily issue for a public DNS name that resolves to a private address (DNS-01 proves zone control, not reachability), and that is still the right choice for anything that should be trusted by default. The bundled CA is for the cases a public CA does not fit: names you don't want in certificate transparency logs, issuance you want governed locally with your own root, and devices that enroll over EST rather than ACME (phase 2; step-ca has no native EST, so that phase is an EST gateway in front of it). Issuance through this tool still uses DNS-01 against Cloudflare, so the runner needs to reach the Cloudflare API and the CA must be able to validate the challenge in public DNS; hosts may be privately addressed, but an air-gapped lab or a purely private DNS zone cannot use the automatic ACME path as shipped (other DNS providers are a separate epic). ClearPass's EST cannot issue server certificates, which is what started this. It is a `step-ca` container next to the cert manager, issuing over ACME with the same Cloudflare DNS-01 flow this tool already uses. Install its root where you choose and lab-CA hosts get a clean padlock there. Decide which names are lab-only before distributing a trusted root; the name constraint should cover exactly those.

### What it is, and what keeps it lab-safe

- **Root + name-constrained intermediate.** The issuing CA carries a *critical* X.509 name constraint: it can only sign names under `LAB_CA_DOMAIN` and never IP addresses. A client that trusts the root will reject a lab-CA certificate for any other name, so a leaked issuing key cannot impersonate public sites.
- **The root key is never online.** Setup generates the root in `./data/pki-root` with its own password, uses it once to sign the intermediate, and never copies it into `./data/pki`, the only directory the `lab-ca` service mounts. The running CA holds the intermediate key only. Moving `./data/pki-root` off the host is a required step before distributing the root, not a recommendation.
- **ACME with DNS-01 only.** HTTP-01 and TLS-ALPN-01 are disabled on the provisioner, so a certificate is only issued to whoever controls the DNS zone, exactly as with Let's Encrypt. Private hosts need nothing exposed.
- **CRL** enabled and regenerated on revoke, with an issuing-distribution-point URL, and **every leaf carries that URL as its CRL distribution point** (both the ACME and the admin provisioner use a template that adds it). Clients that check CRLs can therefore find it; see [Revocation](#revocation) for which clients do. Leaf lifetime is 90 days so the renewal window logic is unchanged.
- **Its own name is constrained too.** The CA serves at `https://<LAB_CA_HOST>:<LAB_CA_PORT>` (port 9000 unless changed, the same inside and outside the container) with a certificate from its own intermediate, so `LAB_CA_HOST` must be a name under `LAB_CA_DOMAIN` with a DNS record (Cloudflare, DNS-only) pointing at the runner's private address. That record is the one piece of DNS the lab CA needs; inside the container the name maps to loopback so the health check can use it.
- **Identity is pinned.** `setup.sh` records the CA's host, domain, port and name at init and refuses a later run that asks for different values, instead of advertising a CA that doesn't exist. Rebuilding is explicit: stop the service, move the directories aside, re-run, re-distribute the root.

Not provided yet: EST enrollment for devices (AOS-CX, EdgeConnect). step-ca itself has no EST provisioner in any released version (only draft pull requests), so the next phase is an EST (RFC 7030) gateway next to the CA that authenticates devices with one-time passwords and signs through a step-ca provisioner; AOS-CX and EdgeConnect both speak EST (EdgeConnect through Orchestrator end-entity profiles since 9.4.3). See `docs/ROADMAP.md`.

### Set it up

```bash
./setup.sh --with-ca --lab-domain lab.example.net           # CA host defaults to ca.lab.example.net
docker compose up -d                                         # COMPOSE_PROFILES=lab-ca is now in .env
docker compose exec -T orchestrator-acme-cert-manager python -m app.cli ca-info
```

`setup.sh --with-ca` initialises the CA inside the pinned `step-ca` image: the root in `./data/pki-root` (offline directory), the constrained intermediate, DNS-01 ACME provisioner, leaf template with CRL distribution point and the CRL itself in `./data/pki` (online volume). It writes `LAB_CA_*` and the Compose profile into `.env` and prints the **root fingerprint**. It needs a reachable Docker daemon. Re-running it is safe: it verifies the stored identity and changes nothing, and values you don't pass are taken from the initialised CA. Passing a different `--lab-domain`, `--ca-host`, `--ca-port` or `--ca-name` is refused. An initialisation interrupted part-way is detected on the next run, its partial online state discarded and redone; the offline root is kept.

Then, **before any client trusts the root**: move `./data/pki-root` (root key and its password) off the host. The CA does not need it to run; only a future re-issue of the intermediate does.

Then, per server: **Settings → Edit → CA → Lab CA (bundled step-ca) → Save → Force renew**. The cert manager reaches the CA by its name on the Compose network and trusts the lab root for the ACME directory. For the Orchestrator API with `verify_ssl` on and no `ca_bundle`, it verifies against the **system roots plus the lab root together**, whatever CA is configured, so switching an appliance from a public certificate to the lab CA (or back) and the rollback path all keep verifying the peer; you never need to turn verification off to migrate. A configured `ca_bundle` stays **exclusive** (pinned to that bundle only) unless its mode is set to `additive`; a missing bundle file fails the deploy rather than widening trust. The dashboard shows a `lab` badge next to `staging` and `production`.

### Distribute the root

Confirm the fingerprint from `ca-info` (or `data/pki/certs/root_ca.fingerprint`) out of band before trusting the root anywhere. Download it from `https://<LAB_CA_HOST>:<LAB_CA_PORT>/roots.pem` (or copy `data/pki/certs/root_ca.crt`).

| Client | How |
|---|---|
| Windows | `certutil -addstore -f Root root_ca.crt`, or push with Group Policy (Computer Configuration → Policies → Windows Settings → Security Settings → Public Key Policies → Trusted Root CAs). |
| macOS | Keychain Access → System → import, set *Always Trust*; or an MDM configuration profile. |
| Linux | Debian/Ubuntu: copy to `/usr/local/share/ca-certificates/lab-root.crt`, `update-ca-certificates`. RHEL-family: `/etc/pki/ca-trust/source/anchors/`, `update-ca-trust`. |
| Firefox | Uses its own store unless `security.enterprise_roots.enabled` is true; otherwise import under Settings → Certificates. |
| ClearPass | Administration → Certificates → Trust List → add the root (enable for the services that will talk to lab-CA hosts). |
| Orchestrator / EdgeConnect | Add the root to the appliance trust store where it validates outbound TLS (needed only when they call lab-CA hosts). |

### Operate

- **Revoke**: from the runner, `docker compose exec lab-ca step ca revoke <serial> --ca-url https://<LAB_CA_HOST>:<LAB_CA_PORT> --root /home/step/certs/root_ca.crt --provisioner lab-admin` (the provisioner password is `data/pki/secrets/password`; the CA's certificate is only valid for its own name, so `localhost` does not work). The CRL at `/1.0/crl` is regenerated on revoke. The root key is not needed.
- **Inventory**: `docker compose exec lab-ca step ca admin ...` is not enabled (no remote management); issued certificates are in the step-ca database under `data/pki/db`. A dashboard view is planned.
- **Back up** `data/pki` with the rest of `data/` (see [Maintenance](#maintenance)); without `secrets/password` the keys are unusable.
- **Rotate / rebuild**: remove `data/pki` and re-run `setup.sh --with-ca`; every client must then trust the new root.

### Revocation

A published CRL only matters on clients that fetch it. Every lab-CA leaf carries `https://<LAB_CA_HOST>:<LAB_CA_PORT>/1.0/crl` as its CRL distribution point and the CRL itself names that URL as its issuing distribution point; the CRL is regenerated on every revoke and cached for 24 h. What clients do with it is platform-dependent:

| Client | Behaviour |
|---|---|
| OpenSSL / curl / Python | No CRL check unless asked (`openssl verify -crl_check`); the check rejects a revoked lab leaf. |
| Windows (Schannel, Edge, Chrome) | Fetches the CDP and honours it for non-public roots; the URL must be reachable from the client and the CA's certificate trusted. |
| macOS / Safari | Best-effort revocation; CRL fetch may be skipped. |
| Firefox | OCSP-oriented; no OCSP responder here, so revocation is generally not enforced. |
| Browsers for Let's Encrypt | Not applicable to the lab CA. |

Treat revocation as defence in depth, not as the control. Issuing a replacement does **not** cancel a stolen leaf: it keeps authenticating until it expires or until a client that checks the CRL rejects it. On a key compromise: revoke the serial (CRL regenerates), re-issue with a **new key** (Force renew always generates a new key), and assume an exposure window of up to the remaining lifetime (≤ 90 days) on any client that does not check revocation. If that window is unacceptable for a given client, make it check the CRL or shorten the leaf lifetime. There is no OCSP responder.

### Root rollover

Two kinds of rotation, both keep the CA's name, domain and port:

- **New intermediate, same root** (no client changes): `docker compose stop lab-ca`, move `data/pki` aside, run `./setup.sh --with-ca` again. The init reuses the offline root in `data/pki-root` (put it back on the host for this one run), signs a new intermediate, and the online volume is rebuilt. Clients keep trusting the same root; re-issue servers at your leisure.
- **New root** (`./setup.sh --rotate-root`): stops the service, moves `data/pki` and `data/pki-root` aside, copies the old root into `data/pki/certs/retired/`, and initialises a new root and intermediate with the same identity. While a retired root exists it stays in the API trust bundle, so **verified deploys and rollback keep working against appliances that still serve leaves from the old root**; the dashboard warns that a rollover is in progress. Then: `docker compose up -d lab-ca` → distribute the new root → Force renew every lab-CA server → when all show Activation live with the new issuer, delete `data/pki/certs/retired/*` and remove the old root from client trust stores. Never disable verification to get through a rollover.

An interrupted root generation is safe: the root is built in a staging directory and promoted only when all three files exist; a half-written set with no CA yet is discarded and regenerated, a half-written set next to an existing CA fails with instructions to restore the missing file from your offline copy.

### Limits

- Only names under `LAB_CA_DOMAIN`, no IP SANs, by design.
- The ACME provisioner is named `lab` and is not configurable; the directory is always `/acme/lab/directory`.
- Lab quality: single container, local database, no HSM, no OCSP (CRL only). Do not use it for anything a browser outside the lab must trust.
- Changing the CA's host, domain or port after init means a rebuild (new intermediate, usually new root) and re-distribution.
- Certificates from the lab CA are only trusted where the root is installed; the dashboard cannot tell you which clients have it.

---

## Configuration Reference

### `config/servers.json`

Written in the `version: 2` shape since 1.3 (a pre-1.3 `servers` list is read as one certificate + one Orchestrator target per entry and rewritten on the next save):

```json
{
  "version": 2,
  "certificates": [
    {
      "id": "orch-lab",
      "name": "Lab Orchestrator",
      "domain": "orchestrator.example.com",
      "acme": { "ca": "letsencrypt_test", "email": "you@example.com", "key_type": "rsa2048" },
      "dns": { "provider": "cloudflare", "api_token": "", "env": {} },
      "targets": [
        {
          "id": "orch-lab",
          "driver": "orchestrator",
          "name": "",
          "settings": {
            "orchestrator_host": "orchestrator.example.com",
            "verify_ssl": false, "ca_bundle": "", "ca_bundle_mode": "exclusive",
            "api_key_env": "ORCH_API_KEY", "api_key": "",
            "allow_cross_env_rollback": false,
            "ssh": {
              "user": "admin",
              "key_path": "/data/ssh/orch_restart",
              "known_hosts": "/data/ssh/known_hosts",
              "port": 22,
              "restart_command": "sudo /bin/systemctl restart --no-block gms.service",
              "nginx_reload_command": "sudo /bin/systemctl reload nginx"
            }
          }
        }
      ]
    }
  ]
}
```

Certificate fields:

| Field               | Meaning                                                                                                   |
|---------------------|-----------------------------------------------------------------------------------------------------------|
| `id`                | Unique slug (letters, numbers, `-`, `_`). Permanent, can't be renamed. The first target uses the same id. |
| `name`              | Display name shown in the dashboard.                                                                      |
| `domain`            | Hostname the certificate is issued for (defaults to the first target's host).                            |
| `acme.ca`           | `letsencrypt` (production), `letsencrypt_test` (staging), or `lab` (the [bundled lab CA](#bundled-lab-ca)). A full ACME directory URL is also accepted. |
| `acme.email`        | Account email for Let's Encrypt (required).                                                               |
| `acme.key_type`     | `rsa2048`, `rsa3072`, `rsa4096`, `ec256`, `ec384`. Orchestrator has been validated with RSA only; ClearPass HTTPS(ECC) needs `ec256`/`ec384`. |
| `dns.provider`      | A [Lego DNS provider code](https://go-acme.github.io/lego/dns/). `cloudflare` uses `dns.api_token`; any other provider takes its variables from `dns.env`. |
| `dns.api_token`     | Inline Cloudflare token. Blank → fall back to `CF_DNS_API_TOKEN`.                                         |
| `dns.env`           | Provider variables passed to Lego's environment (`{"AWS_ACCESS_KEY_ID": "…"}`); stored like other inline secrets, never echoed. |

DNS providers other than Cloudflare take their variables from `dns.env` (the form's *Provider variables* box; one `KEY=value` per line). The names are Lego's, documented per provider at <https://go-acme.github.io/lego/dns/>; the four most common:

| Provider | `dns.provider` | Required variables | Useful tuning |
|---|---|---|---|
| Cloudflare | `cloudflare` | `CF_DNS_API_TOKEN` (the token field, or `.env`) | `CLOUDFLARE_PROPAGATION_TIMEOUT`, `CLOUDFLARE_TTL` |
| Amazon Route 53 | `route53` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` (plus `AWS_REGION`; `AWS_HOSTED_ZONE_ID` to skip zone lookup) | `AWS_PROPAGATION_TIMEOUT`, `AWS_TTL`, `AWS_ASSUME_ROLE_ARN` |
| Azure DNS | `azuredns` | `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `AZURE_RESOURCE_GROUP` | `AZURE_ZONE_NAME`, `AZURE_ENVIRONMENT`, `AZURE_PROPAGATION_TIMEOUT` |
| Infoblox | `infoblox` | `INFOBLOX_HOST`, `INFOBLOX_USERNAME`, `INFOBLOX_PASSWORD` | `INFOBLOX_DNS_VIEW`, `INFOBLOX_WAPI_VERSION`, `INFOBLOX_SSL_VERIFY`, `INFOBLOX_CA_CERTIFICATE` |
| RFC 2136 dynamic update | `dnsupdate` (`rfc2136` is an alias) | `DNSUPDATE_NAMESERVER`, `DNSUPDATE_TSIG_KEY`, `DNSUPDATE_TSIG_SECRET`, `DNSUPDATE_TSIG_ALGORITHM` | `DNSUPDATE_TTL`, `DNSUPDATE_PROPAGATION_TIMEOUT` |

Lego's `VAR_FILE=/path` convention works for any of them (the plain variable wins when both are set). Lego's `exec` provider runs an arbitrary program, so this tool passes Lego an allow-listed environment (never the container's own API keys); `manual` cannot run unattended. Issuance always uses a fixed `--dns.propagation.wait` (`DNS_PROPAGATION_WAIT`, default `60s`), so the provider's own `*_PROPAGATION_TIMEOUT` is not consulted; raise the wait for slow zones (Route 53 and Azure often need more than 60 s).

Target fields: `id` (global slug), `driver` (`orchestrator`, `ssh`, `clearpass`, `edgeconnect`), `name`, and `settings` as the driver's form shows them (the **System** page lists the drivers; the form shows each field's meaning and, for anything configured on the host, the command that sets it up). Orchestrator settings are the ones above: `orchestrator_host`, `verify_ssl`, `ca_bundle`, `ca_bundle_mode` (`exclusive` / `additive`), `api_key_env`, `api_key`, `allow_cross_env_rollback`, and the `ssh` block (`user`, `key_path`, `known_hosts`, `port`, `restart_command`, `nginx_reload_command`, all validated on save and before every activation).

> Secrets (`dns.api_token`, `dns.env`, `api_key`, `client_secret`) are optional. Set them in the web UI or here; either way the file is written `chmod 600`. **`config/servers.json` is gitignored** and must never be committed.

### Environment (`.env` and Compose)

| Variable                     | Purpose                                                                                     |
|------------------------------|---------------------------------------------------------------------------------------------|
| `SERVERS_FILE`               | Path to the server list inside the container. Compose sets `/config/servers.json`.          |
| `CONFIG_DIR` / `DATA_DIR`    | Persistent config directory (`/config`) and runtime data root (`/data`).                    |
| `HISTORY_FILE`               | Renewal history (default `<CONFIG_DIR>/history.json`).                                      |
| `STRICT_STARTUP`             | `true` (default): fail start on an unmounted config path or legacy‑only config. `false`: warn. |
| `CF_DNS_API_TOKEN`           | Cloudflare token fallback (used when a server has no inline token).                         |
| `ORCH_API_KEY`               | Orchestrator API key fallback.                                                              |
| `NOTIFY_WEBHOOK_URL`, `NOTIFY_ON` | Optional Slack‑compatible webhook for alerts; `failed` (default) or `all`.             |
| `RENEW_WINDOW_DAYS`          | Absolute days‑before‑expiry window for scheduled renewals. Unset (default): renew when a third of the certificate's lifetime remains. |
| `OACM_UID`, `OACM_GID`       | uid/gid the cert manager container runs as (image default 10001). `setup.sh` writes your own ids so `config/` and `data/` need no chown. |
| `CPPM_CLIENT_SECRET`         | ClearPass API client secret fallback for ClearPass targets (the env var name is configurable per target). |
| `ACTIVATE_POLL_TIMEOUT`, `ROLLBACK_POLL_TIMEOUT` | Seconds a driver waits for the served certificate after activation / rollback (default 300 / 120). |
| `LOGIN_MAX_FAILURES`, `LOGIN_LOCKOUT_SECONDS` | Sign-in lockout threshold and duration (default 5 / 900).                                  |
| `DEPLOY_VALIDATION_ATTEMPTS` | Attempts for the validation call on transient failures (default 3).                         |
| `DEPLOY_RETRY_BACKOFF`       | Base backoff in seconds between validation attempts, doubled each time (default 5).         |
| `DEPLOY_HTTP_TIMEOUT`        | Per‑request timeout for the Orchestrator API (default 30).                                  |
| `LOG_LEVEL`, `TZ`            | Logging verbosity; container timezone (affects cron and logs).                              |
| `COMPOSE_PROFILES`           | `lab-ca` enables the bundled CA service (written by `setup.sh --with-ca`).                  |
| `LAB_CA_HOST`, `LAB_CA_PORT`, `LAB_CA_DOMAIN` | The lab CA's name (under `LAB_CA_DOMAIN`), the port step-ca listens on inside and outside the container (9000), issuing scope. Pinned at init; `setup.sh` refuses to change them. The ACME provisioner is always `lab`. |
| `LAB_CA_UID`, `LAB_CA_GID`   | uid/gid the step-ca container runs as; must own `./data/pki` (set by `setup.sh`).           |

### Volumes (`docker-compose.yml`)

```yaml
    environment:
      CONFIG_DIR: /config
      SERVERS_FILE: /config/servers.json
      DATA_DIR: /data
    user: "${OACM_UID:-10001}:${OACM_GID:-10001}"   # unprivileged; setup.sh writes your ids to .env
    ports:
      - "127.0.0.1:8090:8080"   # localhost only; reach via SSH tunnel
      # - "8765:8765"           # only for ClearPass targets: the PKCS#12 callback the nodes fetch from
    volumes:
      - ./config:/config        # writable directory mount — servers.json, history.json, admin.json, session.secret
      - ./data/certs:/data/certs
      - ./data/logs:/data/logs
      - ./data/ssh:/data/ssh:ro # private key + known_hosts, read-only in the container
```

---

## Web UI

Reached at `http://localhost:8090` over the SSH tunnel. Dark theme by default, light theme via the toggle in the top bar (remembered per browser). No build step, no external assets: the pages work with no internet access from the browser.

- **Fleet** (`/`) — the overview. Five tiles (targets, healthy, need attention, in the renewal window, soonest expiry), the preflight findings, and one row per **target** sorted worst-first by a **health** roll-up (`attention` / `warning` / `healthy` / `unverified` / `working`, always shown as glyph + label with the top reason). Each row shows the driver, the configured CA, the **Issued** and **Served** certificate serials with staging/production/lab badges, the **Activation** state, the last run with its kind and who started it, and the **Force renew** / **Force deploy** actions. A cron run shows as *working* with the lock holder. Recent activity and the active configuration path sit below.
- **Target** (`/server/<id>`) — everything about one target: Issued / Served / Activation / **Rollback target** cards (with the issued certificate's lifetime meter and the snapshot's environment and policy), the last run as a pipeline (issue → deploy → restart or activate) with elapsed time per step, the target each step ran on, and a **Diagnostics** disclosure on the failed step, the driver's activation settings with their validation state and warnings, API TLS / secrets / CA summary, and the certificate's history. Actions: Force renew (asks for confirmation because it spends an issuance; deploys to every target of the certificate), Force deploy (this target only), the driver's probe (**Test SSH** / **Test API**), Edit.
- **Live refresh** — the Fleet and Server pages re-fetch a server-rendered fragment every 8 s while a run is in progress and every 45 s otherwise (paused in background tabs), so a Force renew's outcome appears without reloading. The top-bar stamp shows the last refresh.
- **Settings** (`/settings`) — certificates with their targets; add a server (certificate + first target), add a target to an existing certificate, edit, delete, probe. The form is built from the driver's schema: pick the driver, fill its section. Everything is validated on save (the SSH block as before, driver-specific rules such as absolute remote paths or slot/key-type consistency) and stored secrets are never echoed. The CA bundle mode (exclusive / additive) and the lab CA's availability are shown inline.
- **System** (`/system`) — the deployment as the container sees it, read-only: version, the full preflight report, every documented environment variable with its state (secrets as set / unset, never the value), the scheduler with its next run, the SSH key and pinned host keys per server, and the lab CA (identity, URLs, root fingerprint, live health probe, **Download root**). Everything that is configured on the Docker host rather than in the UI carries an **ⓘ** indicator naming the exact `setup.sh` flag, `.env` key or command, and a table at the bottom lists all host-side operations. Host-level readiness (Docker, Compose, `.env` drift, ownership) is `./upgrade-check.sh` on the host, because the container cannot see the host.
- **CLI-dependency indicators** — the same **ⓘ** appears in the server form and on the server page next to every field whose value depends on host configuration: key path, known hosts, sudoers-bound commands, CA bundle location, environment-variable fallbacks for secrets, the lab CA option. Hover or focus shows what it depends on and the command that sets it up.
- **Setup / Login** — first-run admin creation, then a login gate on everything else. Every form carries a CSRF token tied to a `csrf` cookie (a POST without it is a 403); five failed sign-ins per user and address lock the account for 15 minutes (logged); the session cookie is `SameSite=Strict`.
- JSON: `/api/servers`, `/api/server/<id>`, `/api/history`, `/api/status` (the System snapshot; `?probe=1` adds the lab CA health probe), `/ca/root.pem` and `/ca/intermediate.pem` (behind the login); `/healthz` is open.

Configuration is read on every request, so UI changes take effect on the next run with no restart.

---

## CLI

All commands run inside the container: `docker compose exec -T orchestrator-acme-cert-manager python -m app.cli <command>`.

| Command | Purpose |
|---|---|
| `list` | Configured servers, their CA and last outcome, plus the active configuration path. |
| `check [--json] [--lenient]` | Preflight: configuration path and persistence, permissions of the service user, legacy‑file detection, per‑target driver preflight, credential presence. Exit 1 on fatal findings. |
| `probe <target-id>` (alias `ssh-test`) | The driver's live, non-disruptive check: SSH auth + `sudo -n -l` for Orchestrator/SSH targets, OAuth2 + node list + slots for ClearPass, version/appliance/reported certificate for EdgeConnect. Restarts nothing. |
| `ca-info` | Bundled lab CA endpoints, root fingerprint and issuer names (the System page shows the same, plus a live health probe). |
| `issue <id>` / `deploy <id>` / `restart <id>` | Run a single stage. |
| `renew <id> [--force] [--source cli\|cron\|web] [--actor NAME]` | Full pipeline for one certificate, every target (contacts the CA). Exit 3 when another run holds the certificate's lock. |
| `redeploy <id>` | Deploy → activate from the certificate already on disk, every target (no CA contact). |
| `renew-all [--force] [--source cron]` | What the scheduler runs (`--source cron` records the pass for `/healthz`). Locked certificates are skipped and reported. |
| `backup <file> [--include-root] [--encrypt]` | Archive config, certificates, SSH material and the visible lab CA state (logs excluded). `--encrypt` uses `BACKUP_PASSPHRASE` (AES-256-GCM). |
| `restore <file> [--force] [--passphrase-env VAR]` | Restore an archive; refuses to overwrite a newer `servers.json` without `--force`; runs preflight afterwards. |

---

## Maintenance

### View logs

```bash
tail -n 100 data/logs/renew.log           # scheduled runs
docker compose logs -f --tail 100         # web + scheduler + preflight
```

### Force a renewal or re‑deploy

Use the dashboard buttons or the CLI. **Force deploy** / `redeploy` is the right choice after an appliance rebuild, a transient `502` during validation, or an SSH fix: it never spends an issuance.

### Switch staging ↔ production

**Settings → edit the server → CA dropdown → Save**, then **Force renew**. See [Staging to production](#staging-to-production).

### Enable API TLS verification after bootstrap

Once the dashboard shows **Activation: live** with a production certificate, edit the server, make sure `orchestrator_host` is a name on that certificate, tick **Verify the Orchestrator's TLS cert**, save, and press **Force deploy** to confirm the API still answers. For a private CA, set the **CA bundle** path (mount it under `./data/ssh` or another mounted directory). SSH host‑key verification is independent of this setting and is always strict.

### Back up and restore

```bash
./setup.sh --backup ../oacm-$(date +%Y%m%d).tgz            # host side: .env, config/, data/ minus logs (and minus the offline root)
./setup.sh --restore ../oacm-20261022.tgz                   # on a new host, before setup.sh --host … and compose up
docker compose exec -T orchestrator-acme-cert-manager python -m app.cli backup /config/backup.tgz   # from inside the container
```

The host-side archive sees everything including the lab CA online state; the in-container one covers what the container can see (config, certificates, SSH material). Both preserve permissions; the offline root (`data/pki-root`) is included only with `--include-root`. Acceptance: backup on host A, restore on host B, `check` passes and **Force deploy** works without re-issuing.

### Reset the admin account

```bash
rm config/admin.json
```

### Update the image (state preserved)

```bash
git pull                        # brings the new pinned tag in docker-compose.yml
docker compose pull && docker compose up -d
# or, to build from this checkout instead of pulling: docker compose up -d --build
```

Certificates, history, and config live in the mounted volumes. A volume, `.env` or Compose change requires `docker compose down && docker compose up -d`.

### Releases and the published image

A release is a git tag `vX.Y.Z` on `main`. The `release` workflow refuses the tag unless `__version__` in `app/__init__.py`, the image tag in `docker-compose.yml` and the dated `CHANGELOG.md` heading all agree (`python3 scripts/check-version.py --tag vX.Y.Z` runs the same check locally), then runs the full CI, builds `linux/amd64` and `linux/arm64`, pushes `ghcr.io/robertsonc/orchestrator-acme-cert-manager:X.Y.Z` and `:X.Y`, attaches a BuildKit SBOM and provenance to the image index, signs a build-provenance attestation and creates the GitHub Release from the CHANGELOG section. There is no `:latest` tag by design: an upgrade is a reviewed change to the pinned tag.

Verify an image before you run it (needs the `gh` CLI):

```bash
gh attestation verify oci://ghcr.io/robertsonc/orchestrator-acme-cert-manager:1.3.0 -R robertsonc/orchestrator-acme-cert-manager
```

Cutting a release: bump `__version__`, the compose tag and the CHANGELOG heading in one commit on `main`, then `git tag -a v1.3.0 -m 'v1.3.0' && git push origin v1.3.0`.

---

## Upgrading

[UPGRADING.md](UPGRADING.md) has the version-to-version procedure (backup, what to export from a 1.0.x container before it is recreated, the idempotent `setup.sh` re-run, verification that touches no appliance, rollback) and the order of operations for enabling the bundled lab CA on a host that already runs the cert manager. Start with the read-only readiness report on the host:

```bash
./upgrade-check.sh                                   # tools, checkout, layout, .env, Compose, SSH material, running container
./upgrade-check.sh --with-ca --lab-domain <zone>     # plus DNS record, port, PKI state before setup.sh --with-ca
```

It prints a numbered fix list and exits non-zero while anything blocks the upgrade. Secrets are reported as present or absent only.

---

## Troubleshooting

Failures are recorded in the dashboard history with the underlying message and a **details** disclosure. `docker compose logs -f` shows the full output.

### Activation fails: `SSH configuration invalid … ssh.key_path is empty`

The server entry has no private key path (or it points at a missing/unreadable/encrypted file, or `known_hosts` has no entry for the host). The message lists every problem. Fix them in **Settings → Edit** (the form refuses to save an invalid SSH block) and confirm with **Test SSH** or `python -m app.cli ssh-test <id>`. If you corrected the file by hand, make sure you edited the **active** path shown on the dashboard's System panel.

### `Certificate validation failed … HTTP 502 (transient)`

The Orchestrator reverse proxy answered before the GMS backend was ready (typically right after a restart). The validation call is retried automatically (3 attempts with backoff). If all attempts fail, the run stops **before** install and is recorded as failed; nothing was changed on the appliance. Wait for the appliance to settle and press **Force deploy**. The same certificate is reused; no issuance is spent.

### `Certificate validation failed … HTTP 400 (rejected)`

The appliance rejected the payload. Check the response excerpt under Diagnostics; typical causes are a key that does not match the certificate or an incomplete chain. This is not retried.

### `Cannot connect to the Docker daemon at unix:///var/run/docker.sock`

Docker is installed but the daemon is not running, or your user cannot reach its socket. `setup.sh` checks this (and starts the service) on every run; by hand:

```bash
sudo systemctl enable --now docker
docker info >/dev/null && echo ok
```

`Unit docker.service not found` means Docker did not come from Docker's repository (snap: `sudo snap start docker`; Docker Desktop: start the app). `permission denied` on the socket means the `docker` group membership has not reached your session yet: `newgrp docker` or log out and back in.

### Lab CA: `DNS name "…" is not permitted by any constraint`

step-ca issues its own TLS certificate from the name-constrained intermediate, so `LAB_CA_HOST` must be a name under `LAB_CA_DOMAIN` (no IP addresses). Fix `.env`, remove `data/pki` if it was initialised with the wrong name, and re-run `setup.sh --with-ca`.

### `setup.sh --with-ca` says the requested identity differs from the initialised CA

The CA's host, domain, port and name are recorded at init in `data/pki/config/lab-ca.meta`. A re-run with different values is refused on purpose: the running CA's certificate and name constraints would no longer match what `.env` advertises. Either re-run without those flags (the stored values are used) or rebuild: `docker compose stop lab-ca`, move `data/pki` aside (and `data/pki-root` for a new root), re-run `setup.sh --with-ca`, re-distribute the root.

### Lab CA certificate is live but browsers still warn

The client does not trust the lab root. Confirm the fingerprint from `ca-info`, then install the root per [Distribute the root](#distribute-the-root). Firefox needs its own import or the enterprise-roots setting.

### `lego … failed` with `x509: certificate signed by unknown authority` against the lab CA

The cert manager cannot find the lab root. `./data/pki/certs` must be mounted at `/data/pki/certs` (the shipped Compose file does this) and `LAB_CA_HOST` must be set; `python -m app.cli ca-info` reports what it sees.

### Container exits at start with `preflight FAILED`

Read the `[FATAL]` lines:

- `perm-config-dir` — the container runs unprivileged (uid shown in the message) and cannot write `/config`. Either set `OACM_UID`/`OACM_GID` in `.env` to the owner of `config/` and `data/` (`./setup.sh` writes your own ids) or `chown` those directories to the uid named in the message, then `docker compose down && docker compose up -d`.

- `config-not-mounted` — `SERVERS_FILE` points somewhere that is not a bind mount or volume. Use the shipped `docker-compose.yml` (mounts `./config:/config`) and do not override `SERVERS_FILE` in `.env` with another path.
- `legacy-config-only` — a server list exists at `/data/servers.json` but not at `/config/servers.json`. Follow [Migrating from `/data/servers.json`](#migrating-from-dataserversjson).

`STRICT_STARTUP=false` turns both into warnings if you need the container up to extract files.

### SSH: `host key … does not match the pinned entry`

The appliance's host key changed (rebuild, reinstall) or `known_hosts` has the wrong entry. Obtain the new fingerprint from a trusted source, remove the stale line from `data/ssh/known_hosts`, and re‑run `./setup.sh` (it re‑scans and asks you to confirm). Do not disable host‑key checking.

### SSH: `authentication failed … not in that account's authorized_keys`

The public key is not installed for that user, or the account disallows public‑key login. Re‑run `./setup.sh` (it offers `ssh-copy-id`) or follow [Step 2](#step-2--install-the-public-key-on-orchestrator). The tested Orchestrator required an RSA key.

### `Test SSH`: authentication OK but `sudo` fails for a command

`sudoers` does not permit that exact command string for that user, or requires a password. Add the scoped `NOPASSWD` rule from [Step 3](#step-3--configure-restricted-passwordless-sudo). The command in `sudoers` must match the configured command character for character (including `--no-block`).

### Dashboard shows `Activation: pending` after a successful‑looking run

The served serial differs from the issued one: `nginx` still holds the old certificate or the restart has not completed. Press **Force deploy**; the activation stage reloads `nginx` and waits for the served serial to match. If it never matches, check that the reload command succeeds over SSH (Test SSH) and that `orchestrator_host` resolves to the appliance you expect.

### Dashboard shows `Activation: unknown`

The container could not read a certificate from `orchestrator_host:443` (unreachable, firewall, wrong host). Issuance and deployment are unaffected, but verification needs this path to work.

### `lego … failed` with an empty error, ARI `replaces` errors, HTTP 429

Unchanged from earlier releases: Lego writes some errors to stdout (captured); `--ari-disable` is passed so a cert from the other environment on disk does not break issuance; production rate limits are recovered with **Force deploy** or by iterating on **staging**.

### The web UI returns 500 on save ("Read‑only file system")

`config/` is mounted read‑only or as a single file. Mount the directory, writable (the shipped Compose file does), and keep `SERVERS_FILE=/config/servers.json`.

### `curl http://localhost:8090/api/...` redirects to `/login`

Expected — the API is behind auth. Use `/healthz`, or log in first with a cookie jar.

### A POST returns 403 "Request rejected" / "form token is missing or stale"

Every state-changing request needs the CSRF token the page carries (tied to the `csrf` cookie). Reload the page and retry; a script should use the CLI inside the container instead.

### Sign-in says "Too many failed sign-in attempts"

Five failures for that username from that address lock sign-in for 15 minutes (`LOGIN_MAX_FAILURES`, `LOGIN_LOCKOUT_SECONDS`). Each attempt is logged with the address. A container restart clears the counters.

### `/healthz` returns 503 `scheduler-stale`; `docker compose ps` shows unhealthy

No scheduled pass finished within twice the cron interval (24 h with the shipped crontab). Check `docker compose logs` for supercronic and `tail data/logs/renew.log`; the System page shows the last pass and any certificate that was skipped because it was locked. The entrypoint also exits when supercronic or the web UI dies, so a restart loop points at a crashing process.

### Run refused: "a renew is already running (pid …, since …, started by …)"

The certificate is locked by another run (a cron pass, or a Force renew from the UI). Wait for it; the lock is released with the process, so a crashed run never leaves a stale lock. If a lock file under `config/locks/` is held by a pid that no longer exists, something else holds the same file: `docker compose restart` clears it.

### `refusing to roll back across CA environments`

A production activation failed and the only snapshot is a staging or lab certificate. The appliance keeps what it serves. Fix the cause (the message above it says which step failed) and press **Force deploy**, or allow cross-environment rollback on the target if a staging certificate is acceptable meanwhile.

### ClearPass: `HTTP 422 … Could not fetch certificate. URL not trusted or Cert File is empty`

ClearPass could not download the PKCS#12 from the callback URL. Check that `callback_host` is an address the nodes can reach, the callback port is published on the cert manager service and open on the host firewall, and look at the step diagnostics: `fetches` counts the downloads that happened and `callback_rejected` lists addresses that connected but are not known cluster nodes (a NAT or a node address missing from `GET /api/cluster/server`). An `https://` callback additionally needs the listener's CA in the ClearPass trust list with usage *Others*.

### The System page says `config-v1`

`config/servers.json` is still in the pre-1.3 shape. It is read correctly; it is rewritten in the `certificates` shape the next time anything is saved. Nothing to do.

---

## Security Considerations

- **Secrets at rest**: With inline secrets, `servers.json` (and its `.bak`) contain a Cloudflare token and Orchestrator API key. They're written `chmod 600`. `config/servers.json`, `.env`, `config/admin.json`, and `config/session.secret` are gitignored; never commit them. Anyone with file access to the host can read them. A secrets vault is the recommended hardening step.
- **SSH private key**: `data/ssh/orch_restart` has no passphrase. The directory is `0700`, the key `0600`, and the container mounts it read‑only. Use a dedicated key and account; revoke the key on the appliance when the tool is decommissioned.
- **Host‑key pinning**: Paramiko runs with `RejectPolicy`; the only trusted keys are those in `known_hosts`. `setup.sh` shows the scanned fingerprints and requires a confirmation (or an explicit `--trust-host-key`), because `ssh-keyscan` alone cannot authenticate the appliance.
- **Scoped `sudo`**: the `sudoers` rule grants exactly two commands. `Test SSH` and `ssh-test` only ever run `sudo -n -l`, which checks authorization and runs nothing.
- **API TLS verification**: `verify_ssl` is off by default because the appliance serves a self‑signed certificate until the first deployment succeeds. The dashboard and the logs say so on every run; enable it once production is live.
- **Diagnostics redaction**: response excerpts stored in history have PEM blocks, data URIs, long base64 runs and credential‑looking JSON fields removed. API keys are sent only in request headers and are never logged.
- **Network exposure**: The UI binds to `127.0.0.1` and is intended to be reached over an SSH tunnel. Do not publish port 8090. The ClearPass callback port, when published, serves one random path for the duration of a run to the cluster's addresses only; the PKCS#12 is protected by a per-run passphrase sent over the authenticated API call, not over the callback. Prefer a firewall rule limiting the port to the ClearPass nodes.
- **Unprivileged container**: the image runs as `OACM_UID:OACM_GID` (default 10001); `setup.sh` sets your own ids so no `chown` of the bind mounts is needed. Preflight refuses to start when the service user cannot write `/config`.
- **Forms**: every non-GET route checks a CSRF token tied to the `csrf` cookie; the session cookie is `SameSite=Strict` and `HttpOnly`; sign-in is throttled per user and address.
- **Least privilege**: Scope the Cloudflare token to *Edit zone DNS* on the single zone. Use an Orchestrator API key with the minimum role that can install a certificate.
- **Private key handling**: Certificate keys are generated on the automation host and pushed to the target. For stricter environments, prefer on‑target key generation (EST, the next phase) and per‑renewal key rotation. Backups made with `backup` contain private keys and the SSH key: encrypt them (`--encrypt`) and keep them off the host.

---

## Orchestrator API Reference

The deploy stage uses the Orchestrator `httpsCertificate` REST API, authenticating with `X-Auth-Token: <api-key>`:

| Call                                              | Purpose                                                    | Retried? |
|---------------------------------------------------|------------------------------------------------------------|----------|
| `POST …/gms/rest/gms/httpsCertificate/validation` | Validate the certificate/key/chain payload before install. | On transport errors and 502/503/504, bounded |
| `POST …/gms/rest/gms/httpsCertificate`            | Install the validated certificate.                         | Never    |

The payload is a JSON object carrying the leaf certificate, private key, and intermediate chain as base64 `data:` URIs (`certificateData`, `keyData`, `intermediateCertFileContent`). Activation is **not** an API call, it's an SSH service restart plus `nginx` reload, followed by a served‑certificate check on `:443`.

Other drivers: ClearPass uses `POST /api/oauth` (client credentials), `GET /api/cluster/server`, `GET`/`PUT /api/server-cert/name/{server_uuid}/{service_name}` ([developer.arubanetworks.com/cppm](https://developer.arubanetworks.com/cppm/reference/servercertnamebyserver_uuidbyservice_nameput)); EdgeConnect-via-Orchestrator uses `GET /gms/rest/gms/versions`, `GET /gms/rest/appliance?nePk=`, `GET /gms/rest/reachability/appliance?nePk=`, `GET /gms/rest/httpsCertificate?nePk=` and, when the experimental write path is on, `POST /gms/rest/appliance/rest?nePk=&url=httpsCertificate/validation|config` and `…url=cnprocess/restart/<name>` (HPE Postman collections 9.3–9.6).

---

## Development

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest -q
shellcheck -S warning setup.sh upgrade-check.sh
```

`upgrade-check.sh` is tested against synthetic 1.0.x and current layouts with a fake `docker` on `PATH` (`tests/test_upgrade_check.py`); every scenario also asserts the tree is byte-for-byte unchanged afterwards.

The lab CA tests run `pki/lab-ca-init.sh` against a real `step` binary when one is on `PATH` (download the pinned release from the smallstep/cli GitHub releases; CI installs it and fails if the tests would skip). CI also runs a Docker smoke job that initialises the CA in the pinned image on a non-default port, starts the `lab-ca` service, waits for a healthy container and queries the ACME directory, root and CRL by the CA's constrained name.

The test suite covers configuration path resolution, v1→v2 migration and legacy detection, every SSH misconfiguration class (empty/missing/unreadable/invalid/passphrase‑protected key, missing `known_hosts` entry, port syntax), the sudo probe, deployment retry/no‑retry behaviour for 502/503/504, 400, TLS and transport errors and install, the "Force deploy never contacts the CA" guarantee, the per-certificate lock (in-process and across processes), the lifetime-fraction renewal window at 90/45/6 days, the rollback environment guard on both the Orchestrator path and the generic driver path, multi-target runs with a fake driver, the SSH driver's SFTP upload, the ClearPass driver against a fake cluster that really fetches the PKCS#12 from the callback listener (including rollback of already-updated nodes and the client allow-list), the EdgeConnect driver's read-only and experimental paths, backup/restore round-trips with encryption, CSRF, login throttling, `/healthz` staleness, lifecycle state derivation, and the web UI's save‑time validation.

---

## License

MIT — see [LICENSE](LICENSE).
