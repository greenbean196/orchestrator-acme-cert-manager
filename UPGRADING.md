# Upgrading an existing deployment

This guide moves a running deployment to the current release and, optionally, enables the bundled lab CA on it. It is written for the operator of a single Docker host with one or more Orchestrators already configured. Nothing in an upgrade touches an appliance: certificates are only deployed when the scheduler decides a renewal is due or when you press **Force renew** / **Force deploy**.

Two tools do the work:

- `./upgrade-check.sh` (host, read-only) reports missing dependencies, stale `.env` keys, absent secrets, ownership and permission problems, SSH material, and the lab CA prerequisites. Run it before and after every step below. It changes nothing and never prints a secret.
- The **System** page in the web UI (and `python -m app.cli check` inside the container) shows what the container sees after the upgrade: preflight findings, environment presence, scheduler, SSH material, lab CA state. Anything on it that is configured on the host carries an indicator with the command that changes it.

---

## 1. Find out what you are running

| Marker | 1.0.x (Aug 2026) | 1.1.x | 1.2.x | 1.3.x (current) |
|---|---|---|---|---|
| `grep __version__ app/__init__.py` in the checkout | `1.0.0` | `1.1.0` | `1.2.0` | `1.3.0` |
| `docker inspect -f '{{.Config.Image}}' orchestrator-acme-cert-manager` | `…:latest` | `…:1.1.0` | `…:1.2.0` | `…:1.3.0` |
| `python -m app.cli check` inside the container | command does not exist | works | works | works; reports `config-v1` until the first save |
| Web UI | card dashboard, Settings | Fleet / Server pages, dark theme | plus **System** page | rows are *targets*; CSRF tokens; drivers |
| `setup.sh` | 21 lines, copies examples only | full host workflow, `--with-ca` | plus `data/pki/certs` ownership, `upgrade-check.sh` | plus `OACM_UID/GID`, `--backup`, `--restore` |
| Where the server list lives | `/data/servers.json` unless `SERVERS_FILE` was set | `/config/servers.json`, enforced by preflight | same | same; `version: 2` shape after the first save |
| Container user | root | root | root | unprivileged (`OACM_UID`/`OACM_GID` from `.env`) |

The version of the **checkout** and the version of the **running image** can differ. The running image is what matters for the data-migration steps; the checkout is what you are upgrading to.

---

## 2. Before you start (every upgrade)

1. **Run the readiness check** from the checkout and read the fix list:

   ```bash
   ./upgrade-check.sh
   ```

2. **Back up** everything the application owns. Logs are excluded; the lab CA's offline root is included only if it is still on the host (it should not be once the CA is in use).

   ```bash
   tar --exclude='data/logs' -czf "../oacm-backup-$(date +%Y%m%d%H%M).tgz" \
       .env config data docker-compose.override.yml 2>/dev/null; echo "backup exit $?"
   ```

   Exit 1 only means `docker-compose.override.yml` does not exist; exit 2 means a file could not be read, so look at the output.

3. **1.0.x only: export the live server list from the running container** before anything recreates it. Releases before 1.1 kept `servers.json` at `/data/servers.json`, which is not covered by the bind mounts, so the list you edited in the UI (including inline secrets) may exist nowhere on the host:

   ```bash
   docker compose exec -T orchestrator-acme-cert-manager sh -c 'cat /data/servers.json' > config/servers.from-container.json
   docker compose exec -T orchestrator-acme-cert-manager sh -c 'cat /data/history.json 2>/dev/null' > config/history.from-container.json
   chmod 600 config/servers.from-container.json
   ```

   `upgrade-check.sh` refuses to report "ready" while the running container holds a legacy file that differs from `config/servers.json`.

4. **Record the current state**: the Fleet page (or `python -m app.cli list`), which servers are on production, and the **Served** serial of each. After the upgrade these must be unchanged, because the upgrade itself never deploys anything.

5. **Pick a window** if you intend to run the end-to-end verification (step 4.5). A Force deploy restarts the Orchestrator's web service, which is a short management-plane interruption. The upgrade without that step is safe at any time. A scheduled run can fire at 02:00 or 14:00 container time if a certificate is already inside the renewal window; the System page shows the next scheduled run.

---

## 3. Upgrade procedure

Works from any earlier version. Version-specific notes follow in section 5.

### 3.1 Bring the code forward

```bash
git fetch origin
git status                     # local modifications to tracked files? move them into .env or docker-compose.override.yml
git pull --ff-only origin main
./upgrade-check.sh             # read the fix list again; it now knows the new layout
```

If `git status` shows modified tracked files (typically `docker-compose.yml` or `setup.sh` edited by hand), `git pull` will stop. Keep your changes in `docker-compose.override.yml` (compose merges it automatically) and `.env`, then `git checkout -- <file>` the tracked copy. `upgrade-check.sh` scans the override for the two traps that have caused outages: a single-file `servers.json` mount and a read-only `/config`.

### 3.2 Re-run the host setup (idempotent)

```bash
./setup.sh --host <orchestrator-fqdn> --ssh-user <user> --email <acme-email>
```

On an existing deployment this:

- creates any missing directory, including `data/pki/certs`, owned by you (if Docker created it first it is owned by root and a later lab CA init cannot write there; the script warns and prints the `chown`);
- keeps the existing SSH key and `config/servers.json` untouched;
- adds `SERVERS_FILE=/config/servers.json` to `.env` if it is missing, and leaves every other value alone;
- pins the Orchestrator host key in `data/ssh/known_hosts` if it is not pinned yet (you confirm the fingerprint), checks that the public key is installed, and probes the sudoers rule. Add `--skip-remote` to do none of the remote steps and print them instead; add `--install-sudoers` to let it write the scoped rule after confirmation.

Nothing on the appliance is restarted.

### 3.3 Recreate the container

`docker compose up -d` alone is not enough when `.env`, the environment block or the volumes changed; the container has to be recreated:

```bash
docker compose down
docker compose pull            # the released image for the tag pinned in docker-compose.yml (or: up -d --build to build here)
docker compose up -d
docker compose logs --tail 60
```

The log must end with the preflight result and the web UI starting. A `preflight FAILED` exit names the finding; the usual ones during an upgrade are `legacy-config-only` (step 2.3 was skipped) and `config-not-mounted` (an override removed the `/config` mount). Fix the cause rather than setting `STRICT_STARTUP=false`.

### 3.4 Verify without touching the appliance

```bash
docker compose exec -T orchestrator-acme-cert-manager python -m app.cli check
docker compose exec -T orchestrator-acme-cert-manager python -m app.cli list
```

Then in the UI (over the SSH tunnel, `http://localhost:8090`):

- **System**: no blocking findings; environment shows the secrets as *set*; SSH material shows the key and a *pinned* host key for every server; scheduler shows the next run.
- **Fleet**: the same servers, the same **Issued** and **Served** serials as before, **Activation: live**. The health roll-up may show *warning* reasons that are new in this release (a staging certificate on a server set to production, or `verify_ssl` off); those describe the state you already had, not a change.
- **Server → Test SSH**: authentication and the sudo probe pass. This restarts nothing.

### 3.5 End-to-end check (optional, needs a window)

**Force deploy** on one server re-pushes the certificate already on disk and restarts the Orchestrator web service. It never contacts the CA, so it costs no issuance and proves the whole deploy/activate path on the new code. Expect **Activation: live** and the same serial after it completes.

### 3.6 Rolling back

The upgrade is a code change plus a container recreate; data on disk is forward-compatible, so a rollback is:

```bash
git checkout <previous commit or tag>
tar -xzf ../oacm-backup-<stamp>.tgz          # only if you need the old .env/config back
docker compose down && docker compose up -d   # the previous checkout pins its own image tag
```

Certificates, the renewal history and the admin account are unchanged by either direction. If you roll back to 1.0.x, `config/servers.json` on the host is still read because `.env` now sets `SERVERS_FILE=/config/servers.json`.

---

## 4. Enable the bundled lab CA on an existing deployment

Read the README section *Bundled lab CA* first for what it is and what keeps it lab-safe. This section is only the order of operations on a host that already runs the cert manager.

### 4.1 Decide the issuing domain first

The lab CA is name-constrained: it can only issue for names under `LAB_CA_DOMAIN`, and its own name must be under it too. **The certificate domain of every server you want on the lab CA must therefore be under that domain.** If the Orchestrator's name is `orch.lab.example.net`, `--lab-domain lab.example.net` works. If the Orchestrator's name is in a different zone, either choose that zone as the lab domain (the CA host becomes `ca.<that zone>`) or give the Orchestrator a second name under the lab domain and change the server's **Certificate domain** and **Orchestrator host** in Settings. Changing the domain later means a CA rebuild and re-distributing the root, so settle this before initialising.

### 4.2 Prerequisites, checked before anything is created

```bash
./upgrade-check.sh --with-ca --lab-domain <zone> [--ca-host ca.<zone>] [--ca-port 9000]
```

It verifies:

- a DNS-only A record for the CA host that resolves to an address of this host (create it in Cloudflare now; ACME clients, the CRL URL and the root download all use that name);
- the port is free (9000 by default; it is pinned at init);
- the Cloudflare token is available (the lab CA validates DNS-01 through Cloudflare exactly like Let's Encrypt);
- `data/pki` either does not exist or is owned by you;
- the Docker daemon is reachable and the pinned `step-ca` image can be pulled.

### 4.3 Initialise (safe while the old stack is running)

```bash
./setup.sh --with-ca --lab-domain <zone>
```

This writes only to `data/pki` (online state), `data/pki-root` (offline root) and `.env` (`COMPOSE_PROFILES=lab-ca`, `LAB_CA_*`). The running cert manager is not affected until it is recreated. It prints the root fingerprint; keep it.

Then, before any client trusts the root:

```bash
mv data/pki-root <offline storage>     # the running CA never needs it
```

### 4.4 Bring the CA up and recreate the cert manager

```bash
docker compose up -d                   # starts lab-ca; recreates the cert manager because .env changed
docker compose ps                      # lab-ca healthy, cert manager healthy
docker compose exec -T orchestrator-acme-cert-manager python -m app.cli ca-info
```

The cert manager restart is a web UI and scheduler restart only; no appliance is touched. On the **System** page the lab CA section must show *healthy* (the container reached the CA by its constrained name with the lab root as trust) and the fingerprint from step 4.3. **Download root** on that page is the same file as `https://<ca-host>:<port>/roots.pem`.

### 4.5 Distribute the root

Install the root on every client that must trust lab-CA hosts (admin workstations, ClearPass if it calls the Orchestrator, monitoring). Per-platform steps are in the README under *Distribute the root*. Confirm the fingerprint out of band on each client. Until a client has the root, a lab-CA certificate on the Orchestrator is a browser warning for that client, which is the only visible change the next step makes.

### 4.6 Move one server to the lab CA (needs a window)

**Settings → Edit → CA → Lab CA (bundled step-ca) → Save**, then **Force renew**. The run issues from the lab CA, deploys and restarts the Orchestrator web service. Expect **Activation: live**, the `lab` badge on the Issued and Served certificates, and a clean padlock on a client that has the root. API TLS verification keeps working throughout: without a CA bundle the trust is the system roots plus the lab root, so a verified deploy against the old Let's Encrypt certificate and a rollback to it both verify.

### 4.7 Backing out

Set the CA back to **Let's Encrypt (production)** and **Force renew**. This spends a public issuance; Let's Encrypt allows five identical certificates per week, so do not flip back and forth to test. Nothing else needs undoing: the lab CA can stay up unused, or `COMPOSE_PROFILES` can be removed from `.env` and the stack recreated to stop it.

---

## 5. Version-specific notes

### From 1.0.x

- **Server list location.** Step 2.3 is mandatory. After the upgrade, merge `config/servers.from-container.json` into `config/servers.json` by hand (both may hold different secrets), `chmod 600`, delete the export, and confirm with `python -m app.cli check` that no `legacy-*` finding remains. The renewal history is copied forward automatically on first start.
- **SSH settings are validated now.** 1.0 accepted an empty `ssh.user`, a missing key or a missing `known_hosts` entry and failed at activation time. The new preflight and the Settings form reject them. `./setup.sh --host …` pins the host key and installs the key; review `restart_command` while you are there: the current default is `sudo /bin/systemctl restart --no-block gms.service` plus `sudo /bin/systemctl reload nginx`, and the sudoers rule must match the commands word for word. A `service gms restart` wrapper without `sudo` or `--no-block` is a known source of confusing failures.
- **`.env`.** `SERVERS_FILE=/config/servers.json` is added by `setup.sh`. New optional keys (`STRICT_STARTUP`, `RENEW_WINDOW_DAYS`, `DEPLOY_*`, `LAB_CA_*`) all have defaults; the System page lists them with their current state.
- **Image tag.** The Compose file pins a version tag instead of `:latest`. The old image can be removed with `docker image prune` after the new container is healthy.
- **UI.** The admin account and session secret are unchanged. Force renew now asks for confirmation because it spends an issuance.

### From 1.1.x

- No data changes. `data/pki/certs` is created by `setup.sh` so that it is owned by you; if Docker already created it (a 1.1 `docker compose up` does), `upgrade-check.sh` reports it and the `chown` to run before any lab CA work.
- New: the **System** page, `/api/status` with the full snapshot, `/ca/root.pem`, `upgrade-check.sh`, this document.

### From 1.2.x (to 1.3)

- **The container no longer runs as root.** It runs as `OACM_UID:OACM_GID` from `.env` (image default `10001:10001`). Step 3.2 (`./setup.sh …`) writes your own uid/gid there, so `config/` and `data/` stay writable without a `chown`. If you skip `setup.sh`, add the two keys by hand; otherwise the container starts, preflight reports `perm-config-dir` with the exact `chown`, and the web UI cannot save. `upgrade-check.sh` blocks until the keys exist. A `docker compose down && up -d` is required (the `user:` line is a container property).
- **Configuration shape.** `config/servers.json` is read as before and rewritten as `{"version": 2, "certificates": [...]}` the first time anything is saved from the UI or the CLI. Each old entry becomes one certificate with one Orchestrator *target* carrying the same id, so `/server/<id>`, history and the CLI arguments are unchanged. The System page shows `config-v1` until then. A 1.2 checkout still reads a v1 file, so a rollback before the first save needs nothing; after it, restore `config/servers.json.v1` (written once, when the v1 file is first rewritten; `servers.json.bak` is only the previous save and becomes a v2 file on the second save) or the backup from step 2.2.
- **Renewal window.** Scheduled runs now renew when a third of the certificate's own lifetime remains instead of at a fixed 30 days. For 90-day certificates that is the same day; for shorter certificates it is proportionally earlier. Set `RENEW_WINDOW_DAYS` in `.env` to keep an absolute window.
- **Rollback policy.** A failed production activation no longer restores a staging or lab certificate silently: the run fails with the reason and the appliance keeps what it serves. Tick *Allow rollback across CA environments* on a target to get the old behaviour; the message then says a cross-environment rollback happened.
- **Locks.** A scheduled run and a Force renew/deploy cannot overlap on one certificate. If the upgrade is done while a run is in flight, wait for it: the lock lives in `config/locks/` and is released with the process.
- **CSRF.** Every button in the UI carries a token tied to a `csrf` cookie. Scripts that POSTed to `/renew/<id>` or `/deploy/<id>` with only the session cookie get 403; use the CLI inside the container instead (`python -m app.cli renew <id> --force`, `redeploy <id>`).
- **Health check.** `/healthz` reports 503 when no scheduled pass finished within twice the cron interval (24 h with the shipped crontab). On the first start after the upgrade it stays healthy until two intervals have passed. The entrypoint now exits when either the web UI or supercronic dies, so `docker compose ps` shows a restart instead of a half-dead container.
- **Published image.** The compose service now references `ghcr.io/robertsonc/orchestrator-acme-cert-manager:<version>`; `docker compose up -d` pulls it and only builds when that tag is not published (`up -d --build` always builds from the checkout). The image you built as `orchestrator-acme-cert-manager:1.2.0` is no longer referenced: `docker image rm orchestrator-acme-cert-manager:1.2.0` once 1.3 runs.
- **Secret variable names.** The Settings form now requires `api_key_env`, `client_secret_env` and similar fields to name a variable that ends in `_API_KEY`, `_KEY`, `_TOKEN`, `_SECRET` or `_PASSWORD`, optionally followed by a suffix (`ORCH_API_KEY_LAB` is fine, `ORCHKEY` is not). Existing entries keep working until edited.
- **SSH to old servers.** The SSH library (paramiko 5) no longer negotiates SHA-1 algorithms. Orchestrator (OpenSSH 7.4 and newer) and any host that offers `rsa-sha2-*`, ECDSA or Ed25519 host keys and a SHA-2 key exchange are unaffected; a server that offers only `ssh-rsa` (SHA-1) host-key signatures, `diffie-hellman-*-sha1` or DSS keys fails Test SSH with a message that says so. Fix it on the server; this tool does not re-enable SHA-1.
- **New in the UI and CLI.** Deploy targets with drivers (Orchestrator, generic SSH/SCP, ClearPass, EdgeConnect-via-Orchestrator), `python -m app.cli probe <target>`, `backup` / `restore`, actor/source on every run. Nothing needs configuring for an existing Orchestrator entry.

---

## 6. Post-upgrade checklist

- [ ] `./upgrade-check.sh` exits 0 on the host.
- [ ] `python -m app.cli check` inside the container reports no blocking findings; the System page agrees.
- [ ] Every server shows the same Served serial as before the upgrade.
- [ ] Test SSH passes for every server.
- [ ] A Force deploy on one server completed with **Activation: live** (if a window was available).
- [ ] The backup from step 2.2 is somewhere other than this host.
- [ ] Lab CA, if enabled: `data/pki-root` is off the host, the root is installed on the clients that need it, and the System page shows the CA as healthy.

---

## 7. Backup and restore (1.3+)

```bash
./setup.sh --backup ../oacm-$(date +%Y%m%d).tgz                 # .env, config/, data/ (logs excluded; offline root excluded)
./setup.sh --backup ../oacm-full.tgz --include-root             # also data/pki-root (keep this one offline)
```

On the new host: clone the repository, `./setup.sh --restore ../oacm-….tgz` (stops if the container is running or the current `config/servers.json` is newer, unless `--force-restore`), then `./setup.sh --host …` to re-check the host key and sudo rule, then `docker compose up -d`. Inside the container, `python -m app.cli backup /config/backup.tgz` and `python -m app.cli restore /config/backup.tgz` do the same for what the container can see (config, certificates, SSH material; the lab CA online state is only visible from the host), optionally encrypted with `--encrypt` and `BACKUP_PASSPHRASE`.

---
