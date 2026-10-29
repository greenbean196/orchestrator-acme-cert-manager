#!/usr/bin/env bash
# =============================================================================
# upgrade-check.sh — READ-ONLY readiness report before upgrading a deployment
#
# Run it on the Docker host from the repository checkout, before and after
# `git pull`, and again before enabling the bundled lab CA. It changes nothing:
# no files are written, no containers are started or stopped, nothing is
# fetched unless you pass --fetch. It reports what is missing, stale or unsafe,
# and prints a numbered fix list. Secrets are reported as present/absent only.
#
#   ./upgrade-check.sh                 # host tools, checkout, layout, .env, compose, SSH, running container
#   ./upgrade-check.sh --with-ca       # also the lab CA prerequisites (DNS, port, PKI state)
#   ./upgrade-check.sh --fetch         # also compare the checkout with origin (network)
#
# Exit status: 0 nothing blocks the upgrade (warnings may remain), 1 at least one
# blocking item, 2 usage error. Companion document: UPGRADING.md.
# =============================================================================
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here" || exit 2

with_ca=0; do_fetch=0; skip_docker=0; plain=0
LAB_CA_DOMAIN="${LAB_CA_DOMAIN:-}"; LAB_CA_HOST="${LAB_CA_HOST:-}"; LAB_CA_PORT="${LAB_CA_PORT:-}"
LAB_CA_IMAGE="${LAB_CA_IMAGE:-smallstep/step-ca:0.30.2}"
CONTAINER="orchestrator-acme-cert-manager"
CA_CONTAINER="lab-ca"

usage() {
  cat <<EOF
Usage: ./upgrade-check.sh [--with-ca] [--lab-domain D] [--ca-host H] [--ca-port P] [--fetch] [--no-docker] [--plain]

  --with-ca        Include the bundled lab CA readiness checks (automatic when .env or data/pki already
                   reference a lab CA). --lab-domain / --ca-host / --ca-port describe the identity you
                   intend to initialise so DNS and port checks can run before setup.sh --with-ca.
  --fetch          Run 'git fetch' and report how far behind origin the checkout is (network access).
  --no-docker      Skip everything that needs the Docker daemon.
  --plain          No colour.

Read-only. Exit 0 = ready (warnings possible), 1 = blocking items, 2 = usage error.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-ca) with_ca=1 ;;
    --lab-domain) LAB_CA_DOMAIN="$2"; with_ca=1; shift ;;
    --ca-host) LAB_CA_HOST="$2"; with_ca=1; shift ;;
    --ca-port) LAB_CA_PORT="$2"; with_ca=1; shift ;;
    --fetch) do_fetch=1 ;;
    --no-docker) skip_docker=1 ;;
    --plain) plain=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if [[ $plain -eq 0 && -t 1 ]]; then
  c_ok=$'\e[32m'; c_warn=$'\e[33m'; c_err=$'\e[31m'; c_bold=$'\e[1m'; c_dim=$'\e[2m'; c_off=$'\e[0m'
else
  c_ok=""; c_warn=""; c_err=""; c_bold=""; c_dim=""; c_off=""
fi

n_ok=0; n_warn=0; n_fail=0
fixes=()
section() { printf '\n%s== %s%s\n' "$c_bold" "$*" "$c_off"; }
pass()  { n_ok=$((n_ok + 1));   printf '%s  ✓ %s%s\n' "$c_ok" "$*" "$c_off"; }
note()  {                       printf '%s  · %s%s\n' "$c_dim" "$*" "$c_off"; }
# warn "message" "fix"   — not blocking
warn()  { n_warn=$((n_warn + 1)); printf '%s  ! %s%s\n' "$c_warn" "$1" "$c_off"; [[ -n "${2:-}" ]] && fixes+=("WARN  $2"); }
# fail "message" "fix"   — blocking
fail()  { n_fail=$((n_fail + 1)); printf '%s  ✗ %s%s\n' "$c_err" "$1" "$c_off"; [[ -n "${2:-}" ]] && fixes+=("FIX   $2"); }
have()  { command -v "$1" >/dev/null 2>&1; }

# ---- helpers -----------------------------------------------------------------
env_get() {  # env_get KEY FILE -> value ('' when absent); never echo secrets elsewhere
  grep -E "^${1}=" "$2" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '\r'
}
env_has() { grep -qE "^${1}=" "$2" 2>/dev/null; }
mode_of() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null; }
owner_of() { stat -c '%u' "$1" 2>/dev/null || stat -f '%u' "$1" 2>/dev/null; }
placeholder() { case "$1" in ""|your-*|changeme|CHANGEME|xxx*|\<*\>) return 0 ;; *) return 1 ;; esac; }

dcmd=""
docker_daemon() {  # sets dcmd to "docker" or "sudo docker"; returns 1 when unreachable
  [[ -n "$dcmd" ]] && return 0
  if docker info >/dev/null 2>&1; then dcmd="docker"; return 0; fi
  if [[ $EUID -ne 0 ]] && sudo -n docker info >/dev/null 2>&1; then dcmd="sudo docker"; return 0; fi
  return 1
}

# servers.json fields as TSV via python3 (id, host, port, key_path, known_hosts, has_api_key, has_cf_token, ca)
servers_tsv() {
  local f="$1"
  have python3 || return 1
  python3 -I - "$f" <<'PY'
import json, sys
try:
    raw = json.load(open(sys.argv[1]))
except Exception as exc:  # noqa: BLE001
    print(f"__ERROR__\t{exc}")
    sys.exit(0)
def row(sid, host, ssh, has_api, dns, acme):
    print("\x1f".join([
        str(sid), str(host), str(ssh.get("port") or 22),
        str(ssh.get("key_path") or ""), str(ssh.get("known_hosts") or "/data/ssh/known_hosts"),
        "1" if has_api else "0", "1" if (dns.get("api_token") or dns.get("env")) else "0",
        str(acme.get("ca", "letsencrypt")),
    ]))

if isinstance(raw, dict) and "certificates" in raw:          # 1.3+ shape: certificates with targets
    for c in raw.get("certificates") or []:
        acme, dns = c.get("acme") or {}, c.get("dns") or {}
        for t in c.get("targets") or []:
            s = t.get("settings") or {}
            if t.get("driver") == "orchestrator":
                row(t.get("id", "?"), s.get("orchestrator_host", ""), s.get("ssh") or {}, s.get("api_key"), dns, acme)
            elif t.get("driver") == "ssh":
                row(t.get("id", "?"), s.get("host", ""),
                    {"port": s.get("ssh_port"), "key_path": s.get("ssh_key_path"), "known_hosts": s.get("ssh_known_hosts")},
                    True, dns, acme)
else:                                                          # pre-1.3 shape: servers list
    entries = raw.get("servers", []) if isinstance(raw, dict) else raw
    for s in entries:
        row(s.get("id", "?"), s.get("orchestrator_host", ""), s.get("ssh") or {}, s.get("api_key"),
            s.get("dns") or {}, s.get("acme") or {})
PY
}

host_path() {  # container path under /data or /config -> host path
  case "$1" in
    /data/*) echo "${here}/data/${1#/data/}" ;;
    /config/*) echo "${here}/config/${1#/config/}" ;;
    *) echo "$1" ;;
  esac
}

# ============================================================================
section "Host tools"
if ((BASH_VERSINFO[0] < 4)); then fail "bash ${BASH_VERSION} — setup.sh needs bash 4+" "install bash 4 or newer"; else pass "bash ${BASH_VERSION}"; fi
for t in git ssh-keygen; do
  if have "$t"; then pass "$t present"; else fail "$t missing" "install $t (git, openssh-client)"; fi
done
for t in python3 openssl curl; do
  if have "$t"; then pass "$t present"; else warn "$t missing — some checks degrade to guesses" "install $t"; fi
done
if have ss || have netstat; then pass "port inspection available (ss/netstat)"; else note "neither ss nor netstat: port checks skipped"; fi

if [[ $skip_docker -eq 1 ]]; then
  note "--no-docker: skipping Docker checks"
elif ! have docker; then
  fail "docker not installed" "./setup.sh installs Docker Engine + Compose plugin (apt/dnf from Docker's repository)"
elif ! docker compose version >/dev/null 2>&1; then
  fail "docker present but 'docker compose' (plugin) missing" "./setup.sh installs the Compose plugin; docker-compose v1 is not supported"
else
  pass "docker $(docker --version 2>/dev/null | sed 's/^Docker version //; s/,.*//') + compose $(docker compose version --short 2>/dev/null)"
  if docker_daemon; then
    if [[ "$dcmd" == "sudo docker" ]]; then
      warn "daemon reachable only via sudo — your user is not in the docker group (or needs a new login)" "sudo usermod -aG docker \$USER && newgrp docker   (or log out and back in)"
    else pass "docker daemon reachable"; fi
  else
    fail "docker daemon not reachable" "sudo systemctl enable --now docker; add your user to the docker group (./setup.sh does both)"
  fi
fi

# ============================================================================
section "Checkout"
version="$(grep -E '^__version__' app/__init__.py 2>/dev/null | sed 's/.*"\(.*\)".*/\1/')"
[[ -n "$version" ]] && note "checked-out application version: ${version}"
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  head_sha="$(git rev-parse --short HEAD)"; branch="$(git rev-parse --abbrev-ref HEAD)"
  pass "git checkout at ${head_sha} (${branch})"
  modified="$(git status --porcelain --untracked-files=no 2>/dev/null)"
  if [[ -n "$modified" ]]; then
    warn "tracked files modified locally — 'git pull' may conflict:" "review 'git diff', keep local changes in docker-compose.override.yml or .env instead, then 'git stash' / commit before pulling"
    printf '%s\n' "$modified" | sed 's/^/      /'
  else pass "no local modifications to tracked files"; fi
  if [[ $do_fetch -eq 1 ]]; then
    if git fetch -q origin 2>/dev/null; then
      upstream="origin/$(git rev-parse --abbrev-ref HEAD 2>/dev/null)"
      git rev-parse --verify -q "$upstream" >/dev/null 2>&1 || upstream="origin/main"
      behind="$(git rev-list --count "HEAD..${upstream}" 2>/dev/null || echo "?")"
      if [[ "$behind" == "0" ]]; then pass "up to date with ${upstream}"; else note "${behind} commit(s) behind ${upstream}; UPGRADING.md lists what changes between versions"; fi
    else warn "git fetch failed (network or credentials)" "check connectivity to the git remote"; fi
  fi
else
  warn "not a git checkout — upgrades are file copies; UPGRADING.md assumes git" "clone the repository and move .env, config/ and data/ into the clone"
fi

# ============================================================================
section "Layout and permissions"
me="$(id -u)"
for d in config data/certs data/logs data/ssh; do
  if [[ -d "$d" ]]; then
    own="$(owner_of "$d")"
    if [[ -w "$d" ]]; then pass "$d exists, writable"
    elif [[ "$own" != "$me" && "$own" == "0" ]]; then
      fail "$d is owned by root and not writable by you — Docker created it; setup.sh and the init container will fail" "sudo chown -R $(id -u):$(id -g) $d"
    else fail "$d not writable by uid $me" "chmod u+w $d (and check ownership)"; fi
  else
    warn "$d missing" "./setup.sh creates it (idempotent)"
  fi
done
if [[ -f config/servers.json ]]; then
  m="$(mode_of config/servers.json)"
  if [[ "$m" == "600" ]]; then pass "config/servers.json present (mode 600)"
  else warn "config/servers.json mode ${m} — it holds inline secrets" "chmod 600 config/servers.json"; fi
else
  warn "config/servers.json absent on the host" "if the old container still runs, copy it out first (see 'Running container' below); otherwise ./setup.sh --host ... writes a new one"
fi
[[ -f config/admin.json ]] && pass "web UI admin account exists (config/admin.json)" || note "no admin account yet; the UI will show the Setup page on first visit"
[[ -f config/history.json ]] && note "renewal history present (config/history.json)"
if [[ -d data/pki ]]; then
  own="$(owner_of data/pki)"
  if [[ "$own" == "0" && "$me" != "0" ]]; then
    fail "data/pki is owned by root (Docker created it for the read-only mount) — the lab CA init runs as your uid and cannot write there" "sudo chown -R $(id -u):$(id -g) data/pki"
  else pass "data/pki owned by uid ${own}"; fi
fi

# ============================================================================
section ".env"
envf=".env"
if [[ ! -f "$envf" ]]; then
  fail ".env missing" "./setup.sh creates it from .env.example; then add CF_DNS_API_TOKEN and ORCH_API_KEY (or set them per server in the UI)"
else
  m="$(mode_of "$envf")"
  [[ "$m" == "600" ]] && pass ".env present (mode 600)" || warn ".env mode ${m} — it holds secrets" "chmod 600 .env"
  if grep -q $'\r' "$envf"; then fail ".env contains CRLF line endings (values would carry a trailing CR)" "sed -i 's/\\r\$//' .env"; else pass "no CRLF in .env"; fi
  if sed 's/\$\$//g' "$envf" | grep -qE "^[A-Z_][A-Z0-9_]*=[^'#]*[$]"; then
    warn "a value in .env contains an unquoted \$ — Compose v2 interpolates it as a variable reference" "single-quote the value (KEY='pa\$sword') or write \$\$ for a literal \$"
  else pass "no unquoted \$ in .env values"; fi
  sf="$(env_get SERVERS_FILE "$envf")"
  if [[ -z "$sf" ]]; then
    note "SERVERS_FILE not in .env — docker-compose.yml sets /config/servers.json explicitly since 1.1.0 (fine)"
  elif [[ "$sf" != "/config/servers.json" ]]; then
    fail "SERVERS_FILE=${sf} — only /config is persistently mounted; UI changes would be lost" "set SERVERS_FILE=/config/servers.json in .env"
  else pass "SERVERS_FILE=/config/servers.json"; fi
  # keys introduced after 1.0.0 (optional, defaults apply); listed so operators know they exist
  if env_has STRICT_STARTUP "$envf"; then note "STRICT_STARTUP=$(env_get STRICT_STARTUP "$envf")"
  else note "STRICT_STARTUP not set (default true): preflight refuses an unmounted or legacy-only config"; fi
  # secrets: present somewhere? (env or inline per server)
  cf="$(env_get CF_DNS_API_TOKEN "$envf")"; ok_key="$(env_get ORCH_API_KEY "$envf")"
  inline_cf=0; inline_api=0; servers_rows=""
  if [[ -f config/servers.json ]] && servers_rows="$(servers_tsv config/servers.json)"; then
    if [[ "$servers_rows" == __ERROR__* ]]; then
      fail "config/servers.json is not valid JSON: ${servers_rows#*	}" "fix the JSON (compare with config/servers.example.json)"
      servers_rows=""
    else
      while IFS=$'\x1f' read -r _ _ _ _ _ hasapi hascf _; do
        [[ "$hasapi" == "1" ]] && inline_api=1; [[ "$hascf" == "1" ]] && inline_cf=1
      done <<< "$servers_rows"
    fi
  fi
  if placeholder "$cf" && [[ $inline_cf -eq 0 ]]; then
    fail "no Cloudflare DNS token: CF_DNS_API_TOKEN is unset/placeholder and no server has an inline token" "set CF_DNS_API_TOKEN in .env, or enter it per server in Settings (the lab CA needs it too: DNS-01)"
  else pass "Cloudflare DNS token available ($( [[ $inline_cf -eq 1 ]] && echo inline || echo .env ))"; fi
  if placeholder "$ok_key" && [[ $inline_api -eq 0 ]]; then
    fail "no Orchestrator API key: ORCH_API_KEY is unset/placeholder and no server has an inline key" "set ORCH_API_KEY in .env, or enter it per server in Settings"
  else pass "Orchestrator API key available ($( [[ $inline_api -eq 1 ]] && echo inline || echo .env ))"; fi
  ouid="$(env_get OACM_UID "$envf")"; ogid="$(env_get OACM_GID "$envf")"
  if [[ -n "$ouid" ]]; then
    # Files written by a pre-1.3 (root) container keep root ownership on the host; the unprivileged
    # container cannot rewrite them.
    foreign=""
    for d in config data/certs data/logs data/ssh; do
      [[ -d "$d" ]] || continue
      f="$(find "$d" -not -user "$ouid" -print -quit 2>/dev/null || true)"
      [[ -n "$f" ]] && foreign="${foreign} ${f}"
    done
    if [[ -n "$foreign" ]]; then
      fail "files not owned by uid ${ouid} under config/ data/certs data/logs data/ssh (first:${foreign}) — written by the pre-1.3 root container; the unprivileged container cannot update them" "sudo chown -R ${ouid}:${ogid:-$ouid} config data/certs data/logs && sudo chown ${ouid}:${ogid:-$ouid} data/ssh data/ssh/*"
    else pass "config/ and data/ files are owned by uid ${ouid}"; fi
  fi
  if [[ -z "$ouid" || -z "$ogid" ]]; then
    fail "OACM_UID/OACM_GID not set in .env — since 1.3 the container runs unprivileged (uid 10001 by default) and cannot write config/ or data/ owned by you" "./setup.sh writes OACM_UID=$(id -u) OACM_GID=$(id -g) to .env (or add them by hand), then docker compose down && docker compose up -d"
  elif [[ "$ouid" != "$(id -u)" ]]; then
    warn "OACM_UID=${ouid} in .env differs from your uid $(id -u): config/ and data/ must be owned by uid ${ouid}" "set OACM_UID/OACM_GID to your ids (./setup.sh) or chown config data/certs data/logs to ${ouid}:${ogid}"
  else pass "OACM_UID/OACM_GID=${ouid}/${ogid} match your ids (the container can write config/ and data/)"; fi
  profiles="$(env_get COMPOSE_PROFILES "$envf")"
  lab_host_env="$(env_get LAB_CA_HOST "$envf")"
  if [[ "$profiles" == *lab-ca* ]]; then with_ca=1; pass "COMPOSE_PROFILES=${profiles} (lab CA service enabled)"; fi
  if [[ -n "$lab_host_env" && "$profiles" != *lab-ca* ]]; then
    with_ca=1; warn "LAB_CA_HOST is set but COMPOSE_PROFILES does not include lab-ca — the cert manager would require the lab root while the CA service never starts" "./setup.sh --with-ca re-writes both; or add COMPOSE_PROFILES=lab-ca"
  fi
fi
[[ -f data/pki/config/lab-ca.meta ]] && with_ca=1

# ============================================================================
section "Compose"
if [[ -f docker-compose.override.yml ]]; then
  note "docker-compose.override.yml present — it is kept across upgrades; checking it for known traps"
  if grep -qE ':/data/servers\.json' docker-compose.override.yml; then
    fail "override mounts a single servers.json file into /data — the app cannot write a single-file bind mount and /data/servers.json is the legacy path" "mount the directory instead: ./config:/config (remove the /data/servers.json line)"
  fi
  if grep -qE '/config:ro|/config:/config:ro' docker-compose.override.yml; then
    fail "override mounts /config read-only — the web UI cannot save" "drop :ro on the /config mount"
  fi
  grep -qE 'privileged:\s*true' docker-compose.override.yml && warn "override sets privileged: true" "remove privileged: true; nothing here needs it"
  grep -qE 'image:.*:latest' docker-compose.override.yml && warn "override pins an image to :latest" "use the version tag from docker-compose.yml"
fi
if [[ $skip_docker -eq 0 ]] && have docker && docker compose version >/dev/null 2>&1 && [[ -f .env ]]; then
  if rendered="$(docker compose config 2>&1)"; then
    pass "docker compose config renders"
    grep -qE 'target: /config$' <<< "$rendered" && pass "/config directory mount present" || fail "/config is not mounted — UI changes would be lost" "restore the ./config:/config volume (docker-compose.yml from the repo has it)"
    grep -qE 'target: /data/pki/certs$' <<< "$rendered" && pass "/data/pki/certs mount present (lab root readable by the cert manager)" || note "/data/pki/certs mount absent — the lab CA root would be invisible to the cert manager (pull docker-compose.yml)"
  else
    fail "docker compose config failed:" "fix the Compose/.env error shown above"
    printf '%s\n' "$rendered" | tail -5 | sed 's/^/      /'
  fi
fi

# ============================================================================
section "Running container"
if [[ $skip_docker -eq 1 ]] || ! docker_daemon; then
  note "Docker daemon not available: cannot inspect the running container"
else
  cstate="$($dcmd ps -a --filter "name=^${CONTAINER}$" --format '{{.Image}}|{{.Status}}' 2>/dev/null | head -1)"
  if [[ -z "$cstate" ]]; then
    note "no container named ${CONTAINER} (fresh install, or it was removed)"
  else
    img="${cstate%%|*}"; st="${cstate#*|}"
    note "container ${CONTAINER}: image ${img}, ${st}"
    [[ "$img" == *:latest ]] && note "image tagged :latest = a 1.0.x build; the current Compose file pins a version tag"
    if [[ "$st" == Up* ]]; then
      legacy="$($dcmd exec "$CONTAINER" sh -c 'test -f /data/servers.json && echo yes || echo no' 2>/dev/null)"
      if [[ "$legacy" == "yes" ]]; then
        if [[ -f config/servers.json ]] && $dcmd exec "$CONTAINER" sh -c 'cat /data/servers.json' 2>/dev/null | cmp -s - config/servers.json; then
          pass "container has a legacy /data/servers.json identical to config/servers.json (safe; preflight will say it can be deleted)"
        else
          fail "the running container holds /data/servers.json (legacy path) that differs from, or does not exist as, config/servers.json — it is NOT on a bind mount and is lost when the container is recreated; copy it out first" "docker compose exec -T ${CONTAINER} sh -c 'cat /data/servers.json' > config/servers.from-container.json; diff/merge into config/servers.json; chmod 600 (UPGRADING.md step 2)"
        fi
      else pass "no legacy /data/servers.json in the running container"; fi
      lh="$($dcmd exec "$CONTAINER" sh -c 'test -f /data/history.json && echo yes || echo no' 2>/dev/null)"
      [[ "$lh" == "yes" && ! -f config/history.json ]] && note "container has /data/history.json; the new preflight copies it to /config/history.json automatically — export it now if you want to keep it in case the migration fails: docker compose exec -T ${CONTAINER} sh -c 'cat /data/history.json' > config/history.json"
      csf="$($dcmd inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$CONTAINER" 2>/dev/null | grep -E '^SERVERS_FILE=' | cut -d= -f2-)"
      [[ -n "$csf" ]] && note "container SERVERS_FILE=${csf}"
    else
      note "container not running — if it was recreated after a 1.0.x run, a legacy /data/servers.json cannot be recovered from it"
    fi
  fi
fi

# ============================================================================
section "SSH material"
default_key="data/ssh/orch_restart"; default_kh="data/ssh/known_hosts"
check_key() {  # check_key <host path> <label>
  local k="$1" label="$2"
  if [[ ! -f "$k" ]]; then fail "${label}: private key not found at ${k}" "./setup.sh generates data/ssh/orch_restart; or point ssh.key_path at the right file (path inside the container)"; return; fi
  local m; m="$(mode_of "$k")"
  [[ "$m" == "600" || "$m" == "400" ]] || warn "${label}: key ${k} mode ${m}" "chmod 600 ${k}"
  if have ssh-keygen; then
    if ssh-keygen -y -P "" -f "$k" >/dev/null 2>&1; then pass "${label}: key ${k} parses, no passphrase"
    else fail "${label}: key ${k} is passphrase-protected or not a private key" "generate an unencrypted key (./setup.sh) — the unattended service cannot prompt"; fi
  fi
  [[ -f "${k}.pub" ]] || note "${label}: ${k}.pub missing (setup.sh regenerates it from the private key)"
}
check_kh() {  # check_kh <host path> <host> <port> <label>
  local kh="$1" host="$2" port="$3" label="$4" name
  if [[ ! -f "$kh" ]]; then fail "${label}: known_hosts not found at ${kh}" "./setup.sh --host ${host} pins the host key after you confirm the fingerprint"; return; fi
  if [[ "$port" == "22" ]]; then name="$host"; else name="[${host}]:${port}"; fi
  if have ssh-keygen && ssh-keygen -F "$name" -f "$kh" >/dev/null 2>&1; then pass "${label}: host key pinned for ${name}"
  else fail "${label}: no known_hosts entry for ${name} in ${kh}" "./setup.sh --host ${host} --ssh-port ${port} (confirm the fingerprint), or ssh-keyscan -p ${port} ${host} >> ${kh} after verifying it"; fi
}
if [[ -n "${servers_rows:-}" ]]; then
  while IFS=$'\x1f' read -r sid shost sport skey skh _ _ sca; do
    [[ -z "$sid" ]] && continue
    kp="$(host_path "${skey:-/data/ssh/orch_restart}")"; khp="$(host_path "$skh")"
    [[ -z "$skey" ]] && warn "${sid}: ssh.key_path is empty in servers.json" "set it to /data/ssh/orch_restart in Settings"
    check_key "$kp" "$sid"
    check_kh "$khp" "$shost" "$sport" "$sid"
    [[ "$sca" == "lab" ]] && { with_ca=1; note "${sid}: uses the lab CA"; }
  done <<< "$servers_rows"
else
  note "no parsable servers.json — checking the default key only"
  [[ -f "$default_key" ]] && check_key "$default_key" "default" || warn "default key ${default_key} absent" "./setup.sh generates it"
  [[ -f "$default_kh" ]] || note "no ${default_kh} yet (setup.sh pins the host key)"
fi

# ============================================================================
if [[ $with_ca -eq 1 ]]; then
  section "Bundled lab CA"
  meta="data/pki/config/lab-ca.meta"
  if [[ -f "$meta" ]]; then
    m_host="$(env_get LAB_CA_HOST "$meta")"; m_dom="$(env_get LAB_CA_DOMAIN "$meta")"; m_port="$(env_get LAB_CA_PORT "$meta")"
    pass "initialised: ${m_host}:${m_port}, issuing scope .${m_dom}"
    [[ -n "$LAB_CA_HOST" && "$LAB_CA_HOST" != "$m_host" ]] && fail "--ca-host ${LAB_CA_HOST} differs from the initialised CA (${m_host})" "a CA cannot be renamed in place; see README 'Root rollover' / rebuild"
    [[ -n "$LAB_CA_DOMAIN" && "$LAB_CA_DOMAIN" != "$m_dom" ]] && fail "--lab-domain ${LAB_CA_DOMAIN} differs from the initialised CA (${m_dom})" "a CA cannot be renamed in place"
    [[ -n "$LAB_CA_PORT" && "$LAB_CA_PORT" != "$m_port" ]] && fail "--ca-port ${LAB_CA_PORT} differs from the initialised CA (${m_port})" "a CA cannot be renamed in place"
    LAB_CA_HOST="$m_host"; LAB_CA_DOMAIN="$m_dom"; LAB_CA_PORT="$m_port"
    if [[ -f .env ]]; then
      for k in LAB_CA_HOST LAB_CA_DOMAIN LAB_CA_PORT; do
        v="$(env_get "$k" .env)"; want="${!k}"
        if [[ -z "$v" ]]; then fail ".env lacks ${k} while the CA is initialised" "./setup.sh --with-ca re-writes the LAB_CA_* keys from the pinned identity"
        elif [[ "$v" != "$want" ]]; then fail ".env ${k}=${v} differs from the initialised CA (${want})" "./setup.sh --with-ca (it refuses drift and restores .env from the pinned identity)"; fi
      done
      [[ "$(env_get COMPOSE_PROFILES .env)" == *lab-ca* ]] || fail "COMPOSE_PROFILES does not include lab-ca" "./setup.sh --with-ca, or add COMPOSE_PROFILES=lab-ca to .env"
      uid_env="$(env_get LAB_CA_UID .env)"; own="$(owner_of data/pki)"
      [[ -n "$uid_env" && -n "$own" && "$uid_env" != "$own" ]] && fail "LAB_CA_UID=${uid_env} but data/pki is owned by uid ${own}; step-ca cannot write its database" "chown -R ${uid_env} data/pki, or set LAB_CA_UID/LAB_CA_GID to the owner"
    fi
    [[ -f data/pki/certs/root_ca.crt ]] && pass "root certificate present" || fail "data/pki/certs/root_ca.crt missing" "./setup.sh --with-ca (resumes an interrupted init)"
    if [[ -f data/pki/secrets/root_ca_key ]]; then
      fail "ROOT KEY IS IN THE ONLINE VOLUME (data/pki/secrets/root_ca_key)" "move it with its password to data/pki-root and then off the host; the running CA only needs the intermediate key"
    else pass "root key not in the online volume"; fi
    [[ -f data/pki/certs/root-key-offline ]] || warn "root-key-offline marker missing (initialised by an older script)" "./setup.sh --with-ca re-checks and writes the marker"
    if [[ -d data/pki-root ]]; then
      warn "data/pki-root (root key + password) is still on this host" "move it to offline storage before distributing the root; the CA runs without it"
    else pass "offline root directory is not on this host"; fi
    retired="$(ls data/pki/certs/retired/*.crt 2>/dev/null | wc -l)"
    [[ "$retired" -gt 0 ]] && note "root rollover in progress: ${retired} retired root(s) still trusted — Force renew every lab-CA server, then delete data/pki/certs/retired/*"
    [[ -f data/pki/config/.init-in-progress ]] && warn "a previous init was interrupted (.init-in-progress)" "./setup.sh --with-ca resumes it"
  else
    note "not initialised yet (no ${meta})"
    if [[ -z "$LAB_CA_DOMAIN" ]]; then
      warn "no --lab-domain given: cannot check the planned DNS record or identity" "./upgrade-check.sh --with-ca --lab-domain <zone> [--ca-host ca.<zone>]"
    else
      [[ -n "$LAB_CA_HOST" ]] || LAB_CA_HOST="ca.${LAB_CA_DOMAIN}"
      [[ -n "$LAB_CA_PORT" ]] || LAB_CA_PORT=9000
      [[ "$LAB_CA_HOST" == *".${LAB_CA_DOMAIN}" ]] && pass "planned identity ${LAB_CA_HOST}:${LAB_CA_PORT} under .${LAB_CA_DOMAIN}" \
        || fail "--ca-host ${LAB_CA_HOST} is not under --lab-domain ${LAB_CA_DOMAIN}" "the CA's own name must be inside the name constraint"
    fi
    [[ -f .env ]] && placeholder "$(env_get CF_DNS_API_TOKEN .env)" && [[ ${inline_cf:-0} -eq 0 ]] && note "the lab CA validates DNS-01 through Cloudflare as well: the token above is required"
    [[ -d data/pki ]] && [[ -n "$(ls -A data/pki 2>/dev/null)" ]] && warn "data/pki exists and is not empty but has no lab-ca.meta" "if this is an abandoned attempt, move data/pki aside before ./setup.sh --with-ca"
  fi
  if [[ -n "$LAB_CA_HOST" ]]; then
    # DNS: the record must exist (clients, Lego and the CRL URL use it) and should point at this host
    resolved="$(getent ahosts "$LAB_CA_HOST" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ')"
    if [[ -z "$resolved" ]]; then
      warn "${LAB_CA_HOST} does not resolve from this host" "create a DNS-only A record in Cloudflare: ${LAB_CA_HOST} -> this host's private address (ACME clients, the CRL URL and roots.pem use that name)"
    else
      local_addrs="$( (hostname -I 2>/dev/null; ip -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1) | tr ' ' '\n' | sort -u)"
      hit=0; for a in $resolved; do grep -qx "$a" <<< "$local_addrs" && hit=1; done
      if [[ $hit -eq 1 ]]; then pass "${LAB_CA_HOST} resolves to an address of this host"
      else warn "${LAB_CA_HOST} resolves to ${resolved}which is not an address of this host" "point the record at this host's private address (DNS-only), or run the CA where the record points"; fi
    fi
    # port: free, or already held by the lab-ca container
    port="${LAB_CA_PORT:-9000}"
    listener=""
    if have ss; then listener="$(ss -ltnH 2>/dev/null | awk -v p=":${port}$" '$4 ~ p {print $4}' | head -1)"
    elif have netstat; then listener="$(netstat -ltn 2>/dev/null | awk -v p=":${port}$" '$4 ~ p {print $4}' | head -1)"; fi
    if [[ -n "$listener" ]]; then
      ca_up=""
      [[ $skip_docker -eq 0 ]] && docker_daemon && ca_up="$($dcmd ps --filter "name=^${CA_CONTAINER}$" --format '{{.Status}}' 2>/dev/null)"
      if [[ "$ca_up" == Up* ]]; then pass "port ${port} is held by the running ${CA_CONTAINER} container"
      else fail "port ${port} is already in use on this host (${listener}) and ${CA_CONTAINER} is not running" "free the port, or initialise with --ca-port <free port> (the port is pinned at init)"; fi
    else pass "port ${port} is free"; fi
    if [[ $skip_docker -eq 0 ]] && docker_daemon; then
      if $dcmd image inspect "$LAB_CA_IMAGE" >/dev/null 2>&1; then pass "image ${LAB_CA_IMAGE} present"; else note "image ${LAB_CA_IMAGE} not pulled yet (setup.sh --with-ca pulls it; needs registry access)"; fi
    fi
  fi
fi

# ============================================================================
section "Summary"
printf '  %s%d ok%s, %s%d warning(s)%s, %s%d blocking%s\n' "$c_ok" "$n_ok" "$c_off" "$c_warn" "$n_warn" "$c_off" "$c_err" "$n_fail" "$c_off"
if [[ ${#fixes[@]} -gt 0 ]]; then
  echo
  echo "  Fix list (blocking items first):"
  i=0
  for f in "${fixes[@]}"; do [[ "$f" == FIX* ]] && { i=$((i + 1)); printf '   %2d. %s\n' "$i" "${f#FIX   }"; }; done
  for f in "${fixes[@]}"; do [[ "$f" == WARN* ]] && { i=$((i + 1)); printf '   %2d. (warn) %s\n' "$i" "${f#WARN  }"; }; done
fi
echo
if [[ $n_fail -eq 0 ]]; then
  echo "  Ready. Next: UPGRADING.md — 'Upgrade procedure' (and 'Enable the bundled lab CA' if that is the goal)."
  exit 0
else
  echo "  Not ready: resolve the blocking items, then run this again. Nothing was changed."
  exit 1
fi
