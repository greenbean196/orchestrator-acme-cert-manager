#!/bin/sh
# Container entrypoint: preflight, then the web UI and the scheduler side by
# side. Both are children of this shell; if either dies the other is stopped
# and the shell exits non-zero, so `restart: unless-stopped` recovers the
# container instead of leaving it half alive (issue #11).
set -e
mkdir -p /data/logs /data/certs 2>/dev/null || true

echo "[entrypoint] orchestrator-acme-cert-manager starting (uid $(id -u):$(id -g))"
echo "[entrypoint] lego: $(lego --version 2>&1 | head -1)"
echo "[entrypoint] SERVERS_FILE=${SERVERS_FILE:-<unset>}  CONFIG_DIR=${CONFIG_DIR:-<unset>}  DATA_DIR=${DATA_DIR:-<unset>}"

# Preflight: refuses to start on a configuration that would silently lose
# changes (unmounted config path, legacy /data/servers.json only) or that the
# service user cannot write. Set STRICT_STARTUP=false to downgrade fatal
# findings to warnings.
if ! python -m app.cli check; then
  echo "[entrypoint] preflight FAILED — fix the items above (or set STRICT_STARTUP=false to override)" >&2
  exit 1
fi
python -m app.cli list || true

# Optional one-shot forced renewal on boot (testing). Only this run is forced:
# the scheduled runs never read FORCE_RENEW.
if [ "${FORCE_RENEW}" = "true" ]; then
  echo "[entrypoint] FORCE_RENEW=true — running renew-all --force once"
  python -m app.cli renew-all --force --source cron || true
fi
unset FORCE_RENEW

python -m app.webui.server &
web=$!
echo "[entrypoint] web UI started (pid $web)"

supercronic /app/crontab &
cron=$!
echo "[entrypoint] supercronic started (pid $cron)"

stop_all() {
  trap - TERM INT
  # supercronic first: it waits for a running renew-all job (compose stop_grace_period covers it).
  kill "$cron" 2>/dev/null || true
  wait "$cron" 2>/dev/null || true
  kill "$web" 2>/dev/null || true
  wait "$web" 2>/dev/null || true
}
trap 'stop_all; exit 0' TERM INT

# Supervise: a plain poll loop, because /bin/sh (dash) has no `wait -n`.
while kill -0 "$web" 2>/dev/null && kill -0 "$cron" 2>/dev/null; do
  sleep 5 &
  wait $!
done
if ! kill -0 "$web" 2>/dev/null; then echo "[entrypoint] web UI exited — stopping the scheduler and restarting the container" >&2; fi
if ! kill -0 "$cron" 2>/dev/null; then echo "[entrypoint] supercronic exited — stopping the web UI and restarting the container" >&2; fi
stop_all
exit 1
