"""Command-line entry point: list / check / probe / issue / deploy / restart / renew / redeploy / renew-all."""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys

from . import config

EXIT_LOCKED = 3


def _setup_logging() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def _actor(args: argparse.Namespace, default: str) -> tuple[str, str]:
    source = getattr(args, "source", None) or "cli"
    actor = getattr(args, "actor", None) or (default if source == "cron" else (os.environ.get("USER") or "cli"))
    return actor, source


def cmd_list(_: argparse.Namespace) -> int:
    from . import store
    try:
        certs = config.load_certificates()
    except config.ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    print(f"Configuration: {config.SERVERS_FILE}")
    if not certs:
        print("No servers configured. Add one in the web UI (Settings) or edit servers.json.")
        return 0
    for c in certs:
        latest = store.latest_for(c.id)
        status = latest["outcome"] if latest else "never run"
        print(f"  {c.id:<16} {c.domain:<36} CA={c.acme_ca:<16} last={status}")
        for t in c.targets:
            if len(c.targets) > 1 or t.id != c.id or t.driver != "orchestrator":
                print(f"      -> {t.id:<13} {t.driver:<13} {_target_host(t)}")
    return 0


def _target_host(t) -> str:
    from . import drivers
    try:
        return drivers.get(t.driver).display_host(t)
    except config.ConfigError:
        return "?"


def cmd_check(args: argparse.Namespace) -> int:
    """Preflight: configuration path/persistence, target settings, credentials."""
    from . import preflight
    report = preflight.run(strict=None if not args.lenient else False)
    if args.json:
        print(json.dumps(report.as_dict(), indent=2))
    else:
        print(f"Configuration: {report.servers_file}")
        print(f"History:       {report.history_file}")
        if report.in_container:
            print(f"Persistent:    {'yes' if report.config_mounted else 'NO' if report.config_mounted is False else 'unknown'}")
        for f in report.findings:
            tag = {"fatal": "FATAL", "warn": "WARN ", "info": "info "}[f.level]
            print(f"  [{tag}] {f.code}: {f.message}")
        print("Result: " + ("OK" if report.ok else "FAILED — fix the FATAL items above"))
    return 0 if report.ok else 1


def cmd_probe(args: argparse.Namespace) -> int:
    """Live, non-disruptive check of one target (SSH auth + sudo for Orchestrator targets)."""
    from . import drivers
    try:
        _, target = config.get_target(args.target_id)
        drv = drivers.get(target.driver)
    except config.ConfigError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    res = drv.probe(target)
    print(f"{target.id} {drv.probe_label.lower()}: {'OK' if res.ok else 'FAILED'} — {res.message}")
    for c in res.detail.get("checks", []):
        state = "ok " if c.get("ok") else "FAIL"
        print(f"  [{state}] {c.get('command')}" + (f"  -> {c.get('hint') or c.get('error')}" if not c.get("ok") else ""))
    return 0 if res.ok else 1


def cmd_ca_info(_: argparse.Namespace) -> int:
    """Bundled lab CA: endpoints, root fingerprint, trust-store hints."""
    if not config.LAB_CA_HOST:
        print("Lab CA not configured (LAB_CA_HOST unset). Run ./setup.sh --with-ca --lab-domain <zone>.")
        return 1
    base = config.lab_ca_base_url()
    print(f"Lab CA:          {base}")
    print(f"ACME directory:  {config.lab_ca_acme_url()}")
    print(f"Root download:   {base}/roots.pem")
    print(f"CRL:             {base}/1.0/crl")
    if config.LAB_CA_ROOT.is_file():
        print(f"Root file:       {config.LAB_CA_ROOT}")
        print(f"Root SHA-256:    {config.lab_ca_root_fingerprint()}")
        names = sorted(config.lab_ca_issuer_names())
        print("Issuers:         " + "; ".join(names))
        print("Root key:        " + ("offline (marker present)" if config.LAB_CA_OFFLINE_MARKER.is_file()
                                     else "UNKNOWN — marker missing; verify the key is not in the online volume"))
        print(f"API trust:       {config.api_trust_bundle()} (servers without ca_bundle)")
    else:
        print(f"Root file:       {config.LAB_CA_ROOT} (MISSING — mount ./data/pki/certs and run setup.sh --with-ca)")
        return 1
    print("Trust the root on clients after confirming the fingerprint out of band (see README 'Bundled lab CA').")
    return 0


def _run_locked(fn) -> int:
    from . import locks
    try:
        return fn()
    except locks.RunLocked as exc:
        print(f"{exc}", file=sys.stderr)
        return EXIT_LOCKED


def _renew_one(args: argparse.Namespace) -> int:
    from . import renew
    actor, source = _actor(args, "cli")

    def go():
        cert = config.get_certificate(args.server_id)
        rec = renew.renew_certificate(cert, force=args.force, actor=actor, source=source)
        print(f"{cert.id}: {rec.outcome}")
        return 0 if rec.outcome == "success" else 1
    return _run_locked(go)


def _redeploy_one(args: argparse.Namespace) -> int:
    from . import renew
    actor, source = _actor(args, "cli")

    def go():
        cert = config.get_certificate(args.server_id)
        rec = renew.redeploy_certificate(cert, actor=actor, source=source)
        print(f"{cert.id}: {rec.outcome}")
        return 0 if rec.outcome == "success" else 1
    return _run_locked(go)


def cmd_renew_all(args: argparse.Namespace) -> int:
    from . import renew
    actor, source = _actor(args, "scheduler")
    records = renew.renew_all(force=args.force, actor=actor, source=source)
    failed = [r for r in records if r.outcome == "failed"]
    return 1 if failed else 0


def _single_step(args: argparse.Namespace, module: str, fn: str) -> int:
    mod = __import__(f"app.{module}", fromlist=[fn])
    server = config.get_server(args.server_id)
    result = getattr(mod, fn)(server)
    print(f"{server.id} {module}: {'OK' if result.ok else 'FAILED'} — {result.message}")
    return 0 if result.ok else 1


def cmd_backup(args: argparse.Namespace) -> int:
    from . import backup
    try:
        out = backup.create(args.file, include_root=args.include_root, passphrase=_passphrase(args))
    except backup.BackupError as exc:
        print(f"backup failed: {exc}", file=sys.stderr)
        return 1
    print(f"backup written: {out.path} ({out.entries} entries, {out.size} bytes{', encrypted' if out.encrypted else ''})")
    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    from . import backup
    try:
        res = backup.restore(args.file, force=args.force, passphrase=_passphrase(args))
    except backup.BackupError as exc:
        print(f"restore failed: {exc}", file=sys.stderr)
        return 1
    print(f"restored {res.entries} entries from {res.path} into {res.destination}")
    if not args.no_check:
        return cmd_check(argparse.Namespace(json=False, lenient=True))
    return 0


def _passphrase(args: argparse.Namespace) -> str:
    env = getattr(args, "passphrase_env", None) or "BACKUP_PASSPHRASE"
    if getattr(args, "encrypt", False) or getattr(args, "passphrase_env", None):
        val = os.environ.get(env, "")
        if not val:
            raise SystemExit(f"{env} is not set (needed for an encrypted backup/restore)")
        return val
    if getattr(args, "command", "") == "restore":
        return os.environ.get(env, "")        # an encrypted archive needs it; a plain one ignores it
    return ""


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)            # every file this process (and Lego) creates starts owner-only
    _setup_logging()
    p = argparse.ArgumentParser(prog="orchestrator-acme-cert-manager")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list configured certificates and targets").set_defaults(func=cmd_list)

    ck = sub.add_parser("check", help="preflight: config persistence, target settings, credentials")
    ck.add_argument("--json", action="store_true", help="machine-readable output")
    ck.add_argument("--lenient", action="store_true", help="report fatal findings as warnings")
    ck.set_defaults(func=cmd_check)

    sub.add_parser("ca-info", help="bundled lab CA endpoints and root fingerprint").set_defaults(func=cmd_ca_info)

    for name in ("probe", "ssh-test"):
        st = sub.add_parser(name, help="live, non-disruptive check of one target (SSH auth + sudo authorization)")
        st.add_argument("target_id")
        st.set_defaults(func=cmd_probe)

    for name, mod, fn in [("issue", "issue", "issue_or_renew"),
                          ("deploy", "deploy", "deploy"),
                          ("restart", "restart", "restart")]:
        sp = sub.add_parser(name, help=f"run the {name} step for one Orchestrator target")
        sp.add_argument("server_id")
        sp.set_defaults(func=lambda a, m=mod, f=fn: _single_step(a, m, f))

    def who(sp):
        sp.add_argument("--source", choices=["cli", "cron", "web"], default="cli", help="recorded in history")
        sp.add_argument("--actor", default=None, help="recorded in history (default: $USER, or 'scheduler' for cron)")

    rp = sub.add_parser("renew", help="run full pipeline for one certificate (contacts the ACME CA)")
    rp.add_argument("server_id", help="certificate id")
    rp.add_argument("--force", action="store_true")
    who(rp)
    rp.set_defaults(func=_renew_one)

    rd = sub.add_parser("redeploy", help="deploy + activate the certificate already on disk (no CA contact)")
    rd.add_argument("server_id", help="certificate id")
    who(rd)
    rd.set_defaults(func=_redeploy_one)

    ra = sub.add_parser("renew-all", help="full pipeline for all certificates (what the scheduler runs)")
    ra.add_argument("--force", action="store_true")
    who(ra)
    ra.set_defaults(func=cmd_renew_all)

    bk = sub.add_parser("backup", help="archive config + runtime state (certs, lab CA online state; logs excluded)")
    bk.add_argument("file", help="output .tar.gz (or .tar.gz.enc with --encrypt)")
    bk.add_argument("--include-root", action="store_true", help="also include the lab CA OFFLINE root (data/pki-root)")
    bk.add_argument("--encrypt", action="store_true", help="encrypt with the passphrase in $BACKUP_PASSPHRASE")
    bk.add_argument("--passphrase-env", default=None, help="env var holding the passphrase (implies --encrypt)")
    bk.set_defaults(func=cmd_backup)

    rs = sub.add_parser("restore", help="restore an archive made by `backup` (refuses to overwrite a newer servers.json)")
    rs.add_argument("file")
    rs.add_argument("--force", action="store_true", help="overwrite a newer servers.json")
    rs.add_argument("--passphrase-env", default=None, help="env var holding the passphrase of an encrypted archive")
    rs.add_argument("--no-check", action="store_true", help="do not run preflight afterwards")
    rs.set_defaults(func=cmd_restore)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
