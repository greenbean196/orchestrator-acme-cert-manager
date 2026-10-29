#!/usr/bin/env python3
"""Fail unless every place that names the release version agrees.

Single source of truth: ``__version__`` in app/__init__.py.
Checked against: the compose image tag of this project's own image, the
CHANGELOG heading, and (when given) the git tag.

    python scripts/check-version.py                 # PR/push: files agree
    python scripts/check-version.py --tag v1.3.0    # release: tag agrees too
"""
import argparse
import os
import pathlib
import re
import sys

SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")
IMAGE_NAME = "orchestrator-acme-cert-manager"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", help="git tag, e.g. v1.3.0 (leading v required)")
    ap.add_argument("--root", default=".", help="repository root")
    args = ap.parse_args()
    root = pathlib.Path(args.root)
    errors: list[str] = []

    init = (root / "app/__init__.py").read_text(encoding="utf-8")
    m = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', init, re.M)
    if not m:
        print("app/__init__.py: no __version__ found", file=sys.stderr)
        return 1
    version = m.group(1)
    if not SEMVER.match(version):
        errors.append(f"__version__ {version!r} is not semver (X.Y.Z[-pre])")

    compose = (root / "docker-compose.yml").read_text(encoding="utf-8")
    tags = re.findall(
        rf'^\s*image:\s*["\']?[^\s"\']*{re.escape(IMAGE_NAME)}:([^\s"\']+)["\']?\s*(?:#.*)?$',
        compose, re.M)
    if len(tags) != 1:
        errors.append(f"docker-compose.yml: expected exactly one '{IMAGE_NAME}:<tag>' image line, found {len(tags)}")
    elif tags[0] != version:
        errors.append(f"docker-compose.yml image tag {tags[0]!r} != __version__ {version!r}")
    if tags and tags[0] == "latest":
        errors.append("docker-compose.yml must not use :latest")

    changelog = root / "CHANGELOG.md"
    heading = None
    if changelog.exists():
        heading = re.search(rf"^## \[{re.escape(version)}\].*$", changelog.read_text(encoding="utf-8"), re.M)
        if not heading:
            errors.append(f"CHANGELOG.md has no '## [{version}]' heading")

    if args.tag is not None:
        if not args.tag.startswith("v"):
            errors.append(f"tag {args.tag!r} must start with 'v'")
        elif args.tag[1:] != version:
            errors.append(f"git tag {args.tag!r} != v{version} (__version__)")
        if heading and "unreleased" in heading.group(0).lower():
            errors.append(f"CHANGELOG.md heading for {version} still says unreleased; date it before tagging")

    for e in errors:
        print(f"::error::{e}" if os.environ.get("GITHUB_ACTIONS") else f"ERROR: {e}", file=sys.stderr)
    if not errors:
        print(f"version OK: {version}" + (f" (tag {args.tag})" if args.tag else ""))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
