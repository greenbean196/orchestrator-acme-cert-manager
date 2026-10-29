"""scripts/check-version.py keeps __version__, the compose image tag and the CHANGELOG in step."""
import pathlib
import re
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check-version.py"


def _run(root, *args):
    return subprocess.run([sys.executable, str(SCRIPT), "--root", str(root), *args],
                          capture_output=True, text=True, timeout=30)


def _copy(tmp_path):
    (tmp_path / "app").mkdir()
    shutil.copy(ROOT / "app" / "__init__.py", tmp_path / "app" / "__init__.py")
    shutil.copy(ROOT / "docker-compose.yml", tmp_path / "docker-compose.yml")
    shutil.copy(ROOT / "CHANGELOG.md", tmp_path / "CHANGELOG.md")
    return re.search(r'__version__ = "([^"]+)"', (tmp_path / "app" / "__init__.py").read_text()).group(1)


def test_repository_files_agree():
    r = _run(ROOT)
    assert r.returncode == 0, r.stderr
    assert "version OK" in r.stdout


def test_tag_must_match_and_changelog_must_be_dated(tmp_path):
    version = _copy(tmp_path)
    r = _run(tmp_path, "--tag", "v9.9.9")
    assert r.returncode == 1 and "git tag" in r.stderr
    r = _run(tmp_path, "--tag", version)          # missing the leading v
    assert r.returncode == 1 and "must start with" in r.stderr
    cl = (tmp_path / "CHANGELOG.md").read_text()
    heading = re.search(rf"^## \[{re.escape(version)}\].*$", cl, re.M).group(0)
    if "unreleased" in heading.lower():
        r = _run(tmp_path, "--tag", f"v{version}")
        assert r.returncode == 1 and "unreleased" in r.stderr
        (tmp_path / "CHANGELOG.md").write_text(cl.replace(heading, f"## [{version}] — 2026-10-22", 1))
    r = _run(tmp_path, "--tag", f"v{version}")
    assert r.returncode == 0, r.stderr


def test_compose_drift_and_latest_are_rejected(tmp_path):
    version = _copy(tmp_path)
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(compose.read_text().replace(f":{version}", ":0.0.1", 1))
    r = _run(tmp_path)
    assert r.returncode == 1 and "docker-compose.yml image tag" in r.stderr
    compose.write_text(compose.read_text().replace(":0.0.1", ":latest", 1))
    r = _run(tmp_path)
    assert r.returncode == 1 and "latest" in r.stderr
    (tmp_path / "CHANGELOG.md").write_text("# Changelog\n")
    r = _run(tmp_path)
    assert "CHANGELOG.md has no" in r.stderr
