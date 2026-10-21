"""Keep patched dependency floors aligned across source and generated locks.

These floors correspond to published advisories in the October 2026
OpenSSF Scorecard report. When dependencies are upgraded, lockfiles
must be updated together rather than only changing the manifest.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from packaging.version import Version

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


ROOT = Path(__file__).resolve().parents[1]


def _toml(path: str) -> dict:
    return tomllib.loads((ROOT / path).read_text(encoding="utf-8"))


def test_python_vulnerability_floors_are_locked() -> None:
    project = _toml("pyproject.toml")
    assert any(dep.startswith("mcp>=1.30.0,<2;") for dep in project["project"]["dependencies"])
    overrides = project["tool"]["uv"]["override-dependencies"]
    assert "pyjwt==2.15.0" in overrides
    assert "multidict>=6.9.1" in overrides
    locked = {package["name"]: package["version"] for package in _toml("uv.lock")["package"]}
    for name, floor in (("mcp", "1.30.0"), ("pyjwt", "2.15.0"), ("multidict", "6.9.1")):
        assert Version(locked[name]) >= Version(floor), name


def test_rust_vulnerability_floors_are_locked() -> None:
    workspace = _toml("rust/Cargo.toml")
    assert workspace["workspace"]["dependencies"]["ruzstd"]["version"] == "=0.9.1"
    locked = {package["name"]: package["version"] for package in _toml("rust/Cargo.lock")["package"]}
    for name, floor in (("rustls", "0.23.46"), ("ruzstd", "0.9.1"), ("webpki-roots", "1.0.10")):
        assert Version(locked[name]) >= Version(floor), name


def test_dashboard_vite_fix_is_consistent_across_locks() -> None:
    package = json.loads((ROOT / "dashboard/package.json").read_text(encoding="utf-8"))
    lock = json.loads((ROOT / "dashboard/package-lock.json").read_text(encoding="utf-8"))
    assert package["devDependencies"]["vite"] == "^7.3.7"
    assert lock["packages"][""]["devDependencies"]["vite"] == "^7.3.7"
    assert Version(lock["packages"]["node_modules/vite"]["version"]) >= Version("7.3.7")
    for lock_path in ("dashboard/pnpm-lock.yaml", "dashboard/bun.lock"):
        text = (ROOT / lock_path).read_text(encoding="utf-8")
        assert "vite@7.3.7" in text
        assert "vite@7.3.6" not in text
