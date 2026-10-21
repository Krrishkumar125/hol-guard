"""Installed reads must survive a symlinked installation prefix (macOS /var, /tmp, junctions)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.catalog_delivery import installed_bundle
from codex_plugin_scanner.guard.extension_builder.errors import BuilderError
from codex_plugin_scanner.guard.extension_builder.io import checked_path, read_bytes

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="creating a symlink on Windows needs a privilege ordinary CI accounts do not hold",
)


def _installation(tmp_path: Path) -> tuple[Path, Path]:
    """Return a package root reached through a symlinked prefix, and the real one."""

    real = tmp_path / "private" / "extraction"
    (real / "codex_plugin_scanner" / "_native").mkdir(parents=True)
    (real / "codex_plugin_scanner" / "_native" / "runtime-manifest.json").write_bytes(b'{"ok":true}')
    (tmp_path / "extraction").symlink_to(real)
    return tmp_path / "extraction" / "codex_plugin_scanner", real / "codex_plugin_scanner"


def test_a_symlinked_installation_prefix_still_reads_the_installed_file(tmp_path: Path) -> None:
    package, real = _installation(tmp_path)
    target = package / "_native" / "runtime-manifest.json"

    with pytest.raises(BuilderError, match="Symlink paths"):
        read_bytes(target, limit=65536)

    assert read_bytes(target, limit=65536, anchor=package) == b'{"ok":true}'
    assert checked_path(target, anchor=package) == real / "_native" / "runtime-manifest.json"


def test_a_symlink_below_the_installation_prefix_is_still_rejected(tmp_path: Path) -> None:
    package, real = _installation(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_bytes(b'{"planted":true}')
    (real / "_native" / "planted.json").symlink_to(outside)

    with pytest.raises(BuilderError, match="Symlink paths"):
        read_bytes(package / "_native" / "planted.json", limit=65536, anchor=package)

    (real / "_native" / "nested").symlink_to(tmp_path)
    with pytest.raises(BuilderError, match="Symlink paths"):
        read_bytes(package / "_native" / "nested" / "outside.json", limit=65536, anchor=package)


def test_a_path_outside_the_installation_prefix_is_rejected(tmp_path: Path) -> None:
    package, _ = _installation(tmp_path)
    (tmp_path / "elsewhere.json").write_bytes(b"{}")

    with pytest.raises(BuilderError, match="installation root"):
        read_bytes(tmp_path / "elsewhere.json", limit=65536, anchor=package)


def test_installed_reads_anchor_on_the_package_the_runtime_was_extracted_into(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package, _ = _installation(tmp_path)
    monkeypatch.setattr(installed_bundle, "_package", lambda: package)

    assert installed_bundle._read_installed(package / "_native" / "runtime-manifest.json", limit=65536) == b'{"ok":true}'
