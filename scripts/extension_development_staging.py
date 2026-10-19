"""Repository-owned checkout staging for maintainer command-pack validation.

The installed runtime has no compilation fallback: `bundle_baseline` refuses an
uninstalled bundle unless a caller supplies this staging callback explicitly.
Only this repository provides one, and only for maintainer tooling that already
runs against the checkout.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def development_release(compiler: Path, directory: Path) -> dict:
    """Stage the checkout's command packs and return their release identity."""
    scripts = str(ROOT / "scripts")
    sys.path.insert(0, scripts)
    try:
        import build_native_command_packs as packs

        packs.stage(compiler, directory, source_root=ROOT)
    finally:
        sys.path.remove(scripts)
    manifest = (directory / "release.json").read_bytes()
    return {"root": json.loads(manifest), "source_context": hashlib.sha256(manifest).hexdigest()}
