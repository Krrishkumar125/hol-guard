#!/usr/bin/env python3
"""Keep every non-Unix behaviour arm in the Rust tree under standing review.

Guard's runtime compiles a `#[cfg(not(unix))]` arm in place of the Unix one on
Windows. Twice now a containment fix shipped with its behaviour behind
`#[cfg(unix)]` and its proof behind `#![cfg(unix)]`, so the Windows arm never
entered a test binary and the platform gap stayed invisible:

* `guard-runtime/src/hook_direct_contained.rs` defers every contained route on
  Windows (PR #5397), proven only by `#![cfg(unix)]` test files.
* `guard-command/src/pretool/contained_wrapper.rs::sibling_project_root`
  returns `None` on Windows (PR #5200), proven only by the `#![cfg(unix)]`
  integration test `tests/pretool_sibling_repository_writes.rs`.

Whether a given arm is reached by some test cannot be decided by reading the
source: a private helper is usually exercised through a public entry point, and
an integration test names neither. So this gate does not guess. It requires
that every non-Unix arm is named in `ci/platform_arms.json` with a verdict a
reviewer wrote, and fails when an arm appears, moves or changes signature
without one, or when an entry no longer matches any arm.

Verdicts:

``posix-primitive``
    The arm substitutes a Windows equivalent for a POSIX-only concept (mode
    bits, uid/gid, unix sockets, signals, symlink semantics). The platform
    difference is the point.
``windows-equivalent``
    A real Windows implementation, not a stub.
``windows-unsupported``
    The capability does not exist on Windows yet and the arm fails closed, so
    the caller falls back to review or deny. Safe, but it is what turns benign
    Windows work into an approval prompt.
``windows-permissive``
    The arm returns the permissive value where Unix proves something. Every one
    of these needs a reason why skipping the proof is sound on Windows.
``other-platform``
    `#[cfg(all(not(unix), not(windows)))]`: Windows takes an arm of its own, so
    this one only covers platforms Guard does not ship for.

Usage::

    python3 scripts/ci/platform_arm_inventory.py            # check
    python3 scripts/ci/platform_arm_inventory.py --write    # refresh entries
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA_VERSION = 1
CRATES = Path("rust/crates")
INVENTORY = Path("ci/platform_arms.json")
VERDICTS = (
    "posix-primitive",
    "windows-equivalent",
    "windows-unsupported",
    "windows-permissive",
    "other-platform",
)
UNREVIEWED = "unreviewed"

# `#[cfg(not(unix))]` and `#[cfg(all(not(unix), ...))]`, but never a test arm:
# a test that only runs off Unix is proof, not behaviour.
ATTRIBUTE = re.compile(r"^(?P<indent>\s*)#\[cfg\((?P<cfg>[^\]]*\bnot\(unix\)[^\]]*)\)\]\s*$")
# `all(test, ..)` is test-only. `any(not(unix), test)` is not: it compiles into
# an ordinary non-Unix build, so it is behaviour and stays under review.
TEST_ONLY = re.compile(r"^\s*all\(.*\btest\b")
SKIPPED = re.compile(r"^\s*(?:#\[|//[/!]?)")
WHITESPACE = re.compile(r"\s+")
# How far a multi-line item signature may run before the opening brace.
SIGNATURE_LINES = 16


SCOPE = re.compile(
    r"^\s*(?:pub\b[^;{]*?)?(?:async\s+|unsafe\s+|default\s+)*"
    r"(?P<kind>fn|impl|mod|trait|struct|enum)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
DECLARATION = re.compile(
    r"^\s*(?:pub\b[^;{]*?)?(?:async\s+|unsafe\s+|extern\s+\"[^\"]*\"\s+|default\s+)*"
    r"(?:fn|mod|impl|struct|enum|trait|type|const|static|use)\b"
)


def declaration(lines: list[str], start: int) -> str:
    """The item's declaration, joined and normalised so a reformat is stable."""
    parts: list[str] = []
    for line in lines[start : start + SIGNATURE_LINES]:
        parts.append(line.strip())
        if any(character in parts[-1] for character in "{;="):
            break
    joined = WHITESPACE.sub(" ", " ".join(parts))
    return joined[: terminator(joined)].strip()


def terminator(joined: str) -> int:
    """Where the declaration ends: the first `{`, `;` or `=` outside brackets.

    `const NAMES: [&str; 3]` carries a `;` inside its type, so a plain search
    would cut the name off its type and make the entry unreadable.
    """
    depth = 0
    for position, character in enumerate(joined):
        if character in "([":
            depth += 1
        elif character in ")]":
            depth -= 1
        elif depth == 0 and character in "{;=":
            return position
    return len(joined)


def enclosing(lines: list[str], start: int) -> str:
    """The nearest enclosing item above `start`, for an arm that is a bare block.

    A `#[cfg(not(unix))] { .. }` block inside a function has no declaration of
    its own, so it is named after the item it stands in.
    """
    for index in range(start, -1, -1):
        match = SCOPE.match(lines[index])
        if match is not None:
            return f"{match.group('kind')} {match.group('name')}"
    return "<file scope>"


def signature(lines: list[str], start: int) -> str:
    """A name for the arm at `start` that survives reformatting."""
    if DECLARATION.match(lines[start]):
        return declaration(lines, start)
    return f"{enclosing(lines, start)} -- non-Unix block"


def arms(root: Path) -> list[dict[str, str]]:
    """Every non-Unix behaviour arm under `root`, in path order."""
    found: list[dict[str, str]] = []
    for path in sorted(root.rglob("*.rs")):
        relative = path.relative_to(root.parent.parent).as_posix()
        if "/src/" not in relative or path.name.endswith("_tests.rs"):
            continue
        text = path.read_text(encoding="utf-8")
        if "not(unix)" not in text:
            continue
        lines = text.splitlines()
        for index, line in enumerate(lines):
            match = ATTRIBUTE.match(line)
            if match is None or TEST_ONLY.match(match.group("cfg")):
                continue
            cursor = index + 1
            while cursor < len(lines) and SKIPPED.match(lines[cursor]):
                cursor += 1
            if cursor >= len(lines):
                continue
            item = signature(lines, cursor)
            repeats = sum(1 for seen in found if seen["file"] == relative and seen["item"].startswith(item))
            if repeats:
                item = f"{item} #{repeats + 1}"
            found.append({"file": relative, "item": item, "cfg": WHITESPACE.sub(" ", match.group("cfg"))})
    return found


def key(entry: dict[str, str]) -> tuple[str, str]:
    return entry["file"], entry["item"]


def load(inventory: Path) -> list[dict[str, str]]:
    document = json.loads(inventory.read_text(encoding="utf-8"))
    if document.get("schema_version") != SCHEMA_VERSION:
        raise SystemExit(f"{inventory}: unsupported schema_version")
    entries = document.get("arms")
    if not isinstance(entries, list):
        raise SystemExit(f"{inventory}: `arms` must be a list")
    return entries


def problems(found: list[dict[str, str]], reviewed: list[dict[str, str]]) -> list[str]:
    """Every difference between the tree and the reviewed inventory."""
    seen: dict[tuple[str, str], dict[str, str]] = {}
    messages: list[str] = []
    for entry in reviewed:
        if not isinstance(entry, dict) or not {"file", "item", "cfg", "verdict", "note"} <= set(entry):
            messages.append(f"inventory entry is missing a required field: {entry!r}")
            continue
        if entry["verdict"] not in VERDICTS:
            messages.append(f"{entry['file']}: unknown verdict {entry['verdict']!r}")
        if not entry["note"].strip() or entry["note"].strip() == UNREVIEWED:
            messages.append(f"{entry['file']}: {entry['item']}: the verdict has no reason")
        if key(entry) in seen:
            messages.append(f"{entry['file']}: duplicate entry for {entry['item']}")
        seen[key(entry)] = entry
    current = {key(arm) for arm in found}
    for arm in found:
        reviewed_arm = seen.get(key(arm))
        if reviewed_arm is not None and reviewed_arm.get("cfg") != arm["cfg"]:
            messages.append(
                f"{arm['file']}: `{arm['item']}` is now `#[cfg({arm['cfg']})]`; review the entry and update its `cfg`."
            )
    for arm in found:
        if key(arm) not in seen:
            messages.append(
                f"{arm['file']}: new non-Unix arm `{arm['item']}` is not reviewed.\n"
                f"    Run `python3 {Path(__file__).as_posix()} --write`, then give the new entry a"
                " verdict and a reason saying whether the Windows arm is a correct platform"
                " difference or a silent gap, and how it is proven off Unix."
            )
    for entry in reviewed:
        if key(entry) not in current:
            messages.append(f"{entry['file']}: reviewed arm `{entry['item']}` no longer exists; drop the entry.")
    return messages


def write(inventory: Path, found: list[dict[str, str]], reviewed: list[dict[str, str]]) -> None:
    """Keep every reviewed verdict and add a placeholder for each new arm."""
    kept = {key(entry): entry for entry in reviewed if isinstance(entry, dict) and {"file", "item"} <= set(entry)}
    merged = [{**kept.get(key(arm), {"verdict": "windows-unsupported", "note": UNREVIEWED}), **arm} for arm in found]
    document = {
        "schema_version": SCHEMA_VERSION,
        "comment": (
            "Every `#[cfg(not(unix))]` behaviour arm in rust/crates/*/src, with the verdict a"
            " reviewer gave it. scripts/ci/platform_arm_inventory.py keeps this list honest."
        ),
        "arms": merged,
    }
    inventory.write_text(json.dumps(document, indent=1) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--write", action="store_true", help="refresh the inventory in place")
    arguments = parser.parse_args(argv)
    crates, inventory = arguments.root / CRATES, arguments.root / INVENTORY
    found = arms(crates)
    reviewed = load(inventory) if inventory.exists() else []
    if arguments.write:
        write(inventory, found, reviewed)
        print(f"{inventory}: {len(found)} arms")
        return 0
    messages = problems(found, reviewed)
    for message in messages:
        print(message, file=sys.stderr)
    if messages:
        print(f"\n{len(messages)} unreviewed non-Unix arm(s).", file=sys.stderr)
        return 1
    print(f"{len(found)} non-Unix arms, all reviewed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
