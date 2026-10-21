"""Self-repair for degraded command-activity evidence health.

A single failed hook write leaves the evidence store flagged as degraded until a
later write, maintenance run or repair probe succeeds. When the dashboard reads
command activity while that flag is set, the daemon runs the same probe and
maintenance batch Protect repair runs, so a transient failure does not leave a
warning the user cannot clear. The probe and maintenance are native store
operations; this module only decides when to call them.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import Final

from ..config import load_guard_config
from ..store import GuardStore
from .server_control_connect_flow import _repair_command_activity_persistence_health

COMMAND_ACTIVITY_AUTO_REPAIR_INTERVAL_SECONDS: Final = 60.0

_attempt_lock = threading.Lock()
_last_attempt_by_home: dict[str, float] = {}
_check_lock = threading.Lock()
_last_check_by_home: dict[str, float] = {}


def command_activity_health_degraded(payload: Mapping[str, object]) -> bool:
    health = payload.get("health")
    return isinstance(health, Mapping) and health.get("status") == "degraded"


def auto_repair_command_activity_health(
    store: GuardStore,
    *,
    clock: Callable[[], float] = time.monotonic,
) -> bool:
    """Run one rate-limited repair attempt; return whether an attempt ran.

    Concurrent callers skip instead of waiting, and every home gets at most one
    attempt per interval so a store that stays broken is not probed on every
    dashboard poll. Failures are swallowed: the health payload the caller reads
    next is the authoritative result.
    """

    home = str(store.guard_home)
    if not _attempt_lock.acquire(blocking=False):
        return False
    try:
        now = clock()
        last = _last_attempt_by_home.get(home)
        if last is not None and now - last < COMMAND_ACTIVITY_AUTO_REPAIR_INTERVAL_SECONDS:
            return False
        _last_attempt_by_home[home] = now
        try:
            config = load_guard_config(store.guard_home)
            if _repair_command_activity_persistence_health(store) is None:
                store.maintain_command_activity(
                    now=datetime.now(timezone.utc),
                    detail_retain_days=config.evidence_retain_days,
                )
        except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
            pass
        return True
    finally:
        _attempt_lock.release()


def auto_repair_command_activity_health_if_degraded(
    store: GuardStore,
    *,
    clock: Callable[[], float] = time.monotonic,
) -> bool:
    """Check stored health at most once per interval and repair it when degraded.

    Routes whose payload does not already carry command-activity health, such as
    the runtime snapshot behind Home and Protect, call this before reading it.
    """

    home = str(store.guard_home)
    with _check_lock:
        now = clock()
        last = _last_check_by_home.get(home)
        if last is not None and now - last < COMMAND_ACTIVITY_AUTO_REPAIR_INTERVAL_SECONDS:
            return False
        _last_check_by_home[home] = now
    try:
        degraded = store.get_command_activity_persistence_health().active_error_count > 0
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
        return False
    return degraded and auto_repair_command_activity_health(store, clock=clock)


def reset_command_activity_auto_repair() -> None:
    """Forget previous checks and attempts. Tests use this to start from a clean limiter."""

    with _attempt_lock:
        _last_attempt_by_home.clear()
    with _check_lock:
        _last_check_by_home.clear()
