"""Module-level diagnostic sink for background workers without a daemon handle.

A catalog preparation or publication thread runs outside every HTTP request and
holds no daemon object, so a failure there has nowhere to report. The daemon
installs its diagnostics here once it has a log file and releases them when it
closes. With no sink installed the record is dropped, which keeps a one-shot
hook off the daemon's file I/O on the fail-closed path.

Callers pass an event name and one bounded detail line. Nothing here reads a
record back, so no decision depends on whether a sink was installed.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from contextlib import suppress

BackgroundSink = Callable[[str, str], object]

_lock = threading.Lock()
_sink: BackgroundSink | None = None


def install_sink(sink: BackgroundSink) -> None:
    """Route later background events to ``sink`` until it is released."""

    global _sink
    with _lock:
        _sink = sink


def release_sink(sink: BackgroundSink) -> None:
    """Stop routing to ``sink``; a newer daemon's sink is left alone."""

    global _sink
    with _lock:
        if _sink == sink:
            _sink = None


def record_background_event(event: str, detail: str) -> bool:
    """Record one background diagnostic. Returns whether a sink took it."""

    with _lock:
        sink = _sink
    if sink is None:
        return False
    # A background worker must never die because diagnostics are closing.
    with suppress(Exception):
        sink(event, detail)
        return True
    return False


__all__ = ["BackgroundSink", "install_sink", "record_background_event", "release_sink"]
