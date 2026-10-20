"""Classify and record the failures behind ``pack_preparation_unavailable``.

Pack preparation reaches local storage, the activation authority and, for a
publication the installed bundle cannot authenticate, the release transport.
Both call sites used to collapse every ``ValueError``/``OSError`` from that
work into one bare code with nothing written to the daemon log, so an operator
who hit it saw a protocol token and had nothing to act on and no record to
read. Keep the public code stable, attach the classified cause and its
recovery action, and record the real exception once at error level.
"""

from __future__ import annotations

import logging
import socket
import ssl
import urllib.error
from collections.abc import Iterator

from .extension_control_errors import ExtensionControlApiError

_LOGGER = logging.getLogger(__name__)

PACK_PREPARATION_UNAVAILABLE = "pack_preparation_unavailable"

# The authority wording raised by preparation when no publication can be
# authenticated locally. Matched on the message because the runtime raises a
# plain ValueError for each of them.
_AUTHORITY_MARKERS = (
    "authority is unavailable",
    "pack_lifecycle_pack_authority_unavailable",
    "requires an existing activation",
)


def _causes(exc: BaseException) -> Iterator[BaseException]:
    """Walk the chained exceptions, because preparation rewraps what it caught."""

    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        current = current.__cause__ or current.__context__


def _named_cause(exc: BaseException) -> str | None:
    from ..catalog_delivery.authority import ExpiredDistributionError
    from ..catalog_delivery.preparation import UnavailablePackError
    from ..catalog_delivery.revocations import RevokedPackError
    from ..catalog_delivery.transport import MissingReleaseError
    from ..extension_builder.native_source_compiler import NativeSourceCompilerError

    for error in _causes(exc):
        if isinstance(error, RevokedPackError):
            return "pack_revoked"
        if isinstance(error, (MissingReleaseError, ExpiredDistributionError, UnavailablePackError)):
            return "release_unavailable"
        # An install whose packaged compiler or its manifest is missing cannot
        # read its own bundle metadata. That is a broken install, not a
        # transient failure, so never tell the operator to simply try again.
        if isinstance(error, NativeSourceCompilerError):
            return "installed_runtime_incomplete"
    return None


_UNREACHABLE = (urllib.error.URLError, socket.gaierror, ssl.SSLError, ConnectionError, TimeoutError)


def classify(exc: BaseException) -> str:
    """Name the step that failed without quoting any part of the message."""

    for error in _causes(exc):
        if isinstance(error, urllib.error.HTTPError):
            return "release_unavailable"
        if isinstance(error, _UNREACHABLE):
            return "offline"
    named = _named_cause(exc)
    if named is not None:
        return named
    if isinstance(exc, ValueError):
        if any(marker in str(exc) for marker in _AUTHORITY_MARKERS):
            return "authority_unavailable"
        return "internal"
    if isinstance(exc, OSError):
        return "local_storage"
    return "internal"


def preparation_unavailable(exc: BaseException, *, stage: str) -> ExtensionControlApiError:
    """Record the real failure and return the classified 503 for the caller."""

    cause = classify(exc)
    _LOGGER.error(
        "Extension-control pack preparation failed at %s (cause=%s): %s",
        stage,
        cause,
        type(exc).__name__,
        exc_info=exc,
    )
    return ExtensionControlApiError(503, PACK_PREPARATION_UNAVAILABLE, cause=cause)
