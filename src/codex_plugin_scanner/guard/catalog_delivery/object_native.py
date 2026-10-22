"""Native checks of delivery objects and containers.

The runtime decides whether fetched bytes are the objects they claim to be.
This adapter moves bytes and file paths to it and turns a rejection back into
the ``ValueError`` its callers expect.
"""

from __future__ import annotations

import base64
import functools
from collections.abc import Callable
from typing import Any, TypeVar

from . import lifecycle

Result = TypeVar("Result")

REQUEST_INVALID = "delivery object request invalid"
# The container checks that the standard ZIP reader used to make.
CONTAINER_STRUCTURE = "delivery container archive invalid"


def _native(**fields: Any) -> dict[str, Any]:
    return lifecycle.invoke("object", **fields)


def sessioned(function: Callable[..., Result]) -> Callable[..., Result]:
    """Verify and copy the runtime once for every native check one operation makes."""

    @functools.wraps(function)
    def run(*args: Any, **kwargs: Any) -> Result:
        with lifecycle.session():
            return function(*args, **kwargs)

    return run


def call(operation: str, *, invalid: str = REQUEST_INVALID, **fields: Any) -> dict[str, Any]:
    """Run one operation; ``invalid`` names a request that cannot be serialised."""
    try:
        reply = _native(operation=operation, **fields)
    except (TypeError, OverflowError) as error:
        raise ValueError(invalid) from error
    rejected = reply.get("rejected")
    if rejected is not None:
        raise ValueError(rejected)
    return reply


def member_at(path, asset: str, name: str, length: int) -> bytes:
    """One verified member of the container file at ``path``."""
    reply = call("member", path=str(path), asset=asset, name=name, length=length)
    return base64.b64decode(reply["data"], validate=True)


def verify(data: bytes, sha256: str, length: int) -> None:
    """Fetched bytes must have the length and digest that were asked for."""
    call("verify", data=base64.b64encode(data).decode("ascii"), sha256=sha256, length=length)
