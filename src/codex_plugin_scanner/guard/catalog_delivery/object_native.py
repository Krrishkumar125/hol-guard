"""Native checks of delivery objects and containers.

The runtime decides whether fetched bytes are the objects they claim to be.
This adapter moves bytes and file paths to it and turns a rejection back into
the ``ValueError`` its callers expect.
"""

from __future__ import annotations

import base64
import functools
import hashlib
import json
import threading
from collections import OrderedDict
from collections.abc import Callable
from typing import Any, TypeVar

from . import lifecycle

Result = TypeVar("Result")

REQUEST_INVALID = "delivery object request invalid"
# The container checks that the standard ZIP reader used to make.
CONTAINER_STRUCTURE = "delivery container archive invalid"

# Verified answers to reads whose request names the digest of every byte they
# return. Enabling one extension re-reads the same catalogs and installed
# members hundreds of times across preview, preparation and publication, and
# each read starts the runtime. Publication then misses its deadline on slower
# hosts. Answers stay in memory up to a byte budget; a replaced or modified
# runtime starts over with fresh native answers.
_ANSWERS: OrderedDict[bytes, str] = OrderedDict()
_ANSWERS_LOCK = threading.Lock()
_ANSWERS_LIMIT = 8 * 1024 * 1024
_ANSWER_LIMIT = 1024 * 1024


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


def addressed(operation: str, *, invalid: str = REQUEST_INVALID, **fields: Any) -> dict[str, Any]:
    """Run a read whose request fixes its answer, reusing an earlier verified answer.

    Only an answer carrying data is kept. A rejection, a partial expansion that
    names missing objects, and a resolved whole asset all go back to the runtime
    every time.
    """
    try:
        runtime = lifecycle.runtime_fingerprint()
        material = json.dumps({"operation": operation, "request": fields, "runtime": runtime}, sort_keys=True)
    except (OSError, TypeError, ValueError):
        # A missing runtime must fail in native verification, not answer from memory.
        return call(operation, invalid=invalid, **fields)
    digest = hashlib.sha256(material.encode()).digest()
    with _ANSWERS_LOCK:
        answer = _ANSWERS.get(digest)
        if answer is not None:
            _ANSWERS.move_to_end(digest)
    if answer is not None:
        return json.loads(answer)
    reply = call(operation, invalid=invalid, **fields)
    if "data" not in reply or "need" in reply:
        return reply
    answer = json.dumps(reply)
    if len(answer) <= _ANSWER_LIMIT:
        with _ANSWERS_LOCK:
            _ANSWERS[digest] = answer
            held = sum(map(len, _ANSWERS.values()))
            while held > _ANSWERS_LIMIT:
                held -= len(_ANSWERS.popitem(last=False)[1])
    return reply


def member_at(path, asset: str, name: str, length: int) -> bytes:
    """One verified member of the container file at ``path``."""
    reply = call("member", path=str(path), asset=asset, name=name, length=length)
    return base64.b64decode(reply["data"], validate=True)


def verify(data: bytes, sha256: str, length: int) -> None:
    """Fetched bytes must have the length and digest that were asked for."""
    call("verify", data=base64.b64encode(data).decode("ascii"), sha256=sha256, length=length)
