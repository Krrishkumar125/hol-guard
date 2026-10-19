"""Bounded native Cloud producer bridge; no Python catalog construction."""

from __future__ import annotations

import base64
import json
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Advertised protocol name only. The native runtime defines and enforces the
# v2 wire contract; nothing here restates its limits or its upload policy.
CAPABILITY = "extension-catalog.v2"


def encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def native_call(home: Path, **request: object) -> dict[str, Any]:
    from ..native_execution import _resident_request
    from .extension_catalog_sync import ExtensionCatalogLimitError

    reply = _resident_request(
        operation="cloud_catalog",
        request={"guard_home": str(home.absolute()), **request},
        guard_home=home,
        timeout_seconds=120.0,
        required_feature="cloud-catalog-producer-v2",
        response_schema="guard-cloud-catalog-result.v2",
        max_request_bytes=4 * 1024 * 1024,
    )
    if not isinstance(reply, dict):
        raise RuntimeError("Native complete catalog producer unavailable")
    if reply.get("error") == "catalog_limit":
        raise ExtensionCatalogLimitError("Complete catalog exceeds native wire limits")
    payload = reply.get("payload")
    if not isinstance(payload, dict) or "error" in reply:
        raise ValueError("Native complete catalog producer rejected metadata")
    if "policy_error" in payload:
        from ..managed_controls_policy_fields import ManagedControlsPolicyError

        raise ManagedControlsPolicyError(payload["policy_error"], payload["message"])
    return payload


@dataclass(frozen=True)
class PreparedCatalogView:
    guard_home: Path
    token: str
    _manifest: bytes
    discovery_root: str
    discovery_authority: str

    @classmethod
    def from_native(cls, home: Path, payload: dict[str, Any]) -> PreparedCatalogView:
        return cls(
            home,
            payload["token"],
            encoded(payload["manifest"]),
            payload["discovery_root"],
            payload["discovery_authority"],
        )

    @property
    def manifest(self) -> dict[str, Any]:
        return json.loads(self._manifest)

    def request_bytes(self, operation: str, ordinal: int | None = None) -> bytes:
        body = bytearray()
        total = expected = None
        while total is None or len(body) < total:
            result = native_call(
                self.guard_home,
                action="request",
                token=self.token,
                operation=operation,
                ordinal=ordinal,
                offset=len(body),
            )
            # The native runtime enforces the wire budget; these checks only keep
            # the reassembly loop well formed when chunks arrive out of order.
            size = result.get("total_bytes")
            if type(size) is not int or size <= 0 or result.get("offset") != len(body):
                raise ValueError("Native catalog request chunk is out of sequence")
            if total is None:
                total, expected = size, result.get("body_sha256")
            if size != total or result.get("body_sha256") != expected:
                raise ValueError("Native catalog request changed between chunks")
            chunk = base64.b64decode(result["body_chunk"], validate=True)
            if not chunk or len(body) + len(chunk) > total:
                raise ValueError("Native catalog chunk exceeds the declared body")
            body.extend(chunk)
        return bytes(body)

    def pages(self):
        for ordinal in range(self.manifest["pageCount"]):
            yield json.loads(self.request_bytes("page", ordinal))["page"]

    def legacy(self):
        with self.pinned():
            return native_call(self.guard_home, action="legacy", token=self.token)["catalog"]

    @contextmanager
    def pinned(self):
        lease = native_call(self.guard_home, action="acquire", token=self.token)["lease"]
        try:
            yield
        finally:
            native_call(self.guard_home, action="release", lease=lease)
