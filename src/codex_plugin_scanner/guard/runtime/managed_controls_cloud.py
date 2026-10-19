"""Local session/discovery adapters for native Cloud policy proofs.

No metadata, enforcement digest or filesystem location from a policy response
is accepted here. Missing authenticated observation identity fails closed.
"""

from __future__ import annotations

import importlib
from datetime import datetime, timezone
from pathlib import Path

from .extension_catalog_provider import observed_view


def local_policy_view(*, guard_home: Path, runtime_summary: dict[str, object], registry) -> dict[str, object]:
    """Marshal a previously authenticated session and current local discovery.

    The session adapter must retain the full authenticated observation identity;
    a response's selected metadata is never a substitute for that local binding.
    """
    view = observed_view(runtime_summary, guard_home)
    discovery = importlib.import_module("..catalog_delivery.discovery", __package__)
    handle = discovery.require_handle(discovery.installed_discovery(guard_home), guard_home)
    from .extension_catalog_pages import native_call

    return native_call(
        guard_home,
        action="policy_view",
        runtime_summary={
            "policyMetadataIdentity": runtime_summary.get("policyMetadataIdentity"),
            "policyMetadataObservedAt": runtime_summary.get("policyMetadataObservedAt"),
            "runtime_credential_id": runtime_summary.get("runtime_credential_id"),
            "runtime_device_id": runtime_summary.get("runtime_device_id"),
        },
        view={
            "token": view.token,
            "manifest": view.manifest,
            "discovery_root": view.discovery_root,
            "discovery_authority": view.discovery_authority,
        },
        discovery={"root": handle.root, "authority": handle.authority},
        enforcement_catalog_digest=registry.catalog_digest,
        now=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    )


def policy_view_ready(*, store, registry) -> bool:
    """Require the compatible native proof path against an authenticated view.

    Authority health and atomic application prerequisites are checked by the
    caller. A native policy view is itself the readiness proof: the runtime
    validates the authenticated completed observation before returning one, and
    an older resident cannot answer the request at all. Nothing here fabricates
    a policy document or restates a negotiated capability set.
    """
    summary = getattr(store, "get_sync_payload", lambda _key: None)("runtime_session_summary")
    if not isinstance(summary, dict):
        return False
    try:
        local_policy_view(guard_home=store.guard_home, runtime_summary=summary, registry=registry)
    except (ImportError, OSError, RuntimeError, TypeError, ValueError):
        return False
    return True
