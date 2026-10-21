"""The served catalog and the effective controls must name one catalog.

The dashboard reads the catalog from the control API and the effective controls
from the runtime snapshot, and refuses to render when the two name different
catalogs. Nothing the operator can do from the page resolves that, so the daemon
has to keep the two bindings together on its own.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.guard.daemon.extension_control_api import ExtensionControlApiService
from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHttpServer
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import (
    ExtensionControlRuntime,
    ExtensionControlRuntimeSnapshot,
)
from codex_plugin_scanner.guard.runtime.generated_command_catalog import GeneratedCommandCatalog
from codex_plugin_scanner.guard.store import GuardStore

_REVISION = 7


def _delivered_registry() -> GeneratedCommandCatalog:
    """A catalog distinct from the core registry, standing in for delivered packs."""

    registry = GeneratedCommandCatalog(tuple(BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions[:4]))
    assert registry.catalog_digest != BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    return registry


def _protected(catalog_digest: str, *, revision: int = _REVISION) -> ExtensionControlAuthorityView:
    return ExtensionControlAuthorityView(
        health=AuthorityHealth.PROTECTED,
        revision=revision,
        catalog_digest=catalog_digest,
        layers=(),
    )


def test_refresh_rebinds_the_control_api_to_the_registry_the_authority_was_read_for(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pack activation found after startup must move both bindings together.

    Durable authority does not change when a pack activation lands, so the
    re-read comes back at the revision already installed. The daemon still has
    to install it, because it is the same authority projected onto another
    catalog, and then serve that catalog from the control API.
    """

    store = GuardStore(tmp_path / "guard-home")
    core = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    delivered = _delivered_registry()
    runtime = ExtensionControlRuntime(_protected(core.catalog_digest))
    api = ExtensionControlApiService(store=store, registry=core, runtime=runtime)
    server = cast(
        _GuardDaemonHttpServer,
        cast(
            object,
            SimpleNamespace(
                store=store,
                extension_control_runtime=runtime,
                extension_control_api=api,
                _installed_authority_pending=False,
                # Startup read the core registry through the ordinary path,
                # because the activation was not committed yet. That path never
                # sets the recovery flag.
                _extension_control_on_core_registry=False,
            ),
        ),
    )

    from codex_plugin_scanner.guard.catalog_delivery import projection

    monkeypatch.setattr(projection, "capture", lambda _store: (None, delivered, "delivered-digest"))
    monkeypatch.setattr(projection, "require_current", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        store,
        "read_extension_control_authority_for_registry",
        lambda registry, *, read_only=False: _protected(registry.catalog_digest),
    )

    snapshot = _GuardDaemonHttpServer.refresh_extension_control_runtime(server)

    assert snapshot.catalog_digest == delivered.catalog_digest
    assert api.catalog_digest == delivered.catalog_digest
    assert api.catalog()["catalog_digest"] == delivered.catalog_digest
    assert api.effective()["catalog_digest"] == delivered.catalog_digest


def test_a_protected_revision_admits_the_same_revision_read_for_another_catalog() -> None:
    core = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    delivered = _delivered_registry()
    runtime = ExtensionControlRuntime(_protected(core.catalog_digest))
    other_catalog = _protected(delivered.catalog_digest)

    installed = runtime.refresh(other_catalog)

    assert installed.catalog_digest == delivered.catalog_digest
    assert (
        installed.effective_digest
        == ExtensionControlRuntimeSnapshot.from_authority_view(other_catalog).effective_digest
    )
    # The revision floor still rejects an authority that moves backwards.
    with pytest.raises(ValueError, match="cannot move backwards"):
        runtime.refresh(_protected(delivered.catalog_digest, revision=_REVISION - 1))


def test_the_refresh_route_recaptures_the_activation_rather_than_its_own_registry() -> None:
    """The dashboard's repair request must be able to move the catalog binding.

    The service's own refresh re-reads durable authority for the registry it is
    already bound to, so a page that posts here to resolve two disagreeing
    catalog digests has to reach the daemon-wide refresh instead.
    """

    from codex_plugin_scanner.guard.daemon.server_control_routes_post import _ControlPostRoutes

    calls: list[str] = []
    daemon = SimpleNamespace(
        refresh_extension_control_runtime=lambda: calls.append("daemon"),
        extension_control_api=SimpleNamespace(
            effective=lambda: {"health": "protected"},
            refresh=lambda: calls.append("service"),
        ),
    )
    written: list[dict[str, object]] = []
    handler = cast(
        _ControlPostRoutes,
        cast(
            object,
            SimpleNamespace(
                _daemon_server=lambda: daemon,
                _write_json=lambda payload, **_kwargs: written.append(payload),
            ),
        ),
    )

    _ControlPostRoutes._dispatch_control_post(
        handler,
        SimpleNamespace(path="/v1/extension-controls/refresh"),
        ["v1", "extension-controls", "refresh"],
        {},
        SimpleNamespace(route_class="extension_control"),
    )

    assert calls == ["daemon"]
    assert written == [{"health": "protected"}]
