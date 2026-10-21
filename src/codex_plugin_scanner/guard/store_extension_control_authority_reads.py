"""Authenticated authority reads and composition with managed controls."""

# pyright: reportAttributeAccessIssue=false, reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import cast

from .managed_controls_policy_bundle import MANAGED_CONTROLS_LAST_GOOD_STATE_KEY
from .native_extension_control_authority import (
    anchor_from_wire,
    extension_control_authority,
    layers_from_wire,
    manifest_sha256,
    raise_fault,
    view_to_wire,
)
from .runtime.command_extensions import CommandSafetyExtensionRegistry
from .runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityError,
    ExtensionControlAuthorityView,
)
from .store_extension_control_authority_schema import ensure_extension_control_authority_schema
from .store_extension_control_authority_support import _row_int, _row_str

# Each writer action runs at most once, and a migration ends the read, so a
# read settles well inside this many resident round trips.
_MAX_READ_ROUNDS = 6


class ExtensionControlAuthorityReadsMixin:
    _extension_control_last_catalog_digest: str = "0" * 64

    def read_extension_control_authority(self, *, catalog_digest: str) -> ExtensionControlAuthorityView:
        self._extension_control_last_catalog_digest = catalog_digest
        from .native_command_control_authority_io import NativeCommandControlAuthorityUnavailableError

        try:
            with self._extension_control_authority_lock():
                return self._read_extension_control_authority_locked(catalog_digest)
        except NativeCommandControlAuthorityUnavailableError:
            # The lease was busy, so nothing about this authority was read. An
            # outage never reads as a verdict: report it instead of claiming a
            # health state this call never observed.
            raise
        except ExtensionControlAuthorityError:
            return self._tampered_view(catalog_digest)
        except Exception:
            return self._degraded_view(catalog_digest)

    def read_extension_control_authority_for_registry(
        self,
        registry: CommandSafetyExtensionRegistry,
        *,
        include_managed_controls: bool = True,
        read_only: bool = False,
        lock_timeout_seconds: float | None = None,
    ) -> ExtensionControlAuthorityView:
        from .native_command_control_authority_io import (
            NativeCommandControlAuthorityUnavailableError,
            NativeCommandControlMutationRequiredError,
        )

        catalog_digest = registry.catalog_digest
        self._extension_control_last_catalog_digest = catalog_digest
        # A read-only caller takes the shared lock, so it must not commit a
        # catalog migration: another reader holding the same lock would race it.
        # Rebind the controls for this registry in memory instead and leave the
        # move to the next writer, which holds the lock exclusively.
        may_migrate = not read_only
        try:
            self._catalog_target_manifest(registry)
            with self._extension_control_authority_lock(shared=read_only, timeout_seconds=lock_timeout_seconds):
                self._require_compatible_extension_control_schema()
                view = self._read_extension_control_authority_locked(
                    catalog_digest,
                    migration_registry=registry,
                    allow_migration=may_migrate,
                )
                stale_manifest: dict[str, str] | None = None
                authority_key: bytes | None = None
                if view.health is AuthorityHealth.PROTECTED:
                    authority_key = self._authority_key(required=True)
                    if authority_key is None:
                        raise ExtensionControlAuthorityError("extension-control authority key is unavailable")
                    view, stale_manifest = self._sync_trusted_catalog_manifest(
                        view, registry, key=authority_key, allow_migration=may_migrate
                    )
                if include_managed_controls:
                    composed = self._with_managed_controls_activation(
                        view,
                        current_manifest=self._catalog_target_manifest(registry),
                        previous_manifest=stale_manifest,
                    )
                else:
                    composed = view
                if stale_manifest is not None and may_migrate:
                    if authority_key is None:
                        raise ExtensionControlAuthorityError("extension-control authority key is unavailable")
                    self._write_catalog_manifest(
                        registry,
                        key=authority_key,
                        manifest=self._catalog_target_manifest(registry),
                        replace=True,
                    )
                return composed
        except (NativeCommandControlAuthorityUnavailableError, NativeCommandControlMutationRequiredError):
            # Neither is a statement about the authority. The first means the
            # lease was busy, the second that this read needs an exclusive one.
            raise
        except ExtensionControlAuthorityError:
            return self._tampered_view(catalog_digest)
        except Exception:
            return self._degraded_view(catalog_digest)

    def _with_managed_controls_activation(
        self,
        view: ExtensionControlAuthorityView,
        *,
        current_manifest: Mapping[str, str] | None = None,
        previous_manifest: Mapping[str, str] | None = None,
    ) -> ExtensionControlAuthorityView:
        try:
            key = self._authority_key(required=False)
        except ExtensionControlAuthorityError:
            # The resident reports a missing key only if managed state needs it.
            key = None
        fields: dict[str, object] = {
            "view": view_to_wire(view),
            "previous_manifest": dict(previous_manifest) if previous_manifest is not None else None,
            "current_manifest_sha256": manifest_sha256(current_manifest) if current_manifest is not None else None,
        }
        reply = self._extension_control_authority_op("compose_managed", key=key, **fields)
        if reply.get("need") == "current_manifest" and current_manifest is not None:
            reply = self._extension_control_authority_op(
                "compose_managed", key=key, **fields, current_manifest=dict(current_manifest)
            )
        return self._view_from_wire(reply.get("view"), view.catalog_digest)

    def managed_controls_lkg_capabilities(
        self,
        policy_bundle: dict[str, object],
    ) -> frozenset[str]:
        """Return negotiation bound to the exact authenticated managed LKG."""

        state = self.get_sync_payload(MANAGED_CONTROLS_LAST_GOOD_STATE_KEY)
        if not isinstance(state, dict):
            return frozenset()
        if state.get("bundleHash") != policy_bundle.get("bundleHash") or state.get(
            "bundleVersion"
        ) != policy_bundle.get("bundleVersion"):
            return frozenset()
        key = self._authority_key(required=False)
        if key is None:
            return frozenset()
        try:
            self._extension_control_authority_op(
                "managed_activation",
                key=key,
                state=state,
                catalog_digest=str(state.get("catalogDigest", "")),
            )
        except ExtensionControlAuthorityError:
            return frozenset()
        raw = state.get("negotiatedCapabilities")
        if not isinstance(raw, list) or any(not isinstance(item, str) for item in raw):
            return frozenset()
        return frozenset(cast(list[str], raw))

    def _extension_control_authority_op(self, op: str, *, key: bytes | None, **fields: object) -> dict[str, object]:
        """Ask the resident, record the migration events it found owed, raise its fault."""

        reply = extension_control_authority(
            store_path=Path(self.path), guard_home=Path(self.guard_home), op=op, key=key, **fields
        )
        events = reply.get("events")
        for event in events if isinstance(events, list) else ():
            if isinstance(event, dict):
                self._record_catalog_migrated_event_once(
                    previous_revision=int(event["previous_revision"]),
                    revision=int(event["revision"]),
                    previous_catalog_digest=str(event["previous_catalog_digest"]),
                    catalog_digest=str(event["catalog_digest"]),
                    layers=layers_from_wire(event.get("layers")),
                    retired_targets=tuple(str(target) for target in cast(list[object], event["retired_targets"])),
                )
        raise_fault(reply)
        return reply

    def _view_from_wire(self, value: object, catalog_digest: str) -> ExtensionControlAuthorityView:
        if not isinstance(value, dict):
            raise ExtensionControlAuthorityError("invalid extension control authority view")
        health = value.get("health")
        if health == "degraded":
            return self._degraded_view(catalog_digest)
        revision, managed_revision = value.get("revision"), value.get("managed_revision", 0)
        digest = value.get("catalog_digest")
        if type(revision) is not int or type(managed_revision) is not int or not isinstance(digest, str):
            raise ExtensionControlAuthorityError("invalid extension control authority view")
        try:
            authority_health = AuthorityHealth(health)
        except ValueError as exc:
            raise ExtensionControlAuthorityError("invalid extension control authority view") from exc
        return ExtensionControlAuthorityView(
            authority_health, revision, digest, layers_from_wire(value.get("layers")), managed_revision
        )

    def _read_extension_control_authority_locked(
        self,
        catalog_digest: str,
        *,
        migration_registry: CommandSafetyExtensionRegistry | None = None,
        allow_migration: bool = True,
    ) -> ExtensionControlAuthorityView:
        """Read the authority through the resident, doing the writer work it asks for.

        The resident never writes. Restoring the last-good export, resuming an
        interrupted migration, rolling back an abandoned transition and
        committing a catalog migration come back as actions; each runs here
        under the lease the caller holds, at most once, before asking again.
        """

        with self._connect() as connection:
            if not ensure_extension_control_authority_schema(connection, require_compatible=False):
                return self._degraded_view(catalog_digest)
        try:
            return self._read_through_resident(
                catalog_digest, migration_registry=migration_registry, allow_migration=allow_migration
            )
        except ExtensionControlAuthorityError:
            return self._tampered_view(catalog_digest)

    def _read_through_resident(
        self,
        catalog_digest: str,
        *,
        migration_registry: CommandSafetyExtensionRegistry | None,
        allow_migration: bool,
    ) -> ExtensionControlAuthorityView:
        migration = migration_registry is not None and migration_registry.catalog_digest == catalog_digest
        attempted: dict[str, bool] = {}
        current_manifest: dict[str, str] | None = None
        for _ in range(_MAX_READ_ROUNDS):
            try:
                key = self._authority_key(required=False)
                anchor_json = self._read_anchor_json() if key is not None else None
            except Exception:
                return self._degraded_view(catalog_digest)
            reply = self._extension_control_authority_op(
                "read",
                key=key,
                anchor_json=anchor_json,
                catalog_digest=catalog_digest,
                migration=migration,
                allow_migration=allow_migration,
                current_manifest=current_manifest,
                **attempted,
            )
            if "view" in reply:
                return self._view_from_wire(reply["view"], catalog_digest)
            if reply.get("need") == "current_manifest" and migration_registry is not None:
                current_manifest = self._catalog_target_manifest(migration_registry)
                continue
            action = reply.get("action")
            if not isinstance(action, dict) or key is None:
                raise ExtensionControlAuthorityError("invalid extension control authority reply")
            kind = action.get("action")
            if kind == "restore_last_good":
                with suppress(Exception):
                    self._restore_last_good_authority(anchor_from_wire(action.get("anchor")), key=key)
                attempted["restore_attempted"] = True
            elif kind == "resume_pending":
                resumed = self._resume_pending_catalog_migration(action, key=key)
                if resumed is not None and resumed.health is AuthorityHealth.PROTECTED:
                    return resumed
                attempted["resume_attempted"] = True
            elif kind == "roll_back_abandoned":
                self._roll_back_abandoned_transition(
                    int(cast(int, action["revision"])),
                    snapshot_digest=str(action["snapshot_digest"]),
                    anchor=anchor_from_wire(action.get("anchor")),
                    key=key,
                )
                attempted["rollback_attempted"] = True
            elif kind == "migrate_catalog" and migration_registry is not None:
                return self._migrate_extension_control_catalog(action, registry=migration_registry, key=key)
            else:
                raise ExtensionControlAuthorityError("invalid extension control authority action")
        raise ExtensionControlAuthorityError("extension control authority read did not settle")

    def _resume_pending_catalog_migration(
        self, action: Mapping[str, object], *, key: bytes
    ) -> ExtensionControlAuthorityView | None:
        pending = self._pending_transition(int(cast(int, action["revision"])))
        if pending is None:
            return None
        with self._connect() as connection:
            return self._resume_idempotent_transition(
                connection,
                pending,
                current=ExtensionControlAuthorityView(
                    AuthorityHealth.RECOVERY_REQUIRED,
                    int(cast(int, action["current_revision"])),
                    str(action["stored_catalog_digest"]),
                    (),
                ),
                catalog_digest=_row_str(pending, "catalog_digest"),
                layers_json=_row_str(pending, "layers_json"),
                actor_hash=_row_str(pending, "actor_id_hash"),
                idempotency_hash=_row_str(pending, "idempotency_key_hash"),
                nonce_hash=_row_str(pending, "nonce_hash"),
                expected_revision=_row_int(pending, "previous_revision"),
                key=key,
            )
