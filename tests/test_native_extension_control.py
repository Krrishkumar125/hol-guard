"""Extension-control answers come from the native runtime, bound and strictly decoded.

The composition and resolution rules are pinned by the Rust op's own tests and
by ``test_guard_extension_control_resolver.py`` against the real runtime. These
tests pin the Python side: the request it builds, how it splits a question
across requests, and that it presents only a bound, well-formed ``ok`` reply
and raises on anything else, with no Python answer to fall back to.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from codex_plugin_scanner.guard import native_daemon_route as route
from codex_plugin_scanner.guard import native_extension_control as bridge
from codex_plugin_scanner.guard import native_resident_decision as shared
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ComposedExtensionControls,
    ControlLayerKind,
    ControlResolverFailure,
    ControlState,
    ControlSurface,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
    ResolverFailureCode,
)
from codex_plugin_scanner.guard.runtime.extension_trust import trust_class_for

pytestmark = pytest.mark.native_route_unpinned

DIGEST = "a" * 64
EXTENSION = "command.git"
PERMISSION = "command.git.permission.push"
_UNBOUND_DIGEST = "sha256:" + "0" * 64


def _layer(
    kind: ControlLayerKind = ControlLayerKind.LOCAL_ADMIN,
    *controls: ExtensionControl,
    lockdown: bool = False,
) -> ExtensionControlLayer:
    return ExtensionControlLayer(CONTROL_SCHEMA_VERSION, kind, DIGEST, lockdown, controls)


def _disabled(kind: ControlTargetKind, target_id: str) -> ExtensionControl:
    return ExtensionControl(ControlTarget(kind, target_id), ControlState.DISABLED)


def _registry() -> SimpleNamespace:
    return SimpleNamespace(
        catalog_digest=DIGEST,
        extensions=(
            SimpleNamespace(
                extension_id=EXTENSION,
                aliases=("command.legacy-git",),
                dependencies=("command.shell",),
                required=False,
            ),
            SimpleNamespace(extension_id="command.shell", aliases=(), dependencies=(), required=True),
        ),
        permissions=(
            SimpleNamespace(
                permission_id=PERMISSION,
                extension_id=EXTENSION,
                dependencies=("command.shell.permission.run",),
                implied_permissions=("command.git.permission.fetch",),
            ),
        ),
    )


def _item_answer(**overrides: object) -> dict[str, object]:
    answer: dict[str, object] = {
        "blocked": False,
        "factor_reason_codes": [],
        "failures": [],
        "explicitly_enabled_permission_ids": [],
        "active": None,
    }
    answer.update(overrides)
    return answer


def _bound(request: dict[str, object], body: dict[str, object], **overrides: object) -> dict[str, object]:
    reply: dict[str, object] = {
        "schema": "guard-extension-control-result.v1",
        "request_id": request["request_id"],
        "request_sha256": "sha256:" + shared._canonical_request_sha256(request),
        "status": "ok",
        "code": "ok",
        "payload": body,
    }
    reply.update(overrides)
    return reply


def _resident(monkeypatch: pytest.MonkeyPatch, reply: Callable[[dict[str, object]], object]) -> list[dict[str, object]]:
    """Answer every ask with ``reply(request)``; the returned list collects the requests."""

    requests: list[dict[str, object]] = []
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=object(),
        capabilities=SimpleNamespace(features={"resident-protocol-v2", bridge.EXTENSION_CONTROL_FEATURE}),
    )

    def transport(*, request: dict[str, object], **_kwargs: object) -> object:
        requests.append(request)
        return reply(request)

    monkeypatch.setattr(shared, "native_runtime_status", lambda: status)
    monkeypatch.setattr(shared, "_resolve_digest_home", lambda _home: Path("/tmp/extension-control-home"))
    monkeypatch.setattr(shared, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(shared, "record_resident", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(route, "_resident_request", transport)
    return requests


def _resolve_payload(*scenarios: list[dict[str, object]], lockdown: bool = False) -> dict[str, object]:
    return {
        "kind": "resolve",
        "scenarios": [{"global_lockdown": lockdown, "results": list(results)} for results in scenarios],
    }


def _query(request: dict[str, object]) -> dict[str, Any]:
    return cast(dict[str, Any], request["query"])


def _echo(request: dict[str, object]) -> dict[str, object]:
    """Answer every asked item, echoing its extension ids as reason codes so order is observable."""

    return _bound(
        request,
        _resolve_payload(
            *[
                [
                    _item_answer(
                        blocked=bool(item["extension_ids"]),
                        factor_reason_codes=list(item["extension_ids"]),
                        active=None if item["active_extension_id"] is None else True,
                    )
                    for item in scenario["items"]
                ]
                for scenario in _query(request)["scenarios"]
            ]
        ),
    )


def test_compose_sends_every_layer_field_and_presents_the_composition(monkeypatch: pytest.MonkeyPatch) -> None:
    body = {
        "kind": "compose",
        "composed": {
            "global_lockdown": True,
            "controls": [{"target_kind": "extension", "target_id": EXTENSION, "state": "disabled"}],
            "failures": [{"code": "duplicate-layer-kind", "layer_kind": "local-admin"}],
        },
    }
    requests = _resident(monkeypatch, lambda request: _bound(request, body))
    layers = (
        _layer(ControlLayerKind.LOCAL_ADMIN, _disabled(ControlTargetKind.EXTENSION, EXTENSION)),
        _layer(ControlLayerKind.SIGNED_CLOUD, lockdown=True),
    )

    composed = bridge.compose_control_layers(layers)

    assert composed == ComposedExtensionControls(
        True,
        (_disabled(ControlTargetKind.EXTENSION, EXTENSION),),
        (ControlResolverFailure(ResolverFailureCode.DUPLICATE_LAYER_KIND, ControlLayerKind.LOCAL_ADMIN),),
    )
    assert len(requests) == 1
    assert requests[0]["schema"] == "guard-extension-control-request.v1"
    assert requests[0]["query"] == {
        "kind": "compose",
        "layers": [
            {
                "schema_version": "1.0.0",
                "kind": "local-admin",
                "catalog_digest": DIGEST,
                "global_lockdown": False,
                "controls": [{"target_kind": "extension", "target_id": EXTENSION, "state": "disabled"}],
            },
            {
                "schema_version": "1.0.0",
                "kind": "signed-cloud",
                "catalog_digest": DIGEST,
                "global_lockdown": True,
                "controls": [],
            },
        ],
    }


def test_compose_of_no_layers_still_asks_the_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    body = {"kind": "compose", "composed": {"global_lockdown": False, "controls": [], "failures": []}}
    requests = _resident(monkeypatch, lambda request: _bound(request, body))

    assert bridge.compose_control_layers(()) == ComposedExtensionControls(False, (), ())
    assert requests[0]["query"] == {"kind": "compose", "layers": []}


def test_resolve_sends_the_registry_projection_and_every_item_field(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = _resident(monkeypatch, _echo)
    scenario = bridge.ControlScenario(
        (_layer(),),
        (
            bridge.ControlItem((EXTENSION,), (PERMISSION,)),
            bridge.ControlItem(active_extension_id=EXTENSION),
        ),
        ControlSurface.TRUSTED_LOCAL_RECOVERY,
        ResolverFailureCode.AUTHORITY_TAMPERED,
    )

    [answered] = bridge.resolve_scenarios(_registry(), (scenario,))
    assert [item.active for item in answered.items] == [None, True]

    query = _query(requests[0])
    assert query["kind"] == "resolve"
    assert query["registry"] == {
        "catalog_digest": DIGEST,
        "extensions": [
            {
                "extension_id": EXTENSION,
                "aliases": ["command.legacy-git"],
                "dependencies": ["command.shell"],
                "required": False,
                "trust_class": None,
            },
            {"extension_id": "command.shell", "aliases": [], "dependencies": [], "required": True, "trust_class": None},
        ],
        "permissions": [
            {
                "permission_id": PERMISSION,
                "extension_id": EXTENSION,
                "dependencies": ["command.shell.permission.run"],
                "implied_permissions": ["command.git.permission.fetch"],
            }
        ],
    }
    [wire] = query["scenarios"]
    assert wire["surface"] == "trusted-local-recovery"
    assert wire["authority_failure"] == "authority-tampered"
    assert wire["items"] == [
        {"extension_ids": [EXTENSION], "permission_ids": [PERMISSION], "active_extension_id": None},
        {"extension_ids": [], "permission_ids": [], "active_extension_id": EXTENSION},
    ]


def test_resolve_sends_the_curated_trust_class_only_when_asked(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = _resident(monkeypatch, lambda request: _bound(request, _resolve_payload([_item_answer(active=True)])))
    scenario = bridge.ControlScenario((_layer(),), (bridge.ControlItem(active_extension_id=EXTENSION),))

    answer = bridge.resolve_scenarios(_registry(), (scenario,), trust_classes=True)[0].items[0]

    assert answer.active is True
    query = _query(requests[0])
    classes = [extension["trust_class"] for extension in query["registry"]["extensions"]]
    assert classes == [trust_class_for(EXTENSION), trust_class_for("command.shell")]
    [wire] = query["scenarios"]
    assert wire["authority_failure"] is None
    assert wire["surface"] == "command-evaluation"


def test_resolve_presents_blocking_reasons_failures_and_enabled_permissions(monkeypatch: pytest.MonkeyPatch) -> None:
    answer = _item_answer(
        blocked=True,
        factor_reason_codes=["control.disabled-extension"],
        failures=[
            {"code": "catalog-digest-mismatch", "layer_kind": "signed-cloud"},
            {"code": "unknown-extension-target", "layer_kind": None},
        ],
        explicitly_enabled_permission_ids=[PERMISSION],
    )
    _resident(monkeypatch, lambda request: _bound(request, _resolve_payload([answer], lockdown=True)))

    result = bridge.resolve_scenarios(
        _registry(), (bridge.ControlScenario((_layer(),), (bridge.ControlItem((EXTENSION,)),)),)
    )

    assert result == (
        bridge.ScenarioAnswer(
            True,
            (
                bridge.ControlAnswer(
                    True,
                    ("control.disabled-extension",),
                    (
                        ControlResolverFailure(
                            ResolverFailureCode.CATALOG_DIGEST_MISMATCH, ControlLayerKind.SIGNED_CLOUD
                        ),
                        ControlResolverFailure(ResolverFailureCode.UNKNOWN_EXTENSION_TARGET, None),
                    ),
                    (PERMISSION,),
                    None,
                ),
            ),
        ),
    )


def test_resolve_keeps_only_the_layers_the_resolver_admits_plus_one(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = _resident(monkeypatch, _echo)
    layers = tuple(_layer(ControlLayerKind.LOCAL_ADMIN) for _ in range(bridge.MAX_CONTROL_LAYERS + 4))

    bridge.resolve_scenarios(_registry(), (bridge.ControlScenario(layers, (bridge.ControlItem((EXTENSION,)),)),))

    query = _query(requests[0])
    assert len(query["scenarios"][0]["layers"]) == bridge.MAX_CONTROL_LAYERS + 1


def test_resolve_of_no_scenarios_asks_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = _resident(monkeypatch, lambda request: pytest.fail("resident must not be asked"))

    assert bridge.resolve_scenarios(_registry(), ()) == ()
    assert requests == []


def test_a_scenario_without_items_is_still_asked_and_answered(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = _resident(monkeypatch, _echo)

    result = bridge.resolve_scenarios(_registry(), (bridge.ControlScenario((_layer(),), ()),))

    assert result == (bridge.ScenarioAnswer(False, ()),)
    assert len(requests) == 1


def test_items_beyond_one_requests_bound_are_split_and_reassembled_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = _resident(monkeypatch, _echo)
    count = bridge._MAX_ITEMS_PER_REQUEST * 2 + 1
    scenario = bridge.ControlScenario(
        (_layer(),), tuple(bridge.ControlItem((f"command.item{index}",)) for index in range(count))
    )

    [answered] = bridge.resolve_scenarios(_registry(), (scenario,))

    assert [len(_query(request)["scenarios"][0]["items"]) for request in requests] == [
        bridge._MAX_ITEMS_PER_REQUEST,
        bridge._MAX_ITEMS_PER_REQUEST,
        1,
    ]
    assert [item.reason_codes for item in answered.items] == [(f"command.item{index}",) for index in range(count)]


def test_scenarios_beyond_one_requests_bound_are_split_and_answered_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = _resident(monkeypatch, _echo)
    count = bridge._MAX_SCENARIOS_PER_REQUEST + 3
    scenarios = tuple(
        bridge.ControlScenario((_layer(),), (bridge.ControlItem((f"command.scenario{index}",)),))
        for index in range(count)
    )

    answered = bridge.resolve_scenarios(_registry(), scenarios)

    assert [len(_query(request)["scenarios"]) for request in requests] == [
        bridge._MAX_SCENARIOS_PER_REQUEST,
        3,
    ]
    assert [scenario.items[0].reason_codes for scenario in answered] == [
        (f"command.scenario{index}",) for index in range(count)
    ]


def test_every_piece_of_one_scenario_must_agree_on_the_lockdown(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[bool] = []

    def reply(request: dict[str, object]) -> dict[str, object]:
        reply = _echo(request)
        seen.append(len(seen) == 1)
        for scenario in cast(dict[str, Any], reply["payload"])["scenarios"]:
            scenario["global_lockdown"] = seen[-1]
        return reply

    _resident(monkeypatch, reply)
    scenario = bridge.ControlScenario(
        (_layer(),), tuple(bridge.ControlItem((EXTENSION,)) for _ in range(bridge._MAX_ITEMS_PER_REQUEST + 1))
    )

    with pytest.raises(bridge.NativeExtensionControlError) as caught:
        bridge.resolve_scenarios(_registry(), (scenario,))
    assert caught.value.code == "native_extension_control_payload_invalid"


def test_resolve_extension_controls_answers_one_item(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident(
        monkeypatch,
        lambda request: _bound(request, _resolve_payload([_item_answer(blocked=True)])),
    )

    answer = bridge.resolve_extension_controls(
        (_layer(),),
        _registry(),
        extension_ids=(EXTENSION,),
        permission_ids=(),
        surface=ControlSurface.COMMAND_EVALUATION,
    )

    assert answer.blocked is True
    assert answer.active is None


_COMPOSED: dict[str, object] = {"global_lockdown": False, "controls": [], "failures": []}


@pytest.mark.parametrize(
    "payload",
    [
        {"kind": "compose"},
        {"kind": "compose", "composed": []},
        {"kind": "compose", "composed": {**_COMPOSED, "extra": 1}},
        {"kind": "compose", "composed": {"global_lockdown": False, "controls": []}},
        {"kind": "compose", "composed": {**_COMPOSED, "global_lockdown": 1}},
        {"kind": "compose", "composed": {**_COMPOSED, "controls": "none"}},
        {"kind": "compose", "composed": {**_COMPOSED, "controls": [{"target_kind": "extension"}]}},
        {
            "kind": "compose",
            "composed": {
                **_COMPOSED,
                "controls": [{"target_kind": "extension", "target_id": EXTENSION, "state": "maybe"}],
            },
        },
        {
            "kind": "compose",
            "composed": {
                **_COMPOSED,
                "controls": [{"target_kind": "extension", "target_id": "Not A Target", "state": "enabled"}],
            },
        },
        {"kind": "compose", "composed": {**_COMPOSED, "failures": [{"code": "made-up", "layer_kind": None}]}},
        {
            "kind": "compose",
            "composed": {**_COMPOSED, "failures": [{"code": "duplicate-layer-kind", "layer_kind": "other"}]},
        },
        {"kind": "compose", "composed": {**_COMPOSED, "failures": [{"code": "duplicate-layer-kind"}]}},
        {"kind": "compose", "composed": {**_COMPOSED, "failures": {}}},
    ],
)
def test_a_malformed_composition_raises(monkeypatch: pytest.MonkeyPatch, payload: dict[str, object]) -> None:
    _resident(monkeypatch, lambda request: _bound(request, payload))

    with pytest.raises(bridge.NativeExtensionControlError) as caught:
        bridge.compose_control_layers((_layer(),))
    assert caught.value.code == "native_extension_control_payload_invalid"


@pytest.mark.parametrize(
    "payload",
    [
        _resolve_payload(),
        _resolve_payload([_item_answer()], [_item_answer()]),
        _resolve_payload([]),
        _resolve_payload([_item_answer(), _item_answer()]),
        {"kind": "resolve", "scenarios": [{"global_lockdown": False}]},
        {"kind": "resolve", "scenarios": [{"global_lockdown": 0, "results": [_item_answer()]}]},
        {"kind": "resolve", "scenarios": [{"global_lockdown": False, "results": [_item_answer()], "extra": 1}]},
        {"kind": "resolve", "scenarios": "none"},
        {"kind": "resolve", "scenarios": [None]},
        _resolve_payload([{**_item_answer(), "extra": 1}]),
        _resolve_payload([{key: value for key, value in _item_answer().items() if key != "failures"}]),
        _resolve_payload([_item_answer(blocked="yes")]),
        _resolve_payload([_item_answer(blocked=1)]),
        _resolve_payload([_item_answer(factor_reason_codes="control.x")]),
        _resolve_payload([_item_answer(factor_reason_codes=[1])]),
        _resolve_payload([_item_answer(explicitly_enabled_permission_ids=[None])]),
        _resolve_payload([_item_answer(failures=[{"code": "made-up", "layer_kind": None}])]),
        _resolve_payload([_item_answer(active=True)]),
        _resolve_payload([_item_answer(active="yes")]),
        {"kind": "compose", "composed": _COMPOSED},
    ],
)
def test_a_malformed_resolution_raises(monkeypatch: pytest.MonkeyPatch, payload: dict[str, object]) -> None:
    _resident(monkeypatch, lambda request: _bound(request, payload))
    scenario = bridge.ControlScenario((_layer(),), (bridge.ControlItem((EXTENSION,)),))

    with pytest.raises(bridge.NativeExtensionControlError):
        bridge.resolve_scenarios(_registry(), (scenario,))


def test_an_item_that_asked_for_activity_must_be_answered_with_a_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident(monkeypatch, lambda request: _bound(request, _resolve_payload([_item_answer(active=None)])))
    scenario = bridge.ControlScenario((_layer(),), (bridge.ControlItem(active_extension_id=EXTENSION),))

    with pytest.raises(bridge.NativeExtensionControlError) as caught:
        bridge.resolve_scenarios(_registry(), (scenario,), trust_classes=True)
    assert caught.value.code == "native_extension_control_payload_invalid"


@pytest.mark.parametrize("active", [True, False])
def test_the_activity_verdict_is_presented_exactly(monkeypatch: pytest.MonkeyPatch, active: bool) -> None:
    _resident(monkeypatch, lambda request: _bound(request, _resolve_payload([_item_answer(active=active)])))
    scenario = bridge.ControlScenario((_layer(),), (bridge.ControlItem(active_extension_id=EXTENSION),))

    answer = bridge.resolve_scenarios(_registry(), (scenario,), trust_classes=True)[0].items[0]

    assert answer.active is active


@pytest.mark.parametrize(
    "mutate",
    [
        lambda request: None,
        lambda request: [],
        lambda request: _bound(request, _resolve_payload([_item_answer()]), request_id="someone-else"),
        lambda request: _bound(request, _resolve_payload([_item_answer()]), request_sha256=_UNBOUND_DIGEST),
        lambda request: _bound(request, _resolve_payload([_item_answer()]), schema="guard-extension-control-result.v0"),
        lambda request: _bound(request, _resolve_payload([_item_answer()]), status="denied"),
        lambda request: _bound(request, _resolve_payload([_item_answer()]), code="other"),
        lambda request: _bound(request, _resolve_payload([_item_answer()]), payload=None),
        lambda request: _bound(request, {**_resolve_payload([_item_answer()]), "kind": "compose"}),
        lambda request: _bound(request, _resolve_payload([_item_answer()]), status="error", code="not-a-code"),
    ],
)
def test_an_unbound_reply_raises(
    monkeypatch: pytest.MonkeyPatch, mutate: Callable[[dict[str, object]], object]
) -> None:
    _resident(monkeypatch, mutate)
    scenario = bridge.ControlScenario((_layer(),), (bridge.ControlItem((EXTENSION,)),))

    with pytest.raises(bridge.NativeExtensionControlError) as caught:
        bridge.resolve_scenarios(_registry(), (scenario,))
    assert caught.value.code == "native_extension_control_unavailable"


def test_a_rejected_request_raises_with_the_runtimes_code(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident(
        monkeypatch,
        lambda request: _bound(
            request, {}, status="error", code="native_extension_control_registry_invalid", payload=None
        ),
    )
    scenario = bridge.ControlScenario((_layer(),), (bridge.ControlItem((EXTENSION,)),))

    with pytest.raises(bridge.NativeExtensionControlError) as caught:
        bridge.resolve_scenarios(_registry(), (scenario,))
    assert caught.value.code == "native_extension_control_registry_invalid"
    with pytest.raises(bridge.NativeExtensionControlError) as composed:
        bridge.compose_control_layers((_layer(),))
    assert composed.value.code == "native_extension_control_registry_invalid"


def test_no_runtime_is_no_answer_and_never_a_default_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident(monkeypatch, lambda request: pytest.fail("resident must not be asked"))
    monkeypatch.setattr(shared, "ensure_resident_prerequisite", lambda _home: False)
    scenario = bridge.ControlScenario((_layer(),), (bridge.ControlItem((EXTENSION,)),))

    with pytest.raises(bridge.NativeExtensionControlError) as resolving:
        bridge.resolve_scenarios(_registry(), (scenario,))
    with pytest.raises(bridge.NativeExtensionControlError) as composing:
        bridge.compose_control_layers((_layer(),))
    assert resolving.value.code == composing.value.code == "native_extension_control_unavailable"


def test_a_failed_later_request_fails_the_whole_question(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[int] = []

    def reply(request: dict[str, object]) -> object:
        asked.append(len(asked))
        return _echo(request) if len(asked) == 1 else None

    _resident(monkeypatch, reply)
    scenario = bridge.ControlScenario(
        (_layer(),), tuple(bridge.ControlItem((EXTENSION,)) for _ in range(bridge._MAX_ITEMS_PER_REQUEST + 1))
    )

    with pytest.raises(bridge.NativeExtensionControlError):
        bridge.resolve_scenarios(_registry(), (scenario,))
    assert len(asked) == 2
