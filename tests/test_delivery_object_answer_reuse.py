from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.catalog_delivery import lifecycle, object_native


@pytest.fixture
def replies(monkeypatch):
    requests = []
    answers = {}
    monkeypatch.setattr(lifecycle, "runtime_fingerprint", lambda: ((1, 2),))

    def native(**fields):
        requests.append(fields)
        return dict(answers.get(fields["reference"], {"data": "ZGF0YQ==", "reads": ["a"]}))

    monkeypatch.setattr(object_native, "_native", native)
    return requests, answers


def expand(reference="r", directory="/cache"):
    return object_native.addressed("expand", mode="pack", directory=directory, reference=reference, depth=0)


def test_a_verified_answer_is_reused_for_the_same_request(replies):
    requests, _answers = replies
    first = expand()
    first["reads"].append("changed")
    assert expand() == {"data": "ZGF0YQ==", "reads": ["a"]}
    assert len(requests) == 1

    expand(reference="other")
    expand(directory="/elsewhere")
    assert len(requests) == 3


def test_rejections_and_partial_answers_are_asked_again(replies):
    requests, answers = replies
    answers["bad"] = {"rejected": "delivery object integrity invalid"}
    answers["partial"] = {"need": [{"sha256": "s"}]}
    for _ in range(2):
        with pytest.raises(ValueError, match="integrity invalid"):
            expand(reference="bad")
        assert "need" in expand(reference="partial")
    assert len(requests) == 4


def test_a_replaced_or_missing_runtime_is_asked_again(replies, monkeypatch):
    requests, _answers = replies
    expand()
    monkeypatch.setattr(lifecycle, "runtime_fingerprint", lambda: ((3, 4),))
    expand()
    assert len(requests) == 2

    def missing():
        raise FileNotFoundError

    monkeypatch.setattr(lifecycle, "runtime_fingerprint", missing)
    expand()
    expand()
    assert len(requests) == 4


def test_answers_stay_within_their_byte_budget(replies, monkeypatch):
    requests, answers = replies
    monkeypatch.setattr(object_native, "_ANSWERS_LIMIT", 200)
    monkeypatch.setattr(object_native, "_ANSWER_LIMIT", 100)
    answers["large"] = {"data": "x" * 120, "reads": []}
    expand(reference="large")
    expand(reference="large")
    assert len(requests) == 2

    for index in range(6):
        expand(reference=str(index))
    assert sum(map(len, object_native._ANSWERS.values())) <= 200
    expand(reference="5")
    assert len(requests) == 8
    expand(reference="0")
    assert len(requests) == 9
