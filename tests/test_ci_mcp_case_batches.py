"""The CI-sized MCP batches must retain the complete native decision matrix."""

from collections import Counter

import pytest

from tests.mcp_case_batches import package_case_batches


@pytest.mark.parametrize("package_count", [1, 34, 80])
def test_native_mcp_batches_cover_every_original_case_exactly_once(package_count):
    original = [
        (f"mcp.example{index}", "npx", f"@example/server{index}", f"tool{tool}", "review")
        for index in range(package_count)
        for tool in range(3 + index % 2)
    ]
    batches = package_case_batches(original)
    flattened = [case for batch in batches for case in batch]
    packages = Counter(case[0] for case in original)
    assert len(batches) == min(64, len(packages))
    assert all(batches)
    assert Counter(flattened) == Counter(original)
    assert max(map(len, batches)) - min(map(len, batches)) <= max(packages.values())
    for identity in packages:
        assert sum(any(case[0] == identity for case in batch) for batch in batches) == 1


def test_empty_native_mcp_inventory_fails_instead_of_skipping_the_matrix():
    with pytest.raises(ValueError, match="must contain package cases"):
        package_case_batches([])
