"""Build/publication-only exhaustive inventory from the package-bound Root."""

from __future__ import annotations

import tempfile
from pathlib import Path

from extension_delivery_inventory_store import InventoryStore
from extension_delivery_objects import entries
from extension_delivery_policy_lookup import read_transport_page, validate_record

from codex_plugin_scanner.guard.catalog_delivery.installed_bundle import target
from codex_plugin_scanner.guard.catalog_delivery.containers import member, verify_inventory
from codex_plugin_scanner.guard.extension_builder.io import read_bytes


def verify_reachable(directory, root, groups):
    with tempfile.TemporaryDirectory(prefix="guard-publication-inventory-") as temporary:
        store = InventoryStore(Path(temporary).resolve())

        def fetch(location, length):
            name, _, _ = target(location, source_sha=root["source_sha"])
            path, spec = groups[location["tag"]][location["asset"]]
            data = read_bytes(path, limit=spec["length"])
            return member(data, location["asset"], name, length) if "member" in location else data

        store.fetch = fetch
        policy = root["policy"]

        def walk(reference, native, count, prefix="", depth=0):
            if depth > 64:
                raise ValueError("installed publication transport depth invalid")
            wrapper, page = read_transport_page(store, reference, native, count, prefix)
            if page["kind"] == "branch":
                for index, (key, size, child) in enumerate(page["children"]):
                    walk(wrapper["children"][index][2], child, size, key, depth + 1)
                return
            for index, (identity, reference) in enumerate(page["entries"]):
                record = validate_record(store.json(wrapper["records"][index][1]), identity, reference)
                store.json(record["catalog_metadata"])
                for archive in record["archives"]:
                    target(archive["location"], source_sha=root["source_sha"])
                    if "member" in archive["location"]:
                        raise ValueError("installed publication policy archives must be independent")
                    store.mark("pack", archive["sha256"], archive["length"], archive["location"])

        native = policy["root"]
        walk(policy["transport"], native["index"], native["extensions"])
        rows = [policy["defaults"], policy["revocations"], *root.get("compatibility", {}).values()]
        for row in rows:
            for _, reference in entries(store, row["index"], row["count"]) if row["count"] else ():
                store.json(reference)
        actual = {(tag, name) for tag, rows in groups.items() for name in rows}
        if actual != set(store.assets):
            raise ValueError("installed publication inventory differs from Root reachability")
        for (tag, name), spec in store.assets.items():
            path, expected = groups[tag][name]
            if spec["kind"] == "container":
                verify_inventory(read_bytes(path, limit=expected["length"]), name, spec["members"])
            elif any(spec[field] != expected[field] for field in ("sha256", "length")):
                raise ValueError("installed publication asset differs from Root reference")
