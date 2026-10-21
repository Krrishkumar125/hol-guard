"""Shared build-time reachability accounting and container inventory checks without directory rendering imports."""

import hashlib

from extension_delivery_located_store import LocatedStore

from codex_plugin_scanner.guard.catalog_delivery.containers import inspect


class InventoryStore(LocatedStore):
    def __init__(self, directory):
        super().__init__(directory)
        self.assets = {}

    def mark(self, kind, digest, length, target):
        key = (target["tag"], target["asset"])
        if "member" in target:
            row = self.assets.setdefault(
                key, {"kind": "container", "location": {"tag": key[0], "asset": key[1]}, "members": {}}
            )
            member = {"sha256": digest, "length": length}
            if row["kind"] != "container" or (
                target["member"] in row["members"] and row["members"][target["member"]] != member
            ):
                raise ValueError("delivery container has conflicting members")
            row["members"][target["member"]] = member
            return
        row = {"sha256": digest, "length": length, "kind": kind, "location": target}
        if key in self.assets and self.assets[key] != row:
            raise ValueError("delivery asset location has conflicting content")
        self.assets[key] = row

    def blob(self, reference, depth=0):
        value = super().blob(reference, depth)
        self.mark("object", reference["sha256"], reference["length"], reference["location"])
        return value


def verify_inventory(data, asset, expected):
    archive, infos = inspect(data, asset)
    with archive:
        if {info.filename for info in infos} != set(expected):
            raise ValueError("new delivery container includes unbound or missing members")
        for info in infos:
            spec = expected[info.filename]
            value = archive.read(info)
            if len(value) != spec["length"] or hashlib.sha256(value).hexdigest() != spec["sha256"]:
                raise ValueError("new delivery container member differs from authenticated reference")
