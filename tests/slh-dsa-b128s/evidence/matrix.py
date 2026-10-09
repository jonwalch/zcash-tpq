#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Check the node evidence index's schema, references and source hashes offline.

This is an index consistency check, never a test runner or acceptance verdict.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
MATRIX = HERE / "node-matrix.json"
KINDS = {"bounded_test_source", "bounded_tool_source", "human_case_prepared",
         "historical_receipt", "reference_source"}
CONTROLS = {
    "primitive": "answers contexts regions sizes profiles",
    "codec": "shapes caps maximum canonical binding precrypto",
    "transaction": "versions independent prevouts shielded-effects family",
    "dispatch": "resolved-only decoys fallback",
    "migration": "funding zero classical-quorum later-pq substitution",
    "mixed": "orders unsupported zero entrypoints lifecycle legal",
    "accounting": "transaction block template profiles atomic no-refund fresh",
    "publication": "complete-success identity selection parents separate maximum",
    "build": "feature-builds config isolation startup public-networks",
    "lifecycle": "queues rollback reorg same-txid prepared-cache",
    "history": "restart replay namespace contract durability",
    "compatibility": "classical active-slh policy shielded unsupported",
}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def fields(value, expected):
    require(type(value) is dict and set(value) == set(expected.split()), "exact_fields")


def string(value):
    require(type(value) is str and 0 < len(value) <= 2048, "bounded_string")


def strict_object(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, "duplicate_key")
        result[name] = value
    return result


def load(path=MATRIX):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 256 * 1024,
            "bounded_matrix_file")
    with path.open("rb") as stream:
        raw = stream.read(256 * 1024 + 1)
    require(len(raw) <= 256 * 1024, "bounded_matrix_file")
    return json.loads(raw, object_pairs_hook=strict_object)


def validate(value, root=ROOT):
    fields(value, "schema_version contract source_checkpoint scope human_execution functional_acceptance_complete references rows")
    require(type(value["schema_version"]) is int and value["schema_version"] == 1, "schema_version")
    require(value["contract"] == "slh-dsa-b-128s-exp-v1"
            and value["scope"] == "source-and-preparation-map-v1", "scope")
    require(type(value["source_checkpoint"]) is str
            and re.fullmatch("[0-9a-f]{40}", value["source_checkpoint"]) is not None, "checkpoint")
    require(value["human_execution"] == "pending"
            and value["functional_acceptance_complete"] is False, "no_acceptance_claim")
    refs = value["references"]
    require(type(refs) is dict and 1 <= len(refs) <= 256, "reference_count")
    root = root.resolve()
    cache = {}
    for name, item in refs.items():
        require(type(name) is str and re.fullmatch("[a-z0-9-]{1,64}", name) is not None, "reference_name")
        fields(item, "kind path anchor sha256 scope")
        require(type(item["kind"]) is str and item["kind"] in KINDS, "reference_kind")
        for field in ("path", "anchor", "scope", "sha256"):
            string(item[field])
        path = PurePosixPath(item["path"])
        require(not path.is_absolute() and path.as_posix() == item["path"]
                and ".." not in path.parts and "\\" not in item["path"], "relative_source_path")
        actual = root / path
        require(actual.resolve().is_relative_to(root)
                and not any(p.is_symlink() for p in [actual, *actual.parents] if p != root), "regular_source_path")
        require(actual.is_file() and actual.stat().st_size <= 8 * 1024 * 1024, "bounded_source_file")
        if path not in cache:
            with actual.open("rb") as stream:
                raw = stream.read(8 * 1024 * 1024 + 1)
            require(len(raw) <= 8 * 1024 * 1024, "bounded_source_file")
            cache[path] = (hashlib.sha256(raw).hexdigest(), raw.decode("utf-8"))
        digest, source = cache[path]
        require(re.fullmatch("[0-9a-f]{64}", item["sha256"]) is not None
                and digest == item["sha256"], "source_hash_changed")
        require(item["anchor"] in source, "source_anchor_missing")
    rows = value["rows"]
    require(type(rows) is list and len(rows) == len(CONTROLS), "twelve_rows_required")
    seen_rows = set()
    gaps = []
    for row in rows:
        fields(row, "id title subcontrols")
        key = row["id"]
        require(type(key) is str and key in CONTROLS and key not in seen_rows, "row_identity")
        seen_rows.add(key)
        string(row["title"])
        controls = row["subcontrols"]
        expected = set(CONTROLS[key].split())
        require(type(controls) is list and len(controls) == len(expected), "subcontrol_count")
        seen = set()
        for item in controls:
            fields(item, "id requirement evidence remaining_preparation")
            control = item["id"]
            require(type(control) is str and control in expected and control not in seen, "subcontrol_identity")
            seen.add(control)
            string(item["requirement"])
            evidence = item["evidence"]
            require(type(evidence) is list and 0 < len(evidence) <= 16
                    and all(type(e) is str and e in refs for e in evidence)
                    and len(set(evidence)) == len(evidence), "evidence_references")
            if item["remaining_preparation"] is not None:
                string(item["remaining_preparation"])
                gaps.append(f"{key}/{control}: {item['remaining_preparation']}")
    return gaps


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list-gaps", action="store_true")
    args = parser.parse_args()
    matrix = load()
    gaps = validate(matrix)
    print(f"12 rows / 63 subcontrols / {len(matrix['references'])} source references consistent; human acceptance pending")
    if args.list_gaps:
        print("\n".join(gaps))
