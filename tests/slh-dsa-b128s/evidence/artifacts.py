#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Bounded independent verification of public transaction artifacts from any case.

Uses the unchanged G2 oracle and pinned Python/portable-C reference. No node,
signer, production verifier, build or network service is invoked.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
TRANSACTIONS = HERE.parent / "transactions"
REFERENCE = HERE.parent / "reference"
sys.path.insert(0, str(TRANSACTIONS))
import oracle  # noqa: E402
from check import bounded_file  # noqa: E402

MAX_ARTIFACTS = 18
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_SIGNATURES = 146
LIMITS = {"artifacts": MAX_ARTIFACTS, "file_bytes": MAX_FILE_BYTES,
          "total_bytes": MAX_TOTAL_BYTES, "signature_callbacks": MAX_SIGNATURES}
CLAIMS = {"producer_verified": False, "previous_outputs_authenticated": False,
          "node_acceptance": False, "daemon_primitive_entries_observed": False,
          "shielded_coverage": False, "production_comparison": False}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def preflight(paths):
    """Check all identities/schemas and aggregate work bounds before any crypto."""
    require(1 <= len(paths) <= MAX_ARTIFACTS, "artifact_count")
    prepared, identities, names, cases, hashes = [], set(), set(), set(), set()
    total_bytes = total_records = 0
    for path in paths:
        path = Path(path)
        require(re.fullmatch(r"[A-Za-z0-9_.-]{1,96}", path.name) is not None, "artifact_filename")
        raw = bounded_file(path, MAX_FILE_BYTES)
        metadata = path.stat()
        identity = (metadata.st_dev, metadata.st_ino)
        require(identity not in identities and path.name not in names, "duplicate_artifact_path")
        digest = oracle.sha256(raw)
        require(digest not in hashes, "duplicate_artifact_bytes")
        artifact = oracle.strict_json(raw)
        oracle.validate_schema(artifact)
        require(artifact["case_id"] not in cases, "duplicate_case_identity")
        identities.add(identity)
        names.add(path.name)
        hashes.add(digest)
        cases.add(artifact["case_id"])
        total_bytes += len(raw)
        total_records += sum(len(item["records"]) for item in artifact["inputs"])
        require(total_bytes <= MAX_TOTAL_BYTES, "aggregate_artifact_bytes")
        require(total_records <= MAX_SIGNATURES, "aggregate_signature_bound")
        prepared.append((path.name, raw))
    return prepared


def evaluate(prepared, verify):
    """Reconstruct every digest/message before independent signature verification."""
    calls = 0
    def bounded_verify(*args):
        nonlocal calls
        require(calls < MAX_SIGNATURES, "signature_callback_bound")
        calls += 1
        verdict = verify(*args)
        require(type(verdict) is bool, "independent_verdict_type")
        return verdict
    rows = []
    for name, raw in prepared:
        before = calls
        artifact, observed = oracle.evaluate(raw, bounded_verify)
        require(observed == artifact["expected"], "independent_expected_mismatch")
        rows.append({"file": name, "file_sha256": oracle.sha256(raw),
            "case_id": artifact["case_id"], "artifact_sha256": artifact["artifact_sha256"],
            "transaction_sha256": artifact["transaction_sha256"],
            "network": artifact["network"], "transaction_version": artifact["transaction_version"],
            "consensus_branch_id": artifact["consensus_branch_id"],
            "producer_claims_sha256": oracle.sha256(oracle.canonical(artifact["producer"])),
            "independent": observed, "signature_callbacks": calls - before})
    return rows, calls


def checker_hashes():
    paths = [HERE / "artifacts.py", TRANSACTIONS / "check.py", TRANSACTIONS / "oracle.py",
             TRANSACTIONS / "wire.py", REFERENCE / "reference.py", REFERENCE / "prepare.py",
             REFERENCE / "sources.json", REFERENCE / "hash_shim.c"]
    return {path.relative_to(ROOT).as_posix(): oracle.sha256(path.read_bytes()) for path in paths}


def reference_identity(inputs):
    """Bind the receipt and library both before loading and after verification."""
    build_raw = bounded_file(inputs / "hash-build.json", 65536)
    build = oracle.strict_json(build_raw)
    require(type(build) is dict and type(build.get("schema_version")) is int
            and build["schema_version"] == 1, "reference_build_schema")
    library_name = build.get("library_name")
    require(library_name in ("libslh_reference_blake3.dylib", "libslh_reference_blake3.so"), "reference_library")
    library_hash = oracle.sha256(bounded_file(inputs / library_name, 16 * 1024 * 1024))
    require(build.get("library_sha256") == library_hash, "reference_library_changed")
    return {"hash_build_sha256": oracle.sha256(build_raw), "library_sha256": library_hash}


def run(paths, reference_inputs, output, *, reference_factory=None):
    output = Path(output)
    require(not output.exists() and not output.is_symlink(), "fresh_receipt_required")
    require(output.parent.is_dir(), "receipt_parent_required")
    prepared = preflight(paths)
    before = checker_hashes()
    if reference_factory is None:
        sys.path.insert(0, str(REFERENCE))
        from reference import Reference
        reference_factory = Reference
    # The existing loader hash-checks every Python/C source and the loaded
    # portable library. Never treat its errors/timeouts as a negative signature.
    reference_inputs = Path(reference_inputs)
    reference_before = reference_identity(reference_inputs)
    reference = reference_factory(reference_inputs)
    vectors = reference.hash_vectors(reference_inputs)
    require(type(vectors) is int and vectors == 105, "official_hash_controls")
    rows, calls = evaluate(prepared, reference.verify)
    require(checker_hashes() == before, "checker_inputs_changed")
    require(reference_identity(reference_inputs) == reference_before, "reference_inputs_changed")
    receipt = {"schema_version": 1, "contract": oracle.CONTRACT,
        "scope": "independent-transparent-public-artifacts-v1", "complete": True,
        "completed_at_utc": datetime.now(timezone.utc).isoformat(), "limits": LIMITS,
        "claims": CLAIMS, "checker_sha256": before,
        "previous_outputs": "ordered caller-supplied artifact values; not authenticated UTXOs",
        "reference": {**reference_before, "official_blake3_controls": vectors},
        "artifacts": rows, "signature_callbacks": calls}
    # The exact bytes retained by preflight are the bytes parsed and hashed in
    # this receipt. Later file replacement cannot silently change this meaning.
    with output.open("x", encoding="ascii") as stream:
        json.dump(receipt, stream, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False)
        stream.write("\n")
    return receipt


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("reference_inputs", type=Path)
    result.add_argument("--artifact", action="append", type=Path, required=True)
    result.add_argument("--output", type=Path, required=True)
    return result


if __name__ == "__main__":
    arguments = parser().parse_args()
    checked = run(arguments.artifact, arguments.reference_inputs, arguments.output)
    print(f"{len(checked['artifacts'])} public artifacts independently checked; "
          f"{checked['signature_callbacks']} signature callbacks; no node acceptance claim")
