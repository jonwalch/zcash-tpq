#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Independently check 18 public transactions and <=60 mutation controls."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import subprocess
import sys

import mutations
import oracle
import wire

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
REFERENCE = HERE.parent / "reference"
NAMES = {f"v{version}-{shape}" for version in (5, 6) for shape in (
    "1of1", "2of3", "3of5", "8of10", "10of10", "15of15", "1of15-index14", "16checks", "17checks")}
HOST_PATHS = (
    "Cargo.toml", "tests/slh-dsa-b128s/fixtures/host", "tests/slh-dsa-b128s/fixtures/generate_transactions.py",
    "crates/pq-slh-dsa-b-exp", "crates/pq-slh-dsa-b-verify", "crates/pq-tx-context", "crates/pq-test-support", "crates/zakura-chain",
)
SIGNER_PATHS = ("tests/slh-dsa-b128s/fixture-signer", "crates/pq-slh-dsa-b-verify")
REPLAY_RECEIPT = HERE / "receipts/g2-review-2026-10-09.json"
REPLAY_RECEIPT_SHA256 = "2313fb725ed873e59efef6e16fecf2ff742d6fec3584f7e93eeb5498c60470d4"


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def bounded_file(path, maximum=oracle.MAX_JSON):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= maximum, "bounded regular input required")
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    require(len(raw) <= maximum, "file grew beyond bound")
    return raw


def inventory(source, paths):
    listed = subprocess.check_output(["git", "-C", str(source), "ls-files", "-z", "--", *paths], timeout=30)
    names = sorted(name.decode("ascii") for name in listed.split(b"\0") if name)
    require(names, "empty source inventory")
    clean = subprocess.check_output(["git", "-C", str(source), "status", "--porcelain", "--", *paths], timeout=30)
    require(not clean, "source inventory must be committed and clean")
    items = []
    for name in names:
        path = Path(name)
        if path.name == "Cargo.lock" or any(part in ("target", "__pycache__", ".git") for part in path.parts):
            continue
        actual = source / path
        require(not actual.is_symlink() and actual.is_file(), "inventory source must be regular")
        items.append({"path": name, "sha256": oracle.sha256(actual.read_bytes())})
    return items


def producer_receipt(source, host, signer):
    host_inventory, signer_inventory = inventory(source, HOST_PATHS), inventory(source, SIGNER_PATHS)
    require(host.is_file() and signer.is_file(), "both invoked binaries required for producer verification")
    claims = {
        "zakura_revision": "9b175e9d3d46a6aa4cfb5552517c3d828852ecbc",
        "algorithm_revision": "b392fe82d2d9770142477a576a758a233888bc0a",
        "blake3_version": "1.8.5",
        "host_source_inventory_sha256": oracle.sha256(oracle.canonical(host_inventory)),
        "signer_source_inventory_sha256": oracle.sha256(oracle.canonical(signer_inventory)),
        "host_lock_sha256": oracle.sha256((source / "Cargo.lock").read_bytes()),
        "signer_lock_sha256": oracle.sha256((source / "tests/slh-dsa-b128s/fixture-signer/Cargo.lock").read_bytes()),
        "host_binary_sha256": oracle.sha256(host.read_bytes()),
        "signer_binary_sha256": oracle.sha256(signer.read_bytes()),
    }
    return {"claims": claims, "host_source_inventory": host_inventory, "signer_source_inventory": signer_inventory,
            "source_commit": subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True, timeout=30).strip()}


def candidate(binary, raw):
    # Preserve duplicate/numeric spelling mutations inside the artifact rather
    # than round-tripping them through a permissive JSON parser.
    request = b'{"schema_version":1,"contract":"' + oracle.CONTRACT.encode() + b'","public_fixture":true,"op":"check","artifact":' + raw + b'}'
    require(len(request) <= oracle.MAX_JSON, "candidate request bound")
    result = subprocess.run([str(binary)], input=request, capture_output=True, timeout=90, check=True)
    require(len(result.stdout) <= oracle.MAX_JSON and len(result.stderr) <= 65536, "candidate output bound")
    response = oracle.strict_json(result.stdout)
    common = {"schema_version", "contract", "public_fixture", "op", "ok"}
    require(type(response) is dict and type(response.get("ok")) is bool, "candidate envelope")
    require(set(response) == common | ({"result"} if response["ok"] else {"error"}), "candidate fields")
    require(type(response["schema_version"]) is int and response["schema_version"] == 1
            and response["contract"] == oracle.CONTRACT and response["public_fixture"] is True
            and (response["op"] == "check" or (not response["ok"] and response["op"] == "unknown")), "candidate identity")
    if response["ok"]:
        body = response["result"]
        require(type(body) is dict and set(body) == {"observed", "expectation_match"}
                and type(body["expectation_match"]) is bool, "candidate result")
        oracle.expected_schema(body["observed"])
    else:
        error = response["error"]
        require(type(error) is dict and set(error) == {"stage", "reason"}, "candidate error")
        require(error["stage"] in ("transport", "schema", "integrity", "correspondence", "generation")
                and type(error["reason"]) is str, "candidate error vocabulary")
    return response


def corpus_contract(artifact):
    """Enforce fixed recipes and coverage independently of producer claims."""
    case = artifact["case_id"]
    require(case in NAMES and artifact["network"] == "Regtest", "corpus identity")
    version = int(case[1])
    require(artifact["transaction_version"] == version and artifact["consensus_branch_id"] == oracle.NU7, "corpus header")
    tx = wire.parse_transaction(bytes.fromhex(artifact["transaction_hex"]))
    require(tx["lock_time"] == 5 and tx["expiry"] == 140, "corpus heights")
    shape = case[3:]
    shapes = {"16checks": [(15, 15), (1, 1)], "17checks": [(15, 15), (2, 3)], "1of15-index14": [(1, 15)]}
    policies = shapes[shape] if shape in shapes else [tuple(int(value) for value in shape.split("of"))]
    require(len(artifact["inputs"]) == len(policies), "corpus input count")
    for index, (item, (m, n)) in enumerate(zip(artifact["inputs"], policies)):
        descriptor = bytes.fromhex(item["descriptor_hex"])
        threshold, commitments = oracle.decode_policy(descriptor)
        require(threshold == m and len(commitments) == n, "corpus policy")
        selected = [14] if shape == "1of15-index14" else list(range(m))
        require([record["signer_index"] for record in item["records"]] == selected, "corpus indices")
        require(item["sequence"] == 0xfffffffe and item["spent_output"]["value_zat"] == 100000, "corpus input value")
        display = oracle.sha256(b"Zakura/SLH-public-corpus/outpoint/v1\0" + case.encode() + b"\0" + wire.le32(index))
        require(item["outpoint"]["txid_display_hex"] == display and item["outpoint"]["index"] == index + 1, "corpus outpoint")
    script = oracle.lock_script(bytes.fromhex(artifact["inputs"][0]["descriptor_hex"])).hex()
    require(artifact["outputs"] == [{"output_index": index, "value_zat": value, "script_hex": script} for index, value in enumerate((20000, 30000))], "corpus outputs")


def check_corpus(directory, reference, host=None, producer=None):
    files = sorted(directory.glob("*.json"))
    require({path.stem for path in files} == NAMES, "corpus must have exactly the prescribed 18 JSON artifacts")
    artifacts, results, file_hashes = {}, [], {}
    for path in files:
        raw = bounded_file(path)
        # Independent reconstruction and crypto always precede the candidate.
        artifact, observed = oracle.evaluate(raw, reference.verify)
        require(artifact["case_id"] == path.stem, "filename identity")
        corpus_contract(artifact)
        require(observed == artifact["expected"], f"independent expected mismatch: {path.stem}")
        require(observed["native_authorization"] == "accept", f"initial corpus native rejection: {path.stem}")
        if producer is not None:
            require(artifact["producer"] == producer["claims"], "producer inputs/binary mismatch")
        comparison = candidate(host, raw) if host else None
        if comparison:
            require(comparison["ok"] and comparison["result"] == {"observed": observed, "expectation_match": True}, f"candidate disagreement: {path.stem}")
        artifacts[path.stem] = artifact
        file_hashes[path.name] = oracle.sha256(raw)
        results.append({"case_id": path.stem, "artifact_sha256": artifact["artifact_sha256"], "independent": observed, "candidate": comparison})
    require(sum(item["independent"]["signature_checks"] for item in results) == 146, "bounded corpus signature count")
    mutation_results = []
    for case in mutations.controls(artifacts):
        try:
            _, observed = oracle.evaluate(case["raw"], reference.verify)
            require(case["interface_stage"] is None and observed == case["outcome"], f"independent mutation result: {case['name']}")
            independent = {"observed": observed}
        except oracle.InterfaceFailure as failure:
            require(case["interface_stage"] == failure.stage, f"independent mutation failure: {case['name']}: {failure}")
            independent = {"error": {"stage": failure.stage, "reason": failure.reason}}
        comparison = candidate(host, case["raw"]) if host else None
        if comparison:
            if case["interface_stage"] is not None:
                require(not comparison["ok"] and comparison["error"]["stage"] == case["interface_stage"], f"candidate mutation stage: {case['name']}: {comparison}")
            else:
                require(comparison["ok"] and comparison["result"] == {"observed": case["outcome"], "expectation_match": True}, f"candidate mutation result: {case['name']}: {comparison}")
        mutation_results.append({"name": case["name"], "request_sha256": oracle.sha256(case["raw"]), "independent": independent, "candidate": comparison})
    # Source-domain framing rejection uses the same independent primitive only.
    first = artifacts["v5-1of1"]["inputs"][0]
    record = first["records"][0]
    public, signature, message = (bytes.fromhex(value) for value in (record["public_key_hex"], record["signature_hex"], first["message_hex"]))
    altered = message.replace(b"/message/v1\0", b"/message/v0\0", 1)
    require(altered != message and not reference.verify(public, signature, altered, b""), "old-domain control")
    require(not reference.verify(public, signature, b"\0\0" + message, b""), "double Pure framing control")
    return {"corpus_files": file_hashes, "cases": results, "mutations": mutation_results,
            "primitive_message_controls": {"old_message_domain": False, "double_pure_framing": False}}


def replay_inputs(directory):
    """Retain the historical producer and exact corpus before any comparison."""
    raw = bounded_file(REPLAY_RECEIPT)
    require(oracle.sha256(raw) == REPLAY_RECEIPT_SHA256, "retained producer receipt changed")
    original = oracle.strict_json(raw)
    files = sorted(directory.glob("*.json"))
    require({path.stem for path in files} == NAMES, "retained corpus requires the prescribed 18 artifacts")
    hashes = {path.name: oracle.sha256(bounded_file(path)) for path in files}
    require(hashes == original["corpus_files"], "retained corpus changed")
    return original["artifact_producer_verification"], hashes


def replay_checker_files():
    paths = sorted(HERE.glob("*.py")) + sorted(REFERENCE.glob("*.py"))
    paths += [REFERENCE / name for name in ("sources.json", "hash_shim.c")]
    paths += [HERE.parent / name for name in (
        "acceptance/common.py", "acceptance/build.py", "evidence/artifacts.py",
        "fixtures/generate_transactions.py")]
    return {path.relative_to(ROOT).as_posix(): oracle.sha256(path.read_bytes()) for path in paths}


def replay_corpus(args):
    """Reuse the checked comparison flow without attributing old signatures to a new host."""
    sys.path[:0] = [str(REFERENCE), str(HERE.parent / "acceptance"), str(HERE.parent / "evidence")]
    from reference import Reference
    from prepare import SOURCES
    from common import source_state, validate_build
    from artifacts import reference_identity

    source = args.candidate_source_tree.resolve()
    host = args.comparison_host.resolve(strict=True)
    require(not args.comparison_host.is_symlink() and host.is_file(), "comparison host must be regular")
    before = source_state(source)
    checker_files = replay_checker_files()
    inventory_before = inventory(source, HOST_PATHS)
    build_raw = bounded_file(args.comparison_build)
    build = oracle.strict_json(build_raw)
    validate_build(build, host, "host", root=source)
    corpus = args.corpus.resolve()
    original, corpus_hashes = replay_inputs(corpus)
    inputs = args.reference_inputs.resolve()
    reference_before = reference_identity(inputs)
    reference = Reference(inputs)
    hash_controls = reference.hash_vectors(inputs)
    require(type(hash_controls) is int and hash_controls == 105, "official hash controls")
    checked = check_corpus(corpus, reference, host, original)
    require(len(checked["cases"]) == 18 and len(checked["mutations"]) == 60,
            "bounded comparison coverage")
    require(checked["corpus_files"] == corpus_hashes, "checked corpus changed")
    require(replay_inputs(corpus) == (original, corpus_hashes), "retained corpus changed during comparison")
    require(bounded_file(args.comparison_build) == build_raw, "comparison build receipt changed")
    validate_build(build, host, "host", root=source)
    require(source_state(source) == before and inventory(source, HOST_PATHS) == inventory_before,
            "comparison source changed")
    require(replay_checker_files() == checker_files, "comparison checker changed")
    require(reference_identity(inputs) == reference_before, "comparison reference changed")
    return {
        "schema_version": 1,
        "scope": "Bounded independent transparent corpus/native comparison; no signing, node, live, proof or wallet acceptance",
        "completed_at_utc": datetime.now(timezone.utc).isoformat(),
        "python": sys.version, "platform": platform.platform(),
        "artifact_producer_and_comparison_target_are_distinct": True,
        "original_producer_receipt_sha256": REPLAY_RECEIPT_SHA256,
        "artifact_producer_verification": original,
        "comparison_target": {"source_commit": before["source_commit"],
                              "host_source_inventory": inventory_before,
                              "build": build, "build_receipt_sha256": oracle.sha256(build_raw)},
        "official_blake3_controls": hash_controls,
        "reference_sources": SOURCES,
        "reference_identity": reference_before,
        "checker_files": checker_files,
        **checked,
    }


def parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reference_inputs", type=Path)
    parser.add_argument("--corpus", type=Path, default=HERE.parent / "fixtures/data")
    parser.add_argument("--host", type=Path)
    parser.add_argument("--signer", type=Path)
    parser.add_argument("--comparison-host", type=Path,
                        help="compare a newly built host against the retained corpus; no signer required")
    parser.add_argument("--comparison-build", type=Path,
                        help="matching acceptance/build.py host receipt for --comparison-host")
    parser.add_argument("--candidate-source-tree", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def validate_mode(args):
    require(not args.output.exists() and not args.output.is_symlink(), "receipt destination must be new")
    comparison = args.comparison_host is not None or args.comparison_build is not None
    if comparison:
        require(args.comparison_host is not None and args.comparison_build is not None,
                "supply comparison host and its build receipt")
        require(args.host is None and args.signer is None, "comparison and producer modes are distinct")
    require((args.host is None) == (args.signer is None), "supply both binaries for producer verification")
    return comparison


def main():
    args = parser().parse_args()
    if validate_mode(args):
        receipt = replay_corpus(args)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x") as stream:
            json.dump(receipt, stream, sort_keys=True, indent=2)
            stream.write("\n")
        print("18 artifacts / 146 signatures, 60 mutations and 2 primitive-message controls passed against comparison host")
        return
    sys.path.insert(0, str(REFERENCE))
    from reference import Reference
    from prepare import SOURCES
    reference = Reference(args.reference_inputs.resolve())
    hash_controls = reference.hash_vectors(args.reference_inputs.resolve())
    producer = producer_receipt(args.candidate_source_tree.resolve(), args.host.resolve(), args.signer.resolve()) if args.host else None
    checked = check_corpus(args.corpus.resolve(), reference, args.host.resolve() if args.host else None, producer)
    receipt = {
        "schema_version": 1,
        "scope": "G2 independent transparent-only NU7 v5/v6 digest/codec/message/crypto; no shielded/node/live/wallet acceptance",
        "completed_at_utc": datetime.now(timezone.utc).isoformat(), "python": sys.version, "platform": platform.platform(),
        "official_blake3_controls": hash_controls, "reference_sources": SOURCES,
        "portable_hash_build": json.loads((args.reference_inputs / "hash-build.json").read_text()),
        "checker_files": {path.name: oracle.sha256(path.read_bytes()) for path in sorted(HERE.glob("*.py"))},
        "reference_glue_files": {path.name: oracle.sha256(path.read_bytes()) for path in sorted(REFERENCE.glob("*.py"))},
        "producer_verification": producer,
        "coverage_pending": ["shielded effects and exclusions", "consensus/relay/mining", "wallet/CLI/recovery", "human live validation"],
        **checked,
    }
    # Local library/compiler absolute paths are operational details, not public evidence.
    build = receipt["portable_hash_build"]
    receipt["portable_hash_build"] = {
        key: build[key] for key in ("schema_version", "library_name", "library_sha256", "shim_sha256", "sources_sha256", "compiler_sha256")
    }
    receipt["portable_hash_build"]["compiler"] = build["compiler"].split("InstalledDir:")[0].rstrip()
    receipt["portable_hash_build"]["flags"] = ["-O2", "-shared", "-fPIC", "-DBLAKE3_USE_NEON=0", "-DBLAKE3_NO_SSE2", "-DBLAKE3_NO_SSE41", "-DBLAKE3_NO_AVX2", "-DBLAKE3_NO_AVX512"]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as stream:
        json.dump(receipt, stream, sort_keys=True, indent=2)
        stream.write("\n")
    print(f"18 artifacts / 146 signatures, {len(checked['mutations'])} mutations and 2 primitive-message controls passed")


if __name__ == "__main__":
    main()
