#!/usr/bin/env python3
"""Run 60 external-Pure verifier comparisons without signing or key generation."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

from prepare import HERE, SOURCES, checked, digest
from reference import Reference

ROOT = HERE.parents[2]
CRATE = Path("crates/pq-slh-dsa-b-verify")
KAT_PATH = CRATE / "tests/data/pure-kats.json"
KAT_SHA256 = "a20ba835aa50f927f69263f259a3176db61048f41c3048bb5fcf14fc0c4b3a21"
MAX_CASES = 60
FIELDS = ("public_key", "signature", "message", "context")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def comparison_cases(kats):
    cases = []

    def add(label, value, expected=False, error="InvalidSignature"):
        cases.append({
            "label": label,
            "request": {name: value[name] for name in FIELDS},
            "expected": expected,
            "error": None if expected else error,
        })

    for case in kats:
        prefix = f"kat-{case['id']}"
        add(prefix, case, True)
        # Mutate both public-key halves and each major signature section boundary.
        for field, offsets in (
            ("public_key", (0, 16)),
            ("signature", (0, 16, 2927, 2928, 3488, 7855)),
        ):
            for offset in offsets:
                data = bytearray.fromhex(case[field])
                data[offset] ^= 1
                add(f"{prefix}-{field}-{offset}", case | {field: data.hex()})
        add(prefix + "-message", case | {"message": case["message"] + "00"})
        add(prefix + "-context", case | {"context": "00"})
        for field, error in (("signature", "SignatureLength"), ("public_key", "PublicKeyLength")):
            add(prefix + "-" + field + "-short", case | {field: case[field][:-2]}, error=error)
            add(prefix + "-" + field + "-long", case | {field: case[field] + "00"}, error=error)
        add(prefix + "-context-256", case | {"context": "00" * 256}, error="ContextTooLong")
        add(prefix + "-message-65537", case | {"message": "00" * 65537}, error="MessageTooLong")
        context = bytes.fromhex(case["context"])
        framed = b"\0" + bytes([len(context)]) + context + bytes.fromhex(case["message"])
        add(prefix + "-double-pure-frame", case | {"message": framed.hex()})
    first = kats[0]
    add("message-at-maximum", first | {"message": "00" * 65536})
    add("context-at-maximum", first | {"context": "00" * 255})
    add("empty-public-key", first | {"public_key": ""}, error="PublicKeyLength")
    add("empty-signature", first | {"signature": ""}, error="SignatureLength")
    add("zero-public-key", first | {"public_key": "00" * 32})
    add("zero-signature", first | {"signature": "00" * 7856})
    require(len(cases) == MAX_CASES, "bounded comparison must contain exactly 60 cases")
    require(len({case["label"] for case in cases}) == MAX_CASES, "duplicate case label")
    return cases


def native(binary, request):
    encoded = json.dumps(request, sort_keys=True) + "\n"
    require(len(encoded.encode()) <= 160000, "request exceeds bounded adapter size")
    completed = subprocess.run(
        [str(binary)], input=encoded, text=True, capture_output=True,
        timeout=30, check=True,
    )
    result = json.loads(completed.stdout)
    require(isinstance(result, dict) and set(result) == {"valid", "error"}, "adapter response schema")
    require(type(result["valid"]) is bool, "adapter verdict type")
    return result


def check(inputs, binary, source_tree):
    require("CREATE_VECTOR_SET" not in os.environ, "CREATE_VECTOR_SET must be absent")
    kats = json.loads(checked(ROOT / KAT_PATH, KAT_SHA256))["cases"]
    require(len(kats) == 3, "expected three retained independent KATs")
    cases = comparison_cases(kats)
    reference = Reference(inputs)
    hash_vectors = reference.hash_vectors(inputs)
    require(hash_vectors > 0, "official portable BLAKE3 controls missing")
    results = []
    for case in cases:
        request = case["request"]
        # Evaluate the independent code first; candidate results cannot supply expectations.
        independent = reference.verify(*(bytes.fromhex(request[name]) for name in FIELDS))
        require(independent is case["expected"], f"independent verdict: {case['label']}")
        result = native(binary, request)
        require(result["valid"] is case["expected"], f"candidate verdict: {case['label']}")
        require(result["error"] == case["error"], f"candidate error: {case['label']}: {result}")
        results.append({
            "label": case["label"],
            "request_sha256": digest(json.dumps(request, sort_keys=True).encode()),
            "expected": case["expected"],
            "independent": independent,
            "candidate": result,
        })
    build = json.loads((inputs / "hash-build.json").read_text())
    source_files = [source_tree / "Cargo.lock", source_tree / "Cargo.toml"]
    source_files.extend(sorted(path for path in (source_tree / CRATE).rglob("*") if path.is_file()))
    require(all(path.is_relative_to(source_tree) for path in source_files), "source provenance outside tree")
    candidate_commit = subprocess.check_output(
        ["git", "-C", str(source_tree), "rev-parse", "HEAD"], text=True, timeout=30
    ).strip()
    candidate_dirty = subprocess.check_output(
        ["git", "-C", str(source_tree), "status", "--porcelain", "--", "Cargo.toml", "Cargo.lock", str(CRATE)],
        text=True, timeout=30,
    ).strip()
    require(not candidate_dirty, "candidate source inputs must be committed and clean")
    return {
        "schema_version": 1,
        "scope": "G1 fixed-profile external Pure verification; no signing/keygen, native transaction, node or wallet acceptance",
        "completed_at_utc": datetime.now(timezone.utc).isoformat(),
        "comparisons": len(results),
        "positive_cases": sum(case["expected"] for case in cases),
        "negative_cases": sum(not case["expected"] for case in cases),
        "official_blake3_controls": hash_vectors,
        "python": sys.version,
        "platform": platform.platform(),
        "candidate_commit": candidate_commit,
        "candidate_binary_sha256": digest(binary.read_bytes()),
        "candidate_source_files": {
            str(path.relative_to(source_tree)): digest(path.read_bytes()) for path in source_files
        },
        "known_answers_sha256": KAT_SHA256,
        "checker_files": {
            name: digest((HERE / name).read_bytes())
            for name in ("check.py", "reference.py", "prepare.py", "hash_shim.c", "sources.json")
        },
        "reference_sources": SOURCES,
        "portable_hash_build": {
            "library_sha256": build["library_sha256"],
            "compiler_sha256": build["compiler_sha256"],
            "compiler": build["compiler"].split("InstalledDir:")[0].rstrip(),
            "flags": ["-O2", "-shared", "-fPIC", "-DBLAKE3_USE_NEON=0", "-DBLAKE3_NO_SSE2", "-DBLAKE3_NO_SSE41", "-DBLAKE3_NO_AVX2", "-DBLAKE3_NO_AVX512"],
        },
        "results": results,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", type=Path)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--candidate-source-tree", type=Path, default=ROOT)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    require(not args.output.exists(), "choose a fresh output receipt")
    receipt = check(args.inputs.resolve(), args.binary.resolve(), args.candidate_source_tree.resolve())
    with args.output.open("x") as output:
        json.dump(receipt, output, indent=2)
        output.write("\n")
    print(json.dumps({name: receipt[name] for name in (
        "comparisons", "positive_cases", "negative_cases", "official_blake3_controls",
        "candidate_binary_sha256",
    )}, indent=2))
