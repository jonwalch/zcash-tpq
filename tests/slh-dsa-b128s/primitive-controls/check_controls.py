#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later
"""Validate source-profile positives independently before BLAKE3 rejection."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE.parent / "reference"))
from check import native, require
from prepare import checked, digest, SOURCES
from reference import Reference
from extract import extract, SELECTION, SOURCE

FIELDS = ("public_key", "signature", "message", "context")
PROFILES = {"SLH-DSA-SHA2-128s": "sha2_128s", "SLH-DSA-SHAKE-128s": "shake_128s"}


def check(inputs, source_cache, binary):
    retained_path = HERE / "wrong-profiles.json"
    retained = json.loads(retained_path.read_bytes())
    require(retained == extract(checked(source_cache, SOURCE["sha256"])), "exact NIST selection")
    require(len(retained["cases"]) == len(SELECTION) == 2, "two fixed profile controls")
    reference = Reference(inputs)
    records = []
    for case in retained["cases"]:
        request = {field: case[field] for field in FIELDS}
        pk, signature, message, context = (bytes.fromhex(request[field]) for field in FIELDS)
        require((len(pk), len(signature)) == (32, 7856), "equal fixed-profile lengths")
        profile = getattr(reference.parameters, PROFILES[case["parameter_set"]])
        framed = reference.frame(message, context)
        require(reference.scheme.verify(framed, signature, (pk[:16], pk[16:]), profile) is True,
                "independent source-profile positive")
        changed = bytes([signature[0] ^ 1]) + signature[1:]
        require(reference.scheme.verify(framed, changed, (pk[:16], pk[16:]), profile) is False,
                "independent source-profile mutation")
        require(reference.verify(pk, signature, message, context) is False,
                "independent BLAKE3 rejection")
        result = native(binary, request)
        require(result == {"valid": False, "error": "InvalidSignature"}, "native BLAKE3 rejection")
        records.append({
            "parameter_set": case["parameter_set"], "tg_id": case["tg_id"], "tc_id": case["tc_id"],
            "request_sha256": digest(json.dumps(request, sort_keys=True).encode()),
            "independent_source_profile": True,
            "independent_source_profile_mutation": False,
            "independent_blake3": False, "candidate": result,
        })
    crate = ROOT / "crates/pq-slh-dsa-b-verify"
    source_files = [ROOT / "Cargo.toml", ROOT / "Cargo.lock", *sorted(path for path in crate.rglob("*") if path.is_file())]
    build = json.loads((inputs / "hash-build.json").read_text())
    dirty = subprocess.check_output([
        "git", "-C", str(ROOT), "status", "--porcelain", "--", "Cargo.toml", "Cargo.lock",
        "crates/pq-slh-dsa-b-verify", "tests/slh-dsa-b128s/primitive-controls",
    ], text=True).strip()
    return {
        "schema_version": 1,
        "scope": "Two valid FIPS 205 wrong-profile primitive controls; no native/node/wallet acceptance",
        "completed_at_utc": datetime.now(timezone.utc).isoformat(),
        "nist_source": SOURCE,
        "independent_source": SOURCES["reference"],
        "candidate_commit": subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip(),
        "candidate_or_controls_dirty": bool(dirty),
        "candidate_binary_sha256": digest(binary.read_bytes()),
        "candidate_source_files": {str(path.relative_to(ROOT)): digest(path.read_bytes()) for path in source_files},
        "control_files": {name: digest((HERE / name).read_bytes()) for name in (
            "extract.py", "check_controls.py", "wrong-profiles.json", "NIST-NOTICE.txt", "README.md"
        )},
        "reference_files": {name: digest((HERE.parent / "reference" / name).read_bytes()) for name in (
            "check.py", "prepare.py", "reference.py", "sources.json", "hash_shim.c"
        )},
        "portable_hash_build": {
            "library_sha256": build["library_sha256"],
            "compiler_sha256": build["compiler_sha256"],
            "compiler": build["compiler"].split("InstalledDir:")[0].rstrip(),
            "shim_sha256": build["shim_sha256"], "sources_sha256": build["sources_sha256"],
        },
        "records": records,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", required=True, type=Path)
    parser.add_argument("--source-cache", required=True, type=Path)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = check(args.inputs.resolve(), args.source_cache.resolve(), args.binary.resolve())
    with args.output.open("x") as output:
        json.dump(result, output, indent=2, sort_keys=True)
        output.write("\n")
    print("PASS: two valid source-profile signatures and mutations; both reject under BLAKE3")
