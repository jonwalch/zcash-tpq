#!/usr/bin/env python3
"""HUMAN ONLY: build exact acceptance binaries and retain failed build evidence.

Adapted from research pq_relay_build.py; no Docker overlay or alternate backend.
Agents may unit-test command construction but must never execute main's build.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess

from common import (ROOT, CONTRACT, FEATURE, AcceptanceError, read_json, require,
                    sha256, source_state, strict_json, validate_identity, write_json)


def command(kind, target):
    require(kind in ("node-default", "node-slh", "wallet-default", "wallet-slh", "host", "signer"), "build_kind")
    package, binary = (("zakura", "zakurad") if kind.startswith("node-") else
                       ("slh-dsa-b128s-fixture-host", "slh-dsa-b128s-fixture-host") if kind == "host"
                       else ("slh-dsa-b128s-public-fixture", "slh-dsa-b128s-public-fixture") if kind == "signer"
                       else ("zakura-pq-cli", "pq-wallet"))
    features = ["default-release-binaries"] if kind.startswith("node-") else []
    if kind.endswith("-slh"):
        features.append(FEATURE)
    argv = ["cargo", "build", "--locked", "--release", "--no-default-features", "-p", package,
            "--bin", binary, "--target-dir", str(target)]
    if features:
        argv += ["--features", ",".join(features)]
    if kind == "signer":
        argv += ["--manifest-path", "tests/slh-dsa-b128s/fixture-signer/Cargo.toml"]
    return argv, binary, features


def build(args):
    directory = args.artifacts.resolve()
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    before = source_state()
    target = directory / "target"
    argv, name, features = command(args.kind, target)
    # Record relevant non-secret compiler knobs. Exact artifact hashes bind the
    # result; this receipt is local provenance, not a reproducibility proof.
    environment = {key: os.environ.get(key) for key in (
        "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTDOCFLAGS", "CC", "CXX", "CFLAGS", "CXXFLAGS")}
    record = {"schema_version": 1, "contract": CONTRACT, "kind": args.kind, "complete": False,
              "source": before, "command": argv, "features": features, "binary_sha256": None,
              "identity": None, "environment": environment,
              "rustc": subprocess.check_output(["rustc", "-Vv"], cwd=ROOT, text=True).strip(),
              "cargo": subprocess.check_output(["cargo", "-V"], cwd=ROOT, text=True).strip()}
    receipt = directory / "build.json"
    write_json(receipt, record)
    with (directory / "build.log").open("xb") as log:
        subprocess.run(argv, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=True)
    require(source_state() == before, "source_changed_during_build")
    binary = directory / name
    shutil.copyfile(target / "release" / name, binary)
    binary.chmod(0o700)
    if args.kind.startswith("node-"):
        response = subprocess.check_output([str(binary), "--slh-dsa-b128s-verifier-identity"],
                                           stderr=subprocess.DEVNULL, timeout=30)
        record["identity"] = strict_json(response, 4096)
        validate_identity(record["identity"], args.kind.endswith("-slh"))
        write_json(directory / "verifier-identity.json", record["identity"])
    record.update(complete=True, binary_sha256=sha256(binary))
    write_json(receipt, record, fresh=False)
    print(f"Build receipt: {receipt}")


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--human-run", action="store_true", required=True)
    result.add_argument("--kind", choices=("node-default", "node-slh", "wallet-default", "wallet-slh", "host", "signer"), required=True)
    result.add_argument("--artifacts", type=Path, required=True, help="new directory under a stable private parent")
    return result


if __name__ == "__main__":
    build(parser().parse_args())
