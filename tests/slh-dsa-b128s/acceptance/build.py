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

KINDS = ("node-default", "node-slh", "wallet-default", "wallet-slh", "host", "signer",
         "host-shielded", "wallet-faults")


def command(kind, target):
    require(kind in KINDS, "build_kind")
    if kind == "wallet-faults":
        return (["cargo", "test", "--locked", "--release", "--no-default-features",
                 "-p", "zakura-pq-wallet", "--lib", "--no-run", "--message-format=json",
                 "--target-dir", str(target), "--features", FEATURE],
                "wallet-fault-tests", [FEATURE])
    package, binary = (("zakura", "zakurad") if kind.startswith("node-") else
                       ("slh-dsa-b128s-fixture-host", "slh-dsa-b128s-fixture-host") if kind in ("host", "host-shielded")
                       else ("slh-dsa-b128s-public-fixture", "slh-dsa-b128s-public-fixture") if kind == "signer"
                       else ("zakura-pq-cli", "pq-wallet"))
    features = ["default-release-binaries"] if kind.startswith("node-") else []
    if kind.endswith("-slh"):
        features.append(FEATURE)
    if kind == "host-shielded":
        features.append("shielded-fixtures")
    argv = ["cargo", "build", "--locked", "--release", "--no-default-features", "-p", package,
            "--bin", binary, "--target-dir", str(target)]
    if features:
        argv += ["--features", ",".join(features)]
    if kind == "signer":
        argv += ["--manifest-path", "tests/slh-dsa-b128s/fixture-signer/Cargo.toml"]
    return argv, binary, features


def wallet_test_artifact(messages, target):
    """Select Cargo's exact wallet lib test executable; never glob stale tests."""
    require(messages.is_file() and not messages.is_symlink()
            and messages.stat().st_size <= 64 * 1024 * 1024, "cargo_messages_size")
    matches = []
    with messages.open("rb") as stream:
        while line := stream.readline(1024 * 1024 + 1):
            require(len(line) <= 1024 * 1024, "cargo_message_size")
            value = strict_json(line, 1024 * 1024)
            require(type(value) is dict, "cargo_message_schema")
            if value.get("reason") != "compiler-artifact":
                continue
            info, profile = value.get("target"), value.get("profile")
            require(type(info) is dict and type(profile) is dict, "cargo_artifact_schema")
            if (info.get("name") == "zakura_pq_wallet" and info.get("kind") == ["lib"]
                    and profile.get("test") is True and value.get("executable") is not None):
                require(info.get("src_path") == str(ROOT / "crates/pq-wallet/src/lib.rs")
                        and type(value["executable"]) is str, "cargo_wallet_target")
                matches.append(Path(value["executable"]))
    require(len(matches) == 1, "cargo_wallet_artifact_count")
    artifact = matches[0]
    base = target / "release" / "deps"
    require(artifact.is_absolute() and artifact.parent == base
            and artifact.name.startswith("zakura_pq_wallet-")
            and not artifact.is_symlink() and artifact.is_file()
            and all(not path.is_symlink() for path in (target, target / "release", base)),
            "cargo_wallet_artifact_path")
    return artifact


def build(args):
    directory = args.artifacts.resolve()
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    before = source_state()
    target = directory / "target"
    argv, name, features = command(args.kind, target)
    # Record relevant non-secret compiler knobs. Exact artifact hashes bind the
    # result; this receipt is local provenance, not a reproducibility proof.
    environment = {key: os.environ.get(key) for key in (
        "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTDOCFLAGS", "CC", "CXX", "CFLAGS", "CXXFLAGS",
        "CARGO_BUILD_TARGET")}
    record = {"schema_version": 1, "contract": CONTRACT, "kind": args.kind, "complete": False,
              "source": before, "command": argv, "features": features, "binary_sha256": None,
              "identity": None, "environment": environment,
              "rustc": subprocess.check_output(["rustc", "-Vv"], cwd=ROOT, text=True).strip(),
              "cargo": subprocess.check_output(["cargo", "-V"], cwd=ROOT, text=True).strip()}
    receipt = directory / "build.json"
    write_json(receipt, record)
    require(not environment["CARGO_BUILD_TARGET"], "native_build_target_required")
    with (directory / "build.log").open("xb") as log:
        if args.kind == "wallet-faults":
            messages = directory / "cargo-artifacts.jsonl"
            with messages.open("xb") as artifacts:
                subprocess.run(argv, cwd=ROOT, stdout=artifacts, stderr=log, check=True)
            artifact = wallet_test_artifact(messages, target)
        else:
            subprocess.run(argv, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=True)
            artifact = target / "release" / name
    require(source_state() == before, "source_changed_during_build")
    binary = directory / name
    shutil.copyfile(artifact, binary)
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
    result.add_argument("--kind", choices=KINDS, required=True)
    result.add_argument("--artifacts", type=Path, required=True, help="new directory under a stable private parent")
    return result


if __name__ == "__main__":
    build(parser().parse_args())
