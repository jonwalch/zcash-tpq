"""Bound the existing acceptance node build and record its actual compiler inputs.

The acceptance helper and its receipt remain unchanged. An outer receipt retains
before/after Cargo configuration, compiler and environment evidence for matched
node comparisons. Importing this module does not build or probe a compiler.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import sys
import tomllib

from provenance import (MAX_JSON, atomic_json, canonical, fresh_directory, read_json, require,
                        sha256, toolchain)

KINDS = ("node-default", "node-slh")
ACCEPTANCE_RECEIPT = "acceptance/build.json"
MAX_BUILD_LOG_BYTES = 64 * 1024 * 1024
ENVIRONMENT_BASE = {"RUSTUP_TOOLCHAIN", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTDOCFLAGS",
                    "CC", "CXX", "CFLAGS", "CXXFLAGS", "SDKROOT", "MACOSX_DEPLOYMENT_TARGET",
                    "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_TARGET", "CARGO_INCREMENTAL"}
ACCEPTANCE_ENVIRONMENT = {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTDOCFLAGS",
                          "CC", "CXX", "CFLAGS", "CXXFLAGS", "CARGO_BUILD_TARGET"}
WRAPPERS = {"RUSTC", "CARGO_BUILD_RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
            "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER"}


def _text(value):
    return type(value) is str and "\0" not in value and len(value.encode()) <= 4096


def _absolute(value):
    return (_text(value) and Path(value).is_absolute() and ".." not in Path(value).parts
            and str(Path(value)) == value and not value.startswith("//"))


def validate_toolchain(identity, *, normalized=False):
    """Validate saved build-time evidence without consulting the current host."""
    require(type(identity) is dict and set(identity) == {"rustc", "cargo", "environment",
            "cargo_configuration_identity_version", "cargo_configurations",
            "workspace_manifest_profiles"}, "node toolchain schema")
    require(type(identity["cargo_configuration_identity_version"]) is int
            and identity["cargo_configuration_identity_version"] == 1, "node Cargo identity version")
    require(all(_text(identity[name]) and identity[name].strip() for name in ("rustc", "cargo")),
            "node compiler version identity")
    environment = identity["environment"]
    require(type(environment) is dict and ENVIRONMENT_BASE <= environment.keys()
            and all(type(name) is str and (name in ENVIRONMENT_BASE or name.startswith(
                ("CARGO_PROFILE_", "CARGO_BUILD_", "CARGO_TARGET_"))) for name in environment)
            and all(value is None or _text(value) for value in environment.values()),
            "node compiler environment identity")
    require(not any(environment.get(name) for name in WRAPPERS), "custom Cargo compiler or wrapper is not supported")
    require(not environment["CARGO_BUILD_TARGET"], "node builds require the native target")
    profiles = identity["workspace_manifest_profiles"]
    require(type(profiles) is dict and all(type(name) is str and bool(name) and type(profile) is dict
                                         for name, profile in profiles.items()), "node workspace profile table")
    from results import _bounded_json
    _bounded_json(profiles)
    configurations = identity["cargo_configurations"]
    require(type(configurations) is list and len(configurations) <= 128, "node Cargo configuration list")
    seen = set()
    for config in configurations:
        fields = {"location", "search_roles", "sha256"} | (set() if normalized else {"path"})
        require(type(config) is dict and set(config) == fields, "node Cargo configuration schema")
        location = config["location"]
        require(type(location) is dict and len(location) == 1, "node Cargo configuration location")
        if "checkout_relative" in location:
            path = location["checkout_relative"]
            require(_text(path) and path and not Path(path).is_absolute() and ".." not in Path(path).parts
                    and str(Path(path)) == path, "node Cargo checkout location")
        else:
            require(set(location) == {"external_absolute"} and _absolute(location["external_absolute"]),
                    "node Cargo external location")
        require(config["search_roles"] in (["ancestor"], ["cargo_home"], ["ancestor", "cargo_home"]),
                "node Cargo search roles")
        require(type(config["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", config["sha256"]),
                "node Cargo configuration hash")
        if not normalized:
            require(_absolute(config["path"]), "node Cargo configuration path")
        key = tuple(location.items())
        require(key not in seen, "duplicate node Cargo configuration")
        seen.add(key)
    return identity


def _capture_toolchain(root):
    # Both the acceptance helper and Cargo run from this root, so rustup's
    # directory override and Cargo's ancestor search have the same scope.
    compiler = toolchain(root, source_root=root)
    compiler["environment"].update({name: os.environ.get(name)
                                  for name in ("RUSTDOCFLAGS", "CARGO_BUILD_TARGET", "CARGO_INCREMENTAL")})
    manifest = Path(root) / "Cargo.toml"
    require(manifest.is_file() and not manifest.is_symlink(), "regular workspace Cargo.toml required")
    with manifest.open("rb") as stream:
        contents = stream.read(MAX_JSON + 1)
    require(len(contents) <= MAX_JSON, "workspace Cargo.toml byte limit")
    # Cargo takes workspace profile defaults, package/build overrides and profile
    # inheritance from this manifest. Keep the whole table, independently of the
    # source inventory deliberately omitted from matched comparison identity.
    compiler["workspace_manifest_profiles"] = tomllib.loads(contents.decode("utf8")).get("profile", {})
    return validate_toolchain(compiler)


def validate_acceptance_toolchain(acceptance, compiler):
    validate_toolchain(compiler)
    require(all(acceptance[name] == compiler[name] for name in ("rustc", "cargo")),
            "acceptance compiler differs from recorded build-time toolchain")
    require(all(name in compiler["environment"] and compiler["environment"][name] == value
                for name, value in acceptance["environment"].items()),
            "acceptance environment differs from recorded build-time toolchain")


def unwrap_build(path, receipt):
    """Return the hash-bound acceptance receipt and complete saved toolchain."""
    fields = {"schema_version", "kind", "complete", "build_kind", "invocation_directory",
              "command", "toolchain", "toolchain_after", "acceptance_receipt",
              "acceptance_receipt_sha256", "binary_sha256", "execution"}
    require(type(receipt) is dict and set(receipt) == fields and receipt["schema_version"] == 1
            and type(receipt["schema_version"]) is int and receipt["kind"] == "tpq-node-build"
            and receipt["complete"] is True and receipt["build_kind"] in KINDS,
            "complete benchmark node build receipt required")
    require(_absolute(receipt["invocation_directory"]), "node build invocation directory")
    compiler = validate_toolchain(receipt["toolchain"])
    require(canonical(validate_toolchain(receipt["toolchain_after"])) == canonical(compiler),
            "node build toolchain changed during compilation")
    for config in compiler["cargo_configurations"]:
        location = config["location"]
        expected = (Path(receipt["invocation_directory"]) / location["checkout_relative"]
                    if "checkout_relative" in location else Path(location["external_absolute"]))
        require(config["path"] == str(expected), "node Cargo configuration path binding")
    require(receipt["acceptance_receipt"] == ACCEPTANCE_RECEIPT, "node acceptance receipt path")
    directory = path.parent
    inner = directory / ACCEPTANCE_RECEIPT
    require(inner.resolve(strict=True) == inner, "node acceptance receipt path contains a symlink")
    require(receipt["acceptance_receipt_sha256"] == sha256(inner), "node acceptance receipt changed")
    command = receipt["command"]
    helper = Path(receipt["invocation_directory"]) / "tests/slh-dsa-b128s/acceptance/build.py"
    require(type(command) is list and len(command) == 7 and _absolute(command[0])
            and command[1:6] == [str(helper), "--human-run", "--kind", receipt["build_kind"], "--artifacts"]
            and _absolute(command[6]) and Path(command[6]).name == "acceptance",
            "node acceptance wrapper command")
    # Commands retain their build-host paths. A copied artifact directory has a
    # new location, but both recorded commands must still describe the same build.
    build_directory = Path(command[6])
    execution = receipt["execution"]
    require(type(execution) is dict and set(execution) == {"pid", "exit_code", "elapsed_ns", "output_bytes"}
            and all(type(value) is int and value >= 0 for value in execution.values())
            and execution["pid"] > 0 and execution["exit_code"] == 0, "node acceptance execution receipt")
    acceptance = read_json(inner)
    require(type(acceptance) is dict and acceptance.get("kind") == receipt["build_kind"]
            and acceptance.get("binary_sha256") == receipt["binary_sha256"], "node wrapped build identity")
    from node_run import validate_acceptance_build
    validate_acceptance_build(acceptance, directory / "acceptance/zakurad")
    require(acceptance["command"][10] == str(build_directory / "target"), "node wrapped build target")
    validate_acceptance_toolchain(acceptance, compiler)
    return acceptance, compiler


def validate_comparison_toolchain(compatibility, variant=None):
    """Old reports remain readable, but missing evidence is never comparable."""
    compiler = validate_toolchain(compatibility.get("toolchain"), normalized=True)
    node = compatibility.get("node_collection")
    require(type(node) is dict, "node comparison identity")
    if "comparison_identity_version" in node:
        require(type(node["comparison_identity_version"]) is int and node["comparison_identity_version"] == 2
                and "build" not in node, "node comparison identity version")
        require(type(variant) is dict and set(variant) == {"kind", "features"}
                and variant["kind"] in KINDS, "node comparison build variant")
        expected = ["default-release-binaries"] + (["experimental-slh-dsa-b128s"]
                                                   if variant["kind"] == "node-slh" else [])
        require(variant["features"] == expected, "node comparison feature metadata")
        return
    require(type(node.get("build")) is dict, "node comparison build identity")
    build = node["build"]
    require(set(build) == {"kind", "features", "rustc", "cargo", "environment", "toolchain"}
            and build["kind"] in KINDS, "node comparison recipe metadata")
    features = ["default-release-binaries"] + (["experimental-slh-dsa-b128s"]
                                              if build["kind"] == "node-slh" else [])
    require(build["features"] == features, "node comparison feature metadata")
    require(build.get("toolchain") == compiler, "node comparison toolchain binding")
    require(all(build.get(name) == compiler[name] for name in ("rustc", "cargo"))
            and type(build.get("environment")) is dict
            and set(build["environment"]) == ACCEPTANCE_ENVIRONMENT
            and all(name in compiler["environment"] and compiler["environment"][name] == value
                    for name, value in build["environment"].items()), "node comparison compiler binding")


def build_node(args):
    import run as runner
    runner.require_execute(args)
    require(args.kind in KINDS and type(args.timeout) is int and 1 <= args.timeout <= 86400,
            "node build kind or deadline")
    output = fresh_directory(args.output).resolve()
    command = [sys.executable, str(runner.ROOT / "tests/slh-dsa-b128s/acceptance/build.py"),
               "--human-run", "--kind", args.kind, "--artifacts", str(output / "acceptance")]
    receipt = {"schema_version": 1, "kind": "tpq-node-build", "complete": False,
               "build_kind": args.kind, "invocation_directory": str(runner.ROOT), "command": command,
               "toolchain": None, "toolchain_after": None, "acceptance_receipt": ACCEPTANCE_RECEIPT,
               "acceptance_receipt_sha256": None, "binary_sha256": None, "execution": None}
    atomic_json(output / "build.json", receipt)

    def bound_log():
        log = output / "acceptance/build.log"
        if log.exists():
            require(not log.is_symlink() and log.is_file() and log.stat().st_size <= MAX_BUILD_LOG_BYTES,
                    "node acceptance build log byte limit")

    try:
        receipt["toolchain"] = _capture_toolchain(runner.ROOT)
        atomic_json(output / "build.json", receipt)
        receipt["execution"] = runner.supervise(command, root=runner.ROOT, directory=output / "logs",
                                                 timeout=args.timeout, max_bytes=MAX_BUILD_LOG_BYTES,
                                                 on_poll=bound_log)
        bound_log()
        receipt["toolchain_after"] = _capture_toolchain(runner.ROOT)
        require(canonical(receipt["toolchain_after"]) == canonical(receipt["toolchain"]),
                "node build toolchain changed during compilation")
        inner = output / ACCEPTANCE_RECEIPT
        receipt["acceptance_receipt_sha256"] = sha256(inner)
        acceptance = read_json(inner)
        require(type(acceptance) is dict, "node acceptance receipt schema")
        # unwrap_build validates this digest against the current binary once.
        receipt["binary_sha256"] = acceptance.get("binary_sha256")
        receipt["complete"] = True
        unwrap_build(output / "build.json", receipt)
    except BaseException as error:
        receipt.update(complete=False, failure=type(error).__name__)
        if hasattr(error, "process_id"):
            receipt["execution"] = {"pid": error.process_id, "elapsed_ns": error.elapsed_ns,
                                    "outcome": getattr(error, "outcome", "error")}
        raise
    finally:
        atomic_json(output / "build.json", receipt)
    return receipt


def add_node_build_parser(commands):
    parser = commands.add_parser("build-node", help="human: build an acceptance node with comparison provenance")
    parser.add_argument("--kind", choices=KINDS, required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--execute", action="store_true")
    parser.set_defaults(action=build_node)
