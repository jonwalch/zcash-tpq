"""Register and supervise one attached Regtest sampler; never manage its node.

Reuse the benchmark supervisor, artifact contract and reports. Acceptance
node-build receipt checks are adapted without requiring the current benchmark
instrumentation commit to equal the separately recorded compiled source.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import stat
import sys
import uuid

import run as runner
from provenance import (MAX_JSON, artifact_inventory, atomic_json, canonical, claim_run,
                        digest_value, fresh_directory, host_state, read_json, require,
                        sha256, strict_json)
from results import MAX_INPUT_BYTES, MAX_RECORD_BYTES, summarize, validate_record

INSTRUMENTS = ("run.py", "node_run.py", "node_sampling.py", "collectors.py", "adapters.py", "provenance.py")
MAX_FRAME_BYTES = 2 * 1024 * 1024
PROFILE_FIELDS = {"schema_version", "network", "pid", "binary_path", "build_receipt_path",
                  "config_path", "metrics_url", "process_identity", "workload",
                  "cgroup_path", "cgroup_boundary"}
WORKLOAD_FIELDS = {"id", "description", "fixture_sha256", "topology", "state", "activity"}
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}\Z", re.ASCII)
SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
SCOPE = {
    "collection": "Attach to one existing Regtest node; never start, stop, fund, mine or generate traffic.",
    "association": "The operator associates the metrics endpoint with the node. Config, executable and process epoch are checked; listener ownership is not independently proved.",
    "resources": "Process interval CPU and current RSS; optional declared cgroup. Attached lifetime peaks cannot establish a case-local peak and remain unavailable.",
    "mempool": "Verified mempool gauges and their adjacent-scrape growth; policy accounting cost is not heap use or an admission queue.",
    "limits": "This collector does not measure block validation, transaction propagation, peer bandwidth or chain acceptance.",
}


def _text(value, name, maximum=1024):
    require(type(value) is str and bool(value.strip()) and "\0" not in value
            and len(value.encode()) <= maximum, "invalid node declaration: " + name)


def _path(value, name):
    _text(value, name, 4096)
    require(Path(value).is_absolute() and ".." not in Path(value).parts
            and str(Path(value)) == value and not value.startswith("//"),
            "node path must be canonical and absolute: " + name)


def validate_node_profile(profile):
    """Only static declarations; do not read procfs or contact the endpoint."""
    require(type(profile) is dict and set(profile) == PROFILE_FIELDS, "node profile schema")
    require(type(profile["schema_version"]) is int and profile["schema_version"] == 1
            and profile["network"] == "Regtest", "node collection is Regtest only")
    require(type(profile["pid"]) is int and 0 < profile["pid"] < 2**31, "node PID declaration")
    for name in ("binary_path", "build_receipt_path", "config_path"):
        _path(profile[name], name)
    _text(profile["metrics_url"], "metrics_url", 4096)
    identity = profile["process_identity"]
    require(type(identity) is dict and set(identity) == {"start_ticks", "boot_id"}, "node process identity schema")
    require(type(identity["start_ticks"]) is int and 0 <= identity["start_ticks"] < 2**64,
            "node process start ticks")
    _text(identity["boot_id"], "boot_id", 128)
    workload = profile["workload"]
    require(type(workload) is dict and set(workload) == WORKLOAD_FIELDS, "node workload schema")
    require(type(workload["id"]) is str and TOKEN.fullmatch(workload["id"]), "node workload ID")
    for name in ("description", "topology", "state", "activity"):
        _text(workload[name], "workload." + name)
    require(workload["fixture_sha256"] is None or
            (type(workload["fixture_sha256"]) is str and SHA256.fullmatch(workload["fixture_sha256"])),
            "node fixture identity must be a SHA256 or explicit null")
    if profile["cgroup_path"] is None:
        require(profile["cgroup_boundary"] is None, "cgroup boundary without a cgroup")
    else:
        for name in ("cgroup_path", "cgroup_boundary"):
            _path(profile[name], name)
        require(Path(profile["cgroup_path"]).is_relative_to(profile["cgroup_boundary"]),
                "cgroup must be inside its declared boundary")
    require(len(canonical(profile)) <= 12 * 1024, "node profile byte limit")
    return profile


def validate_node_settings(settings):
    require(type(settings) is dict and set(settings) == {
        "samples", "interval_ms", "timeout_seconds", "max_output_bytes"}, "node settings schema")
    for name, low, high in (("samples", 1, 1000), ("interval_ms", 10, 60000),
                            ("timeout_seconds", 1, 3600), ("max_output_bytes", 1024, 64 * 1024 * 1024)):
        require(type(settings[name]) is int and low <= settings[name] <= high, "node bound: " + name)
    require(settings["samples"] * settings["interval_ms"] < settings["timeout_seconds"] * 1000,
            "node deadline must exceed planned sampling intervals")
    return settings


def node_build(profile):
    """Bind an existing acceptance node-* receipt, without executing its binary."""
    for name in ("binary_path", "build_receipt_path", "config_path"):
        path = Path(profile[name])
        require(str(path.resolve(strict=True)) == str(path), "node registration path contains a symlink")
    receipt = read_json(profile["build_receipt_path"])
    fields = {"schema_version", "contract", "kind", "complete", "source", "command", "features",
              "binary_sha256", "identity", "rustc", "cargo", "environment"}
    require(type(receipt) is dict and set(receipt) == fields and receipt["schema_version"] == 1
            and type(receipt["schema_version"]) is int and receipt["complete"] is True
            and receipt["contract"] == "slh-dsa-b-128s-exp-v1"
            and receipt["kind"] in ("node-default", "node-slh"), "complete acceptance node build receipt required")
    enabled = receipt["kind"] == "node-slh"
    features = ["default-release-binaries"] + (["experimental-slh-dsa-b128s"] if enabled else [])
    command = receipt["command"]
    require(type(command) is list and len(command) == 13 and all(type(arg) is str for arg in command),
            "node build command schema")
    expected = ["cargo", "build", "--locked", "--release", "--no-default-features", "-p", "zakura",
                "--bin", "zakurad", "--target-dir", command[10], "--features", ",".join(features)]
    require(command == expected and receipt["features"] == features, "node build recipe changed")
    identity = receipt["identity"]
    require(type(identity) is dict and type(identity.get("runtime_supported")) is bool,
            "node verifier identity schema")
    expected_identity = {"schema_version": 1, "contract": "slh-dsa-b-128s-exp-v1", "suite_id": "f7",
                         "backend": "portable-rust" if enabled else "disabled",
                         "algorithm_revision": "b392fe82d2d9770142477a576a758a233888bc0a", "blake3_version": "1.8.5",
                         "verifier_compiled": enabled, "runtime_supported": identity["runtime_supported"]}
    require(type(identity.get("schema_version")) is int and type(identity.get("verifier_compiled")) is bool
            and identity == expected_identity and (enabled or not identity["runtime_supported"]),
            "node verifier identity mismatch")
    source = receipt["source"]
    require(type(source) is dict and set(source) == {"source_commit", "source_inventory",
            "source_inventory_sha256", "lock_sha256", "fixture_lock_sha256"}, "node build source schema")
    require(type(source["source_commit"]) is str and re.fullmatch("[0-9a-f]{40}", source["source_commit"]),
            "node build source commit")
    require(type(source["source_inventory"]) is list and bool(source["source_inventory"])
            and digest_value(source["source_inventory"]) == source["source_inventory_sha256"],
            "node source inventory identity")
    for name in ("lock_sha256", "fixture_lock_sha256"):
        require(type(source[name]) is str and SHA256.fullmatch(source[name]), "node build " + name)
    for name in ("rustc", "cargo"):
        _text(receipt[name], name, 4096)
    environment = receipt["environment"]
    require(type(environment) is dict and set(environment) == {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTDOCFLAGS",
            "CC", "CXX", "CFLAGS", "CXXFLAGS", "CARGO_BUILD_TARGET"}
            and all(value is None or (type(value) is str and len(value) <= 4096) for value in environment.values())
            and not environment["CARGO_BUILD_TARGET"], "node compiler environment schema")
    require(receipt["binary_sha256"] == sha256(profile["binary_path"]), "node binary changed")
    return receipt


def node_identity(profile, build):
    return {"binary_sha256": build["binary_sha256"], "config_sha256": sha256(profile["config_path"]),
            "build_receipt_sha256": sha256(profile["build_receipt_path"]),
            "source": {key: value for key, value in build["source"].items() if key != "source_inventory"}}


def node_compatibility(manifest):
    """Ignore runtime PIDs and binary paths; retain the cgroup accounting scope."""
    profile, build = manifest["node_profile"], manifest["build"]
    return {"network": profile["network"], "workload": profile["workload"],
            "config_sha256": manifest["node_identity"]["config_sha256"],
            "resources": {"process": "attached-node", "cgroup": profile["cgroup_path"] is not None,
                          "cgroup_path": profile["cgroup_path"],
                          "cgroup_boundary": profile["cgroup_boundary"]},
            "endpoint_association": "operator-declared-loopback-metrics-config",
            "build": {name: build[name] for name in ("kind", "features", "rustc", "cargo", "environment")}}


def plan_node(args):
    from node_sampling import validate_endpoint_config
    profile = validate_node_profile(read_json(args.node_profile))
    host_profile = runner.validate_host_profile(read_json(args.host_profile))
    settings = validate_node_settings({"samples": args.samples, "interval_ms": args.interval_ms,
                                      "timeout_seconds": args.timeout, "max_output_bytes": args.max_output_bytes})
    validate_endpoint_config(profile)
    build = node_build(profile)
    manifest = {"schema_version": 1, "kind": "node-collection", "run_id": uuid.uuid4().hex,
                "settings": settings, "node_profile": profile, "build": build,
                "node_identity": node_identity(profile, build), "host": host_state(), "host_profile": host_profile,
                "expected_records": settings["samples"] * (2 + (profile["cgroup_path"] is not None)),
                "metric_catalog_sha256": sha256(runner.HERE / "schema/metrics.json"),
                "instrumentation": {name: sha256(runner.HERE / name) for name in INSTRUMENTS},
                "scope": {**SCOPE, "samples": settings["samples"], "interval_ms": settings["interval_ms"],
                          "planned_interval_total_ms": settings["samples"] * settings["interval_ms"],
                          "timeout_seconds": settings["timeout_seconds"]}}
    compatibility = node_compatibility(manifest)
    require(len(canonical({"node": compatibility, "host_profile": host_profile})) <= 12 * 1024,
            "node comparison metadata byte limit")
    manifest["configuration_id"] = digest_value({"settings": settings, "node": compatibility})
    output = fresh_directory(args.output)
    atomic_json(output / "manifest.json", manifest)
    return manifest


def _normalize(record, manifest, index):
    record = dict(record)
    phases = ["resource-process", "mempool"] + (["resource-cgroup"] if manifest["node_profile"]["cgroup_path"] else [])
    phase = phases[index % len(phases)]
    require(record.get("phase") == phase and record.get("warmup") is False
            and record.get("cache_mode") == "not-applicable", "node record scope/order mismatch")
    record.update(schema_version=1, run_id=manifest["run_id"], configuration_id=manifest["configuration_id"],
                  case_id="node." + manifest["node_profile"]["workload"]["id"],
                  process_id=f"attached.pid{manifest['node_profile']['pid']}.{phase}", attempt_id=f"a{index}")
    return validate_record(record)


def _bound_artifacts(output, maximum):
    total = count = 0
    for parent, dirs, files in os.walk(output, followlinks=False):
        for name in dirs + files:
            path = Path(parent) / name
            info = path.lstat()
            count += 1
            require(count <= 32 and (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)),
                    "node artifact entry limit or nonregular artifact")
            total += info.st_size if stat.S_ISREG(info.st_mode) else 0
            require(total <= maximum, "node artifact byte limit")


def execute_node(args, manifest):
    from node_sampling import records_from_snapshots, validate_endpoint_config
    runner.require_execute(args)
    output = Path(args.directory).resolve()
    require(manifest.get("schema_version") == 1 and manifest.get("kind") == "node-collection", "unknown node plan")
    require(not (output / "receipt.json").exists(), "run already attempted; register a new directory")
    validate_node_profile(manifest["node_profile"])
    settings = validate_node_settings(manifest["settings"])
    require(manifest["instrumentation"] == {name: sha256(runner.HERE / name) for name in INSTRUMENTS}
            and manifest["metric_catalog_sha256"] == sha256(runner.HERE / "schema/metrics.json"),
            "node collector or catalog changed")
    require(manifest["configuration_id"] == digest_value({"settings": settings, "node": node_compatibility(manifest)}),
            "node registered settings changed")
    per_sample = 2 + (manifest["node_profile"]["cgroup_path"] is not None)
    require(manifest["expected_records"] == settings["samples"] * per_sample, "node expected count mismatch")
    runner.validate_host_profile(manifest["host_profile"])
    require(host_state() == manifest["host"], "registered host facts changed")
    claim_run(output)
    receipt = {"schema_version": 1, "complete": False, "successful": False, "status": "running",
               "manifest_sha256": sha256(output / "manifest.json"), "records": 0, "snapshots": 0, "processes": []}
    atomic_json(output / "receipt.json", receipt)
    all_records, snapshots, pending = [], [], []
    disk_bound = 2 * settings["max_output_bytes"] + MAX_INPUT_BYTES + 2 * MAX_JSON + 1024 * 1024
    try:
        with (output / "attempts.jsonl").open("xb") as attempts, (output / "evidence.jsonl").open("xb") as evidence:
            def write_record(record):
                encoded = canonical(record) + b"\n"
                require(len(encoded) <= MAX_RECORD_BYTES and attempts.tell() + len(encoded) <= MAX_INPUT_BYTES,
                        "node normalized record byte limit")
                attempts.write(encoded)
                attempts.flush()
                os.fsync(attempts.fileno())
                all_records.append(record)
                receipt["records"] += 1

            def accept(_pid, line):
                require(len(line) <= MAX_FRAME_BYTES, "node evidence frame byte limit")
                frame = strict_json(line)
                require(type(frame) is dict and frame.get("frame") in {"snapshot", "record"}, "node frame schema")
                index = frame.get("index")
                require(type(index) is int, "node frame index")
                if frame["frame"] == "snapshot":
                    require(set(frame) == {"frame", "index", "evidence"} and index == len(snapshots)
                            and index <= settings["samples"] and not pending, "node snapshot order/count")
                    require(type(frame["evidence"]) is dict, "node snapshot evidence schema")
                    encoded = canonical(frame) + b"\n"
                    require(evidence.tell() + len(encoded) <= settings["max_output_bytes"], "node evidence byte limit")
                    evidence.write(encoded)
                    evidence.flush()
                    os.fsync(evidence.fileno())
                    snapshots.append(frame["evidence"])
                    receipt["snapshots"] += 1
                    if index and frame["evidence"].get("error") is None:
                        pending.extend(records_from_snapshots(snapshots[-2], snapshots[-1], manifest, index - 1))
                        require(len(pending) == per_sample, "node replay record count")
                else:
                    require(set(frame) == {"frame", "index", "record"} and index == receipt["records"]
                            and index < manifest["expected_records"] and bool(pending), "node record order/count")
                    record = _normalize(frame["record"], manifest, index)
                    require(record == _normalize(pending.pop(0), manifest, index), "node evidence/record mismatch")
                    write_record(record)

            command = [sys.executable, str(runner.HERE / "node_sampling.py"), "--manifest", str(output / "manifest.json"), "--execute"]
            receipt["processes"].append({"command": command, "complete": False, "scope": "private sampler child; attached node is not owned"})
            result = {}
            try:
                validate_endpoint_config(manifest["node_profile"])
                build = node_build(manifest["node_profile"])
                require(build == manifest["build"] and node_identity(manifest["node_profile"], build) == manifest["node_identity"],
                        "registered node binary/config/build changed")
                result = runner.supervise(command, root=runner.ROOT, directory=output / "sampler",
                                          timeout=settings["timeout_seconds"], max_bytes=settings["max_output_bytes"],
                                          max_line_bytes=MAX_FRAME_BYTES, on_line=accept,
                                          on_poll=lambda: _bound_artifacts(output, disk_bound))
                receipt["processes"][0].update(**result)
                require(receipt["records"] == manifest["expected_records"] and not pending
                        and len(snapshots) == settings["samples"] + 1, "incomplete node collection")
                require(node_identity(manifest["node_profile"], node_build(manifest["node_profile"])) == manifest["node_identity"],
                        "node inputs changed during collection")
                receipt["processes"][0]["complete"] = True
            except BaseException as error:
                elapsed = getattr(error, "elapsed_ns", result.get("elapsed_ns", 0))
                outcome = getattr(error, "outcome", "cancelled" if isinstance(error, KeyboardInterrupt) else "error")
                receipt["processes"][0].update(elapsed_ns=elapsed, pid=getattr(error, "process_id", result.get("pid")))
                failure = {"schema_version": 1, "run_id": manifest["run_id"], "configuration_id": manifest["configuration_id"],
                           "case_id": "node." + manifest["node_profile"]["workload"]["id"],
                           "process_id": "node-sampler", "attempt_id": "supervisor", "phase": "collection",
                           "cache_mode": "not-applicable", "warmup": False, "outcome": outcome,
                           "metrics": {"attempt_elapsed_ns": elapsed}, "unavailable": {}, "censored": ["attempt_elapsed_ns"],
                           "details": {"failure": type(error).__name__, "scope": "private sampler including setup; attached node is never signalled"}}
                write_record(validate_record(failure))
                raise
        checked = summarize(all_records, complete=True)
        receipt.update(complete=True, successful=checked["successful"], status="complete")
    except BaseException as error:
        receipt.update(status="failed", failure=type(error).__name__,
                       outcome=getattr(error, "outcome", "cancelled" if isinstance(error, KeyboardInterrupt) else "error"))
        raise
    finally:
        try:
            _bound_artifacts(output, disk_bound)
            receipt["artifacts"] = artifact_inventory(output)
        except BaseException as error:
            receipt.update(complete=False, successful=False, status="failed",
                           artifact_failure=type(error).__name__, artifact_inventory_complete=False)
            raise
        finally:
            atomic_json(output / "receipt.json", receipt)
    return receipt


def add_node_parser(commands):
    parser = commands.add_parser("plan-node", help="register one attached Regtest collection without contacting the node")
    for name in ("node-profile", "host-profile", "output"):
        parser.add_argument("--" + name, required=True)
    for name in ("samples", "interval-ms", "timeout"):
        parser.add_argument("--" + name, type=int, required=True)
    parser.add_argument("--max-output-bytes", type=int, default=16 * 1024 * 1024)
    parser.set_defaults(action=plan_node)
