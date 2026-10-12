#!/usr/bin/env python3
"""Register, execute and inspect bounded SLH measurements.

Build/measurement commands require --execute and are human-run commands.
Planning and saved-artifact analysis launch no measured workload.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import subprocess
import sys
import time
import uuid

from provenance import (BenchmarkError, artifact_inventory, atomic_json, canonical, claim_run,
                        digest_value, fresh_directory, host_state, read_json, require,
                        sha256, source_state, strict_json, toolchain, toolchain_compatibility,
                        verify_artifacts)

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
CASES = ("keygen", "sign", "verify", "verify-invalid")
CACHE_MODES = ("repeated-input", "varied-input")
MAX_LINE = 1024 * 1024


def validate_host_profile(profile):
    require(type(profile) is dict, "host profile must be an object")
    for name in ("description", "cpu_model", "affinity", "power_policy"):
        require(type(profile.get(name)) is str and bool(profile[name].strip()), "host profile needs " + name)
    require(type(profile.get("effective_cpu_cores")) in {int, float}
            and 0 < profile["effective_cpu_cores"] <= 65536, "declare effective CPU entitlement")
    require(type(profile.get("memory_limit_bytes")) is int and profile["memory_limit_bytes"] > 0,
            "declare available memory limit in bytes")
    return profile


class ExecutionError(BenchmarkError):
    def __init__(self, reason, outcome="error"):
        super().__init__(reason)
        self.outcome = outcome


def supervise(argv, *, root, directory, timeout, max_bytes, on_line=None, on_poll=None, max_line_bytes=MAX_LINE):
    """Bound both streams, wall time and a private process group; no shell."""
    require(os.name == "posix", "execution currently requires Linux or macOS")
    require(timeout > 0 and max_bytes > 0 and 0 < max_line_bytes <= 2 * MAX_LINE, "positive execution bounds required")
    directory = fresh_directory(directory)
    started = time.monotonic_ns()
    with (directory / "stdout.log").open("xb") as stdout_log, \
         (directory / "stderr.log").open("xb") as stderr_log:
        child = subprocess.Popen(argv, cwd=root, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 start_new_session=True)
        pending = bytearray()
        total = 0
        try:
            with selectors.DefaultSelector() as selector:
                for stream, output in ((child.stdout, stdout_log), (child.stderr, stderr_log)):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, output)
                while selector.get_map():
                    if on_poll is not None:
                        on_poll()
                    if (time.monotonic_ns() - started) / 1e9 > timeout:
                        raise ExecutionError("process deadline exceeded", "timeout")
                    for key, _ in selector.select(0.1):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        total += len(chunk)
                        require(total <= max_bytes, "process output limit exceeded")
                        key.data.write(chunk)
                        key.data.flush()
                        if key.fileobj is child.stdout and on_line is not None:
                            pending.extend(chunk)
                            while b"\n" in pending:
                                line, _, remainder = pending.partition(b"\n")
                                pending = bytearray(remainder)
                                require(len(line) <= max_line_bytes and bool(line), "invalid output line")
                                on_line(child.pid, bytes(line))
                            require(len(pending) <= max_line_bytes, "unterminated output line limit")
            require(not pending, "partial final output line")
            remaining = max(0.01, timeout - (time.monotonic_ns() - started) / 1e9)
            try:
                returncode = child.wait(timeout=remaining)
            except subprocess.TimeoutExpired as error:
                raise ExecutionError("process deadline exceeded", "timeout") from error
            require(returncode == 0, f"process exited with status {returncode}")
            if on_poll is not None:
                on_poll()
            return {"pid": child.pid, "exit_code": returncode,
                    "elapsed_ns": time.monotonic_ns() - started, "output_bytes": total}
        except BaseException as error:
            error.process_id = child.pid
            error.elapsed_ns = time.monotonic_ns() - started
            raise
        finally:
            # The group belongs only to this invocation. Kill surviving descendants
            # even if the leader exited after closing its pipes.
            child.poll()  # Reap an exited leader before signalling its old group.
            try:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            finally:
                child.wait(timeout=5)
                child.stdout.close()
                child.stderr.close()


def require_execute(args):
    require(args.execute, "this command starts a human measurement/build; add --execute")


def build(args):
    require_execute(args)
    before = source_state(ROOT)
    compiler = toolchain(HERE, source_root=ROOT)
    output = fresh_directory(args.output)
    receipt = {"schema_version": 1, "kind": "tpq-primitive-build", "complete": False,
               "source": before, "toolchain": compiler, "host": host_state()}
    atomic_json(output / "build.json", receipt)
    manifest = HERE / "Cargo.toml"
    command = ["cargo", "build", "--release", "--locked", "--manifest-path", str(manifest),
               "--target-dir", str(output / "target"), "--message-format=json"]
    receipt["command"] = command
    binaries = []

    def artifact(_pid, line):
        row = strict_json(line)
        if row.get("reason") == "compiler-artifact" and row.get("target", {}).get("name") == "tpq-bench":
            if row.get("executable"):
                binaries.append(Path(row["executable"]))

    try:
        receipt["execution"] = supervise(command, root=HERE, directory=output / "logs",
                                          timeout=args.timeout, max_bytes=64 * 1024 * 1024,
                                          on_line=artifact)
        require(len(binaries) == 1, "expected exactly one benchmark executable")
        require(source_state(ROOT) == before and toolchain(HERE, source_root=ROOT) == compiler,
                "build inputs changed during compilation")
        binary = output / "tpq-bench"
        shutil.copy2(binaries[0], binary)
        receipt.update(complete=True, binary_sha256=sha256(binary),
                       manifest_sha256=sha256(manifest), lock_sha256=sha256(HERE / "Cargo.lock"))
    except BaseException as error:
        receipt["failure"] = type(error).__name__
        raise
    finally:
        atomic_json(output / "build.json", receipt)
    return receipt


def validate_build(directory):
    directory = Path(directory).resolve()
    receipt = read_json(directory / "build.json")
    require(receipt.get("schema_version") == 1 and receipt.get("kind") == "tpq-primitive-build"
            and receipt.get("complete") is True, "incomplete/unknown build receipt")
    require(receipt["source"] == source_state(ROOT), "build source is stale")
    require(receipt["manifest_sha256"] == sha256(HERE / "Cargo.toml") and
            receipt["lock_sha256"] == sha256(HERE / "Cargo.lock"), "build manifest/lock changed")
    require(receipt["binary_sha256"] == sha256(directory / "tpq-bench"), "build binary changed")
    return receipt


def plan(args):
    require(len(args.case) == len(set(args.case)), "duplicate case")
    require(1 <= args.samples <= 10000 and 0 <= args.warmup <= 100 and
            1 <= args.repetitions <= 100, "sample/repetition bounds")
    require(0 < args.timeout <= 86400 and 0 < args.max_output_bytes <= 1024 ** 3,
            "time/output bounds")
    host_profile = read_json(args.host_profile)
    validate_host_profile(host_profile)
    build_dir = Path(args.build).resolve()
    receipt = validate_build(build_dir)
    output = fresh_directory(args.output)
    settings = {"cases": args.case, "samples": args.samples, "warmup": args.warmup,
                "repetitions": args.repetitions, "cache_mode": args.cache_mode,
                "timeout_seconds_per_process": args.timeout, "max_output_bytes_per_process": args.max_output_bytes}
    expected = validate_settings(settings)
    instrumentation = {name: sha256(HERE / name) for name in (
        "run.py", "provenance.py", "src/config.rs", "src/fixture.rs", "src/main.rs", "src/measurement.rs")}
    manifest = {"schema_version": 1, "kind": "primitive", "run_id": uuid.uuid4().hex,
                "configuration_id": digest_value(settings), "settings": settings,
                "build_directory": str(build_dir), "build_receipt_sha256": sha256(build_dir / "build.json"),
                "build": receipt, "host": host_state(), "host_profile": host_profile,
                "expected_records": expected,
                "metric_catalog_sha256": sha256(HERE / "schema/metrics.json"),
                "instrumentation": instrumentation,
                "runner_sha256": sha256(__file__),
                "limits_note": "Includes timed/warmup attempts. Primitive setup cost is separately described by the executable metadata; the process wall deadline covers setup too."}
    atomic_json(output / "manifest.json", manifest)
    return manifest


def validate_settings(settings):
    require(type(settings) is dict and set(settings) == {"cases", "samples", "warmup", "repetitions",
            "cache_mode", "timeout_seconds_per_process", "max_output_bytes_per_process"}, "run settings schema")
    require(type(settings["cases"]) is list and 0 < len(settings["cases"]) <= len(CASES)
            and all(type(case) is str and case in CASES for case in settings["cases"])
            and len(set(settings["cases"])) == len(settings["cases"]), "registered cases")
    for name, lower, upper in (("samples", 1, 10000), ("warmup", 0, 100), ("repetitions", 1, 100),
                               ("timeout_seconds_per_process", 1, 86400),
                               ("max_output_bytes_per_process", 1, 1024 ** 3)):
        require(type(settings[name]) is int and lower <= settings[name] <= upper, "registered bound: " + name)
    require(settings["cache_mode"] in CACHE_MODES, "registered cache mode")
    # Each fresh process also emits one lifetime high-water observation.
    expected = len(settings["cases"]) * settings["repetitions"] * (settings["samples"] + settings["warmup"] + 1)
    require(expected < 100000, "registered total observation limit (reserves a failure record)")
    return expected


def normalized_child_record(raw, manifest, case, repetition, index, pid):
    from results import validate_record
    require(type(raw) is dict, "child output must be an object")
    require(raw.get("case_id") == "primitive." + case, "child case mismatch")
    require(raw.get("warmup") is (index < manifest["settings"]["warmup"]), "child warmup order mismatch")
    require(raw.get("cache_mode") == manifest["settings"]["cache_mode"], "child cache mode mismatch")
    final = index == manifest["settings"]["samples"] + manifest["settings"]["warmup"]
    require(raw.get("phase") == ("process" if final else "primitive"), "child phase mismatch")
    metric = {"keygen": "keygen_ns", "sign": "sign_release_ns", "verify": "signature_verify_ns",
              "verify-invalid": "signature_verify_ns"}[case]
    required = {"process_peak_rss_bytes"} if final else {
        metric, "attempt_elapsed_ns", "process_cpu_ns", "process_cpu_core_equivalents",
        "rss_before_bytes", "rss_after_bytes", "public_key_bytes"}
    if not final and case != "keygen":
        required.update({"message_bytes", "signature_bytes"})
    require(type(raw.get("metrics")) is dict and set(raw["metrics"]) == required,
            "child required metric set mismatch")
    record = dict(raw)
    for name in ("schema_version", "run_id", "configuration_id", "process_id", "attempt_id"):
        record.pop(name, None)
    record.update(schema_version=1, run_id=manifest["run_id"],
                  configuration_id=manifest["configuration_id"], process_id=f"{case}.r{repetition}.pid{pid}",
                  attempt_id=f"a{index}")
    validate_record(record)
    return record


def execute(args):
    from results import MAX_INPUT_BYTES, MAX_RECORD_BYTES, summarize
    require_execute(args)
    output = Path(args.directory).resolve()
    manifest = read_json(output / "manifest.json")
    if manifest.get("kind") == "payment":
        from payment_run import execute_payment
        return execute_payment(args, manifest)
    if manifest.get("kind") == "node-collection":
        from node_run import execute_node
        return execute_node(args, manifest)
    require(manifest.get("kind") == "primitive" and manifest.get("schema_version") == 1, "unknown run plan")
    require(not (output / "receipt.json").exists(), "run already attempted; register a new directory")
    require(sha256(HERE / "schema/metrics.json") == manifest["metric_catalog_sha256"] and
            sha256(__file__) == manifest["runner_sha256"], "runner or metric catalog changed")
    build_dir = Path(manifest["build_directory"])
    require(sha256(build_dir / "build.json") == manifest["build_receipt_sha256"], "build receipt changed")
    require(validate_build(build_dir) == manifest["build"], "registered build changed")
    require(host_state() == manifest["host"], "registered host facts changed")
    validate_host_profile(manifest["host_profile"])
    settings = manifest["settings"]
    require(validate_settings(settings) == manifest["expected_records"] and
            digest_value(settings) == manifest["configuration_id"], "registered settings changed")
    claim_run(output)
    receipt = {"schema_version": 1, "complete": False, "successful": False, "status": "running",
               "manifest_sha256": sha256(output / "manifest.json"), "processes": [], "records": 0}
    atomic_json(output / "receipt.json", receipt)
    all_records = []
    try:
        with (output / "attempts.jsonl").open("xb") as stream:
            for repetition in range(settings["repetitions"]):
                for case in settings["cases"]:
                    count = 0

                    def accept(pid, line):
                        nonlocal count
                        require(count < settings["samples"] + settings["warmup"] + 1, "extra child record")
                        record = normalized_child_record(strict_json(line), manifest, case, repetition, count, pid)
                        encoded = canonical(record) + b"\n"
                        require(len(encoded) <= MAX_RECORD_BYTES and
                                stream.tell() + len(encoded) <= MAX_INPUT_BYTES - MAX_RECORD_BYTES,
                                "run record byte limit")
                        stream.write(encoded)
                        stream.flush()
                        os.fsync(stream.fileno())
                        all_records.append(record)
                        count += 1
                        receipt["records"] += 1
                        expected_outcome = ("expected_rejection" if case == "verify-invalid"
                                            and record["phase"] == "primitive" else "success")
                        require(record["outcome"] == expected_outcome, "primitive attempt outcome mismatch")

                    command = [str(build_dir / "tpq-bench"), "measure", "--case", case,
                               "--samples", str(settings["samples"]), "--warmup", str(settings["warmup"]),
                               "--cache-mode", settings["cache_mode"], "--execute"]
                    receipt["processes"].append({"case": case, "repetition": repetition,
                                                  "command": command, "complete": False})
                    atomic_json(output / "receipt.json", receipt)
                    result = {}
                    try:
                        result = supervise(command, root=ROOT, directory=output / f"process-{repetition}-{case}",
                                           timeout=settings["timeout_seconds_per_process"],
                                           max_bytes=settings["max_output_bytes_per_process"], on_line=accept)
                        require(count == settings["samples"] + settings["warmup"] + 1, "missing child records")
                    except BaseException as error:
                        pid = getattr(error, "process_id", result.get("pid", "unstarted"))
                        outcome = getattr(error, "outcome", "cancelled" if isinstance(error, KeyboardInterrupt) else "error")
                        failure = {"schema_version": 1, "run_id": manifest["run_id"],
                                   "configuration_id": manifest["configuration_id"], "case_id": "primitive." + case,
                                   "process_id": f"{case}.r{repetition}.pid{pid}", "attempt_id": "supervisor",
                                   "phase": "process", "cache_mode": settings["cache_mode"], "warmup": False,
                                   "outcome": outcome, "metrics": {"attempt_elapsed_ns": getattr(error, "elapsed_ns", result.get("elapsed_ns", 0))},
                                   "unavailable": {}, "censored": ["attempt_elapsed_ns"],
                                   "details": {"failure": type(error).__name__, "scope": "whole child; includes setup"}}
                        stream.write(canonical(failure) + b"\n")
                        stream.flush()
                        os.fsync(stream.fileno())
                        receipt["records"] += 1
                        raise
                    receipt["processes"][-1].update(complete=True, **result)
            require(receipt["records"] == manifest["expected_records"], "incomplete matrix")
            require(validate_build(build_dir) == manifest["build"], "inputs changed during run")
            checked = summarize(all_records, complete=True)
            receipt.update(complete=True, successful=checked["successful"], status="complete")
    except BaseException as error:
        receipt.update(status="failed", failure=type(error).__name__,
                       outcome=getattr(error, "outcome", "cancelled" if isinstance(error, KeyboardInterrupt) else "error"))
        raise
    finally:
        receipt["artifacts"] = artifact_inventory(output)
        atomic_json(output / "receipt.json", receipt)
    return receipt


def read_records(path):
    from results import read_records as checked_records
    path = Path(path)
    require(not path.is_symlink() and path.is_file(), "record input must be a regular file")
    return list(checked_records(path))


def summarize_run(args):
    from results import summarize, write_reports
    directory = Path(args.directory)
    manifest = read_json(directory / "manifest.json")
    receipt = read_json(directory / "receipt.json")
    require(manifest["metric_catalog_sha256"] == sha256(HERE / "schema/metrics.json"),
            "metric catalog changed; use the original source revision to report this run")
    from results import PAYMENT_CATALOG_SHA256, PAYMENT_METRICS
    extensions = manifest.get("metric_catalog_extensions", {})
    require(extensions in ({}, {"payment": PAYMENT_CATALOG_SHA256}), "payment metric catalog changed")
    require(manifest.get("kind") != "payment" or extensions == {"payment": PAYMENT_CATALOG_SHA256},
            "payment catalog identity missing")
    if manifest.get("kind") == "payment" and manifest.get("wallet_storage") is not None:
        from payment_run import validate_wallet_storage
        validate_wallet_storage(manifest.get("wallet_storage"), manifest["host_profile"])
    require(receipt["manifest_sha256"] == sha256(directory / "manifest.json"), "manifest changed")
    verify_artifacts(directory, receipt["artifacts"])
    records = read_records(directory / "attempts.jsonl")
    require(not any(set(record["metrics"]).intersection(PAYMENT_METRICS) for record in records)
            or extensions == {"payment": PAYMENT_CATALOG_SHA256}, "payment metric catalog identity missing")
    verify_artifacts(directory, receipt["artifacts"])
    require(len(records) == receipt["records"], "receipt record count mismatch")
    if args.process_id:
        records = [record for record in records if record["process_id"] == args.process_id]
        require(bool(records), "unknown process selection")
    summary = summarize(records, complete=receipt["complete"])
    summary["compatibility"] = {"kind": manifest["kind"], "settings": manifest.get("settings"),
                                "host": manifest.get("host"), "host_profile": manifest.get("host_profile"),
                                "metric_catalog_sha256": manifest["metric_catalog_sha256"],
                                "instrumentation": manifest.get("instrumentation"),
                                "reporter_sha256": sha256(HERE / "results.py"),
                                "toolchain": toolchain_compatibility(manifest.get("build", {}).get("toolchain")),
                                "adapter_compatibility": manifest.get("adapter_compatibility")}
    if extensions:
        summary["compatibility"]["metric_catalog_extensions"] = extensions
    if manifest.get("kind") == "payment":
        summary["compatibility"]["independent_checker"] = manifest["independent_checker"]
        summary["compatibility"]["wallet_storage"] = manifest.get("wallet_storage")
    if manifest.get("kind") == "node-collection":
        from node_run import node_compatibility
        summary["compatibility"]["node_collection"] = node_compatibility(manifest)
    summary["provenance"] = {"manifest_sha256": receipt["manifest_sha256"],
                             "source": manifest.get("build", {}).get("source", {}).get("commit"),
                             "html_renderer_sha256": sha256(HERE / "html_report.py"),
                             "toolchain": manifest.get("build", {}).get("toolchain"),
                             "execution_status": receipt["status"], "process_selection": args.process_id,
                             "imported_evidence": manifest.get("provenance"),
                             "adapter_metadata": manifest.get("adapter_metadata")}
    if manifest.get("kind") == "payment":
        summary["provenance"]["payment_scope"] = manifest["scope"]
        summary["provenance"]["wallet_storage"] = manifest.get("wallet_storage")
        if manifest.get("wallet_storage") is None:
            summary["provenance"]["wallet_storage_unavailable"] = (
                "This historical run did not register wallet storage; matched payment comparison is unavailable.")
        summary["provenance"]["independent_checks"] = receipt.get("independent_checks", [])
    if manifest.get("kind") == "node-collection":
        summary["provenance"].update(node_scope=manifest["scope"], node_profile=manifest["node_profile"],
                                     node_identity=manifest["node_identity"],
                                     node_execution=receipt.get("processes", [{}])[0],
                                     source=manifest["build"]["source"]["source_commit"])
    require(not (receipt["complete"] and receipt["records"] != manifest["expected_records"]),
            "complete receipt missing expected records")
    require(not Path(args.output).resolve().is_relative_to(directory.resolve()), "reports must be outside immutable run artifacts")
    output = fresh_directory(args.output)
    write_reports(summary, output)
    return {"output": str(output), "successful": summary["successful"], "complete": summary["complete"]}


def compare(args):
    from results import compare_summaries
    result = compare_summaries(read_json(args.baseline), read_json(args.candidate))
    output = Path(args.output)
    require(not output.exists(), "comparison output exists")
    atomic_json(output, result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    building = commands.add_parser("build", help="human: compile the isolated benchmark executable")
    building.add_argument("--output", required=True)
    building.add_argument("--timeout", type=int, default=1800)
    building.add_argument("--execute", action="store_true")
    building.set_defaults(action=build)
    planning = commands.add_parser("plan", help="register a bounded primitive run without executing it")
    planning.add_argument("--build", required=True)
    planning.add_argument("--output", required=True)
    planning.add_argument("--host-profile", required=True)
    planning.add_argument("--case", choices=CASES, action="append", required=True)
    planning.add_argument("--samples", type=int, required=True)
    planning.add_argument("--warmup", type=int, required=True)
    planning.add_argument("--repetitions", type=int, default=1)
    planning.add_argument("--cache-mode", choices=CACHE_MODES, required=True)
    planning.add_argument("--timeout", type=int, required=True)
    planning.add_argument("--max-output-bytes", type=int, default=16 * 1024 * 1024)
    planning.set_defaults(action=plan)
    from payment_run import add_payment_parser
    add_payment_parser(commands)
    from node_run import add_node_parser
    add_node_parser(commands)
    running = commands.add_parser("run", help="human: execute one registered run exactly once")
    running.add_argument("directory")
    running.add_argument("--execute", action="store_true")
    running.set_defaults(action=execute)
    summarizing = commands.add_parser("summarize", help="check saved artifacts and write reports offline")
    summarizing.add_argument("directory")
    summarizing.add_argument("--output", required=True)
    summarizing.add_argument("--process-id")
    summarizing.set_defaults(action=summarize_run)
    comparing = commands.add_parser("compare", help="compare compatible saved summaries offline")
    comparing.add_argument("--baseline", required=True)
    comparing.add_argument("--candidate", required=True)
    comparing.add_argument("--output", required=True)
    comparing.set_defaults(action=compare)
    importing = commands.add_parser("import", help="validate and archive saved measurements offline")
    importing.add_argument("--kind", choices=("normalized", "transaction", "resources", "mempool", "block-trace", "propagation"), required=True)
    importing.add_argument("--input", required=True)
    importing.add_argument("--profile", required=True)
    importing.add_argument("--output", required=True)

    def saved(args):
        from imports import import_saved
        return import_saved(args)

    importing.set_defaults(action=saved)
    args = parser.parse_args(argv)
    try:
        result = args.action(args)
    except (ValueError, OSError, subprocess.SubprocessError, KeyError) as error:
        parser.exit(1, f"benchmark: {error}\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
