"""Register and supervise bounded offline wallet workflows; never runs on import."""

from __future__ import annotations

import itertools
import os
from pathlib import Path
import re
import stat
import sys
import uuid

import run as runner
from provenance import (artifact_inventory, atomic_json, canonical, claim_run, digest_value,
                        fresh_directory, host_state, read_json, require, sha256, strict_json)
from results import (MAX_INPUT_BYTES, MAX_RECORD_BYTES, PAYMENT_CATALOG_SHA256,
                     summarize, validate_record)

ALGORITHMS = ("slh-dsa-b128s", "ecdsa-secp256k1")
VERSIONS = ("v5", "v6")
POLICIES = ("single", "multisig")
INPUTS = (1, 2, 5)
INVENTORIES = ("cached", "generated")
CASE_FIELDS = ("algorithm", "version", "policy", "inputs", "inventory")
DIMENSION_CHOICES = (ALGORITHMS, VERSIONS, POLICIES, INPUTS, INVENTORIES)
COMMON_METRICS = {"payment_verify_ns", "payment_total_ns",
                  "transaction_bytes", "input_count", "signature_count", "attempt_elapsed_ns",
                  "process_cpu_ns", "process_cpu_core_equivalents", "rss_before_bytes", "rss_after_bytes"}
SLH_METRICS = {"payment_wallet_setup_ns", "payment_prepare_persist_ns", "payment_sign_persist_ns",
               "payment_assemble_persist_ns"}
CLASSICAL_METRICS = {"payment_assembly_ns", "payment_sign_ns"}
INSTRUMENTS = ("run.py", "payment_run.py", "payment_checks.py", "src/payment.rs", "src/payment_fixture.rs",
               "src/classical.rs", "src/measurement.rs", "src/main.rs", "provenance.py")
SCOPE = {
    "trust": "Offline fixture supplied at the wallet trusted-node interface; previous outputs are not authenticated against a live chain.",
    "slh": "Complete product WatchStore prepare/sign/assemble lifecycle with coupled durable journal writes.",
    "classical": "Matched transparent transaction controls; no equivalent durable classical wallet implementation.",
    "cache": "Cached public enrolled SLH inventory is prepared outside foreground timing; both SLH modes derive secret signing keys through the actual wallet and create fresh watch stores with empty journals. Classical cached controls reuse prepared secp256k1 key pairs.",
    "timing": "Total is one enclosing observed interval, never a sum of stage percentiles. Independent checks run after the measured child exits.",
}


def case_id(case):
    return "payment.{algorithm}.{version}.{policy}.i{inputs}.{inventory}".format(**case)


def validate_payment_settings(settings):
    expected_fields = {"cases", "samples", "warmup", "repetitions", "timeout_seconds_per_process",
                       "max_output_bytes_per_process", "max_artifact_bytes_per_process",
                       "checker_timeout_seconds", "checker_max_output_bytes"}
    require(type(settings) is dict and set(settings) == expected_fields, "payment settings schema")
    cases = settings["cases"]
    require(type(cases) is list and 1 <= len(cases) <= 48, "payment registered cases")
    identities = set()
    for case in cases:
        require(type(case) is dict and set(case) == set(CASE_FIELDS), "payment case schema")
        for name, choices in zip(CASE_FIELDS, DIMENSION_CHOICES):
            require(type(case[name]) is type(choices[0]) and case[name] in choices,
                    "payment case dimension: " + name)
        identity = case_id(case)
        require(identity not in identities, "duplicate payment case")
        identities.add(identity)
    for name, lower, upper in (("samples", 1, 100), ("warmup", 0, 10), ("repetitions", 1, 100),
                               ("timeout_seconds_per_process", 1, 86400),
                               ("max_output_bytes_per_process", 1, 64 * 1024 * 1024),
                               ("max_artifact_bytes_per_process", 1, 512 * 1024 * 1024),
                               ("checker_timeout_seconds", 1, 600),
                               ("checker_max_output_bytes", 1, 1024 * 1024)):
        require(type(settings[name]) is int and lower <= settings[name] <= upper,
                "payment registered bound: " + name)
    expected = len(cases) * settings["repetitions"] * (settings["samples"] + settings["warmup"] + 1)
    require(expected <= 4096, "payment observation limit (4096) reserves a failure record")
    require(len(cases) * settings["repetitions"] <= 2000, "payment process limit")
    process_count = len(cases) * settings["repetitions"]
    allowance = process_count * (settings["max_artifact_bytes_per_process"] + settings["max_output_bytes_per_process"])
    allowance += (expected - process_count + 1) * settings["checker_max_output_bytes"]
    require(allowance <= 2 * 1024 ** 3 - 64 * 1024 ** 2,
            "payment total registered artifact allowance exceeds 2 GiB (including reference and receipt reserve)")
    return expected


def checker_identity(reference_inputs):
    from payment_checks import reference_identity, checker_identity as code_identity
    return {"reference": reference_identity(Path(reference_inputs)),
            "checker_sha256": code_identity()}


def plan_payment(args):
    dimensions = []
    for field in CASE_FIELDS:
        values = getattr(args, field)
        require(len(values) == len(set(values)), "duplicate payment selection: " + field)
        dimensions.append(values)
    settings = {"cases": [dict(zip(CASE_FIELDS, values)) for values in itertools.product(*dimensions)],
                "samples": args.samples, "warmup": args.warmup, "repetitions": args.repetitions,
                "timeout_seconds_per_process": args.timeout,
                "max_output_bytes_per_process": args.max_output_bytes,
                "max_artifact_bytes_per_process": args.max_artifact_bytes,
                "checker_timeout_seconds": args.checker_timeout,
                "checker_max_output_bytes": args.checker_max_output_bytes}
    expected = validate_payment_settings(settings)
    host_profile = runner.validate_host_profile(read_json(args.host_profile))
    build_dir = Path(args.build).resolve()
    receipt = runner.validate_build(build_dir)
    instruments = {name: sha256(runner.HERE / name) for name in INSTRUMENTS}
    output = fresh_directory(args.output)
    from provenance import snapshot_payment_reference
    reference = snapshot_payment_reference(Path(args.reference_inputs).resolve(), output / "reference-inputs")
    checker = checker_identity(reference)
    manifest = {"schema_version": 1, "kind": "payment", "run_id": uuid.uuid4().hex,
                "configuration_id": digest_value(settings), "settings": settings,
                "build_directory": str(build_dir), "build_receipt_sha256": sha256(build_dir / "build.json"),
                "build": receipt, "host": host_state(), "host_profile": host_profile,
                "expected_records": expected, "metric_catalog_sha256": sha256(runner.HERE / "schema/metrics.json"),
                "metric_catalog_extensions": {"payment": PAYMENT_CATALOG_SHA256},
                "reference_inputs": str(reference), "independent_checker": checker,
                "instrumentation": instruments, "runner_sha256": sha256(runner.HERE / "run.py"),
                "scope": SCOPE}
    atomic_json(output / "manifest.json", manifest)
    return manifest


def bound_artifacts(directory, *, max_bytes, max_files):
    """Bound public outputs during execution, before hashing or JSON decoding."""
    directory = Path(directory)
    require(not directory.is_symlink() and directory.is_dir(), "payment artifact directory changed")
    total = 0
    names = []
    with os.scandir(directory) as entries:
        for entry in entries:
            require(len(names) < max_files, "payment artifact file limit")
            info = entry.stat(follow_symlinks=False)
            require(stat.S_ISREG(info.st_mode), "payment artifacts must be regular files without subdirectories")
            total += info.st_size
            require(info.st_size <= 16 * 1024 * 1024 and total <= max_bytes, "payment artifact byte limit")
            names.append(entry.name)
    return set(names)


def bound_run_artifacts(directory):
    """Reject oversized failed output before final inventory would hash its bytes."""
    pending = [Path(directory)]
    size = count = 0
    while pending:
        parent = pending.pop()
        with os.scandir(parent) as entries:
            for entry in entries:
                count += 1
                require(count <= 25000, "payment run artifact entry limit")
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    pending.append(Path(entry.path))
                else:
                    require(stat.S_ISREG(info.st_mode), "payment run artifact is not a regular file")
                    require(info.st_size <= 64 * 1024 * 1024, "payment run single artifact byte limit")
                    size += info.st_size
                    require(size <= 2 * 1024 ** 3, "payment run artifact byte limit")


def normalize_payment_record(raw, manifest, case, repetition, index, pid):
    require(type(raw) is dict, "payment child output must be an object")
    settings = manifest["settings"]
    successful = raw.get("outcome") == "success"
    final = raw.get("phase") == "process"
    require(not final or not successful or index == settings["samples"] + settings["warmup"],
            "early successful payment process record")
    require(raw.get("case_id") == case_id(case), "payment child case mismatch")
    require(raw.get("cache_mode") == case["inventory"], "payment inventory mismatch")
    require(raw.get("warmup") is (not final and index < settings["warmup"]), "payment warmup order mismatch")
    require(raw.get("phase") == ("process" if final else "wallet"), "payment phase mismatch")
    require(final or index < settings["samples"] + settings["warmup"], "extra payment wallet attempt")
    required = {"process_peak_rss_bytes"} if final else COMMON_METRICS | (
        SLH_METRICS if case["algorithm"] == ALGORITHMS[0] else CLASSICAL_METRICS)
    if not final and case["inventory"] == "generated":
        required = required | {"payment_inventory_ns"}
    require(type(raw.get("metrics")) is dict, "payment required metric set mismatch")
    if successful or final:
        require(set(raw["metrics"]) == required, "payment required metric set mismatch")
    else:
        completed_bounds = {"payment_total_ns", "attempt_elapsed_ns", "process_cpu_ns",
                            "process_cpu_core_equivalents", "rss_before_bytes", "rss_after_bytes"}
        require(completed_bounds <= set(raw["metrics"]) <= required, "partial payment metric set mismatch")
    record = dict(raw)
    for name in ("schema_version", "run_id", "configuration_id", "process_id", "attempt_id"):
        record.pop(name, None)
    record.update(schema_version=1, run_id=manifest["run_id"], configuration_id=manifest["configuration_id"],
                  process_id=f"{case_id(case)}.r{repetition}.pid{pid}", attempt_id=f"a{index}")
    validate_record(record)
    if not final:
        metrics = record["metrics"]
        require(all(metrics[name] == expected for name, expected in (
            ("input_count", case["inputs"]), ("signature_count", case["inputs"] * (1 if case["policy"] == "single" else 2)))
            if name in metrics), "payment shape metric mismatch")
        require(record.get("details", {}).get("inventory_timing") ==
                ("prepared outside foreground; not measured for cached mode" if case["inventory"] == "cached"
                 else "wallet creation, key derivation, policy enrollment and verified backup publication inside foreground"
                 if case["algorithm"] == ALGORITHMS[0] else "disposable classical key creation inside foreground"),
                "payment inventory measurement scope")
        details = record.get("details", {})
        require(details.get("public_fixture") is True and details.get("offline_fixture") is True
                and details.get("trusted_utxos") is False and details.get("node_acceptance") is False,
                "payment offline fixture scope mismatch")
        require(details.get("measurement_scope") == ("offline-wallet-with-durable-journal"
                if case["algorithm"] == ALGORITHMS[0] else "classical-transaction-control-no-wallet-journal"),
                "payment implementation scope mismatch")
        if successful or "artifact_path" in details:
            require(details.get("artifact_path") == f"attempt-{index:06}.json", "payment public artifact path mismatch")
            require(type(details.get("artifact_sha256")) is str and
                    re.fullmatch("[0-9a-f]{64}", details["artifact_sha256"]), "payment artifact hash missing or invalid")
        if "transaction_bytes" in metrics:
            require(metrics["transaction_bytes"] is not None and metrics["transaction_bytes"] > 0,
                    "empty payment transaction")
        require(type(metrics["payment_total_ns"]) is int, "payment foreground interval unavailable")
        require(all(metrics["payment_total_ns"] >= value for name, value in metrics.items()
                    if name.startswith("payment_") and name.endswith("_ns") and value is not None),
                "payment stage exceeds enclosing foreground interval")
    return record


def independent_check(manifest, output, *, artifact=None, name):
    settings = manifest["settings"]
    command = [sys.executable, "-B", str(runner.HERE / "payment_checks.py"), "--repo-root", str(runner.ROOT),
               "--reference-inputs", manifest["reference_inputs"]]
    command += ["--artifact", str(artifact)] if artifact else ["--preflight"]
    rows = []

    def accept(_pid, line):
        require(not rows, "extra independent checker receipt")
        rows.append(strict_json(line))

    execution = runner.supervise(command, root=runner.ROOT, directory=output / name,
                                 timeout=settings["checker_timeout_seconds"],
                                 max_bytes=settings["checker_max_output_bytes"], on_line=accept)
    require(len(rows) == 1 and type(rows[0]) is dict and rows[0].get("schema_version") == 1
            and rows[0].get("complete") is True, "independent checker did not complete")
    require(rows[0].get("reference") == manifest["independent_checker"]["reference"] and
            rows[0].get("checker_sha256") == manifest["independent_checker"]["checker_sha256"],
            "independent checker receipt inputs mismatch")
    if artifact:
        require(rows[0].get("artifact_sha256") == sha256(artifact), "independent artifact identity mismatch")
    require(checker_identity(manifest["reference_inputs"]) == manifest["independent_checker"],
            "independent checker inputs changed")
    return {"receipt": rows[0], "execution": execution, "logs": name}


def checked_index(checked, output, **identity):
    """Receipts keep compact indices; full checker evidence remains in hashed stdout."""
    return {**identity, "logs": checked["logs"], "complete": True,
            "receipt_sha256": sha256(output / checked["logs"] / "stdout.log"),
            "artifact_sha256": checked["receipt"].get("artifact_sha256"),
            "execution": checked["execution"]}


def execute_payment(args, manifest):
    runner.require_execute(args)
    output = Path(args.directory).resolve()
    require(manifest.get("schema_version") == 1 and manifest.get("kind") == "payment", "unknown payment plan")
    require(not (output / "receipt.json").exists(), "run already attempted; register a new directory")
    require(manifest["runner_sha256"] == sha256(runner.HERE / "run.py") and
            manifest["metric_catalog_sha256"] == sha256(runner.HERE / "schema/metrics.json") and
            manifest["metric_catalog_extensions"] == {"payment": PAYMENT_CATALOG_SHA256},
            "payment runner or catalog changed")
    require(manifest["instrumentation"] == {name: sha256(runner.HERE / name) for name in INSTRUMENTS},
            "payment instrumentation changed")
    settings = manifest["settings"]
    require(validate_payment_settings(settings) == manifest["expected_records"] and
            digest_value(settings) == manifest["configuration_id"], "payment registered settings changed")
    build_dir = Path(manifest["build_directory"])
    require(sha256(build_dir / "build.json") == manifest["build_receipt_sha256"] and
            runner.validate_build(build_dir) == manifest["build"], "payment registered build changed")
    require(host_state() == manifest["host"], "payment host facts changed")
    runner.validate_host_profile(manifest["host_profile"])
    require(checker_identity(manifest["reference_inputs"]) == manifest["independent_checker"],
            "payment independent checker inputs changed")
    claim_run(output)
    receipt = {"schema_version": 1, "complete": False, "successful": False, "status": "running",
               "manifest_sha256": sha256(output / "manifest.json"), "processes": [], "records": 0,
               "independent_checks": []}
    atomic_json(output / "receipt.json", receipt)
    all_records = []
    active_case, repetition, process_id, phase = settings["cases"][0], 0, "preflight", "independent-check"
    try:
        with (output / "attempts.jsonl").open("xb") as stream:
            def save(record):
                encoded = canonical(record) + b"\n"
                require(len(encoded) <= MAX_RECORD_BYTES and
                        stream.tell() + len(encoded) <= MAX_INPUT_BYTES - MAX_RECORD_BYTES,
                        "payment run record byte limit")
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
                all_records.append(record)
                receipt["records"] += 1

            try:
                preflight = independent_check(manifest, output, name="preflight")
                receipt["independent_checks"].append(checked_index(preflight, output))
                atomic_json(output / "receipt.json", receipt)
                for repetition in range(settings["repetitions"]):
                    for active_case in settings["cases"]:
                        identifier = case_id(active_case)
                        process_name = f"process-{repetition}-{identifier}"
                        artifacts = fresh_directory(output / (process_name + "-artifacts"))
                        count, rows = 0, []
                        phase, process_id = "process", f"{identifier}.r{repetition}.unstarted"

                        def accept(pid, line):
                            nonlocal count, process_id
                            require(count < settings["samples"] + settings["warmup"] + 1, "extra payment record")
                            record = normalize_payment_record(strict_json(line), manifest, active_case, repetition, count, pid)
                            process_id = record["process_id"]
                            save(record)
                            rows.append(record)
                            count += 1

                        def check_bounds():
                            bound_artifacts(artifacts, max_bytes=settings["max_artifact_bytes_per_process"],
                                            max_files=settings["samples"] + settings["warmup"])

                        command = [str(build_dir / "tpq-bench"), "payment"]
                        for name in CASE_FIELDS:
                            command += ["--" + name, str(active_case[name])]
                        command += ["--samples", str(settings["samples"]), "--warmup", str(settings["warmup"]),
                                    "--artifact-directory", str(artifacts), "--execute"]
                        process = {"case": active_case, "repetition": repetition, "command": command, "complete": False}
                        receipt["processes"].append(process)
                        atomic_json(output / "receipt.json", receipt)
                        execution = runner.supervise(command, root=runner.ROOT, directory=output / process_name,
                                                     timeout=settings["timeout_seconds_per_process"],
                                                     max_bytes=settings["max_output_bytes_per_process"],
                                                     on_line=accept, on_poll=check_bounds)
                        process.update(execution)
                        require(all(row["outcome"] == "success" for row in rows), "payment attempt outcome mismatch")
                        require(count == settings["samples"] + settings["warmup"] + 1, "missing payment records")
                        expected_paths = {f"attempt-{index:06}.json" for index in range(count - 1)}
                        require(bound_artifacts(artifacts, max_bytes=settings["max_artifact_bytes_per_process"],
                                                max_files=count - 1) == expected_paths, "payment artifact inventory mismatch")
                        phase = "independent-check"
                        for index, row in enumerate(rows[:-1]):
                            artifact = artifacts / row["details"]["artifact_path"]
                            require(sha256(artifact) == row["details"]["artifact_sha256"], "measured payment artifact changed")
                            checked = independent_check(manifest, output, artifact=artifact,
                                                        name=f"check-{repetition}-{identifier}-{index}")
                            evidence = checked["receipt"]
                            require(sha256(artifact) == row["details"]["artifact_sha256"], "measured payment artifact changed")
                            require(evidence.get("algorithm") == active_case["algorithm"] and
                                    type(evidence.get("version")) is int and
                                    evidence["version"] == int(active_case["version"][1:]) and
                                    evidence.get("policy") == active_case["policy"] and
                                    evidence.get("inventory") == active_case["inventory"] and
                                    evidence.get("input_count") == active_case["inputs"] and
                                    evidence.get("transaction_bytes") == row["metrics"]["transaction_bytes"],
                                    "independent checker shape or size mismatch")
                            receipt["independent_checks"].append(checked_index(checked, output,
                                                                 process_id=row["process_id"], attempt_id=row["attempt_id"]))
                            atomic_json(output / "receipt.json", receipt)
                        process["complete"] = True
                        atomic_json(output / "receipt.json", receipt)
                require(receipt["records"] == manifest["expected_records"], "incomplete payment matrix")
                require(runner.validate_build(build_dir) == manifest["build"], "payment inputs changed during run")
                checked = summarize(all_records, complete=True)
                receipt.update(complete=True, successful=checked["successful"], status="complete")
            except BaseException as error:
                outcome = getattr(error, "outcome", "cancelled" if isinstance(error, KeyboardInterrupt) else "error")
                failure = {"schema_version": 1, "run_id": manifest["run_id"],
                           "configuration_id": manifest["configuration_id"], "case_id": case_id(active_case),
                           "process_id": process_id, "attempt_id": "supervisor", "phase": phase,
                           "cache_mode": active_case["inventory"], "warmup": False, "outcome": outcome,
                           "metrics": {"attempt_elapsed_ns": getattr(error, "elapsed_ns", 0)},
                           "unavailable": {}, "censored": ["attempt_elapsed_ns"],
                           "details": {"failure": type(error).__name__, "scope": phase,
                                       "note": "Independent checker failures do not erase measured attempts."}}
                save(failure)
                raise
    except BaseException as error:
        receipt.update(status="failed", failure=type(error).__name__,
                       outcome=getattr(error, "outcome", "cancelled" if isinstance(error, KeyboardInterrupt) else "error"))
        raise
    finally:
        try:
            bound_run_artifacts(output)
            receipt["artifacts"] = artifact_inventory(output)
        except (ValueError, OSError) as error:
            receipt.update(complete=False, successful=False, status="failed",
                           artifact_inventory_failure=type(error).__name__)
            raise
        finally:
            atomic_json(output / "receipt.json", receipt)
    return receipt


def add_payment_parser(commands):
    parser = commands.add_parser("plan-payment", help="register bounded offline wallet cases without measuring")
    for field, choices in zip(CASE_FIELDS, DIMENSION_CHOICES):
        parser.add_argument("--" + field, choices=choices, type=type(choices[0]), action="append", required=True)
    for name in ("build", "output", "host-profile", "reference-inputs"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--samples", type=int, required=True)
    parser.add_argument("--warmup", type=int, required=True)
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--timeout", type=int, required=True)
    parser.add_argument("--max-output-bytes", type=int, default=16 * 1024 * 1024)
    parser.add_argument("--max-artifact-bytes", type=int, default=32 * 1024 * 1024)
    parser.add_argument("--checker-timeout", type=int, default=120)
    parser.add_argument("--checker-max-output-bytes", type=int, default=256 * 1024)
    parser.set_defaults(action=plan_payment)
