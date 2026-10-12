"""Import bounded saved artifacts without starting collectors or workloads.

The profile describes operator-supplied evidence. Hashing the supplied files
establishes their identity, not the truth of their source, execution, clock,
configuration or completion declarations. See tests for synthetic examples.
"""

from __future__ import annotations

import math
import hashlib
import os
from pathlib import Path
import stat
import tomllib

import results

KINDS = ("normalized", "transaction", "block-trace", "propagation", "mempool", "resources")
CONTEXT_FIELDS = {
    "run_id", "case_id", "configuration_id", "process_id", "attempt_id", "phase", "cache_mode", "warmup",
}
PROFILE_FIELDS = {
    "schema_version", "context", "expected_records", "complete", "host_profile", "provenance", "options",
}
MAX_PROFILE_BYTES = 1024 * 1024
EVIDENCE_NOTE = (
    "operator-supplied saved evidence; file hashes identify the imported bytes, "
    "not an authenticated workload receipt; source, binary, configuration, host, "
    "clock, freshness and completion declarations are not independently verified"
)


def _saved_bytes(path, maximum):
    """Require a regular file before reading; a FIFO cannot block the import."""
    from provenance import require
    path = Path(path)
    require(not path.is_symlink(), "saved input must not be a symlink")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as handle:
        before = os.fstat(handle.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum,
                "saved input must be a bounded regular file")
        data = handle.read(maximum + 1)
        after = os.fstat(handle.fileno())
    require(len(data) <= maximum, "saved input exceeds the byte limit")
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
            "saved input changed while reading")
    return data


def _json_value(value, *, depth=0):
    """Reject invalid values even if a JSON parser admitted exponent overflow."""
    from provenance import require
    require(depth <= 12, "profile or source JSON nesting limit")
    if type(value) is dict:
        require(len(value) <= 2048 and all(type(key) is str for key in value), "JSON object limit")
        for item in value.values():
            _json_value(item, depth=depth + 1)
    elif type(value) is list:
        require(len(value) <= results.MAX_RECORDS, "JSON array limit")
        for item in value:
            _json_value(item, depth=depth + 1)
    elif type(value) in (int, float):
        require(abs(value) <= results.MAX_NUMBER and math.isfinite(value), "nonfinite or unbounded JSON number")
    elif value is not None and type(value) not in (str, bool):
        require(False, "value is not JSON")


def _validate_profile(profile, kind):
    from provenance import require
    require(kind in KINDS, "unknown import kind")
    require(type(profile) is dict and set(profile) == PROFILE_FIELDS, "import profile fields")
    require(type(profile["schema_version"]) is int and profile["schema_version"] == 1,
            "import profile schema version")
    require(type(profile["context"]) is dict and set(profile["context"]) == CONTEXT_FIELDS,
            "import profile context fields")
    results.validate_record({**profile["context"], "schema_version": 1, "outcome": "success",
                             "metrics": {}, "unavailable": {}, "censored": []})
    require(type(profile["expected_records"]) is int
            and 0 < profile["expected_records"] <= results.MAX_RECORDS, "expected record bound")
    require(type(profile["complete"]) is bool, "completion declaration must be boolean")
    for name in ("host_profile", "provenance"):
        require(type(profile[name]) is dict and bool(profile[name]), f"nonempty declared {name} required")
        results._bounded_json(profile[name])
    require(type(profile["options"]) is dict, "adapter options must be an object")
    required, allowed = {
        "normalized": (set(), set()),
        "transaction": (set(), set()),
        "block-trace": (set(), {"throughput_probe_disabled", "effective_config_toml"}),
        "propagation": ({"expected_peers", "observation_end_ns", "verified_clock_domain"},
                        {"expected_peers", "observation_end_ns", "verified_clock_domain"}),
        "mempool": ({"monotonic_ns", "process_epoch"}, {"monotonic_ns", "process_epoch", "labels",
                    "previous_text", "previous_monotonic_ns", "previous_process_epoch"}),
        "resources": (set(), {"fresh_process", "fresh_cgroup", "effective_cpu_cores"}),
    }[kind]
    require(required <= profile["options"].keys() <= allowed, "missing or unknown adapter options")
    _json_value(profile)


def _block_config(profile):
    """Inspect archived configuration bytes without authenticating their use."""
    from provenance import require
    options = profile["options"]
    disabled = options.get("throughput_probe_disabled", False)
    require(type(disabled) is bool, "throughput_probe_disabled must be boolean")
    if not disabled:
        require("effective_config_toml" not in options, "effective config is only accepted with probe disablement declaration")
        return False, None
    text = options.get("effective_config_toml")
    require(type(text) is str, "probe disablement requires saved effective_config_toml")
    fingerprint = hashlib.sha256(text.encode("utf-8")).hexdigest()
    require(profile["provenance"].get("effective_config_sha256") == fingerprint,
            "effective config SHA256 mismatch or missing declaration")
    config = tomllib.loads(text)
    sync = config.get("sync", {})
    require(type(sync) is dict and "debug_blocksync_throughput_target_height" not in sync,
            "saved effective config enables or cannot establish disabled throughput probe")
    return True, fingerprint


def _jsonl(data):
    from provenance import require, strict_json
    require(data.endswith(b"\n"), "JSONL input must end with a newline")
    lines = data.splitlines(keepends=True)
    require(0 < len(lines) <= results.MAX_RECORDS, "JSONL record bound")
    rows = []
    for line in lines:
        require(line.endswith(b"\n") and len(line) <= results.MAX_RECORD_BYTES and line.strip(),
                "blank, partial or oversized JSONL line")
        row = strict_json(line.decode("utf-8"))
        _json_value(row)
        rows.append(row)
    return rows


def _convert(kind, data, profile):
    from provenance import require, strict_json
    context, options = profile["context"], profile["options"]
    if kind == "normalized":
        records = _jsonl(data)
        for record in records:
            results.validate_record(record)
            # Preserve source attempt/process identities and warmup flags.
            # Other population dimensions must match the declared context.
            require(all(record[key] == context[key] for key in CONTEXT_FIELDS - {"attempt_id", "process_id", "warmup"}),
                    "normalized record differs from declared context")
        return records, {"adapter": "normalized-records-v1"}, {
            "warmup_records": sum(record["warmup"] for record in records),
        }
    if kind == "resources":
        from collectors import resource_record
        snapshots = strict_json(data.decode("utf-8"))
        _json_value(snapshots)
        require(type(snapshots) is dict and set(snapshots) == {"before", "after"}, "resource pair fields")
        record = resource_record(snapshots["before"], snapshots["after"], context, **options)
        metadata = {"adapter": "saved-resource-pair-v1", "collector_kind": snapshots["before"]["kind"],
                    "freshness_and_entitlement": "operator declarations; not independently verified"}
        compatible = {"collector_kind": metadata["collector_kind"],
                      "fresh_process": options.get("fresh_process", False),
                      "fresh_cgroup": options.get("fresh_cgroup", False),
                      "effective_cpu_cores": options.get("effective_cpu_cores"),
                      "rate_interval_ns": record["details"]["rate_interval_ns"]}
        return [record], metadata, compatible
    from adapters import (transaction_size, import_block_trace, import_propagation, import_mempool)
    if kind == "transaction":
        records, metadata = transaction_size(data.decode("utf-8"), context)
        compatible = {}
    elif kind == "block-trace":
        disabled, fingerprint = _block_config(profile)
        records, metadata = import_block_trace(_jsonl(data), context, throughput_probe_disabled=disabled)
        metadata["probe_configuration_evidence"] = (
            "archived TOML omits the throughput probe field; applicability and absence of CLI overrides remain operator-declared"
            if disabled else "probe disablement not established")
        metadata["effective_config_sha256"] = fingerprint
        for record in records:
            record["details"]["probe_configuration_evidence"] = metadata["probe_configuration_evidence"]
            record["details"]["effective_config_sha256"] = fingerprint
        compatible = {"throughput_probe_disabled": disabled,
                      "probe_evidence_kind": "archived config plus operator applicability declaration" if disabled else "unknown"}
    elif kind == "propagation":
        records, metadata = import_propagation(_jsonl(data), context, **options)
        metadata["clock_evidence"] = "operator declaration only; shared clocks and cutoff were not independently checked"
        compatible = {"expected_peer_nodes": sorted(options["expected_peers"]),
                      "clock_domain": options["verified_clock_domain"],
                      "clock_evidence_kind": "operator declaration"}
    else:
        records, metadata = import_mempool(data.decode("utf-8"), context, **options)
        compatible = {"labels": options.get("labels", {}), "growth_interval_ns": None}
        if options.get("previous_text") is not None:
            compatible["growth_interval_ns"] = options["monotonic_ns"] - options["previous_monotonic_ns"]
    return records, metadata, compatible


def import_saved(args):
    """Archive and normalize --kind/--input/--profile into a fresh --output.

    Profiles require schema_version=1, eight context fields, expected_records,
    complete, nonempty host_profile/provenance, and kind-specific options.
    A mempool previous scrape, when used, is embedded as options.previous_text
    in the copied profile. Resource input is exactly {before, after} snapshots.
    No source path inside imported JSON is opened or executed.
    """
    from provenance import (artifact_inventory, atomic_json, canonical, digest_value,
                            fresh_directory, require, sha256, strict_json)
    profile_bytes = _saved_bytes(args.profile, MAX_PROFILE_BYTES)
    profile = strict_json(profile_bytes.decode("utf-8"))
    _validate_profile(profile, args.kind)
    source_bytes = _saved_bytes(args.input, results.MAX_INPUT_BYTES)
    output = fresh_directory(args.output)
    for name, data in (("source.input", source_bytes), ("profile.json", profile_bytes)):
        with (output / name).open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    context = profile["context"]
    settings = {key: context[key] for key in ("case_id", "configuration_id", "phase", "cache_mode", "warmup")}
    settings["expected_records"] = profile["expected_records"]
    evidence = {"origin": "operator-supplied saved evidence", "notice": EVIDENCE_NOTE,
                "source_input_sha256": sha256(output / "source.input"),
                "profile_sha256": sha256(output / "profile.json"),
                "workload_receipt_authenticated": False}
    manifest = {
        "schema_version": 1, "kind": "import." + args.kind,
        "run_id": context["run_id"], "configuration_id": context["configuration_id"],
        "settings": settings, "profile_identity_sha256": digest_value(profile),
        "host": {"identity_source": "operator declaration", "profile": profile["host_profile"]},
        "host_profile": profile["host_profile"],
        "provenance": {"kind": "operator declaration", "authenticated": False,
                       "declarations": profile["provenance"]},
        "expected_records": profile["expected_records"],
        "metric_catalog_sha256": results.METRIC_CATALOG_SHA256,
        "adapter_metadata": {"evidence": evidence}, "adapter_compatibility": {},
    }
    atomic_json(output / "manifest.json", manifest)
    receipt = {"schema_version": 1, "complete": False, "successful": False, "status": "importing",
               "manifest_sha256": sha256(output / "manifest.json"), "records": 0,
               "completion_basis": "operator declaration plus local schema/count checks; no workload executed"}
    atomic_json(output / "receipt.json", receipt)
    try:
        with (output / "attempts.jsonl").open("xb") as handle:
            records, metadata, compatibility = _convert(args.kind, source_bytes, profile)
            total = 0
            for record in records:
                results.validate_record(record)
                encoded = canonical(record) + b"\n"
                total += len(encoded)
                require(len(encoded) <= results.MAX_RECORD_BYTES and total <= results.MAX_INPUT_BYTES,
                        "normalized input exceeds byte limit")
                require(receipt["records"] < results.MAX_RECORDS, "normalized record count limit")
                handle.write(encoded)
                receipt["records"] += 1
            handle.flush()
            os.fsync(handle.fileno())
        require(receipt["records"] == profile["expected_records"], "import expected record count mismatch")
        checked = results.summarize(records, complete=profile["complete"])
        import adapters
        import collectors
        manifest["adapter_metadata"] = {**metadata, "evidence": evidence}
        manifest["adapter_compatibility"] = {"adapter": metadata["adapter"], **compatibility,
                                             "evidence_kind": "operator declaration",
                                             "implementation_sha256": {
                                                 "imports.py": sha256(__file__),
                                                 "adapters.py": sha256(adapters.__file__),
                                                 "collectors.py": sha256(collectors.__file__),
                                             }}
        receipt.update(complete=profile["complete"], successful=checked["successful"], status=checked["status"])
    except BaseException as error:
        receipt.update(status="failed", failure=type(error).__name__, reason=str(error)[:1024])
        raise
    finally:
        atomic_json(output / "manifest.json", manifest)
        receipt["manifest_sha256"] = sha256(output / "manifest.json")
        receipt["artifacts"] = artifact_inventory(output)
        atomic_json(output / "receipt.json", receipt)
    return {"output": str(output), "records": receipt["records"], "complete": receipt["complete"],
            "successful": receipt["successful"], "status": receipt["status"]}
