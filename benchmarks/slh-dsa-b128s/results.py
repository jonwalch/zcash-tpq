#!/usr/bin/env python3
"""Strict, bounded benchmark records and reproducible offline reports.

Nearest-rank selection follows research pq-bench-support/src/lib.rs::stats
(MIT OR Apache-2.0). The coordinator records the pinned source in the import
ledger. This module extends it to every metric and keeps failures, censored
bounds, absent measurements, and warmups separate from exact observations.
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
import re
from collections import Counter
from pathlib import Path

from html_report import render_report

SCHEMA_VERSION = 1
MAX_RECORD_BYTES = 65_536
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_RECORDS = 100_000
MAX_GROUPS = 10_000
MAX_METRICS = 128
MAX_NUMBER = 2**64 - 1
OUTCOMES = (
    "success", "expected_rejection", "unexpected_rejection", "timeout",
    "cancelled", "error",
)
UNEXPECTED_OUTCOMES = OUTCOMES[2:]
DIMENSIONS = (
    "run_id", "case_id", "configuration_id", "process_id", "phase", "cache_mode",
)
ID_FIELDS = DIMENSIONS + ("attempt_id",)
REQUIRED_FIELDS = set(ID_FIELDS) | {
    "schema_version", "warmup", "outcome", "metrics", "unavailable", "censored",
}
ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)
_CATALOG_PATH = Path(__file__).parent / "schema" / "metrics.json"
_CATALOG_BYTES = _CATALOG_PATH.read_bytes()
METRIC_CATALOG = json.loads(_CATALOG_BYTES)["metrics"]
METRIC_CATALOG_SHA256 = hashlib.sha256(_CATALOG_BYTES).hexdigest()
_PAYMENT_CATALOG_BYTES = (_CATALOG_PATH.parent / "payment-metrics.json").read_bytes()
PAYMENT_METRICS = json.loads(_PAYMENT_CATALOG_BYTES)["metrics"]
if set(PAYMENT_METRICS).intersection(METRIC_CATALOG):
    raise ValueError("payment catalog cannot redefine an existing metric")
PAYMENT_CATALOG_SHA256 = hashlib.sha256(_PAYMENT_CATALOG_BYTES).hexdigest()
METRIC_CATALOG.update(PAYMENT_METRICS)


class ValidationError(ValueError):
    """Input cannot be interpreted under the versioned result contract."""


def _bounded_json(value, *, max_bytes=16_384):
    """Validate JSON without relying on recursive serialization for bounds."""
    pending = [(value, 0)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if depth > 8 or nodes > 2048:
            raise ValidationError("JSON nesting or item count exceeds the limit")
        if type(item) is dict:
            if len(item) > 2048 - nodes:
                raise ValidationError("JSON item count exceeds the limit")
            if any(type(key) is not str or len(key) > 256 for key in item):
                raise ValidationError("JSON object keys must be short strings")
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            if len(item) > 2048 - nodes:
                raise ValidationError("JSON item count exceeds the limit")
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            if len(item) > 4096:
                raise ValidationError("JSON string exceeds the limit")
        elif item is None or type(item) is bool:
            pass
        elif type(item) in (int, float):
            if abs(item) > MAX_NUMBER or not math.isfinite(item):
                raise ValidationError("JSON numbers must be finite and bounded")
        else:
            raise ValidationError("value is not a JSON value")
    try:
        encoded = json.dumps(value, allow_nan=False, ensure_ascii=True,
                             separators=(",", ":")).encode("ascii")
    except (ValueError, TypeError) as error:
        raise ValidationError("value is not valid JSON") from error
    if len(encoded) > max_bytes:
        raise ValidationError("JSON value exceeds the byte limit")
    return encoded


def validate_record(record):
    """Return a valid record unchanged, or raise ValidationError.

    One attempt emits one record containing all its metrics. Identity is the
    tuple (run_id, process_id, attempt_id); summarize checks its uniqueness.
    Units are fixed by the metric registry, never supplied by a result producer.
    """
    if type(record) is not dict:
        raise ValidationError("record must be an object")
    if not REQUIRED_FIELDS <= record.keys() or record.keys() - REQUIRED_FIELDS - {"details"}:
        raise ValidationError("record has missing or unknown fields")
    if type(record["schema_version"]) is not int or record["schema_version"] != SCHEMA_VERSION:
        raise ValidationError("unsupported schema_version")
    for field in ID_FIELDS:
        if type(record[field]) is not str or not ID_PATTERN.fullmatch(record[field]):
            raise ValidationError(f"{field} must be a bounded identifier token")
    if type(record["warmup"]) is not bool:
        raise ValidationError("warmup must be a boolean")
    if record["outcome"] not in OUTCOMES:
        raise ValidationError("unknown outcome")
    metrics = record["metrics"]
    if type(metrics) is not dict or len(metrics) > MAX_METRICS:
        raise ValidationError("metrics must be a bounded object")
    for name, value in metrics.items():
        if name not in METRIC_CATALOG:
            raise ValidationError(f"unknown metric: {name!r}")
        if value is None:
            continue
        spec = METRIC_CATALOG[name]
        if type(value) not in (int, float) or abs(value) > MAX_NUMBER or not math.isfinite(value):
            raise ValidationError(f"{name} must be a finite bounded number or null")
        if spec["integer"] and type(value) is not int:
            raise ValidationError(f"{name} requires an integer in {spec['unit']}")
        if not spec.get("signed", False) and value < 0:
            raise ValidationError(f"{name} cannot be negative")
        if spec.get("positive", False) and value <= 0:
            raise ValidationError(f"{name} must be positive")
    unavailable = record["unavailable"]
    null_metrics = {name for name, value in metrics.items() if value is None}
    if type(unavailable) is not dict or set(unavailable) != null_metrics:
        raise ValidationError("unavailable must give exactly one reason for each null metric")
    if any(type(reason) is not str or not reason.strip() or len(reason) > 1024
           for reason in unavailable.values()):
        raise ValidationError("unavailable reasons must be nonempty bounded strings")
    censored = record["censored"]
    if (type(censored) is not list or len(censored) > MAX_METRICS
            or any(type(name) is not str for name in censored)
            or len(set(censored)) != len(censored)
            or any(name not in metrics or metrics[name] is None for name in censored)):
        raise ValidationError("censored must name distinct numeric metrics")
    if record["outcome"] == "success" and censored:
        raise ValidationError("a success cannot contain censored measurements")
    if "details" in record:
        if type(record["details"]) is not dict:
            raise ValidationError("details must be an object")
        _bounded_json(record["details"])
    _bounded_json(record, max_bytes=MAX_RECORD_BYTES)
    return record


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValidationError(f"nonstandard JSON number: {value}")


def read_records(path):
    """Yield bounded strict JSONL; malformed/truncated lines never disappear."""
    total = 0
    with Path(path).open("rb") as handle:
        for index in range(MAX_RECORDS + 1):
            line = handle.readline(MAX_RECORD_BYTES + 1)
            if not line:
                return
            total += len(line)
            if index == MAX_RECORDS or len(line) > MAX_RECORD_BYTES or total > MAX_INPUT_BYTES:
                raise ValidationError("raw input exceeds the record or byte limit")
            if not line.endswith(b"\n"):
                raise ValidationError(f"line {index + 1}: missing final newline (possible interruption)")
            try:
                record = json.loads(line.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys,
                                    parse_constant=_reject_constant)
                yield validate_record(record)
            except (ValueError, UnicodeError, RecursionError) as error:
                raise ValidationError(f"line {index + 1}: {error}") from error


def _quantiles(values):
    """Empirical nearest rank, including the lower middle value for even n."""
    values = sorted(values)
    count = len(values)
    result = {"samples": count, "min": None, "max": None,
              "p50": None, "p95": None, "p99": None}
    if not count:
        result["reason"] = "no uncensored non-warmup observations"
        return result
    result.update(min=values[0], max=values[-1])
    for percentile in (50, 95, 99):
        result[f"p{percentile}"] = values[(count * percentile + 99) // 100 - 1]
    return result


def _outcome_counts(counter):
    return {outcome: counter[outcome] for outcome in OUTCOMES}


def summarize(records, *, complete=False):
    """Summarize homogeneous populations without pooling runs or processes.

    complete means the producer reconciled and closed the run. successful also
    requires measured records, no unexpected outcomes, and no missing/censored
    observations. Warmups remain in outcome counts and raw-record references,
    but never in percentiles. The all_outcomes population keeps completed
    failure durations beside their separate outcome-specific distributions.
    """
    if type(complete) is not bool:
        raise ValidationError("complete must be a boolean")
    groups = {}
    identities = set()
    outcomes = Counter()
    warmup_outcomes = Counter()
    record_count = warmup_count = censored_count = unavailable_count = total_bytes = 0
    unmeasured_count = 0
    for record in records:
        validate_record(record)
        record_count += 1
        total_bytes += len(_bounded_json(record, max_bytes=MAX_RECORD_BYTES)) + 1
        if record_count > MAX_RECORDS or total_bytes > MAX_INPUT_BYTES:
            raise ValidationError("raw input exceeds the record or byte limit")
        identity = tuple(record[field] for field in ("run_id", "process_id", "attempt_id"))
        if identity in identities:
            raise ValidationError(f"duplicate attempt identity: {identity}")
        identities.add(identity)
        outcomes[record["outcome"]] += 1
        warmup_count += record["warmup"]
        if record["warmup"]:
            warmup_outcomes[record["outcome"]] += 1
        censored_count += len(record["censored"])
        unavailable_count += len(record["unavailable"])
        unmeasured_count += not record["warmup"] and not record["metrics"]
        dimensions = tuple(record[field] for field in DIMENSIONS)
        for outcome in (record["outcome"], "all_outcomes"):
            key = dimensions + (outcome,)
            if key not in groups:
                if len(groups) >= MAX_GROUPS:
                    raise ValidationError("group count exceeds the limit")
                groups[key] = {"records": 0, "warmups": 0, "outcomes": Counter(),
                               "attempt_ids": [], "warmup_attempt_ids": [], "metrics": {}}
            group = groups[key]
            group["records"] += 1
            group["warmups"] += record["warmup"]
            group["outcomes"][record["outcome"]] += 1
            group["attempt_ids"].append(record["attempt_id"])
            if record["warmup"]:
                group["warmup_attempt_ids"].append(record["attempt_id"])
            for name, value in record["metrics"].items():
                metric = group["metrics"].setdefault(name, {
                    "values": [], "lower_bounds": [], "unavailable": Counter(), "present": 0,
                })
                if record["warmup"]:
                    continue
                metric["present"] += 1
                if value is None:
                    metric["unavailable"][record["unavailable"][name]] += 1
                elif name in record["censored"]:
                    metric["lower_bounds"].append(value)
                else:
                    metric["values"].append(value)

    result_groups = []
    missing_count = 0
    for key, group in sorted(groups.items()):
        observation_count = group["records"] - group["warmups"]
        result = dict(zip(DIMENSIONS + ("outcome",), key))
        result.update(record_count=group["records"], warmup_count=group["warmups"],
                      observation_count=observation_count,
                      outcome_counts=_outcome_counts(group["outcomes"]),
                      attempt_ids=group["attempt_ids"],
                      warmup_attempt_ids=group["warmup_attempt_ids"], metrics={})
        for name, metric in sorted(group["metrics"].items()):
            lower_bounds = metric["lower_bounds"]
            absent = observation_count - metric["present"]
            if key[-1] == "all_outcomes":
                missing_count += absent
            result["metrics"][name] = {
                "unit": METRIC_CATALOG[name]["unit"],
                **_quantiles(metric["values"]),
                "present_count": metric["present"],
                "missing_count": absent,
                "unavailable_count": sum(metric["unavailable"].values()),
                "unavailable_reasons": dict(sorted(metric["unavailable"].items())),
                "censored_count": len(lower_bounds),
                "lower_bound_min": min(lower_bounds, default=None),
                "lower_bound_max": max(lower_bounds, default=None),
                "tail_incomplete": bool(lower_bounds or absent or metric["unavailable"]),
            }
        result_groups.append(result)
    measured = record_count - warmup_count
    issues = []
    if not complete:
        issues.append("producer did not finalize the run")
    if not measured:
        issues.append("no non-warmup observations")
    if any(outcomes[name] for name in UNEXPECTED_OUTCOMES):
        issues.append("unexpected outcomes occurred")
    if censored_count:
        issues.append("censored measurements occurred")
    if unavailable_count or missing_count:
        issues.append("measurements are unavailable or missing")
    if unmeasured_count:
        issues.append("attempts without any measurements occurred")
    successful = not issues
    summary = {
        "schema_version": SCHEMA_VERSION,
        "metric_catalog_sha256": METRIC_CATALOG_SHA256,
        "quantile_method": "empirical-nearest-rank",
        "sample_unit": "one recorded metric value per attempt; runs and processes remain separate",
        "complete": complete,
        "successful": successful,
        "status": "incomplete" if not complete else ("complete" if successful else "complete_with_issues"),
        "issues": issues,
        "record_count": record_count,
        "warmup_count": warmup_count,
        "observation_count": measured,
        "outcome_counts": _outcome_counts(outcomes),
        "warmup_outcome_counts": _outcome_counts(warmup_outcomes),
        "measurement_outcome_counts": _outcome_counts(outcomes - warmup_outcomes),
        "censored_count": censored_count,
        "unavailable_count": unavailable_count,
        "missing_count": missing_count,
        "unmeasured_count": unmeasured_count,
        "groups": result_groups,
    }
    if any(set(group["metrics"]).intersection(PAYMENT_METRICS) for group in result_groups):
        summary["metric_catalog_extensions"] = {"payment": PAYMENT_CATALOG_SHA256}
    return summary


def write_reports(summary, output_dir):
    """Write escaped JSON/CSV/HTML reports, refusing to replace existing files."""
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    for name in ("summary.json", "summary.csv", "report.html"):
        if (destination / name).exists():
            raise FileExistsError(f"report already exists: {destination / name}")
    payload = json.dumps(summary, indent=2, sort_keys=True, allow_nan=False) + "\n"
    fields = list(DIMENSIONS) + [
        "outcome", "metric", "unit", "summary_status", "run_complete", "run_successful",
        "record_count", "warmup_count", "observation_count",
        "outcome_counts", "samples", "p50", "p95", "p99", "min", "max", "missing_count",
        "unavailable_count", "censored_count", "lower_bound_min", "lower_bound_max",
        "tail_incomplete", "reason", "unavailable_reasons",
    ]
    rows = []
    for group in summary["groups"]:
        for name, metric in (group["metrics"].items() or [("", {})]):
            row = {field: group.get(field, "") for field in fields}
            row.update({key: value for key, value in metric.items() if key in fields})
            row["metric"] = name
            row["summary_status"] = summary["status"]
            row["run_complete"] = summary["complete"]
            row["run_successful"] = summary["successful"]
            row["outcome_counts"] = json.dumps(group["outcome_counts"], sort_keys=True)
            row["unavailable_reasons"] = json.dumps(metric.get("unavailable_reasons", {}), sort_keys=True)
            rows.append(row)
    with (destination / "summary.csv").open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    document = render_report(summary, METRIC_CATALOG)
    with (destination / "report.html").open("x", encoding="utf-8") as handle:
        handle.write(document)
    with (destination / "summary.json").open("x", encoding="utf-8") as handle:
        handle.write(payload)
    return {name: str(destination / name) for name in ("summary.json", "summary.csv", "report.html")}


def compare_summaries(left, right):
    """Compare matched single-process populations; never average percentiles.

    The runner supplies a source-independent compatibility object describing
    hardware, workload, cache and instrumentation. Source identity can differ.
    Repeated process populations must be selected explicitly before comparison.
    """
    for summary in (left, right):
        if summary.get("schema_version") != SCHEMA_VERSION or summary.get("metric_catalog_sha256") != METRIC_CATALOG_SHA256:
            raise ValidationError("comparison requires the current schema and metric catalog")
        uses_payment = any(set(group.get("metrics", {})).intersection(PAYMENT_METRICS)
                           for group in summary.get("groups", []))
        expected_extensions = {"payment": PAYMENT_CATALOG_SHA256} if uses_payment else {}
        if summary.get("metric_catalog_extensions", {}) != expected_extensions:
            raise ValidationError("comparison requires the current payment metric catalog")
        if summary.get("complete") is not True:
            raise ValidationError("comparison requires finalized summaries")
        if not summary.get("groups") or not summary.get("observation_count"):
            raise ValidationError("comparison requires measured populations")
        compatibility = summary.get("compatibility")
        if type(compatibility) is not dict or not compatibility:
            raise ValidationError("comparison requires nonempty compatibility metadata")
        _bounded_json(compatibility)
    if (json.dumps(left["compatibility"], sort_keys=True)
            != json.dumps(right["compatibility"], sort_keys=True)):
        raise ValidationError("incompatible hardware, workload, cache or instrumentation")
    dimensions = ("case_id", "configuration_id", "phase", "cache_mode", "outcome")
    populations = []
    for summary in (left, right):
        indexed = {}
        for group in summary["groups"]:
            key = tuple(group[name] for name in dimensions)
            if key in indexed:
                raise ValidationError("ambiguous process populations; select one run and process per case")
            indexed[key] = group
        populations.append(indexed)
    if populations[0].keys() != populations[1].keys():
        raise ValidationError("comparison requires identical case/configuration/phase/cache/outcome populations")
    comparisons = []
    for key in sorted(populations[0]):
        first, second = (population[key] for population in populations)
        if first["metrics"].keys() != second["metrics"].keys():
            raise ValidationError("comparison requires identical metric populations")
        row = dict(zip(dimensions, key))
        row["left"] = {name: first[name] for name in ("run_id", "process_id", "outcome_counts")}
        row["right"] = {name: second[name] for name in ("run_id", "process_id", "outcome_counts")}
        row["metrics"] = {}
        for name in sorted(first["metrics"]):
            a, b = first["metrics"][name], second["metrics"][name]
            changes = {}
            for percentile in ("p50", "p95", "p99"):
                av, bv = a[percentile], b[percentile]
                delta = None if av is None or bv is None else bv - av
                percent = None if delta is None or av == 0 else 100 * delta / av
                if percent is not None and not math.isfinite(percent):
                    percent = None
                changes[percentile] = {
                    "left": av, "right": bv, "delta": delta,
                    "change_percent": percent,
                }
            row["metrics"][name] = {
                "unit": a["unit"], "left_samples": a["samples"], "right_samples": b["samples"],
                "left_censored_count": a["censored_count"], "right_censored_count": b["censored_count"],
                "tail_incomplete": a["tail_incomplete"] or b["tail_incomplete"], **changes,
            }
        comparisons.append(row)
    return {"schema_version": SCHEMA_VERSION, "compatibility": left["compatibility"],
            "method": "descriptive per-process nearest-rank differences; no pooled quantiles or significance test",
            "left_successful": left["successful"], "right_successful": right["successful"],
            "groups": comparisons}
