"""Strict imports of saved measurements; this module never contacts a node.

Block trace field mapping follows scripts/zakura-bench-digest.py and the actual
block_driver.rs emitter. Unlike the inherited best-effort digest, this importer
rejects ambiguous boundaries and preserves unsuccessful attempts. No inherited
code is copied. Propagation events are a proposed benchmark interchange format;
the product does not yet emit these events at its transaction boundaries.
"""

import hashlib
import json
from decimal import Decimal
import re

from collectors import CollectionError, _integer, _record


class AdapterError(CollectionError):
    """Saved evidence is malformed, ambiguous, or cannot establish an interval."""


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise AdapterError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _rows(rows):
    if isinstance(rows, str):
        if not rows.endswith("\n"):
            raise AdapterError("JSONL input must end with a newline; final record may be truncated")
        parsed = []
        for number, line in enumerate(rows.splitlines(), 1):
            if not line.strip():
                raise AdapterError(f"blank JSONL row {number}")
            try:
                row = json.loads(line, object_pairs_hook=_object,
                                 parse_constant=lambda value: (_ for _ in ()).throw(AdapterError(f"nonfinite JSON value {value}")))
            except (ValueError, TypeError) as error:
                raise AdapterError(f"invalid JSONL row {number}: {error}") from error
            parsed.append(row)
        rows = parsed
    else:
        rows = list(rows)
    if not rows:
        raise AdapterError("empty event input")
    if any(not isinstance(row, dict) for row in rows):
        raise AdapterError("each event must be a JSON object")
    return rows


def _text(value, name):
    if not isinstance(value, str) or not value or len(value) > 256 or any(ord(char) < 32 for char in value):
        raise AdapterError(f"{name} must be nonempty text of at most 256 characters")
    return value


def _hash(value, name):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise AdapterError(f"{name} must be a 32-byte hexadecimal digest")
    return value.lower()


def _phase(context, suffix):
    """Keep populations with different timing boundaries in separate groups."""
    name = f"{context['phase']}.{suffix}"
    if len(name) > 128:
        name = "phase-" + hashlib.sha256(name.encode()).hexdigest()[:32]
    return {**context, "phase": name}


def transaction_size(hex_text, context):
    """Measure exact serialized bytes and SHA-256; neither is a consensus TXID.

    A single final line ending is accepted for a normal text file. Prefixes,
    odd-length input, internal or other surrounding whitespace are rejected.
    This adapter does not parse, validate, submit, or establish chain inclusion.
    """
    if not isinstance(hex_text, str):
        raise AdapterError("transaction hex must be text")
    text = hex_text.removesuffix("\n").removesuffix("\r")
    if not text or len(text) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", text):
        raise AdapterError("transaction must be nonempty, even-length hexadecimal without whitespace")
    raw = bytes.fromhex(text)
    fingerprint = hashlib.sha256(raw).hexdigest()
    metadata = {
        "adapter": "serialized-transaction-v1", "serialized_sha256": fingerprint,
        "fidelity": "exact input byte count; transaction validity, TXID, and onchain inclusion are not established",
    }
    record = _record(context, f"transaction:{fingerprint}", metrics={"transaction_bytes": len(raw)},
                     unavailable={}, details=metadata)
    return [record], metadata


def import_block_trace(rows, context, *, throughput_probe_disabled=False):
    """Import current commit_state.jsonl block-driver events.

    Identity is (node, process_trace_id, apply_token), checked against hash,
    height and apply_class at every boundary. Each attempt requires queued,
    start and finish rows. A missing log row cannot establish a timeout.
    Explicit timed_out results are retained with a censored duration bound.
    Actual validation durations require external evidence that the debug
    throughput probe, which bypasses consensus, was disabled for this run.
    """
    if not isinstance(throughput_probe_disabled, bool):
        raise AdapterError("throughput_probe_disabled must be boolean")
    groups = {}
    ignored = 0
    for row in _rows(rows):
        if row.get("source") != "block_sync_driver" or row.get("event") not in {
            "block_submit_queued", "commit_start", "commit_finish", "commit_stalled",
        }:
            ignored += 1
            continue
        node = _text(row.get("node"), "node")
        process = _text(row.get("process_trace_id"), "process_trace_id")
        token = _integer(row.get("apply_token"), "apply_token")
        ts = _integer(row.get("ts"), "ts")
        height = _integer(row.get("height"), "height")
        block_hash = _hash(row.get("hash"), "block hash")
        apply_class = row.get("apply_class")
        if apply_class not in {"full", "checkpoint"}:
            raise AdapterError("unknown block apply_class")
        # Concurrent emitters can enqueue different blocks out of timestamp
        # order. Validate each attempt's boundary order after correlation.
        key = (node, process, token)
        identity = (height, block_hash, apply_class)
        group = groups.setdefault(key, {"identity": identity, "events": {}, "stalls": []})
        if group["identity"] != identity:
            raise AdapterError("block identity or class mismatched across boundaries")
        event = row["event"]
        if event == "commit_stalled":
            _integer(row.get("elapsed_ms"), "elapsed_ms")
            group["stalls"].append(row)
        else:
            if event in group["events"]:
                raise AdapterError(f"duplicate block boundary {event}")
            group["events"][event] = row
    if not groups:
        raise AdapterError("no block-driver attempts in trace")
    records = []
    for key, group in sorted(groups.items()):
        events = group["events"]
        if set(events) != {"block_submit_queued", "commit_start", "commit_finish"}:
            raise AdapterError("incomplete block boundaries; missing logs do not establish completion or timeout")
        queued, start, finish = (events[name] for name in ("block_submit_queued", "commit_start", "commit_finish"))
        if not queued["ts"] <= start["ts"] <= finish["ts"]:
            raise AdapterError("block boundaries are out of order")
        elapsed_ms = _integer(finish.get("elapsed_ms"), "elapsed_ms")
        if elapsed_ms * 1000 > finish["ts"] - start["ts"] + 1:
            raise AdapterError("elapsed_ms exceeds trace boundary duration")
        for stalled in group["stalls"]:
            if not start["ts"] <= stalled["ts"] <= finish["ts"] or stalled["elapsed_ms"] > elapsed_ms:
                raise AdapterError("stall event lies outside matching block attempt")
        result = finish.get("result")
        outcomes = {"committed": "success", "rejected": "unexpected_rejection", "duplicate": "error",
                    "unavailable": "error", "timed_out": "timeout"}
        if result not in outcomes:
            raise AdapterError(f"unknown block result: {result}")
        height, block_hash, apply_class = group["identity"]
        metric = "block_verify_commit_ns" if apply_class == "full" else "checkpoint_residence_ns"
        metrics = {"attempt_elapsed_ns": elapsed_ms * 1_000_000,
                   "trace_queue_ns": (start["ts"] - queued["ts"]) * 1000}
        unavailable, censored = {}, []
        if throughput_probe_disabled and result in {"committed", "timed_out"}:
            metrics[metric] = elapsed_ms * 1_000_000
            if result == "timed_out":
                censored.append(metric)
        else:
            metrics[metric] = None
            unavailable[metric] = ("debug throughput probe disablement not established" if not throughput_probe_disabled
                                   else f"block result {result}; no committed block duration")
        details = {
            "adapter": "zakura-block-trace-v1", "node": key[0], "process_trace_id": key[1],
            "apply_token": key[2], "height": height, "block_hash": block_hash, "apply_class": apply_class,
            "result": result, "stalls": len(group["stalls"]), "elapsed_precision_ns": 1_000_000,
            "queued_ts_us": queued["ts"], "start_ts_us": start["ts"], "finish_ts_us": finish["ts"],
            "throughput_probe_disabled": throughput_probe_disabled,
            "fidelity": ("driver elapsed includes consensus verification and state commit; these stages are not separated"
                         if apply_class == "full" else "checkpoint range batching and head-of-line residence; not per-block processing cost"),
        }
        records.append(_record(_phase(context, apply_class), f"block:{key}", metrics=metrics, unavailable=unavailable,
                               details=details, outcome=outcomes[result], censored=censored, source=key[:2]))
    return records, {
        "adapter": "zakura-block-trace-v1", "attempts": len(records), "ignored_rows": ignored,
        "throughput_probe_disabled": throughput_probe_disabled,
        "fidelity": "emitter-local monotonic timestamps; no cross-process timing; integer-millisecond elapsed; full verify+commit and checkpoint residence are separate",
    }


PROPAGATION_FIELDS = {"schema_version", "event", "txid", "auth_digest", "node", "process_epoch",
                      "attempt_id", "monotonic_ns", "clock_domain"}


def import_propagation(rows, context, *, expected_peers, observation_end_ns, verified_clock_domain):
    """Import proposed explicit events using an externally verified clock domain.

    ``expected_peers`` maps peer node names to exact process epochs, including
    peers with no received events. The observation end is an actual collection
    cutoff, not a planned future deadline. Missing delivery/admission is a
    timeout lower bound; it never becomes successful delivery. Equal labels
    alone do not verify shared clocks: the caller must provide that evidence.
    """
    domain = _text(verified_clock_domain, "verified_clock_domain")
    end = _integer(observation_end_ns, "observation_end_ns")
    if not isinstance(expected_peers, dict) or not expected_peers:
        raise AdapterError("expected_peers must map at least one node to a process epoch")
    peers = {_text(node, "peer node"): _text(epoch, "peer process epoch") for node, epoch in expected_peers.items()}
    attempts = {}
    for row in _rows(rows):
        if set(row) != PROPAGATION_FIELDS or row.get("schema_version") != 1 or isinstance(row.get("schema_version"), bool):
            raise AdapterError("propagation event fields do not match schema version 1")
        if row["event"] not in {"origin_submit", "origin_admit", "peer_receive", "peer_admit"}:
            raise AdapterError("unknown propagation event")
        node, epoch = _text(row["node"], "node"), _text(row["process_epoch"], "process_epoch")
        _text(row["attempt_id"], "attempt_id")
        ts = _integer(row["monotonic_ns"], "monotonic_ns")
        if ts > end:
            raise AdapterError("propagation event after observation cutoff")
        if row["clock_domain"] != domain:
            raise AdapterError("propagation events lack the same verified clock domain")
        key = (_hash(row["txid"], "txid"), _hash(row["auth_digest"], "auth_digest"), row["attempt_id"])
        group = attempts.setdefault(key, {})
        event_key = (row["event"], node)
        if event_key in group:
            raise AdapterError("duplicate propagation event")
        if row["event"].startswith("peer_") and peers.get(node) != epoch:
            raise AdapterError("peer node or process epoch differs from expected topology")
        group[event_key] = row
    records = []
    for key, events in sorted(attempts.items()):
        submissions = [row for (event, _), row in events.items() if event == "origin_submit"]
        if len(submissions) != 1:
            raise AdapterError("each propagation attempt requires exactly one origin_submit")
        origin = submissions[0]
        node = origin["node"]
        if node in peers:
            raise AdapterError("origin cannot also be an expected peer")
        admissions = [row for (event, _), row in events.items() if event == "origin_admit"]
        if len(admissions) > 1 or (admissions and (admissions[0]["node"], admissions[0]["process_epoch"]) != (node, origin["process_epoch"])):
            raise AdapterError("origin admission identity mismatch")
        admit = admissions[0] if admissions else None
        if admit is not None and admit["monotonic_ns"] < origin["monotonic_ns"]:
            raise AdapterError("origin admission precedes submission")
        if admit is None and any(event.startswith("peer_") for event, _ in events):
            raise AdapterError("peer events are missing the origin admission boundary")
        common = {
            "adapter": "proposed-propagation-v1", "txid": key[0], "auth_digest": key[1],
            "source_attempt_id": key[2], "origin_node": node, "origin_process_epoch": origin["process_epoch"],
            "clock_domain": domain, "observation_end_ns": end,
            "fidelity": "imported explicit events; clock-domain validity is asserted externally; current node instrumentation is not supplied by this adapter",
        }
        origin_metric = "propagation_origin_admit_ns"
        duration = (admit["monotonic_ns"] if admit else end) - origin["monotonic_ns"]
        records.append(_record(context, f"propagation:{key}:origin", metrics={origin_metric: duration},
                               unavailable={}, details=common, outcome="success" if admit else "timeout",
                               censored=[] if admit else [origin_metric], source=(node, origin["process_epoch"])))
        for peer, peer_epoch in sorted(peers.items()):
            receive, peer_admit = events.get(("peer_receive", peer)), events.get(("peer_admit", peer))
            if peer_admit is not None and receive is None:
                raise AdapterError("peer admission is missing its receive boundary")
            if receive is not None and receive["monotonic_ns"] < admit["monotonic_ns"]:
                raise AdapterError("peer receive precedes origin admission")
            if peer_admit is not None and peer_admit["monotonic_ns"] < receive["monotonic_ns"]:
                raise AdapterError("peer admission precedes receive")
            metrics, unavailable, censored = {}, {}, []
            outcome = "success"
            for event, metric, endpoint in (("receive", "propagation_receive_ns", receive),
                                             ("admit", "propagation_admit_ns", peer_admit)):
                if admit is None:
                    metrics[metric] = None
                    unavailable[metric] = "origin admission absent; propagation start boundary unknown"
                    outcome = "error"
                else:
                    metrics[metric] = (endpoint["monotonic_ns"] if endpoint else end) - admit["monotonic_ns"]
                    if endpoint is None:
                        outcome = "timeout"
                        censored.append(metric)
            details = {**common, "peer_node": peer, "peer_process_epoch": peer_epoch,
                       "boundary": "origin_admit to peer_receive and peer_admit"}
            records.append(_record(context, f"propagation:{key}:{peer}", metrics=metrics,
                                   unavailable=unavailable, details=details, outcome=outcome,
                                   censored=censored, source=(peer, peer_epoch)))
    return records, {
        "adapter": "proposed-propagation-v1", "attempts": len(attempts), "expected_peers": peers,
        "verified_clock_domain": domain, "observation_end_ns": end,
        "fidelity": "requires new node event instrumentation and externally verified common monotonic clocks; absent peer events are censored, not delivered",
    }


MEMPOOL_SERIES = {
    "zcash_mempool_size_transactions": "mempool_transactions",
    "zcash_mempool_size_bytes": "mempool_bytes",
    "zcash_mempool_cost_bytes": "mempool_cost",
}
_PROM_NAME = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)")
_PROM_LABEL = re.compile(r'\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*"((?:[^"\\\n]|\\[\\"n])*)"\s*')


def _labels(text):
    values, offset = {}, 0
    if not text.strip():
        return ()
    while offset < len(text):
        match = _PROM_LABEL.match(text, offset)
        if match is None or match[1] in values:
            raise AdapterError("malformed or duplicate Prometheus label")
        # Prometheus labels accept only \\, \", and \n escapes.
        values[match[1]] = re.sub(r"\\([\\\"n])", lambda part: "\n" if part[1] == "n" else part[1], match[2])
        offset = match.end()
        if offset == len(text):
            break
        if text[offset] != ",":
            raise AdapterError("malformed Prometheus label separator")
        offset += 1
        if not text[offset:].strip():
            break  # the text exposition format permits a trailing comma
    return tuple(sorted(values.items()))


def parse_mempool_metrics(text, *, labels=None):
    """Parse exact current product gauges from a saved Prometheus scrape.

    Unknown metric families are ignored. All lines in the three needed
    families are parsed strictly, including duplicates outside the selector.
    ``labels`` selects an exact label set (default: no labels).
    """
    if not isinstance(text, str):
        raise AdapterError("Prometheus scrape must be text")
    if labels is not None and (not isinstance(labels, dict) or any(not isinstance(key, str) or not isinstance(value, str) for key, value in labels.items())):
        raise AdapterError("labels must map strings to strings")
    selector = tuple(sorted((labels or {}).items()))
    series, types = {}, {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            parts = line.split()
            if len(parts) >= 3 and parts[0:2] == ["#", "TYPE"] and parts[2] in MEMPOOL_SERIES:
                if len(parts) != 4 or parts[3] != "gauge" or parts[2] in types:
                    raise AdapterError("needed Prometheus family has duplicate or non-gauge TYPE")
                types[parts[2]] = "gauge"
            continue
        name_match = _PROM_NAME.match(line)
        if name_match is None or name_match[1] not in MEMPOOL_SERIES:
            continue
        name = name_match[1]
        rest = line[name_match.end():]
        parsed_labels = ()
        if rest.startswith("{"):
            # Locate the closing brace outside quoted label values.
            quoted, escaped, close = False, False, None
            for index, char in enumerate(rest[1:], 1):
                if escaped:
                    escaped = False
                elif quoted and char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = not quoted
                elif char == "}" and not quoted:
                    close = index
                    break
            if close is None:
                raise AdapterError("unterminated Prometheus labels")
            parsed_labels = _labels(rest[1:close])
            rest = rest[close + 1:]
        if not rest or not rest[0].isspace():
            raise AdapterError("needed Prometheus series lacks value separator")
        fields = rest.split()
        if len(fields) not in {1, 2} or not re.fullmatch(r"[+]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?", fields[0]):
            raise AdapterError("malformed needed Prometheus gauge value")
        if len(fields) == 2 and not re.fullmatch(r"-?[0-9]+", fields[1]):
            raise AdapterError("malformed Prometheus timestamp")
        number = Decimal(fields[0])
        if not number.is_finite() or number != number.to_integral_value() or not 0 <= number <= 2**64 - 1:
            raise AdapterError("needed mempool gauges must be bounded nonnegative integers")
        key = (name, parsed_labels)
        if key in series:
            raise AdapterError("duplicate needed Prometheus series")
        series[key] = int(number)
    metrics, unavailable = {}, {}
    for name, metric in MEMPOOL_SERIES.items():
        value = series.get((name, selector))
        metrics[metric] = value
        if value is None:
            unavailable[metric] = f"{name} absent for exact requested labels"
    return metrics, unavailable


def import_mempool(text, context, *, monotonic_ns, process_epoch, labels=None,
                   previous_text=None, previous_monotonic_ns=None, previous_process_epoch=None):
    """Import a scrape, optionally deriving signed growth over a known epoch.

    Timestamps must refer to collected scrapes on one monotonic clock. These
    gauges measure verified mempool state, not the internal admission queue.
    Shrinkage is valid negative growth; process restarts are not one interval.
    """
    ts = _integer(monotonic_ns, "monotonic_ns")
    epoch = _text(process_epoch, "process_epoch")
    metrics, unavailable = parse_mempool_metrics(text, labels=labels)
    details = {"adapter": "zakura-mempool-scrape-v1", "monotonic_ns": ts, "process_epoch": epoch,
               "labels": labels or {}, "fidelity": "verified mempool gauges; cost is policy accounting bytes, not heap memory; admission queue is not exposed"}
    if previous_text is not None:
        previous_ts = _integer(previous_monotonic_ns, "previous_monotonic_ns")
        if _text(previous_process_epoch, "previous_process_epoch") != epoch:
            raise AdapterError("mempool process epoch changed; start a new interval")
        if previous_ts >= ts:
            raise AdapterError("mempool interval must be positive")
        previous, previous_unavailable = parse_mempool_metrics(previous_text, labels=labels)
        elapsed = (ts - previous_ts) / 1_000_000_000
        for metric, growth in (("mempool_transactions", "mempool_growth_transactions_per_second"),
                              ("mempool_bytes", "mempool_growth_bytes_per_second")):
            if metrics[metric] is None or previous[metric] is None:
                metrics[growth] = None
                unavailable[growth] = unavailable.get(metric) or previous_unavailable[metric]
            else:
                metrics[growth] = (metrics[metric] - previous[metric]) / elapsed
        details["previous_monotonic_ns"] = previous_ts
    elif previous_monotonic_ns is not None or previous_process_epoch is not None:
        raise AdapterError("previous timestamp/epoch supplied without previous scrape")
    record = _record(context, f"mempool:{epoch}:{ts}", metrics=metrics, unavailable=unavailable,
                     details=details, source=epoch)
    return [record], details
