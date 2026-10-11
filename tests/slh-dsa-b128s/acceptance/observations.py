#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Bounded opt-in SLH primitive-attempt capture; never launches a node.

Adapted from the pinned research observe_entry/check_entries mechanism. Counts
are observed process/window entries, not per-RPC work or verification success.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import stat

from common import (CONTRACT, read_json, require, sha256, source_state,
                    validate_build, write_json)

ENVIRONMENT = "ZAKURA_SLH_PRIMITIVE_OBSERVE"
MARKER = "slh_primitive_v1"
MAX_LOG_BYTES = 32 * 1024 * 1024
MAX_LINE_BYTES = 16 * 1024
MAX_EVENTS = 4096
TOKEN = re.compile(r"[0-9a-f]{32}")
HEX = re.compile(r"[0-9a-f]{64}")
ANSI = re.compile(rb"\x1b\[[0-9;]*m")
ENTRY = re.compile(
    r"slh_primitive_v1 token=([0-9a-f]{32}) pid=([1-9][0-9]{0,9}) "
    r"seq=([1-9][0-9]{0,19}) txid=([0-9a-f]{64}) auth_digest=([0-9a-f]{64}) "
    r"input=(0|[1-9][0-9]{0,9}) check=(0|[1-9][0-9]?) "
    r"backend=portable-rust contract=slh-dsa-b-128s-exp-v1"
)
CAPTURE_FIELDS = {"schema_version", "contract", "scope", "complete", "token", "pid",
    "start_offset", "end_offset", "prefix_sha256", "log_sha256", "binary_sha256",
    "config_sha256", "source", "exit_code"}


def valid_token(token):
    require(type(token) is str and TOKEN.fullmatch(token) is not None, "observation_token")
    return token


def environment(token=None):
    result = dict(os.environ)
    # An inherited token must never turn an ordinary acceptance run into capture.
    result.pop(ENVIRONMENT, None)
    if token is not None:
        result[ENVIRONMENT] = valid_token(token)
    return result


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def bounded_log(path):
    path = Path(path)
    require(not path.is_symlink(), "observation_log_regular")
    before = path.stat()
    require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_LOG_BYTES,
            "observation_log_bound")
    with path.open("rb") as stream:
        raw = stream.read(MAX_LOG_BYTES + 1)
    after = path.stat()
    require(len(raw) <= MAX_LOG_BYTES and len(raw) == before.st_size == after.st_size
            and (before.st_dev, before.st_ino, before.st_mtime_ns)
                == (after.st_dev, after.st_ino, after.st_mtime_ns), "observation_log_changed")
    return raw, (after.st_dev, after.st_ino)


def begin(log, binary, config, token):
    """Called before launching an explicitly configured disposable Regtest node."""
    valid_token(token)
    raw, identity = bounded_log(log)
    require(not raw or raw.endswith(b"\n"), "observation_start_boundary")
    return {"token": token, "start_offset": len(raw), "prefix_sha256": digest(raw),
            "binary_sha256": sha256(binary), "config_sha256": sha256(config),
            "source": source_state(), "file_identity": identity}


def finish(start, log, binary, config, pid, exit_code):
    """Seal only after a successful process wait and closed output stream."""
    require(type(pid) is int and 0 < pid <= 2**32 - 1
            and type(exit_code) is int and exit_code == 0, "observation_clean_shutdown")
    raw, identity = bounded_log(log)
    require(identity == start["file_identity"] and len(raw) >= start["start_offset"]
            and digest(raw[:start["start_offset"]]) == start["prefix_sha256"],
            "observation_log_replaced")
    require(sha256(binary) == start["binary_sha256"] and sha256(config) == start["config_sha256"]
            and source_state() == start["source"], "observation_inputs_changed")
    segment = raw[start["start_offset"]:]
    require(segment and segment.endswith(b"\n"), "observation_end_boundary")
    return {"schema_version": 1, "contract": CONTRACT, "scope": "closed-process-log-v1",
            "complete": True, "token": start["token"], "pid": pid,
            "start_offset": start["start_offset"], "end_offset": len(raw),
            "prefix_sha256": start["prefix_sha256"], "log_sha256": digest(segment),
            "binary_sha256": start["binary_sha256"], "config_sha256": start["config_sha256"],
            "source": start["source"], "exit_code": exit_code}


def parse_entries(raw, token, pid):
    """Read exact diagnostic lines, requiring a complete contiguous process sequence."""
    valid_token(token)
    require(type(pid) is int and 0 < pid <= 2**32 - 1, "observation_process_identity")
    require(type(raw) is bytes and 0 < len(raw) <= MAX_LOG_BYTES and raw.endswith(b"\n"),
            "observation_complete_log")
    rows = []
    for line in raw.splitlines():
        require(len(line) <= MAX_LINE_BYTES, "observation_line_bound")
        if MARKER.encode() not in line:
            continue
        plain = ANSI.sub(b"", line)
        require(b"\x1b" not in plain and plain.count(MARKER.encode()) == 1, "observation_line_encoding")
        try:
            text = plain.decode("ascii")
        except UnicodeDecodeError:
            require(False, "observation_line_encoding")
        position = text.index(MARKER)
        require(position == 0 or text[position - 1] in " :", "observation_marker_boundary")
        match = ENTRY.fullmatch(text[position:])
        require(match is not None, "observation_entry_schema")
        run, process, sequence, txid, auth, input_index, check = match.groups()
        process, sequence, input_index, check = map(int, (process, sequence, input_index, check))
        require(run == token and process == pid and process <= 2**32 - 1
                and sequence <= 2**64 - 1 and input_index <= 2**32 - 1 and check <= 14,
                "observation_entry_identity")
        rows.append({"sequence": sequence, "txid": txid, "auth_digest": auth,
                     "input_index": input_index, "check_ordinal": check})
        require(len(rows) <= MAX_EVENTS, "observation_event_bound")
    require(rows and sorted(row["sequence"] for row in rows) == list(range(1, len(rows) + 1)),
            "observation_sequence_incomplete")
    return sorted(rows, key=lambda row: row["sequence"])


def identity(value):
    require(type(value) is dict and set(value) == {"txid", "auth_digest"}
            and all(type(item) is str and HEX.fullmatch(item) for item in value.values()),
            "observation_transaction_identity")
    return value["txid"], value["auth_digest"]


def compare(rows, before, after, subjects):
    """A sequence window excludes both positive controls and preserves all retries."""
    first, last = identity(before), identity(after)
    require(first != last and type(subjects) is list and 1 <= len(subjects) <= 32,
            "observation_control_identity")
    keys = [identity(subject) for subject in subjects]
    require(len(set(keys)) == len(keys) and not ({first, last} & set(keys)),
            "observation_subject_identity")
    preceding = [row["sequence"] for row in rows if (row["txid"], row["auth_digest"]) == first]
    following = [row["sequence"] for row in rows if (row["txid"], row["auth_digest"]) == last]
    require(preceding and following and max(preceding) < min(following),
            "observation_positive_brackets")
    low, high = max(preceding), min(following)
    window = [row for row in rows if low < row["sequence"] < high]
    return {"start_after_sequence": low, "end_before_sequence": high,
            "positive_before_entries": len(preceding), "positive_after_entries": len(following),
            "window_entries": len(window), "subjects": [
                {**subject, "process_observed_entries": sum((row["txid"], row["auth_digest"]) == key for row in rows),
                 "window_observed_entries": sum((row["txid"], row["auth_digest"]) == key for row in window),
                 "window_coordinates": [{"input_index": row["input_index"], "check_ordinal": row["check_ordinal"]}
                     for row in window if (row["txid"], row["auth_digest"]) == key]}
                for subject, key in zip(subjects, keys)]}


def analyze(capture, log, binary, config, build, before, after, subjects):
    require(type(capture) is dict and set(capture) == CAPTURE_FIELDS
            and type(capture["schema_version"]) is int and capture["schema_version"] == 1
            and capture["contract"] == CONTRACT and capture["scope"] == "closed-process-log-v1"
            and capture["complete"] is True, "observation_capture_schema")
    valid_token(capture["token"])
    for name in ("pid", "start_offset", "end_offset", "exit_code"):
        require(type(capture[name]) is int, "observation_capture_numbers")
    require(0 < capture["pid"] <= 2**32 - 1 and capture["exit_code"] == 0
            and 0 <= capture["start_offset"] < capture["end_offset"] <= MAX_LOG_BYTES,
            "observation_capture_bounds")
    for name in ("prefix_sha256", "log_sha256", "binary_sha256", "config_sha256"):
        require(type(capture[name]) is str and HEX.fullmatch(capture[name]) is not None,
                "observation_capture_hashes")
    validate_build(build, Path(binary), "node-slh", runtime_required=True)
    require(capture["source"] == build["source"] and sha256(binary) == capture["binary_sha256"]
            and sha256(config) == capture["config_sha256"], "observation_build_binding")
    raw, _ = bounded_log(log)
    start, end = capture["start_offset"], capture["end_offset"]
    require(end <= len(raw) and digest(raw[:start]) == capture["prefix_sha256"]
            and digest(raw[start:end]) == capture["log_sha256"], "observation_log_binding")
    rows = parse_entries(raw[start:end], capture["token"], capture["pid"])
    window = compare(rows, before, after, subjects)
    return {"schema_version": 1, "contract": CONTRACT, "complete": True,
            "scope": "observed-primitive-entry-window-v1", "capture": capture,
            "positive_before": before, "positive_after": after, "process_observed_entries": len(rows),
            "window": window, "claims": {"isolated_request_counts": False, "verification_success": False,
                "node_acceptance": False, "resource_measurement": False,
                "outside_window_absence": False},
            "limits": {"log_bytes": MAX_LOG_BYTES, "line_bytes": MAX_LINE_BYTES, "events": MAX_EVENTS}}


def argument_identity(value):
    parts = value.split(":")
    require(len(parts) == 2, "observation_identity_argument")
    result = dict(zip(("txid", "auth_digest"), parts))
    identity(result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("capture", "log", "node", "config", "node-build", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--positive-before", required=True, type=argument_identity)
    parser.add_argument("--positive-after", required=True, type=argument_identity)
    parser.add_argument("--subject", required=True, action="append", type=argument_identity)
    args = parser.parse_args()
    require(not args.output.exists() and not args.output.is_symlink(), "observation_fresh_output")
    result = analyze(read_json(args.capture), args.log, args.node, args.config,
                     read_json(args.node_build), args.positive_before, args.positive_after, args.subject)
    write_json(args.output, result)
