#!/usr/bin/env python3
"""Check benchmark snapshot use without opening or changing a database."""

import argparse
import json
import os
from pathlib import Path
import re
import sys
import time
from urllib.parse import quote
from urllib.request import urlopen


MAX_LINE_BYTES = 64 * 1024
MAX_SOURCE_BYTES = 256 * 1024
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
CACHE_MESSAGE = re.compile(r"loaded (?:Zakura|Zebra) state cache")


def cached_tip(line):
    """Read only the initial cache event, never a later sync/peer height."""
    line = ANSI.sub("", line)
    if line.lstrip().startswith("{"):
        record = json.loads(line)
        if not isinstance(record, dict) or not isinstance(record.get("fields"), dict):
            raise ValueError("unsupported JSON startup log record")
        fields = record.get("fields", {})
        line = f"{fields.get('message', '')} chain_tip={fields.get('chain_tip', '')}"
    if not CACHE_MESSAGE.search(line):
        return None
    height = re.search(r"\bchain_tip=Some\(\(.*?, Height\(([0-9]+)\)\)\)", line)
    if not height or int(height[1]) == 0:
        raise ValueError("node did not load a nonzero snapshot tip; refusing a genesis-sync benchmark")
    return int(height[1])


def wait_for_snapshot(log_path, pid, timeout, expected=None):
    """Wait for normal writable startup, including supported database upgrades."""
    deadline = time.monotonic() + timeout
    pending = b""
    with Path(log_path).open("rb") as log:
        while True:
            chunk = log.readline(MAX_LINE_BYTES + 1 - len(pending))
            pending += chunk
            if len(pending) > MAX_LINE_BYTES:
                raise ValueError("startup log line exceeds the snapshot-check limit")
            if pending.endswith(b"\n"):
                height = cached_tip(pending.decode("utf-8", errors="replace"))
                pending = b""
                if height is not None:
                    if expected is not None and height != expected:
                        raise ValueError(f"initial snapshot tip {height} differs from expected {expected}")
                    return height
            if time.monotonic() >= deadline:
                raise ValueError("timed out waiting for the initial snapshot cache report")
            if not chunk:
                try:
                    os.kill(pid, 0)
                except ProcessLookupError as error:
                    raise ValueError("node exited before reporting its initial snapshot tip") from error
                time.sleep(min(0.1, max(0, deadline - time.monotonic())))


def check_release_layout(repo, tag):
    """Reject incompatible release source before binary or snapshot downloads."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise ValueError("release repository must be an owner/repository name")
    url = (f"https://raw.githubusercontent.com/{repo}/{quote(tag, safe='')}/"
           "crates/zakura-state/src/constants.rs")
    with urlopen(url, timeout=60) as response:
        source = response.read(MAX_SOURCE_BYTES + 1)
    if len(source) > MAX_SOURCE_BYTES:
        raise ValueError("release state constants exceed the inspection limit")
    kind = re.search(rb'\bSTATE_DATABASE_KIND\s*:\s*&str\s*=\s*"([^"]+)"\s*;', source)
    if kind is None or kind[1] != b"state":
        raise ValueError("release does not use the upstream state/ snapshot layout; "
                         "state-tpq requires a fresh devnet snapshot, not renamed upstream indexes")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    startup = commands.add_parser("startup")
    startup.add_argument("--log", required=True)
    startup.add_argument("--pid", type=int, required=True)
    startup.add_argument("--timeout", type=int, required=True)
    startup.add_argument("--expected-height", type=int)
    release = commands.add_parser("release-layout")
    release.add_argument("--repo", required=True)
    release.add_argument("--tag", required=True)
    args = parser.parse_args()
    try:
        if args.command == "release-layout":
            check_release_layout(args.repo, args.tag)
        else:
            if args.pid <= 0 or args.timeout < 0:
                raise ValueError("startup check requires a positive PID and non-negative timeout")
            height = wait_for_snapshot(args.log, args.pid, args.timeout, args.expected_height)
            print(f"Verified initial snapshot tip: {height}")
    except (OSError, ValueError) as error:
        print(f"FATAL: snapshot check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
