"""Read bounded Linux resource snapshots without starting a workload.

Counters are cumulative until ``resource_record`` subtracts two snapshots.
Snapshot windows use the caller's monotonic clock. An unavailable capability
has a null value and a reason; it never becomes a measured zero. These readers
do not change cgroups, interfaces, affinity, or machine configuration.
"""

import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat as file_stat
import time

MAX_FILE_BYTES = 65_536
MAX_NUMBER = 2**64 - 1


class CollectionError(ValueError):
    """Malformed input, changed identity, or a counter reset."""


def _integer(value, name, *, positive=False):
    if isinstance(value, bool) or not isinstance(value, int) or not int(positive) <= value <= MAX_NUMBER:
        raise CollectionError(f"{name} must be a bounded {'positive' if positive else 'nonnegative'} integer")
    return value


def _counter(text, name):
    if not re.fullmatch(r"[0-9]+", text.strip()):
        raise CollectionError(f"invalid {name} counter")
    return _integer(int(text), name)


def _read(path):
    try:
        # procfs counters report a zero stat size; bound the actual read.
        # NONBLOCK prevents supplied fixture paths from blocking on a FIFO.
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as handle:
            if not file_stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise CollectionError(f"{path.name} is not a regular pseudo-file or fixture")
            raw = handle.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            raise CollectionError(f"{path.name} exceeds the {MAX_FILE_BYTES}-byte input limit")
        return raw.decode("ascii"), None
    except (OSError, UnicodeError) as error:
        return None, f"{path.name} unavailable: {type(error).__name__}"


def _bounded_json(value, name, *, max_bytes=MAX_FILE_BYTES):
    """Check JSON types and bounds before serializing imported data."""
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if count > 2048 or depth > 8:
            raise CollectionError(f"{name} exceeds JSON nesting or item limits")
        if type(item) is dict:
            if len(item) > 2048 or any(type(key) is not str or len(key) > 256 for key in item):
                raise CollectionError(f"{name} has invalid JSON keys")
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            if len(item) > 2048:
                raise CollectionError(f"{name} exceeds JSON item limits")
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            if len(item) > 4096:
                raise CollectionError(f"{name} has an oversized JSON string")
        elif type(item) in (int, float):
            if abs(item) > MAX_NUMBER or not math.isfinite(item):
                raise CollectionError(f"{name} has a nonfinite or oversized JSON number")
        elif item is not None and type(item) is not bool:
            raise CollectionError(f"{name} contains a non-JSON value")
    raw = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("ascii")
    if len(raw) > max_bytes:
        raise CollectionError(f"{name} exceeds its JSON byte limit")
    return raw


def _window(snapshot, start, clock):
    end = _integer(clock(), "window_end_ns")
    if end < start:
        raise CollectionError("monotonic clock moved backwards")
    snapshot.update(window_start_ns=start, window_end_ns=end)
    return validate_snapshot(snapshot)


def _snapshot(kind):
    return {"kind": kind, "identity": None, "metrics": {}, "unavailable": {}, "details": {}}


def _put(snapshot, name, value, reason=None):
    snapshot["metrics"][name] = value
    if value is None:
        snapshot["unavailable"][name] = reason or "capability unavailable"


def cpuset_count(text):
    """Count a Linux CPU list; reject duplicate, reversed, or overlapping ranges."""
    ranges = []
    for token in text.strip().split(","):
        match = re.fullmatch(r"([0-9]+)(?:-([0-9]+))?", token)
        if not match:
            raise CollectionError("invalid CPU list")
        low, high = int(match[1]), int(match[2] or match[1])
        if high < low:
            raise CollectionError("reversed CPU range")
        ranges.append((low, high))
    ranges.sort()
    if any(right[0] <= left[1] for left, right in zip(ranges, ranges[1:])):
        raise CollectionError("overlapping CPU ranges")
    return sum(high - low + 1 for low, high in ranges)


def _stat(text, expected_pid):
    # comm can contain spaces and ')' characters; all later fields are scalar.
    prefix, separator, suffix = text.rpartition(") ")
    if not separator or not prefix.startswith(f"{expected_pid} ("):
        raise CollectionError("malformed /proc PID stat")
    fields = suffix.split()
    if len(fields) < 22:
        raise CollectionError("short /proc PID stat")
    return {
        "user_ticks": _counter(fields[11], "utime"),
        "system_ticks": _counter(fields[12], "stime"),
        "start_ticks": _counter(fields[19], "starttime"),
    }


def _status(text):
    fields = {}
    for line in text.splitlines():
        name, colon, value = line.partition(":")
        if colon and name in {"VmRSS", "VmHWM", "Cpus_allowed_list"}:
            if name in fields:
                raise CollectionError(f"duplicate process status field {name}")
            fields[name] = value.strip()
    return fields


def read_process(pid, *, proc_root="/proc", clock=time.monotonic_ns, clock_ticks=None):
    """Read one PID (not its children), bound to boot ID and start-time ticks.

    VmHWM is a process-lifetime high-water mark, including startup and warmup.
    ``resource_record`` exports it only for a caller-declared fresh process.
    ``affinity_cores`` describes only the process leader thread. Other threads
    can have different CPU masks, so this is not a process-wide entitlement.
    """
    _integer(pid, "pid", positive=True)
    start = _integer(clock(), "window_start_ns")
    root = Path(proc_root)
    directory = root / str(pid)
    snapshot = _snapshot("process")
    text, reason = _read(directory / "stat")
    status_text, status_reason = _read(directory / "status")
    text_after, after_reason = _read(directory / "stat")
    boot_id, boot_reason = _read(root / "sys/kernel/random/boot_id")
    if text is not None and text_after is not None:
        first, last = _stat(text, pid), _stat(text_after, pid)
        if first["start_ticks"] != last["start_ticks"]:
            raise CollectionError("PID was reused during the snapshot")
        if any(last[key] < first[key] for key in ("user_ticks", "system_ticks")):
            raise CollectionError("process CPU counter moved backwards during snapshot")
        if clock_ticks is None:
            try:
                clock_ticks = os.sysconf("SC_CLK_TCK")
            except (OSError, ValueError):
                clock_ticks = None
        if clock_ticks is not None:
            _integer(clock_ticks, "clock_ticks", positive=True)
        for name, ticks in (
            ("process_user_cpu_ns", last["user_ticks"]),
            ("process_system_cpu_ns", last["system_ticks"]),
            ("process_cpu_ns", last["user_ticks"] + last["system_ticks"]),
        ):
            _put(snapshot, name, None if clock_ticks is None else ticks * 1_000_000_000 // clock_ticks,
                 "SC_CLK_TCK unavailable")
        if boot_id is not None and boot_id.strip():
            snapshot["identity"] = {
                "pid": pid, "start_ticks": last["start_ticks"], "boot_id": boot_id.strip(),
                "proc_root": str(root.resolve()),
            }
        else:
            snapshot["details"]["identity_unavailable"] = boot_reason or "empty boot ID"
        snapshot["details"].update(last, clock_ticks=clock_ticks)
    else:
        for name in ("process_cpu_ns", "process_user_cpu_ns", "process_system_cpu_ns"):
            _put(snapshot, name, None, reason or after_reason)
        snapshot["details"]["identity_unavailable"] = reason or after_reason
    fields = _status(status_text) if status_text is not None else {}
    for source, metric in (("VmRSS", "rss_current_bytes"), ("VmHWM", "process_peak_rss_bytes")):
        raw = fields.get(source)
        if raw is None:
            _put(snapshot, metric, None, status_reason or f"{source} absent (for example, exited process)")
        else:
            match = re.fullmatch(r"([0-9]+)\s+kB", raw)
            if not match:
                raise CollectionError(f"malformed {source}")
            _put(snapshot, metric, int(match[1]) * 1024)
    if "Cpus_allowed_list" in fields:
        snapshot["details"]["affinity_cores"] = cpuset_count(fields["Cpus_allowed_list"])
    snapshot["details"]["affinity_scope"] = "process leader thread only; other threads may have different CPU masks"
    snapshot["details"]["scope"] = "one process, excludes children; memory is not an operation-local allocation count"
    return _window(snapshot, start, clock)


def _key_values(text, source):
    values = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) != 2 or fields[0] in values:
            raise CollectionError(f"malformed or duplicate {source} entry")
        values[fields[0]] = _counter(fields[1], source)
    return values


def _cgroup_entitlement(path, boundary):
    if boundary is None:
        return None, "cgroup mount boundary not supplied; ancestor quota limits unknown", {}
    boundary = Path(boundary).resolve()
    try:
        path.relative_to(boundary)
    except ValueError as error:
        raise CollectionError("cgroup path lies outside supplied mount boundary") from error
    cpus, reason = _read(path / "cpuset.cpus.effective")
    if cpus is None or not cpus.strip():
        return None, reason or "effective cpuset is empty or unavailable", {}
    allowed = cpuset_count(cpus)
    limits = []
    current = path
    while True:
        quota, reason = _read(current / "cpu.max")
        # cgroup-v2's root has no cpu.max; its cpuset describes available CPUs.
        if quota is None and (current != boundary or reason != "cpu.max unavailable: FileNotFoundError"):
            return None, reason + "; ancestor CPU quota unknown", {}
        if quota is not None:
            fields = quota.split()
            if len(fields) != 2:
                raise CollectionError("malformed cpu.max")
            period = _counter(fields[1], "cpu.max period")
            if not period:
                raise CollectionError("cpu.max period is zero")
            if fields[0] != "max":
                limit = _counter(fields[0], "cpu.max quota")
                if not limit:
                    raise CollectionError("cpu.max quota is zero")
                limits.append(limit / period)
        if current == boundary:
            break
        current = current.parent
    return min([float(allowed)] + limits), None, {"cpuset_cores": allowed, "ancestor_quota_cores": limits}


def read_cgroup(path, *, boundary=None, clock=time.monotonic_ns):
    """Read cgroup-v2 counters and, with a mount boundary, effective CPU limits.

    The entitlement is an upper limit shared with other members of the cgroup
    and restricted ancestors; it is not a promise of dedicated CPU capacity.
    """
    start = _integer(clock(), "window_start_ns")
    path = Path(path).resolve()
    snapshot = _snapshot("cgroup")
    try:
        identity_before = path.stat()
    except OSError:
        identity_before = None
    raw, reason = _read(path / "cpu.stat")
    counters = _key_values(raw, "cpu.stat") if raw is not None else {}
    for source, metric in (
        ("usage_usec", "cgroup_cpu_ns"), ("user_usec", "cgroup_user_cpu_ns"),
        ("system_usec", "cgroup_system_cpu_ns"), ("throttled_usec", "cgroup_throttled_ns"),
    ):
        value = counters.get(source)
        _put(snapshot, metric, None if value is None else value * 1000, reason or f"{source} absent")
    for source, metric in (("memory.current", "cgroup_memory_current_bytes"), ("memory.peak", "cgroup_memory_peak_bytes")):
        raw, reason = _read(path / source)
        _put(snapshot, metric, None if raw is None else _counter(raw, source), reason)
    entitlement, reason, limits = _cgroup_entitlement(path, boundary)
    _put(snapshot, "effective_cpu_cores", entitlement, reason)
    snapshot["details"].update(limits, cpu_periods=counters.get("nr_periods"),
                               cpu_throttled_periods=counters.get("nr_throttled"),
                               scope="cgroup and descendants; ancestor quota may be shared")
    try:
        identity_after = path.stat()
    except OSError:
        identity_after = None
    if identity_before is not None and identity_after is not None:
        before = (identity_before.st_dev, identity_before.st_ino)
        after = (identity_after.st_dev, identity_after.st_ino)
        if before != after:
            raise CollectionError("cgroup identity changed during snapshot")
        snapshot["identity"] = {"path": str(path), "device": after[0], "inode": after[1]}
    else:
        snapshot["details"]["identity_unavailable"] = "cgroup directory is unavailable"
    return _window(snapshot, start, clock)


def read_interface(name, *, sys_root="/sys", namespace_id=None, isolated=False, clock=time.monotonic_ns):
    """Read byte counters for a caller-declared isolated Linux interface.

    These count all interface traffic, including protocol overhead and retries.
    They do not isolate transaction bytes. Non-isolated sources are unavailable.
    A fixture root needs an explicit network namespace identity.
    """
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", name) or name in {".", ".."}:
        raise CollectionError("invalid interface name")
    if not isinstance(isolated, bool):
        raise CollectionError("isolated must be boolean")
    start = _integer(clock(), "window_start_ns")
    snapshot = _snapshot("interface")
    path = Path(sys_root) / "class/net" / name
    if namespace_id is None and str(sys_root) == "/sys":
        try:
            namespace_id = os.readlink("/proc/self/ns/net")
        except OSError:
            pass
    if namespace_id is not None and (not isinstance(namespace_id, str) or not namespace_id):
        raise CollectionError("network namespace identity must be nonempty")
    if isolated and namespace_id is not None:
        index_before, index_reason = _read(path / "ifindex")
        for direction in ("rx", "tx"):
            raw, reason = _read(path / f"statistics/{direction}_bytes")
            _put(snapshot, f"interface_{direction}_bytes", None if raw is None else _counter(raw, direction), reason)
        index_after, _ = _read(path / "ifindex")
        if index_before is not None and index_after is not None:
            before, after = _counter(index_before, "ifindex"), _counter(index_after, "ifindex")
            if before != after:
                raise CollectionError("interface changed during snapshot")
            snapshot["identity"] = {"interface": name, "ifindex": after, "namespace": namespace_id,
                                    "sys_root": str(Path(sys_root).resolve())}
        else:
            snapshot["details"]["identity_unavailable"] = index_reason or "interface disappeared"
    else:
        reason = "interface isolation not declared" if not isolated else "network namespace identity unavailable"
        for direction in ("rx", "tx"):
            _put(snapshot, f"interface_{direction}_bytes", None, reason)
        snapshot["details"]["identity_unavailable"] = reason
    snapshot["details"]["scope"] = "all bytes on isolated interface; not transaction payload or peer-specific protocol traffic"
    return _window(snapshot, start, clock)


def _record(context, suffix, *, metrics, unavailable, details, outcome="success", censored=None, source=None):
    """Make the common result envelope; consumers validate it with results.py."""
    required = ("run_id", "case_id", "configuration_id", "process_id", "attempt_id", "phase", "cache_mode", "warmup")
    missing = set(required) - context.keys()
    if missing:
        raise CollectionError(f"missing record context: {', '.join(sorted(missing))}")
    record = {key: context[key] for key in required}
    digest = hashlib.sha256(f"{context['attempt_id']}:{suffix}".encode()).hexdigest()[:32]
    record["attempt_id"] = f"import-{digest}"
    if source is not None:
        record["process_id"] = "source-" + hashlib.sha256(str(source).encode()).hexdigest()[:32]
    record.update(schema_version=1, outcome=outcome, metrics=metrics, unavailable=unavailable,
                  censored=list(censored or []), details={**context.get("details", {}), **details})
    return record


SNAPSHOT_METRICS = {
    "process": {"process_cpu_ns", "process_user_cpu_ns", "process_system_cpu_ns",
                "rss_current_bytes", "process_peak_rss_bytes"},
    "cgroup": {"cgroup_cpu_ns", "cgroup_user_cpu_ns", "cgroup_system_cpu_ns", "cgroup_throttled_ns",
               "cgroup_memory_current_bytes", "cgroup_memory_peak_bytes", "effective_cpu_cores"},
    "interface": {"interface_rx_bytes", "interface_tx_bytes"},
}


def validate_snapshot(snapshot):
    """Validate a saved snapshot from these readers before interval arithmetic."""
    _bounded_json(snapshot, "resource snapshot")
    if type(snapshot) is not dict or set(snapshot) != {
        "kind", "identity", "metrics", "unavailable", "details", "window_start_ns", "window_end_ns",
    }:
        raise CollectionError("resource snapshot has missing or unknown fields")
    kind = snapshot["kind"]
    if not isinstance(kind, str) or kind not in SNAPSHOT_METRICS:
        raise CollectionError("unknown resource snapshot kind")
    metrics, unavailable, details = (snapshot[key] for key in ("metrics", "unavailable", "details"))
    if type(metrics) is not dict or set(metrics) != SNAPSHOT_METRICS[kind]:
        raise CollectionError("resource snapshot metrics differ from collector schema")
    for name, value in metrics.items():
        if value is None:
            continue
        if name == "effective_cpu_cores":
            if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
                raise CollectionError("effective_cpu_cores must be finite and positive")
        else:
            _integer(value, name)
    if type(unavailable) is not dict or set(unavailable) != {key for key, value in metrics.items() if value is None}:
        raise CollectionError("snapshot unavailable reasons must match null metrics")
    if any(not isinstance(reason, str) or not reason.strip() or len(reason) > 1024 for reason in unavailable.values()):
        raise CollectionError("snapshot unavailable reason must be bounded nonempty text")
    if type(details) is not dict:
        raise CollectionError("snapshot details must be an object")
    _bounded_json(details, "snapshot details", max_bytes=16_384)
    for key in ("cpu_periods", "cpu_throttled_periods", "user_ticks", "system_ticks", "start_ticks"):
        if details.get(key) is not None:
            _integer(details[key], key)
    for key in ("affinity_cores", "clock_ticks"):
        if details.get(key) is not None:
            _integer(details[key], key, positive=True)
    identity = snapshot["identity"]
    if identity is not None:
        identity_fields = {"process": {"pid", "start_ticks", "boot_id", "proc_root"},
                           "cgroup": {"path", "device", "inode"},
                           "interface": {"interface", "ifindex", "namespace", "sys_root"}}[kind]
        if type(identity) is not dict or set(identity) != identity_fields:
            raise CollectionError("resource snapshot identity differs from collector schema")
        for key, value in identity.items():
            if key in {"pid", "ifindex", "inode", "device", "start_ticks"}:
                _integer(value, key, positive=key in {"pid", "ifindex", "inode"})
            elif not isinstance(value, str) or not value or len(value) > 4096:
                raise CollectionError("resource snapshot identity text must be bounded and nonempty")
    for key in ("window_start_ns", "window_end_ns"):
        _integer(snapshot[key], key)
    if snapshot["window_end_ns"] < snapshot["window_start_ns"]:
        raise CollectionError("invalid collection window")
    return snapshot


def _interval(before, after):
    validate_snapshot(before)
    validate_snapshot(after)
    if before["kind"] != after["kind"]:
        raise CollectionError("cannot compare different collector kinds")
    if after["window_start_ns"] <= before["window_end_ns"]:
        raise CollectionError("resource snapshot windows overlap or have no interval")
    if before["identity"] is not None and after["identity"] is not None and before["identity"] != after["identity"]:
        raise CollectionError("resource identity changed; start a new epoch")
    # Both endpoints carry read uncertainty; preserve their complete windows.
    # Subtract integers before division, preserving small differences at large
    # monotonic epochs (converting absolute nanoseconds to float loses bits).
    return ((after["window_start_ns"] - before["window_start_ns"])
            + (after["window_end_ns"] - before["window_end_ns"])) / 2


def resource_record(before, after, context, *, fresh_process=False, fresh_cgroup=False, effective_cpu_cores=None):
    """Convert two snapshots into one normalized interval observation.

    ``fresh_process``/``fresh_cgroup`` assert a new subject for the entire case,
    including setup and warmup. They do not make lifetime peaks phase-local.
    CPU uses delta CPU seconds / midpoint wall seconds. Network rates use the
    same interval. Read-window widths remain in details, not hidden precision.
    For a process, ``effective_cpu_cores`` must describe the whole process for
    this interval. Leader thread affinity cannot establish or cap that bound.
    """
    if not isinstance(fresh_process, bool) or not isinstance(fresh_cgroup, bool):
        raise CollectionError("fresh-process and fresh-cgroup declarations must be boolean")
    elapsed = _interval(before, after)
    metrics, unavailable = {}, {}
    identity_known = before["identity"] is not None and after["identity"] is not None

    def put(name, value, reason=None):
        metrics[name] = value
        if value is None:
            unavailable[name] = reason or "capability unavailable"

    def delta(name):
        left, right = before["metrics"].get(name), after["metrics"].get(name)
        if left is None or right is None or not identity_known:
            reason = (before["unavailable"].get(name) or after["unavailable"].get(name)
                      or "resource identity unavailable; interval cannot be correlated")
            put(name, None, reason)
            return None
        if right < left:
            raise CollectionError(f"{name} counter reset; start a new epoch")
        put(name, right - left)
        return right - left

    kind = before["kind"]
    if kind in {"process", "cgroup"}:
        for name in (f"{kind}_cpu_ns", f"{kind}_user_cpu_ns", f"{kind}_system_cpu_ns"):
            delta(name)
        if kind == "cgroup":
            delta("cgroup_throttled_ns")
            periods = [sample["details"].get("cpu_throttled_periods") for sample in (before, after)]
            if None in periods or not identity_known:
                put("cgroup_throttled_periods", None, "nr_throttled or cgroup identity unavailable")
            elif periods[1] < periods[0]:
                raise CollectionError("cgroup throttled periods reset; start a new epoch")
            else:
                put("cgroup_throttled_periods", periods[1] - periods[0])
            left = before["metrics"].get("effective_cpu_cores")
            right = after["metrics"].get("effective_cpu_cores")
            if left is not None and right is not None and left != right:
                raise CollectionError("CPU entitlement changed during interval")
            effective_cpu_cores = left if left == right else None
        if effective_cpu_cores is not None:
            if isinstance(effective_cpu_cores, bool) or not isinstance(effective_cpu_cores, (int, float)) or not math.isfinite(effective_cpu_cores) or effective_cpu_cores <= 0:
                raise CollectionError("effective_cpu_cores must be finite and positive")
        put("effective_cpu_cores", effective_cpu_cores, "effective CPU entitlement unknown")
        cpu = metrics[f"{kind}_cpu_ns"]
        cores = None if cpu is None else cpu / elapsed
        put(f"{kind}_cpu_core_equivalents", cores, "CPU delta unavailable")
        put(f"{kind}_cpu_normalized_percent", None if cores is None or effective_cpu_cores is None else 100 * cores / effective_cpu_cores,
            "CPU delta or effective CPU entitlement unavailable")
        current = "rss_current_bytes" if kind == "process" else "cgroup_memory_current_bytes"
        put(current, after["metrics"].get(current) if identity_known else None,
            after["unavailable"].get(current) or "resource identity unavailable")
        if kind == "process":
            put("rss_before_bytes", before["metrics"].get(current) if identity_known else None,
                before["unavailable"].get(current) or "resource identity unavailable")
            put("rss_after_bytes", after["metrics"].get(current) if identity_known else None,
                after["unavailable"].get(current) or "resource identity unavailable")
        peak = "process_peak_rss_bytes" if kind == "process" else "cgroup_memory_peak_bytes"
        fresh = fresh_process if kind == "process" else fresh_cgroup
        put(peak, after["metrics"].get(peak) if fresh and identity_known else None,
            after["unavailable"].get(peak) or "a fresh subject was not declared; lifetime peak cannot describe this case")
        if identity_known:
            left, right = before["metrics"].get(peak), after["metrics"].get(peak)
            if left is not None and right is not None and right < left:
                raise CollectionError(f"{peak} reset; start a new epoch")
    elif kind == "interface":
        for direction in ("rx", "tx"):
            name = f"interface_{direction}_bytes"
            value = delta(name)
            put(f"{name}_per_second", None if value is None else value * 1_000_000_000 / elapsed,
                unavailable.get(name))
    else:
        raise CollectionError(f"unsupported collector kind: {kind}")
    details = {
        "collector": kind, "source_identity": after["identity"],
        "before_window_ns": [before["window_start_ns"], before["window_end_ns"]],
        "after_window_ns": [after["window_start_ns"], after["window_end_ns"]],
        "rate_interval_ns": elapsed, "interval_method": "difference of collection-window midpoints",
        "source_details": after["details"], "fresh_process": fresh_process, "fresh_cgroup": fresh_cgroup,
        "peak_scope": "lifetime including setup and warmup; never an operation-local allocation measurement",
    }
    if kind == "process":
        details.update(
            leader_thread_affinity_cores=[sample["details"].get("affinity_cores") for sample in (before, after)],
            affinity_scope="process leader thread only; diagnostic, not a process-wide CPU entitlement",
            cpu_entitlement_source="caller declaration for the whole process and interval; not independently verified",
        )
    return _record(context, f"resource:{kind}:{after['window_end_ns']}", metrics=metrics,
                   unavailable=unavailable, details=details, source=after["identity"])
