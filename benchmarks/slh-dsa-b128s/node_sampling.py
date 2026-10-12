"""Read one existing Linux Regtest node; never starts or changes the subject.

This small attachment layer reuses collectors.py for resource accounting and
adapters.py for the product's exact Prometheus gauges. The supervising runner
owns the hard deadline and output limit. Planning uses only the static config
validator: it does not inspect /proc or contact an endpoint.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import io
import ipaddress
import os
from pathlib import Path
import stat
import sys
import time
import tomllib
from urllib.parse import urlsplit

import adapters
import collectors
from provenance import canonical, read_json, require
from results import validate_record

PROC_ROOT = Path("/proc")
MAX_SCRAPE_BYTES = 256 * 1024
MAX_MEMPOOL_EVIDENCE_BYTES = 16 * 1024
SCRAPE_TIMEOUT_SECONDS = 2
MAX_CONFIG_BYTES = 1024 * 1024
MEMPOOL_GROWTH = ("mempool_growth_transactions_per_second", "mempool_growth_bytes_per_second")
ASSOCIATION = (
    "Endpoint association is an operator declaration checked against the running "
    "command and retained config; listener socket ownership is not independently proven."
)


def _read(path, limit):
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "expected a regular input file")
        data = stream.read(limit + 1)
    require(len(data) <= limit, "node sampling input exceeds byte limit")
    return data


def _endpoint(url):
    require(type(url) is str and len(url) <= 512 and all(ord(c) > 32 for c in url),
            "metrics URL must be bounded and contain no whitespace")
    parsed = urlsplit(url)
    require(parsed.scheme == "http" and parsed.username is None and parsed.password is None
            and not parsed.query and not parsed.fragment and "?" not in url and "#" not in url and "%" not in url,
            "metrics URL must use HTTP without credentials, query or fragment")
    try:
        address = ipaddress.ip_address(parsed.hostname or "")
        port = parsed.port
    except ValueError as error:
        raise collectors.CollectionError("metrics endpoint must use a literal loopback IP and port") from error
    require(address.is_loopback and port is not None and 1 <= port <= 65535,
            "metrics endpoint must use a literal loopback IP and explicit port")
    require(parsed.path in {"", "/", "/metrics"}, "metrics endpoint path must be / or /metrics")
    return str(address), port, parsed.path or "/"


def validate_endpoint_config(profile):
    """Validate retained TOML and endpoint only; no process or network access."""
    host, port, path = _endpoint(profile["metrics_url"])
    config = tomllib.loads(_read(profile["config_path"], MAX_CONFIG_BYTES).decode("utf8"))
    network, metrics = config.get("network"), config.get("metrics")
    require(type(network) is dict and type(metrics) is dict, "config requires network and metrics tables")
    require(network.get("network") == "Regtest",
            "node sampling requires explicit network.network = 'Regtest'")
    configured = metrics.get("endpoint_addr")
    require(type(configured) is str, "config must declare metrics.endpoint_addr")
    declared_host, declared_port, _ = _endpoint("http://" + configured + "/")
    require((declared_host, declared_port) == (host, port), "metrics URL differs from node config")
    return host, port, path


def _file_identity(path):
    info = Path(path).stat()
    require(stat.S_ISREG(info.st_mode), "node binary must be a regular file")
    return {key: getattr(info, "st_" + key) for key in ("dev", "ino", "size", "mtime_ns", "ctime_ns")}


def _hash(path):
    """Hash the live /proc executable symlink; provenance.sha256 rejects symlinks."""
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _expected_identity(profile):
    return {"pid": profile["pid"], **profile["process_identity"], "proc_root": str(PROC_ROOT)}


def _membership(profile):
    """Require an ordinary cgroup-v2 root mount, not an ambiguous subtree mount."""
    if profile["cgroup_path"] is None:
        return None
    boundary, target = (Path(profile[key]).resolve() for key in ("cgroup_boundary", "cgroup_path"))
    require(target.is_relative_to(boundary), "cgroup lies outside the declared mount boundary")
    mount_rows = _read(PROC_ROOT / "self/mountinfo", collectors.MAX_FILE_BYTES).decode("ascii").splitlines()
    roots = []
    for row in mount_rows:
        left, separator, right = row.partition(" - ")
        fields = left.split()
        if separator and len(fields) >= 6 and right.split() and right.split()[0] == "cgroup2":
            # Escaped mount paths are deliberately unsupported in this bounded adapter.
            if fields[4] == str(boundary):
                roots.append(fields[3])
    require(roots == ["/"], "cgroup boundary must be the unique cgroup-v2 root mount")
    raw = _read(PROC_ROOT / str(profile["pid"]) / "cgroup", collectors.MAX_FILE_BYTES).decode("ascii")
    paths = [row[3:] for row in raw.splitlines() if row.startswith("0::")]
    require(len(paths) == 1 and paths[0].startswith("/") and ".." not in Path(paths[0]).parts,
            "node cgroup-v2 membership unavailable or malformed")
    member = (boundary / paths[0].lstrip("/")).resolve()
    require(member.is_relative_to(target), "declared cgroup does not contain the registered node")
    return {"process_path": paths[0], "resolved_process_path": str(member),
            "scope": "declared cgroup and descendants, including other members; not node-only accounting"}


def _binding(manifest, previous=None):
    profile, identity = manifest["node_profile"], manifest["node_identity"]
    directory = PROC_ROOT / str(profile["pid"])
    binary, config = Path(profile["binary_path"]), Path(profile["config_path"])
    require(str(binary.resolve()) == str(binary), "registered binary path is not canonical")
    require(os.readlink(directory / "exe") == str(binary), "node executable path changed or was deleted")
    binary_stat = _file_identity(binary)
    require(_file_identity(directory / "exe") == binary_stat, "running executable differs from registered binary")
    if previous is None:
        require(_hash(directory / "exe") == identity["binary_sha256"], "running executable hash differs from build")
        require(_file_identity(directory / "exe") == binary_stat, "node executable changed while hashing")
    else:
        require(previous["binary_file_identity"] == binary_stat, "node executable changed during collection")
    raw_command = _read(directory / "cmdline", collectors.MAX_FILE_BYTES)
    require(raw_command.endswith(b"\0"), "node command line is unavailable")
    command = [part.decode("utf8") for part in raw_command[:-1].split(b"\0")]
    require(len(command) == 4 and command[1] in {"-c", "--config"} and command[2] == str(config)
            and command[3] == "start", "node must run with the registered explicit config and start command")
    require(hashlib.sha256(_read(config, MAX_CONFIG_BYTES)).hexdigest() == identity["config_sha256"],
            "node config changed after registration")
    membership = _membership(profile)
    if previous is not None:
        require(previous["cgroup_membership"] == membership, "node cgroup membership changed during collection")
    return {"binary_sha256": identity["binary_sha256"], "config_sha256": identity["config_sha256"],
            "binary_file_identity": binary_stat, "cgroup_membership": membership,
            "endpoint_association": ASSOCIATION}


class _DeadlineReader(io.RawIOBase):
    """Refresh the absolute deadline before every socket read, including framing."""

    def __init__(self, sock, remaining):
        self._sock = sock
        self._remaining = remaining
        # Retain the descriptor while HTTPConnection releases Connection: close
        # sockets; HTTPResponse owns this stream until body completion.
        self._stream = None
        self._stream = sock.makefile("rb", buffering=0)

    def readable(self):
        return True

    def readinto(self, buffer):
        self._sock.settimeout(self._remaining())
        size = self._stream.readinto(buffer)
        self._remaining()
        return size

    def close(self):
        try:
            if self._stream is not None:
                self._stream.close()
        finally:
            super().close()


class _DeadlineSocket:
    """Give HTTPConnection and its standard parser one shared request deadline."""

    def __init__(self, sock, remaining):
        self._sock = sock
        self._remaining = remaining

    def sendall(self, data):
        self._sock.settimeout(self._remaining())
        self._sock.sendall(data)
        self._remaining()

    def makefile(self, mode):
        require(mode == "rb", "metrics response requires a binary read stream")
        return io.BufferedReader(_DeadlineReader(self._sock, self._remaining))

    def close(self):
        self._sock.close()


def _mempool_evidence_text(text):
    """Keep exact needed-family lines after validating the complete response."""
    expected = adapters.parse_mempool_metrics(text)
    lines = []
    for line in text.splitlines(keepends=True):
        stripped = line.lstrip()
        parts = stripped.split()
        name = adapters._PROM_NAME.match(stripped)
        if ((name is not None and name[1] in adapters.MEMPOOL_SERIES)
                or (len(parts) >= 3 and parts[:2] == ["#", "TYPE"]
                    and parts[2] in adapters.MEMPOOL_SERIES)):
            lines.append(line)
    retained = "".join(lines)
    require(len(retained.encode("utf8")) <= MAX_MEMPOOL_EVIDENCE_BYTES,
            "needed mempool families exceed evidence byte limit")
    require(adapters.parse_mempool_metrics(retained) == expected, "mempool evidence changed parsed gauges")
    return retained


def _scrape(endpoint, *, deadline, clock=time.monotonic_ns):
    start = clock()
    observation = {"window_start_ns": start, "window_end_ns": start, "text": None, "error": None,
                   "text_scope": "mempool-families-v1", "response_sha256": None, "response_bytes": None}
    connection = response = None
    try:
        scrape_deadline = min(deadline, start + SCRAPE_TIMEOUT_SECONDS * 1_000_000_000)

        def remaining():
            seconds = (scrape_deadline - clock()) / 1_000_000_000
            if seconds <= 0:
                raise TimeoutError("metrics response exceeded request deadline")
            return seconds

        host, port, path = endpoint
        # HTTPConnection neither follows redirects nor reads proxy environment variables.
        connection = http.client.HTTPConnection(host, port, timeout=remaining())
        connection.connect()
        remaining()
        connection.sock = _DeadlineSocket(connection.sock, remaining)
        connection.request("GET", path, headers={"Accept": "text/plain", "Accept-Encoding": "identity",
                                                 "Connection": "close"})
        response = connection.getresponse()
        remaining()
        require(response.status == 200, "metrics endpoint did not return HTTP 200 (redirects are rejected)")
        require(response.getheader("Content-Encoding", "identity") == "identity",
                "compressed metrics response is unsupported")
        length = response.getheader("Content-Length")
        require(length is None or (length.isascii() and length.isdigit() and int(length) <= MAX_SCRAPE_BYTES),
                "metrics response exceeds body limit or has invalid Content-Length")
        chunks, size = [], 0
        while not response.isclosed():
            remaining()
            chunk = response.read1(min(65536, MAX_SCRAPE_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            require(size <= MAX_SCRAPE_BYTES, "metrics response exceeds body limit")
        if length is not None:
            require(size == int(length), "metrics response body was truncated")
        raw = b"".join(chunks)
        observation.update(response_sha256=hashlib.sha256(raw).hexdigest(), response_bytes=len(raw))
        # Validate the complete response before retaining only the needed families.
        # Replay still parses exact gauge/TYPE lines; unrelated families need not
        # consume the sampler's bounded output twice in stdout and evidence.jsonl.
        observation["text"] = _mempool_evidence_text(raw.decode("utf8"))
        remaining()
    except (OSError, ValueError, http.client.HTTPException) as error:
        observation["text"] = None
        observation["error"] = f"{type(error).__name__}: {error}"[:512]
    finally:
        if response is not None:
            response.close()
        if connection is not None:
            connection.close()
        observation["window_end_ns"] = clock()
    return observation


def _observe(manifest, endpoint, deadline, previous_binding, *, clock):
    evidence = dict(process=None, process_guard=None, cgroup=None, mempool=None, binding=None, error=None)
    profile = manifest["node_profile"]
    try:
        evidence["binding"] = _binding(manifest, previous_binding)
        evidence["process"] = collectors.read_process(profile["pid"], proc_root=PROC_ROOT, clock=clock)
        require(evidence["process"]["identity"] == _expected_identity(profile),
                "registered process exited, changed or has no readable identity")
        if profile["cgroup_path"] is not None:
            evidence["cgroup"] = collectors.read_cgroup(profile["cgroup_path"],
                                                        boundary=profile["cgroup_boundary"], clock=clock)
        evidence["mempool"] = _scrape(endpoint, deadline=deadline, clock=clock)
        evidence["process_guard"] = collectors.read_process(profile["pid"], proc_root=PROC_ROOT, clock=clock)
        require(evidence["process_guard"]["identity"] == _expected_identity(profile),
                "registered process exited or changed during observation")
        _binding(manifest, evidence["binding"])
    except (OSError, ValueError) as error:
        evidence["error"] = f"{type(error).__name__}: {error}"[:512]
    return evidence


def _context(manifest, interval_index, phase):
    return {"run_id": manifest.get("run_id", "node-sampler"),
            "configuration_id": manifest.get("configuration_id", "node-sampler"),
            "case_id": "node." + manifest["node_profile"]["workload"]["id"],
            "process_id": "node-sampler", "attempt_id": f"node-interval-{interval_index}",
            "phase": phase, "cache_mode": "not-applicable", "warmup": False}


def records_from_snapshots(before, after, manifest, interval_index):
    """Pure replay of retained observations, including unavailable and failed scrapes."""
    profile = manifest["node_profile"]
    for evidence in (before, after):
        require(type(evidence) is dict and set(evidence) == {
            "process", "process_guard", "cgroup", "mempool", "binding", "error"}, "snapshot evidence schema")
        require(evidence["error"] is None, "cannot normalize an incomplete node snapshot")
        binding = evidence["binding"]
        require(type(binding) is dict and set(binding) == {
            "binary_sha256", "config_sha256", "binary_file_identity", "cgroup_membership", "endpoint_association"},
            "node binding schema")
        require(binding["binary_sha256"] == manifest["node_identity"]["binary_sha256"]
                and binding["config_sha256"] == manifest["node_identity"]["config_sha256"]
                and binding["endpoint_association"] == ASSOCIATION, "node binding differs from registration")
        info = binding["binary_file_identity"]
        require(type(info) is dict and set(info) == {"dev", "ino", "size", "mtime_ns", "ctime_ns"}
                and all(type(value) is int and 0 <= value <= collectors.MAX_NUMBER for value in info.values()),
                "invalid binary file identity")
        member = binding["cgroup_membership"]
        if profile["cgroup_path"] is None:
            require(member is None, "unregistered cgroup membership")
        else:
            require(type(member) is dict and set(member) == {"process_path", "resolved_process_path", "scope"}
                    and type(member["process_path"]) is str and member["process_path"].startswith("/")
                    and ".." not in Path(member["process_path"]).parts, "invalid cgroup membership evidence")
            expected_member = Path(profile["cgroup_boundary"]) / member["process_path"].lstrip("/")
            require(str(expected_member) == member["resolved_process_path"]
                    and expected_member.is_relative_to(profile["cgroup_path"]), "cgroup does not contain registered node")
        for name in ("process", "process_guard"):
            collectors.validate_snapshot(evidence[name])
            require(evidence[name]["identity"] == _expected_identity(profile), "snapshot node identity differs")
        scrape = evidence["mempool"]
        legacy_fields = {"window_start_ns", "window_end_ns", "text", "error"}
        compact_fields = legacy_fields | {"text_scope", "response_sha256", "response_bytes"}
        require(type(scrape) is dict and set(scrape) in (legacy_fields, compact_fields),
                "mempool observation schema")
        if set(scrape) == compact_fields:
            require(scrape["text_scope"] == "mempool-families-v1", "mempool evidence scope")
            digest, size = scrape["response_sha256"], scrape["response_bytes"]
            require((digest is None and size is None and scrape["text"] is None)
                    or (type(digest) is str and len(digest) == 64
                        and all(char in "0123456789abcdef" for char in digest)
                        and type(size) is int and 0 <= size <= MAX_SCRAPE_BYTES),
                    "mempool response identity invalid")
            require(scrape["text"] is None or (type(scrape["text"]) is str
                    and len(scrape["text"].encode("utf8")) <= min(size, MAX_MEMPOOL_EVIDENCE_BYTES)),
                    "mempool compact text invalid")
        require(all(type(scrape[name]) is int and 0 <= scrape[name] <= collectors.MAX_NUMBER
                    for name in ("window_start_ns", "window_end_ns"))
                and scrape["window_start_ns"] <= scrape["window_end_ns"], "mempool read window invalid")
        require(scrape["text"] is None or (type(scrape["text"]) is str
                and len(scrape["text"].encode("utf8")) <= MAX_SCRAPE_BYTES), "mempool raw text invalid")
        require(scrape["error"] is None or (type(scrape["error"]) is str and 0 < len(scrape["error"]) <= 512),
                "mempool error invalid")
        require(scrape["text"] is not None or scrape["error"] is not None, "missing scrape needs error reason")
        require(evidence["process"]["window_end_ns"] <= scrape["window_start_ns"]
                and scrape["window_end_ns"] <= evidence["process_guard"]["window_start_ns"],
                "node and scrape read windows are out of order")
        if profile["cgroup_path"] is not None:
            cgroup = collectors.validate_snapshot(evidence["cgroup"])
            require(cgroup["kind"] == "cgroup" and cgroup["identity"] is not None
                    and cgroup["identity"]["path"] == profile["cgroup_path"],
                    "cgroup snapshot identity differs from registration")
            require(evidence["process"]["window_end_ns"] <= cgroup["window_start_ns"]
                    and cgroup["window_end_ns"] <= scrape["window_start_ns"],
                    "cgroup read window is out of order")
    require(before["binding"] == after["binding"], "node binding changed between observations")
    # Guard-to-endpoint checks detect a reset during a scrape as well as between snapshots.
    for left, right in ((before["process"], before["process_guard"]),
                        (before["process_guard"], after["process"]),
                        (after["process"], after["process_guard"])):
        for metric in ("process_cpu_ns", "process_user_cpu_ns", "process_system_cpu_ns", "process_peak_rss_bytes"):
            values = [sample["metrics"][metric] for sample in (left, right)]
            require(None in values or values[1] >= values[0], "process counter reset within observation interval")
    process = collectors.resource_record(before["process"], after["process"],
                                         _context(manifest, interval_index, "resource-process"))
    process["details"]["sampling_scope"] = "attached existing process; time-interval observations, not transaction latency"
    first, last = before["mempool"], after["mempool"]
    require(first["window_end_ns"] < last["window_start_ns"], "mempool read windows overlap")
    epoch = hashlib.sha256(canonical(_expected_identity(profile))).hexdigest()
    times = [(sample["window_start_ns"] + sample["window_end_ns"]) // 2 for sample in (first, last)]
    kwargs = {}
    if first["text"] is not None and first["error"] is None:
        kwargs = dict(previous_text=first["text"], previous_monotonic_ns=times[0], previous_process_epoch=epoch)
    # An HTTP/parse failure cannot turn a partly read body into a valid gauge.
    text = last["text"] if last["error"] is None else ""
    mempool = adapters.import_mempool(text, _context(manifest, interval_index, "mempool"),
                                     monotonic_ns=times[1], process_epoch=epoch, **kwargs)[0][0]
    # A record samples the ending gauges. A failed starting scrape prevents
    # growth calculation but must not reclassify a recovered endpoint as error.
    failure = last["error"] or first["error"]
    if failure:
        mempool["outcome"] = "error" if last["error"] else "success"
        for name in MEMPOOL_GROWTH:
            mempool["metrics"][name] = None
            mempool["unavailable"][name] = "scrape interval unavailable: " + failure
        for name, value in mempool["metrics"].items():
            if value is None and last["error"]:
                mempool["unavailable"][name] = "scrape failed: " + last["error"]
    mempool["details"].update(endpoint_association=ASSOCIATION,
                              before_window_ns=[first["window_start_ns"], first["window_end_ns"]],
                              after_window_ns=[last["window_start_ns"], last["window_end_ns"]],
                              interval_method="difference of scrape-window midpoints (integer nanoseconds)",
                              sampling_scope="time snapshots of verified mempool gauges; no admission or propagation latency")
    records = [process, mempool]
    if profile["cgroup_path"] is not None:
        records.append(collectors.resource_record(before["cgroup"], after["cgroup"],
                                                  _context(manifest, interval_index, "resource-cgroup")))
    else:
        require(before["cgroup"] is None and after["cgroup"] is None, "unregistered cgroup observation")
    return [validate_record(record) for record in records]


def collect(manifest, emit, *, clock=time.monotonic_ns, sleep=time.sleep):
    """Emit bounded observations and records; the caller supervises this process."""
    require(sys.platform == "linux", "attached node resource collection requires Linux")
    profile, settings = manifest["node_profile"], manifest["settings"]
    endpoint = validate_endpoint_config(profile)
    deadline = clock() + settings["timeout_seconds"] * 1_000_000_000
    previous = None
    record_index = 0
    for index in range(settings["samples"] + 1):
        if index:
            sleep(settings["interval_ms"] / 1000)
        require(clock() < deadline, "node collection deadline reached")
        observation = _observe(manifest, endpoint, deadline, previous["binding"] if previous else None, clock=clock)
        emit({"frame": "snapshot", "index": index, "evidence": observation})
        require(observation["error"] is None, observation["error"])
        if previous is not None:
            for record in records_from_snapshots(previous, observation, manifest, index - 1):
                emit({"frame": "record", "index": record_index, "record": record})
                record_index += 1
        previous = observation


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--execute", action="store_true", help="attach and collect actual resource observations")
    args = parser.parse_args()

    def emit(frame):
        sys.stdout.buffer.write(canonical(frame) + b"\n")
        sys.stdout.buffer.flush()

    try:
        require(args.execute, "node sampling requires --execute")
        collect(read_json(args.manifest), emit)
    except (OSError, ValueError) as error:
        print(f"node sampler: {type(error).__name__}: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
