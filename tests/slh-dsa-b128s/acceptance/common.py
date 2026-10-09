"""Shared bounded acceptance adapters. Importing this module launches nothing.

Adapted from the pinned research pq_live/pq_relay_build/sqisign_acceptance
helpers; see sources.json. The existing public fixture parser is reused.
"""
from decimal import Decimal
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tests/slh-dsa-b128s/fixtures"))
from generate_transactions import canonical, strict_json, hex_field, source_inventory  # noqa: E402

CONTRACT = "slh-dsa-b-128s-exp-v1"
FEATURE = "experimental-slh-dsa-b128s"
ALGORITHM = "b392fe82d2d9770142477a576a758a233888bc0a"
MAX_JSON = 16 * 1024 * 1024


class AcceptanceError(Exception):
    """Fixed public diagnostic; never contains a password or terminal output."""


def require(condition, reason):
    if not condition:
        raise AcceptanceError(reason)


def sha256(path):
    path = Path(path)
    require(not path.is_symlink() and stat.S_ISREG(path.stat().st_mode), "regular_file_required")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_json(path, maximum=MAX_JSON):
    path = Path(path)
    require(not path.is_symlink() and path.is_file(), "regular_json_required")
    with path.open("rb") as stream:
        data = stream.read(maximum + 1)
    return strict_json(data, maximum)


def write_json(path, value, *, fresh=True):
    path = Path(path)
    data = canonical(value) + b"\n"
    require(len(data) <= MAX_JSON, "artifact_size")
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    flags |= os.O_EXCL if fresh else os.O_TRUNC
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return path


def git(root, *arguments):
    try:
        return subprocess.run(["git", "-C", str(root), *arguments], check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=30).stdout.decode("ascii").strip()
    except (OSError, subprocess.SubprocessError, UnicodeError):
        raise AcceptanceError("git_source_state") from None


def source_state(root=ROOT):
    # Broad tracked source inventory deliberately includes all product crates,
    # manifests, build scripts and acceptance helpers. Docs are not build inputs.
    paths = ["Cargo.toml", "crates", "tests/slh-dsa-b128s", "scripts"]
    paths += [name for name in (".cargo", "rust-toolchain.toml", "build.rs", "deploy")
              if (root / name).exists()]
    require(not git(root, "status", "--porcelain=v1", "--untracked-files=all", "--",
                    *paths, "Cargo.lock"), "dirty_build_inputs")
    inventory = source_inventory(root, paths)
    commit = git(root, "rev-parse", "HEAD")
    hex_field(commit, 20)
    return {"source_commit": commit, "source_inventory": inventory,
            "source_inventory_sha256": hashlib.sha256(canonical(inventory)).hexdigest(),
            "lock_sha256": sha256(root / "Cargo.lock"),
            "fixture_lock_sha256": sha256(root / "tests/slh-dsa-b128s/fixture-signer/Cargo.lock")}


def identity_expected(enabled, supported):
    return {"schema_version": 1, "contract": CONTRACT, "suite_id": "f7",
            "backend": "portable-rust" if enabled else "disabled",
            "algorithm_revision": ALGORITHM, "blake3_version": "1.8.5",
            "verifier_compiled": enabled, "runtime_supported": supported}


def validate_identity(identity, enabled, *, runtime_required=False):
    require(type(identity) is dict and type(identity.get("runtime_supported")) is bool,
            "verifier_identity_schema")
    supported = identity["runtime_supported"]
    require(identity == identity_expected(enabled, supported), "verifier_identity_mismatch")
    require(not supported or enabled, "disabled_runtime_identity")
    require(not runtime_required or supported, "runtime_not_supported")


def validate_build(record, binary, kind, *, root=ROOT, runtime_required=False):
    fields = {"schema_version", "contract", "kind", "complete", "source", "command",
              "features", "binary_sha256", "identity", "rustc", "cargo", "environment"}
    require(type(record) is dict and set(record) == fields and record["schema_version"] == 1
            and record["complete"] is True and record["contract"] == CONTRACT
            and record["kind"] == kind, "build_receipt_schema")
    require(kind in ("node-default", "node-slh", "wallet-default", "wallet-slh", "host", "signer"), "build_kind")
    enabled = kind.endswith("-slh")
    features = (["default-release-binaries"] if kind.startswith("node-") else [])
    if enabled:
        features.append(FEATURE)
    require(record["features"] == features, "build_features")
    require(record["source"] == source_state(root), "stale_build_source")
    require(record["binary_sha256"] == sha256(binary), "stale_build_binary")
    if kind.startswith("node-"):
        validate_identity(record["identity"], enabled, runtime_required=runtime_required)
    else:
        require(record["identity"] is None, "wallet_identity_schema")
    return record


def endpoint(value):
    # Match the wallet's numeric, loopback-only SocketAddr boundary.
    try:
        if value.startswith("["):
            host, port = value[1:].split("]:")
        else:
            host, port = value.rsplit(":", 1)
        address = ipaddress.ip_address(host)
        require(address.is_loopback and port.isascii() and port.isdecimal()
                and 0 < int(port) <= 65535, "loopback_endpoint")
        require((address.version == 6) == value.startswith("["), "loopback_endpoint")
    except (ValueError, AttributeError):
        raise AcceptanceError("loopback_endpoint") from None
    return value


def zat(value):
    amount = Decimal(str(value)) * 100_000_000
    require(amount.is_finite() and amount == amount.to_integral_value()
            and 0 <= amount <= 2_100_000_000_000_000, "rpc_amount")
    return int(amount)


class Node:
    """Attached trusted local node. Does not start, build or configure a daemon."""
    def __init__(self, address, events=None):
        self.address = endpoint(address)
        self.url = "http://" + self.address
        self.events = events
        # Never use proxy environment variables for trusted loopback RPC.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def rpc(self, method, *params):
        body = canonical({"jsonrpc": "2.0", "id": 1, "method": method, "params": list(params)})
        request = urllib.request.Request(self.url, body, {"Content-Type": "application/json"})
        with self.opener.open(request, timeout=45) as response:
            raw = response.read(MAX_JSON + 1)
        require(len(raw) <= MAX_JSON, "rpc_response_size")
        reply = json.loads(raw, parse_float=Decimal)
        require(type(reply) is dict and reply.get("id") == 1, "rpc_response_schema")
        if self.events is not None:
            # Public receipt hashes bind exact RPC bytes; never log CLI/passwords.
            self.events.write(canonical({"method": method,
                "request_sha256": hashlib.sha256(body).hexdigest(),
                "response_sha256": hashlib.sha256(raw).hexdigest()}) + b"\n")
            self.events.flush()
        require(reply.get("error") is None and "result" in reply, "rpc_rejected_" + method)
        return reply["result"]

    def tip(self):
        info = self.rpc("getblockchaininfo")
        return info["blocks"], info["bestblockhash"]


def wait_for(action, reason, timeout=60):
    deadline = time.monotonic() + timeout
    while True:
        result = action()
        if result:
            return result
        require(time.monotonic() < deadline, reason)
        time.sleep(0.1)


def common_tip(nodes):
    tips = [node.tip() for node in nodes]
    require(len(tips) == 2 and tips[0] == tips[1], "nodes_do_not_share_tip")
    return {"height": tips[0][0], "hash": tips[0][1]}


def fingerprint(inventory):
    return hashlib.sha256(b"ZcashTransparentPQ/wallet-inventory/v1\0" + canonical(inventory)).hexdigest()


def object_output(transcript):
    # Reused research terminal/public JSON separation. No transcript is persisted.
    try:
        text = transcript.decode("ascii")
        return json.JSONDecoder().raw_decode(text[text.index("{"):])[0]
    except (ValueError, UnicodeError):
        raise AcceptanceError("cli_public_json") from None
