"""Bounded loopback history faults for HUMAN acceptance; imports are inert.

Reuses the existing trusted RPC endpoint/strict JSON helpers and loopback fake
discovery pattern. Only mock upstreams are used by the offline unit tests.
"""
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import threading
import time
import urllib.request

from common import AcceptanceError, canonical, endpoint, require, strict_json
from generate_transactions import FixtureError

MAX_REQUEST = 4096
MAX_RESPONSE = 16 * 1024 * 1024
MAX_REQUESTS = 4096
MODES = ("honest", "unavailable", "missing-hash", "inconsistent-tip", "pruned", "inconsistent-block")


def request(raw):
    try:
        value = strict_json(raw, MAX_REQUEST)
    except FixtureError:
        raise AcceptanceError("history_request_json") from None
    require(type(value) is dict and set(value) == {"jsonrpc", "id", "method", "params"}
            and value["jsonrpc"] == "2.0" and type(value["id"]) is int and value["id"] == 1,
            "history_request_envelope")
    method, params = value["method"], value["params"]
    require(type(params) is list, "history_request_params")
    def number(v):
        return type(v) is int and 0 <= v <= 0xffffffff
    def digest(v):
        return type(v) is str and len(v) == 64 and all(c in "0123456789abcdef" for c in v)
    valid = ((method == "getblockchaininfo" and params == [])
             or (method == "getblockhash" and len(params) == 1 and number(params[0]))
             or (method == "getblock" and len(params) == 2 and digest(params[0])
                 and type(params[1]) is int and params[1] == 0)
             or (method == "gettxout" and len(params) == 3 and digest(params[0])
                 and number(params[1]) and type(params[2]) is bool)
             or (method == "getrawtransaction" and len(params) == 2 and digest(params[0])
                 and type(params[1]) is int and params[1] == 1))
    require(valid, "history_read_only_method")
    return value


def error(code=-32099):
    return canonical({"id": 1, "result": None, "error": {"code": code, "message": "history fault service"}})


class HistoryService:
    """Serial loopback-only proxy with fixed bounds; it cannot submit or mine."""
    def __init__(self, upstream, mode="honest", *, block_hash=None, height=None, relay=None):
        self.upstream = endpoint(upstream)
        require(mode in MODES, "history_fault_mode")
        require(block_hash is None or (type(block_hash) is str and len(block_hash) == 64
                and all(c in "0123456789abcdef" for c in block_hash)), "history_fault_hash")
        require(height is None or type(height) is int and 0 <= height <= 0xffffffff, "history_fault_height")
        require(mode not in ("pruned", "inconsistent-block") or block_hash is not None,
                "history_fault_hash_required")
        self.mode, self.block_hash, self.height = mode, block_hash, height
        self.relay = relay or self.forward
        self.events, self.count, self.server, self.thread = [], 0, None, None
        self.lock = threading.Lock()
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def forward(self, raw):
        query = urllib.request.Request("http://" + self.upstream, raw, {"Content-Type": "application/json"})
        with self.opener.open(query, timeout=5) as response:
            require(response.status == 200, "history_upstream_status")
            deadline, chunks, size = time.monotonic() + 5, [], 0
            while True:
                require(time.monotonic() <= deadline, "history_upstream_deadline")
                chunk = response.read1(min(65536, MAX_RESPONSE + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                require(size <= MAX_RESPONSE, "history_upstream_size")
            result = b"".join(chunks)
        require(len(result) <= MAX_RESPONSE, "history_upstream_size")
        return result

    def begin(self):
        with self.lock:
            require(self.count < MAX_REQUESTS, "history_request_count")
            require(time.monotonic() <= self.deadline, "history_service_deadline")
            self.count += 1

    def respond(self, raw, *, reserved=False):
        if not reserved:
            self.begin()
        query = request(raw)
        with self.lock:
            mode = self.mode
        upstream = self.relay(raw)
        require(type(upstream) is bytes and len(upstream) <= MAX_RESPONSE, "history_upstream_size")
        value = json.loads(upstream)
        require(type(value) is dict and type(value.get("id")) is int and value["id"] == 1,
                "history_upstream_envelope")
        output, applied = upstream, False
        # A genuine upstream failure never counts as an injected negative.
        if value.get("error") is None and "result" in value:
            method, params = query["method"], query["params"]
            if mode == "unavailable" and method == "getblockchaininfo":
                # Pinned Zakura reports BIP70's "test" name for Regtest too.
                require(type(value["result"]) is dict and value["result"].get("chain") == "test"
                        and type(value["result"].get("blocks")) is int
                        and type(value["result"].get("bestblockhash")) is str, "history_upstream_context")
                output, applied = error(), True
            elif mode == "missing-hash" and method == "getblockhash" and (self.height is None or params[0] == self.height):
                require(type(value["result"]) is str and len(value["result"]) == 64
                        and all(c in "0123456789abcdef" for c in value["result"]), "history_upstream_hash")
                output, applied = canonical({"id": 1, "result": None, "error": None}), True
            elif mode == "inconsistent-tip" and method == "getblockchaininfo":
                changed = copy.deepcopy(value)
                original = changed["result"]["bestblockhash"]
                require(type(original) is str and len(original) == 64
                        and all(c in "0123456789abcdef" for c in original), "history_upstream_tip")
                changed["result"]["bestblockhash"] = ("1" if original[0] == "0" else "0") + original[1:]
                output, applied = canonical(changed), True
            elif mode in ("pruned", "inconsistent-block") and method == "getblock" and params[0] == self.block_hash:
                require(type(value["result"]) is str, "history_upstream_block")
                block = bytearray.fromhex(value["result"])
                require(len(block) >= 80, "history_upstream_block")
                if mode == "pruned":
                    output = error(-1)
                else:
                    changed = copy.deepcopy(value)
                    block[4] ^= 1  # Header previous-hash byte: preserve parseability, break identity.
                    changed["result"] = block.hex()
                    output = canonical(changed)
                applied = True
        require(len(output) <= MAX_RESPONSE, "history_response_size")
        with self.lock:
            self.events.append({"method": query["method"], "mode": mode, "fault_applied": applied,
                "request_sha256": hashlib.sha256(raw).hexdigest(),
                "upstream_sha256": hashlib.sha256(upstream).hexdigest(),
                "response_sha256": hashlib.sha256(output).hexdigest()})
        return output

    def clear(self):
        with self.lock:
            self.mode = "honest"

    def __enter__(self):
        owner = self
        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"
            def log_message(self, *_):
                pass
            def setup(self):
                self.request.settimeout(2)
                super().setup()
            def do_POST(self):
                status = 200
                try:
                    owner.begin()
                    lengths = self.headers.get_all("Content-Length", [])
                    require(self.path == "/" and len(lengths) == 1 and lengths[0].isascii()
                            and lengths[0].isdecimal() and not self.headers.get("Transfer-Encoding"), "history_http_frame")
                    size = int(lengths[0])
                    require(0 < size <= MAX_REQUEST, "history_request_size")
                    raw = self.rfile.read(size)
                    require(len(raw) == size, "history_request_truncated")
                    result = owner.respond(raw, reserved=True)
                except (AcceptanceError, OSError, ValueError, KeyError, TypeError):
                    status, result = 503, error()
                try:
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(result)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(result)
                except OSError:
                    pass
        self.deadline = time.monotonic() + 300
        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.address = "127.0.0.1:" + str(self.server.server_port)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=10)
        require(not self.thread.is_alive(), "history_service_shutdown")
