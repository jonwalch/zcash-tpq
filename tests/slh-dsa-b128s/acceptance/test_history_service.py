"""Offline loopback service tests: relay is always an in-memory fake."""
import hashlib
import json
import socket
import unittest
from unittest.mock import Mock, patch
import urllib.error
import urllib.request

from common import AcceptanceError, canonical
import history_service as history

BLOCK = "11" * 32


def query(method="getblockchaininfo", params=None):
    return canonical({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []})


def reply(value):
    return canonical({"id": 1, "result": value, "error": None})


def relay(raw):
    call = json.loads(raw)
    if call["method"] == "getblockchaininfo":
        return reply({"chain": "test", "blocks": 111, "bestblockhash": BLOCK})
    if call["method"] == "getblockhash":
        return reply(BLOCK)
    if call["method"] == "getblock":
        return reply("00" * 100)
    raise AssertionError("unexpected mocked method")


def wallet_http(address, body):
    """Pinned LocalRpc::call_nullable framing, with no wallet or node process."""
    request = (f"POST / HTTP/1.0\r\nHost: {address}\r\nContent-Type: application/json\r\n"
               f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
    with socket.create_connection(("127.0.0.1", int(address.split(":")[1])), timeout=2) as client:
        client.sendall(request)
        response = bytearray()
        while data := client.recv(8192):
            response.extend(data)
            if len(response) > 16384:
                raise AssertionError("mock response exceeds the small fixture bound")
    header, raw = bytes(response).split(b"\r\n\r\n", 1)
    return header, raw


class ServiceTests(unittest.TestCase):
    def test_only_numeric_loopback_upstream_and_read_only_rpc_are_allowed(self):
        for address in ("localhost:1234", "example.com:1234", "192.0.2.1:1234", "http://127.0.0.1:1234"):
            with self.subTest(address=address), self.assertRaises(AcceptanceError):
                history.HistoryService(address, relay=relay)
        bad = [query("sendrawtransaction", ["00"]), query("generate", [1]),
               query("getblock", [BLOCK, True]), query("getblockhash", [True]),
               query("gettxout", [BLOCK, 0, 1]), query("getrawtransaction", [BLOCK, 0])]
        for raw in bad:
            with self.subTest(raw=raw), self.assertRaisesRegex(AcceptanceError, "read_only_method"):
                history.request(raw)
        for raw in (b'{"id":1,"id":1}', b"{}", query().replace(b'"id":1', b'"id":true')):
            with self.assertRaises(AcceptanceError):
                history.request(raw)

    def test_honest_proxy_preserves_exact_decimal_bytes_and_only_logs_hashes(self):
        original = b'{"id":1,"error":null,"result":{"value":0.03000001}}\n'
        request = query("gettxout", [BLOCK, 0, False])
        with history.HistoryService("127.0.0.1:1", relay=lambda _: original) as service:
            self.assertEqual(service.respond(request), original)
            self.assertEqual(service.events[0], {"method": "gettxout", "mode": "honest", "fault_applied": False,
                "request_sha256": hashlib.sha256(request).hexdigest(),
                "upstream_sha256": hashlib.sha256(original).hexdigest(),
                "response_sha256": hashlib.sha256(original).hexdigest()})

    def test_wallet_http_context_fault_uses_pinned_regtest_name_then_reconciles(self):
        raw = query()
        upstream = Mock(side_effect=relay)
        with history.HistoryService("127.0.0.1:1", "unavailable", relay=upstream) as service:
            header, body = wallet_http(service.address, raw)
            self.assertTrue(header.startswith(b"HTTP/1.0 200 "))
            self.assertIn(f"Content-Length: {len(body)}".encode(), header)
            self.assertEqual(body, history.error())
            self.assertTrue(service.events[0]["fault_applied"])
            self.assertEqual(service.events[0]["request_sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(service.events[0]["upstream_sha256"], hashlib.sha256(relay(raw)).hexdigest())
            self.assertEqual(service.events[0]["response_sha256"], hashlib.sha256(body).hexdigest())
            service.clear()
            header, body = wallet_http(service.address, raw)
            self.assertTrue(header.startswith(b"HTTP/1.0 200 "))
            self.assertEqual(body, relay(raw))
            self.assertEqual([event["fault_applied"] for event in service.events], [True, False])
            self.assertEqual(service.count, 2)
            self.assertEqual([call.args for call in upstream.call_args_list], [(raw,), (raw,)])

    def test_wallet_http_invalid_context_and_real_upstream_error_do_not_count_as_faults(self):
        for chain in ("main", "regtest", "", None, True):
            with self.subTest(chain=chain), history.HistoryService("127.0.0.1:1", "unavailable",
                    relay=lambda _: reply({"chain": chain, "blocks": 111, "bestblockhash": BLOCK})) as service:
                header, _ = wallet_http(service.address, query())
                self.assertTrue(header.startswith(b"HTTP/1.0 503 "))
                self.assertEqual(service.events, [])
        original = history.error(-8)
        with history.HistoryService("127.0.0.1:1", "unavailable", relay=lambda _: original) as service:
            header, body = wallet_http(service.address, query())
            self.assertTrue(header.startswith(b"HTTP/1.0 200 "))
            self.assertEqual(body, original)
            self.assertFalse(service.events[0]["fault_applied"])

    def test_context_missing_tip_and_pruned_faults_clear_to_original_response(self):
        cases = [("unavailable", query(), None), ("missing-hash", query("getblockhash", [111]), None),
                 ("inconsistent-tip", query(), "01" + "11" * 31),
                 ("pruned", query("getblock", [BLOCK, 0]), None)]
        for mode, raw, expected in cases:
            with self.subTest(mode=mode), history.HistoryService("127.0.0.1:1", mode,
                    height=111, block_hash=BLOCK, relay=relay) as service:
                changed = json.loads(service.respond(raw))
                self.assertTrue(service.events[-1]["fault_applied"])
                if mode == "inconsistent-tip":
                    self.assertEqual(changed["result"]["bestblockhash"], expected)
                else:
                    self.assertIsNone(changed["result"])
                service.clear()
                self.assertEqual(service.respond(raw), relay(raw))
                self.assertFalse(service.events[-1]["fault_applied"])

    def test_block_fault_preserves_size_changes_only_header_and_requires_target(self):
        with history.HistoryService("127.0.0.1:1", "inconsistent-block", block_hash=BLOCK, relay=relay) as service:
            other = query("getblock", ["22" * 32, 0])
            self.assertEqual(service.respond(other), relay(other))
            raw = bytes.fromhex(json.loads(service.respond(query("getblock", [BLOCK, 0])))["result"])
            self.assertEqual(raw, b"\0" * 4 + b"\1" + b"\0" * 95)
            self.assertEqual([e["fault_applied"] for e in service.events], [False, True])

    def test_missing_hash_only_changes_requested_height(self):
        with history.HistoryService("127.0.0.1:1", "missing-hash", height=111, relay=relay) as service:
            raw = query("getblockhash", [0])
            self.assertEqual(service.respond(raw), relay(raw))
            self.assertFalse(service.events[-1]["fault_applied"])

    def test_real_upstream_error_or_invalid_result_cannot_count_as_injected_fault(self):
        original = history.error(-8)
        with history.HistoryService("127.0.0.1:1", "unavailable", relay=lambda _: original) as service:
            self.assertEqual(service.respond(query()), original)
            self.assertFalse(service.events[-1]["fault_applied"])
        for mode, raw in (("unavailable", query()), ("missing-hash", query("getblockhash", [0])),
                          ("pruned", query("getblock", [BLOCK, 0]))):
            with self.subTest(mode=mode), history.HistoryService("127.0.0.1:1", mode,
                    block_hash=BLOCK, relay=lambda _: reply(None)) as service:
                with self.assertRaises(AcceptanceError):
                    service.respond(raw)
                self.assertEqual(service.events, [])

    def test_request_response_count_and_deadline_bounds(self):
        with history.HistoryService("127.0.0.1:1", relay=relay) as service:
            with self.assertRaisesRegex(AcceptanceError, "request_json"):
                service.respond(b"x" * (history.MAX_REQUEST + 1))
            service.count = history.MAX_REQUESTS
            with self.assertRaisesRegex(AcceptanceError, "request_count"):
                service.respond(query())
            service.count, service.deadline = 0, 0
            with self.assertRaisesRegex(AcceptanceError, "service_deadline"):
                service.respond(query())
        with history.HistoryService("127.0.0.1:1", relay=lambda _: b"x" * 65) as service, \
                patch.object(history, "MAX_RESPONSE", 64):
            with self.assertRaisesRegex(AcceptanceError, "upstream_size"):
                service.respond(query())
            self.assertEqual(service.events, [])

    def test_http_path_framing_readonly_and_shutdown_are_bounded(self):
        upstream = Mock(side_effect=relay)
        with history.HistoryService("127.0.0.1:1", relay=upstream) as service:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(urllib.request.Request("http://" + service.address, query()), timeout=2) as response:
                self.assertEqual(response.read(), relay(query()))
            with self.assertRaises(urllib.error.HTTPError) as error:
                opener.open(urllib.request.Request("http://" + service.address, query("sendrawtransaction", ["00"])), timeout=2)
            self.assertEqual(error.exception.code, 503)
            error.exception.close()
            malformed = [b"Content-Length: 2\r\nContent-Length: 2\r\n", b"Content-Length: 4097\r\n",
                         b"Content-Length: 2\r\nTransfer-Encoding: chunked\r\n"]
            for headers in malformed:
                with socket.create_connection(("127.0.0.1", int(service.address.split(":")[1])), timeout=2) as client:
                    client.sendall(b"POST / HTTP/1.0\r\n" + headers + b"\r\n{}")
                    self.assertIn(b"503", client.recv(1024))
            self.assertEqual(upstream.call_count, 1)
            self.assertEqual(service.count, 5)
        self.assertFalse(service.thread.is_alive())

    def test_forward_uses_unproxied_bounded_reads_and_a_body_deadline(self):
        response = Mock(status=200)
        response.read1.side_effect = [b"abc", b""]
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        service = history.HistoryService("127.0.0.1:1", relay=relay)
        service.opener.open = Mock(return_value=response)
        self.assertEqual(service.forward(query()), b"abc")
        self.assertEqual(service.opener.open.call_args.kwargs["timeout"], 5)
        self.assertEqual(response.read1.call_args.args, (65536,))
        with patch.object(history.time, "monotonic", side_effect=[0, 6]):
            with self.assertRaisesRegex(AcceptanceError, "upstream_deadline"):
                service.forward(query())


if __name__ == "__main__":
    unittest.main()
