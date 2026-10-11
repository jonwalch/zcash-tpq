"""Offline startup readiness controls; process and HTTP interfaces are mocked."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import urllib.error

import common
import nodes


# Exact public response bytes reconstructed from the failed startup RPC hash.
EMPTY_STATE = b'{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"No blocks in state"}}'


def height(value):
    return json.dumps({"jsonrpc": "2.0", "id": 1, "result": value}).encode()


class StartupTests(unittest.TestCase):
    @contextlib.contextmanager
    def node(self, replies, *, polls=None):
        with tempfile.TemporaryDirectory() as temporary:
            node = object.__new__(nodes.ManagedNode)
            node.directory = Path(temporary)
            node.config = node.directory / "node.toml"
            node.binary = Path("never-executed-zakurad")
            node.process, node.log, node.observation_token = None, None, None
            events = io.BytesIO()
            common.Node.__init__(node, "127.0.0.1:12345", events)
            process = Mock()
            process.poll = Mock(side_effect=polls) if polls is not None else Mock(return_value=None)
            sequence = iter(replies)

            def response(_request, *, timeout):
                self.assertEqual(timeout, 45)
                value = next(sequence)
                if isinstance(value, Exception):
                    raise value
                return io.BytesIO(value)

            with patch.object(nodes.subprocess, "Popen", return_value=process) as launch, \
                    patch.object(node.opener, "open", side_effect=response) as rpc, \
                    patch.object(common.time, "sleep") as sleep, \
                    patch.object(nodes, "wait_for", wraps=common.wait_for) as wait:
                try:
                    yield node, events, launch, rpc, sleep, wait
                finally:
                    if node.log is not None:
                        node.log.close()

    def test_empty_state_retries_then_genesis_is_ready_and_both_responses_are_hashed(self):
        with self.node([EMPTY_STATE, height(0)]) as (node, events, launch, rpc, sleep, wait):
            node.start()
            self.assertEqual(rpc.call_count, 2)
            launch.assert_called_once()
            sleep.assert_called_once_with(0.1)
            self.assertEqual(wait.call_args.args[1:], ("node_startup_timeout", 60))
            records = [json.loads(line) for line in events.getvalue().splitlines()]
            self.assertEqual([row["method"] for row in records], ["getblockcount"] * 2)
            self.assertEqual(records[0]["response_sha256"],
                             "0e4bedf53fb73b1f6d161c7565bc788e6bb869ac90fd3e3485f2d4eb67329a86")
            self.assertEqual(records[0]["request_sha256"],
                             "6aea8a571afd270cba5cd926ff41a80b6428e11298ac93cf1e373aa36293d2e2")
            self.assertEqual(records[1]["response_sha256"], hashlib.sha256(height(0)).hexdigest())

    def test_healthy_heights_need_one_request_and_no_retry(self):
        for value in (0, 1, 113, 1114):
            with self.subTest(height=value), self.node([height(value)]) as state:
                node, _, launch, rpc, sleep, _ = state
                node.start()
                launch.assert_called_once()
                rpc.assert_called_once()
                sleep.assert_not_called()

    def test_existing_transport_startup_retries_are_preserved(self):
        for error in (urllib.error.URLError("not listening"), TimeoutError(), ConnectionError()):
            with self.subTest(error=type(error).__name__), self.node([error, height(0)]) as state:
                node, events, _, rpc, sleep, _ = state
                node.start()
                self.assertEqual(rpc.call_count, 2)
                sleep.assert_called_once_with(0.1)
                self.assertEqual(len(events.getvalue().splitlines()), 1)

    def test_other_rpc_errors_and_inconsistent_empty_state_do_not_retry(self):
        errors = [
            {"code": -28, "message": "Loading block index"},
            {"code": -1, "message": "Database unavailable"},
            {"code": -2, "message": "No blocks in state"},
            {"code": -1.0, "message": "No blocks in state"},
            {"code": "-1", "message": "No blocks in state"},
            {"code": True, "message": "No blocks in state"},
            {"code": -1, "message": "No blocks in state", "data": None},
            "No blocks in state",
        ]
        replies = [{"jsonrpc": "2.0", "id": 1, "error": error} for error in errors]
        replies.append({**json.loads(EMPTY_STATE), "result": 0})
        for reply in replies:
            with self.subTest(reply=reply), self.node([json.dumps(reply).encode()]) as state:
                node, _, _, rpc, sleep, _ = state
                with self.assertRaisesRegex(common.AcceptanceError, "^rpc_rejected_getblockcount$"):
                    node.start()
                rpc.assert_called_once()
                sleep.assert_not_called()

    def test_invalid_height_is_not_readiness(self):
        for value in (True, False, None, -1, 0.0, "0", [], {}):
            with self.subTest(value=value), self.node([height(value)]) as state:
                node, _, _, rpc, sleep, _ = state
                with self.assertRaisesRegex(common.AcceptanceError, "^node_startup_height$"):
                    node.start()
                rpc.assert_called_once()
                sleep.assert_not_called()

    def test_response_schema_and_json_errors_do_not_retry(self):
        for reply, error in (
                (b'{"jsonrpc":"2.0","id":2,"result":0}', common.AcceptanceError),
                (b'[]', common.AcceptanceError),
                (b'{"jsonrpc":"2.0","id":1}', common.AcceptanceError),
                (b'{', json.JSONDecodeError)):
            with self.subTest(reply=reply), self.node([reply]) as state:
                node, _, _, rpc, sleep, _ = state
                with self.assertRaises(error):
                    node.start()
                rpc.assert_called_once()
                sleep.assert_not_called()

    def test_exited_process_fails_before_another_rpc(self):
        for polls, replies, count in (([1], [], 0), ([None, 1], [EMPTY_STATE], 1)):
            with self.subTest(polls=polls), self.node(replies, polls=polls) as state:
                node, _, _, rpc, _, _ = state
                with self.assertRaisesRegex(common.AcceptanceError, "^node_startup_failed$"):
                    node.start()
                self.assertEqual(rpc.call_count, count)

    def test_empty_state_keeps_original_timeout_without_rearming_it(self):
        with self.node([EMPTY_STATE] * 3) as state, \
                patch.object(common.time, "monotonic", side_effect=[0, 0, 30, 60]):
            node, _, _, rpc, sleep, wait = state
            with self.assertRaisesRegex(common.AcceptanceError, "^node_startup_timeout$"):
                node.start()
            self.assertEqual(rpc.call_count, 3)
            self.assertEqual(sleep.call_count, 2)
            wait.assert_called_once()
            self.assertEqual(wait.call_args.args[1:], ("node_startup_timeout", 60))

    def test_empty_state_still_rejects_outside_startup(self):
        with self.node([EMPTY_STATE]) as (node, _, launch, rpc, sleep, _):
            with self.assertRaisesRegex(common.AcceptanceError, "^rpc_rejected_getblockcount$"):
                node.rpc("getblockcount")
            rpc.assert_called_once()
            launch.assert_not_called()
            sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
