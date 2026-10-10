# SPDX-License-Identifier: MIT OR Apache-2.0
"""Offline diagnostic/capture controls; never start a real process or node."""
import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import common
import nodes
import observations as observed

TOKEN = "0123456789abcdef0123456789abcdef"
BEFORE = {"txid": "11" * 32, "auth_digest": "22" * 32}
AFTER = {"txid": "33" * 32, "auth_digest": "44" * 32}
SUBJECT = {"txid": "55" * 32, "auth_digest": "66" * 32}


def line(sequence, identity=SUBJECT, *, token=TOKEN, pid=42, index=0, ordinal=0):
    return (f"2026-10-09 INFO slh_primitive: slh_primitive_v1 token={token} pid={pid} "
            f"seq={sequence} txid={identity['txid']} auth_digest={identity['auth_digest']} "
            f"input={index} check={ordinal} backend=portable-rust contract={common.CONTRACT}\n").encode()


class ParserTests(unittest.TestCase):
    def parse(self, raw):
        return observed.parse_entries(raw, TOKEN, 42)

    def test_sequence_order_is_independent_of_concurrent_log_write_order(self):
        rows = self.parse(b"node initialized\n" + line(3, AFTER) + line(1, BEFORE) + line(2))
        self.assertEqual([row["sequence"] for row in rows], [1, 2, 3])
        result = observed.compare(rows, BEFORE, AFTER, [SUBJECT])
        self.assertEqual(result["subjects"][0]["window_observed_entries"], 1)
        self.assertEqual(result["subjects"][0]["window_coordinates"], [{"input_index": 0, "check_ordinal": 0}])

    def test_zero_requires_two_distinct_positive_controls(self):
        rows = self.parse(line(1, BEFORE) + line(2, AFTER))
        result = observed.compare(rows, BEFORE, AFTER, [SUBJECT])
        self.assertEqual(result["subjects"][0]["window_observed_entries"], 0)
        for bad in ([], self.parse(line(1, BEFORE)), self.parse(line(1, AFTER))):
            with self.assertRaises(common.AcceptanceError):
                observed.compare(bad, BEFORE, AFTER, [SUBJECT])
        for raw in (b"", b"node initialized\n", line(1, BEFORE)[:-1]):
            with self.assertRaises(common.AcceptanceError):
                self.parse(raw)

    def test_later_retry_is_reported_in_process_count_not_window_or_request_count(self):
        rows = self.parse(line(1, BEFORE) + line(2, AFTER) + line(3))
        result = observed.compare(rows, BEFORE, AFTER, [SUBJECT])
        self.assertEqual(result["subjects"][0]["window_observed_entries"], 0)
        self.assertEqual(result["subjects"][0]["process_observed_entries"], 1)
        with self.assertRaisesRegex(common.AcceptanceError, "positive_brackets"):
            observed.compare(self.parse(line(1, BEFORE) + line(2, AFTER) + line(3, BEFORE)),
                             BEFORE, AFTER, [SUBJECT])

    def test_missing_duplicate_zero_and_overflow_sequence_fail(self):
        for raw in (line(2), line(1) + line(3), line(1) + line(1), line(0), line(2**64)):
            with self.subTest(raw=raw[:90]), self.assertRaises(common.AcceptanceError):
                self.parse(raw)

    def test_exact_backend_contract_coordinates_and_identity(self):
        for pid in (True, 0, -1, 2**32, "42"):
            with self.assertRaises(common.AcceptanceError):
                observed.parse_entries(line(1), TOKEN, pid)
        changes = [line(1, token="00" * 16), line(1, pid=43), line(1, index=2**32),
                   line(1, ordinal=15), line(1).replace(b"portable-rust", b"other"),
                   line(1).replace(b"exp-v1", b"exp-v2"), line(1).replace(b"seq=1", b"seq=01"),
                   line(1).replace(b"input=0", b"input=true"), line(1).replace(b" check=0", b""),
                   line(1)[:-1] + b" extra=1\n", line(1).replace(b"txid=55", b"txid=FF")]
        for raw in changes:
            with self.subTest(raw=raw[:80]), self.assertRaises(common.AcceptanceError):
                self.parse(raw)

    def test_ansi_is_narrow_and_malformed_marker_is_not_ignored(self):
        self.assertEqual(len(self.parse(b"\x1b[32m" + line(1)[:-1] + b"\x1b[0m\n")), 1)
        for raw in (line(1).replace(b"token=", b"token=\xff"), b"\x1b[2J" + line(1),
                    line(1).replace(b"slh_primitive_v1", b"Xslh_primitive_v1"),
                    line(1)[:-1] + b" slh_primitive_v1\n"):
            with self.assertRaises(common.AcceptanceError):
                self.parse(raw)

    def test_fixed_log_line_and_event_bounds(self):
        with patch.object(observed, "MAX_LOG_BYTES", 10), self.assertRaises(common.AcceptanceError):
            self.parse(line(1))
        with patch.object(observed, "MAX_LINE_BYTES", 10), self.assertRaises(common.AcceptanceError):
            self.parse(line(1))
        with patch.object(observed, "MAX_EVENTS", 1), self.assertRaises(common.AcceptanceError):
            self.parse(line(1) + line(2))

    def test_subject_identities_are_exact_distinct_and_separate_from_controls(self):
        rows = self.parse(line(1, BEFORE) + line(2, AFTER))
        for subjects in ([], [SUBJECT, SUBJECT], [BEFORE], [{"txid": "11" * 32}],
                         [{**SUBJECT, "success": True}], [dict(txid=True, auth_digest="00" * 32)]):
            with self.assertRaises(common.AcceptanceError):
                observed.compare(rows, BEFORE, AFTER, subjects)
        with self.assertRaises(common.AcceptanceError):
            observed.compare(rows, BEFORE, BEFORE, [SUBJECT])


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.log, self.binary, self.config = [self.root / name for name in ("node.log", "node", "node.toml")]
        self.log.write_bytes(b"previous process ended\n")
        self.binary.write_bytes(b"mock binary never executed")
        self.config.write_text('network="Regtest"\n')
        self.source = {"source_commit": "aa" * 20, "source_inventory_sha256": "bb" * 32}
        patcher = patch.object(observed, "source_state", return_value=self.source)
        patcher.start()
        self.addCleanup(patcher.stop)

    def capture(self):
        start = observed.begin(self.log, self.binary, self.config, TOKEN)
        with self.log.open("ab") as stream:
            stream.write(line(1, BEFORE) + line(2) + line(3, AFTER))
        return observed.finish(start, self.log, self.binary, self.config, 42, 0)

    def analyze(self, capture):
        with patch.object(observed, "validate_build") as validate:
            result = observed.analyze(capture, self.log, self.binary, self.config,
                                      {"source": self.source}, BEFORE, AFTER, [SUBJECT])
            validate.assert_called_once_with({"source": self.source}, self.binary, "node-slh", runtime_required=True)
            return result

    def test_closed_capture_binds_bytes_inputs_and_limited_claims(self):
        capture = self.capture()
        result = self.analyze(capture)
        self.assertTrue(capture["complete"])
        self.assertEqual(result["process_observed_entries"], 3)
        self.assertTrue(all(value is False for value in result["claims"].values()))
        with self.log.open("ab") as stream:
            stream.write(b"another process begins later\n")
        self.assertEqual(self.analyze(capture), result)

    def test_prefix_replacement_truncation_and_mutation_refuse(self):
        original = self.log.read_bytes()
        for change in (lambda raw: b"changed" + raw, lambda raw: raw[:-1],
                       lambda raw: raw.replace(b"seq=2", b"seq=9")):
            self.log.write_bytes(original)
            capture = self.capture()
            self.log.write_bytes(change(self.log.read_bytes()))
            with self.assertRaises(common.AcceptanceError):
                self.analyze(capture)

    def test_source_binary_config_and_shutdown_changes_refuse(self):
        start = observed.begin(self.log, self.binary, self.config, TOKEN)
        with self.log.open("ab") as stream:
            stream.write(line(1))
        for status in (1, -9, None, False):
            with self.assertRaises(common.AcceptanceError):
                observed.finish(start, self.log, self.binary, self.config, 42, status)
        for target in (self.binary, self.config):
            original = target.read_bytes()
            target.write_bytes(original + b"changed")
            with self.assertRaises(common.AcceptanceError):
                observed.finish(start, self.log, self.binary, self.config, 42, 0)
            target.write_bytes(original)
        with patch.object(observed, "source_state", return_value={}):
            with self.assertRaises(common.AcceptanceError):
                observed.finish(start, self.log, self.binary, self.config, 42, 0)

    def test_rotated_symlink_missing_and_oversized_logs_fail(self):
        start = observed.begin(self.log, self.binary, self.config, TOKEN)
        old = self.root / "old.log"
        self.log.rename(old)
        self.log.write_bytes(old.read_bytes() + line(1))
        with self.assertRaisesRegex(common.AcceptanceError, "log_replaced"):
            observed.finish(start, self.log, self.binary, self.config, 42, 0)
        self.log.unlink()
        self.log.symlink_to(old)
        with self.assertRaises(common.AcceptanceError):
            observed.bounded_log(self.log)
        with self.assertRaises(FileNotFoundError):
            observed.bounded_log(self.root / "missing")
        with patch.object(observed, "MAX_LOG_BYTES", 2), self.assertRaises(common.AcceptanceError):
            observed.bounded_log(old)

    def test_exact_capture_schema_and_numbers(self):
        original = self.capture()
        changes = [dict(schema_version=True), dict(pid=True), dict(complete=False), dict(extra=0),
                   dict(start_offset=-1), dict(end_offset=2**32), dict(exit_code=False),
                   dict(token="1"), dict(log_sha256="x"), dict(source={})]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(common.AcceptanceError):
                self.analyze({**original, **change})
        missing = copy.deepcopy(original)
        del missing["scope"]
        with self.assertRaises(common.AcceptanceError):
            self.analyze(missing)


class NodePlumbingTests(unittest.TestCase):
    def test_capture_preparation_failure_closes_log_before_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            node = nodes.ManagedNode(root / "unused-node", root, "node-a", "miner", 1234,
                                     observation_token=TOKEN)
            with patch.object(observed, "begin", side_effect=common.AcceptanceError("test_failure")), \
                 patch.object(nodes.subprocess, "Popen") as launch:
                with self.assertRaisesRegex(common.AcceptanceError, "test_failure"):
                    node.start()
                launch.assert_not_called()
                self.assertTrue(node.log.closed)
                self.assertIsNone(node.process)
            node.close()

    def test_default_environment_strips_opt_in_and_token_is_exact(self):
        with patch.dict(os.environ, {observed.ENVIRONMENT: TOKEN}):
            self.assertNotIn(observed.ENVIRONMENT, observed.environment())
            self.assertEqual(observed.environment(TOKEN)[observed.ENVIRONMENT], TOKEN)
        for token in (True, "1", "A" * 32, "0" * 31, "0" * 33):
            with self.assertRaises(common.AcceptanceError):
                observed.environment(token)

    def test_node_opt_in_records_closed_process_and_leaves_default_unchanged(self):
        for token in (None, TOKEN):
            with self.subTest(token=token), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                binary = root / "mock-node"
                binary.write_bytes(b"never execute")
                node = nodes.ManagedNode(binary, root, "node-a", "public-miner", 1234,
                                         observation_token=token)
                node.response = Mock(return_value={"jsonrpc": "2.0", "id": 1, "result": 0})
                process = Mock(pid=42)
                process.poll.return_value = None
                process.wait.return_value = 0
                def fake_launch(*args, **kwargs):
                    if token:
                        self.assertEqual(kwargs["env"][observed.ENVIRONMENT], TOKEN)
                    else:
                        self.assertNotIn(observed.ENVIRONMENT, kwargs["env"])
                    kwargs["stdout"].write(b"ready\n" + (line(1, BEFORE) + line(2, AFTER) if token else b""))
                    kwargs["stdout"].flush()
                    return process
                with patch.object(nodes.subprocess, "Popen", side_effect=fake_launch), \
                     patch.object(nodes, "wait_for", side_effect=lambda ready, *_: ready()), \
                     patch.object(observed, "source_state", return_value={"mock": True}):
                    node.start()
                    node.stop()
                node.response.assert_called_once_with("getblockcount")
                self.assertEqual(node.stops, [0])
                self.assertEqual(len(node.observation_captures), int(token is not None))
                if token:
                    capture = common.read_json(node.directory / "observation-0.json")
                    self.assertEqual(capture["pid"], 42)
                    self.assertIn("slh_primitive=info", node.config.read_text())
                else:
                    self.assertNotIn("slh_primitive=info", node.config.read_text())
                node.close()


if __name__ == "__main__":
    unittest.main()
