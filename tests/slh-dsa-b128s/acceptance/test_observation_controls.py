"""Causal source-only ledger and capture mocks; no daemon, signer or CLI starts."""
from contextlib import ExitStack
from copy import deepcopy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from common import AcceptanceError, read_json, sha256, write_json
import observation_controls as capture
import observations
import transparent_controls
from test_transparent_controls import FakeNode, Ledger, identity

TOKEN = "0123456789abcdef0123456789abcdef"
SOURCE = {"mock_source": "source-only-test"}


class ObservedLedger(Ledger):
    def __init__(self):
        super().__init__()
        self.nodes = [ObservedNode(self, index) for index in range(2)]
        self.a, self.b = self.nodes
        self.no_capture = self.no_rollback = self.no_reactivation = False
        self.late_subject = self.wrong_identity = self.unrelated_rejection = False
        self.omit_saved_entry = self.dirty_shutdown = False
        self.proposal_counts = {}

    def attach(self, binary, directory, _miner, *, observation_token):
        assert observation_token == TOKEN
        for node in self.nodes:
            node.binary = binary
            node.directory = directory / f"node-{node.index}"
            node.directory.mkdir()
            node.config = node.directory / "node.toml"
            node.config.write_text("mock Regtest enabled only")
            (node.directory / "node.log").write_bytes(b"")
            node.start()
        return self

    def __exit__(self, *_):
        for node in self.nodes:
            node.stop()
        self.closed = True

    def restart(self):
        result = super().restart()
        for node in self.nodes:
            node.stop()
            node.start()
        return result

    def mine(self, count=1):
        if self.no_reactivation and self.height == 108 and self.restarts:
            return []
        return super().mine(count)

    def slh(self, _args, keys, _producer, txid, index, _expiry, case):
        assert keys == {self.public: "public mock key"}
        assert capture.zat(self.output(txid, index)["value"]) == 3_000_000
        _, script = capture.policy([self.public], 1)
        return self.tx(case, [{"value_zat": 2_000_000, "script_hex": script}], [(txid, index)])

    def host(self, binary, operation, **fields):
        if operation == "classical-spend":
            recipe = fields["recipe"]
            parent = self.transactions[recipe["parent_hex"]]
            name = "classical-positive" if parent["name"] == "funding" else "classical-funding"
            index = recipe["output_index"]
            outputs = deepcopy(recipe["outputs"])
            outputs.append({"value_zat": parent["outputs"][index]["value_zat"]
                - sum(row["value_zat"] for row in outputs) - recipe["fee_zat"],
                "script_hex": self.classical_script})
            return self.tx(name, outputs, [(parent["txid"], index)])
        result = super().host(binary, operation, **fields)
        if operation == "control-block":
            old = self.blocks.pop(result["block_hex"])
            raw = repr((fields["recipe"], result)).encode().hex()
            result.update(block_hex=raw, block_hash=identity(raw))
            self.blocks[raw] = dict(old, **result)
        return result


class ObservedNode(FakeNode):
    def __init__(self, ledger, index):
        super().__init__(ledger)
        self.index, self.process, self.sequence = index, None, 0
        self.stops, self.observation_captures = [], []

    def start(self):
        self.sequence = 0
        self.process = SimpleNamespace(pid=40 + self.index + 2 * len(self.stops))
        self.capture = observations.begin(self.directory / "node.log", self.binary, self.config, TOKEN)
        with (self.directory / "node.log").open("ab") as output:
            output.write(b"mock startup\n")

    def entry(self, tx):
        if tx["name"] not in ("saved", "zero-before", "zero-after", "cache-before", "cache-after", "corrupt-slh"):
            return
        if self.state.omit_saved_entry and tx["name"] == "saved":
            return
        self.sequence += 1
        raw = (f"slh_primitive_v1 token={TOKEN} pid={self.process.pid} seq={self.sequence} "
            f'txid={tx["txid"]} auth_digest={tx["auth_digest"]} input=0 check=0 '
            "backend=portable-rust contract=slh-dsa-b-128s-exp-v1\n").encode()
        with (self.directory / "node.log").open("ab") as output:
            output.write(raw)

    def stop(self):
        if self.process is None:
            return
        if self.state.late_subject:
            tx = next(tx for tx in self.state.transactions.values() if tx["name"] == "classical-on-slh")
            self.entry(dict(tx, name="saved"))
        status = 1 if self.state.dirty_shutdown else 0
        if not self.state.no_capture:
            record = observations.finish(self.capture, self.directory / "node.log", self.binary,
                                         self.config, self.process.pid, status)
            name = f"observation-{len(self.observation_captures)}.json"
            path = write_json(self.directory / name, record)
            self.observation_captures.append({"file": name, "sha256": sha256(path)})
        self.stops.append(status)
        self.process = None

    def response(self, method, *args):
        if method == "sendrawtransaction":
            tx = self.state.transactions[args[0]]
            self.entry(tx)
            if self.state.unrelated_rejection and tx["reason"]:
                return {"error": {"code": -25, "message": "missing inputs"}}
        return super().response(method, *args)

    def rpc(self, method, *args):
        if method == "getblock" and args[1] == 1:
            block = self.state.blocks[args[0]]
            if block["block_hex"].startswith("generated-"):
                return {"tx": [self.state.transactions[raw]["txid"] for raw in block["raws"]]}
        if method == "decoderawtransaction":
            tx = self.state.transactions[args[0]]
            return {"txid": identity("wrong") if self.state.wrong_identity else tx["txid"],
                    "authdigest": tx["auth_digest"]}
        if method == "invalidateblock" and self.state.no_rollback:
            return None
        if method == "submitblock" or method == "getblocktemplate" and args:
            raw = args[0] if method == "submitblock" else args[0]["data"]
            block = self.state.blocks[raw]
            for raw_tx in block["raws"]:
                tx = self.state.transactions[raw_tx]
                self.entry(tx)
                if method == "getblocktemplate":
                    key = (self.index, len(self.stops), tx["name"], raw)
                    self.state.proposal_counts[key] = self.state.proposal_counts.get(key, 0) + 1
        return super().rpc(method, *args)


class CaptureDriverTests(unittest.TestCase):
    def run_flow(self, state, inject=None, version=5):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory)
            binary = root / "public-node"
            binary.write_bytes(b"not executable; source-only mock")
            args = SimpleNamespace(host=Path("public-host"), signer=Path("public-signer"),
                node=binary, root=Path("product"), version=version, token=TOKEN)
            receipt = {"builds": {"node": {"source": SOURCE}}}
            for name, replacement in {"Network": state.attach, "host_call": state.host,
                    "signer_call": state.signer, "authenticate_coinbase": state.coinbase,
                    "single_artifact": state.slh, "producer_identity": lambda *_: ({}, {})}.items():
                stack.enter_context(patch.object(capture, name, side_effect=replacement))
            stack.enter_context(patch.object(transparent_controls, "host_call", side_effect=state.host))
            stack.enter_context(patch.object(transparent_controls, "signer_call", side_effect=state.signer))
            stack.enter_context(patch.object(observations, "source_state", return_value=SOURCE))
            stack.enter_context(patch.object(observations, "validate_build"))
            # Fail immediately in a mock on a no-op lifecycle rather than waiting a minute.
            def wait(action, reason, *_):
                capture.require(action(), reason)
            stack.enter_context(patch.object(transparent_controls, "wait_for", side_effect=wait))
            if inject:
                inject(stack)
            capture.execute(args, root, receipt)
            reports = [read_json(root / item["path"]) for item in receipt["observations"]]
            return receipt, reports, json.loads((root / "attempts.json").read_bytes())

    def test_funded_brackets_captures_and_exact_saved_lifecycle(self):
        state = ObservedLedger()
        receipt, reports, attempts = self.run_flow(state)
        self.assertEqual(state.restarts, [110, 108])
        self.assertEqual(receipt["final_tip"]["height"], 110)
        self.assertEqual(len(reports), 12)
        self.assertEqual([len(node.observation_captures) for node in state.nodes], [3, 3])
        self.assertTrue(all(row["complete"] for row in attempts))
        for stage in receipt["stages"]:
            self.assertEqual(len(stage["windows"][0]["subjects"]), 8)
            self.assertEqual(len(stage["replay"]["mined_blocks"]), 1)
            self.assertEqual(set(stage["replay"]["initial_states"].values()), {"absent"})
            ids = [stage["windows"][0][name] for name in ("before", "after")]
            self.assertNotEqual(ids[0], ids[1])
        for report in reports:
            if report["window"]["window_entries"] == 0:
                self.assertTrue(all(row["process_observed_entries"] == 0
                                    for row in report["window"]["subjects"]))
            else:
                first, changed = report["window"]["subjects"]
                self.assertEqual(first["txid"], changed["txid"])
                self.assertNotEqual(first["auth_digest"], changed["auth_digest"])
                self.assertEqual(first["window_observed_entries"], 3)
                self.assertGreaterEqual(first["process_observed_entries"], first["window_observed_entries"])
        saved = [(key, count) for key, count in state.proposal_counts.items() if key[2] == "saved"]
        self.assertEqual(len(saved), 6)
        self.assertTrue(all(count == 3 for _, count in saved))
        self.assertFalse(receipt["claims"]["queue_drain_barrier"])

    def test_version_six_uses_the_same_funded_lifecycle(self):
        state = ObservedLedger()
        receipt, reports, _ = self.run_flow(state, version=6)
        self.assertEqual(len(reports), 12)
        self.assertEqual(receipt["final_tip"]["height"], 110)
        self.assertTrue(all(recipe["transaction_version"] == 6 for recipe in state.mixed_recipes))

    def test_missing_subject_manifest_and_noop_analysis_cannot_complete(self):
        original = capture.mixed_artifacts
        with self.assertRaisesRegex(AcceptanceError, "capture_mixed_subject_manifest"):
            self.run_flow(ObservedLedger(), lambda stack: stack.enter_context(
                patch.object(capture, "mixed_artifacts", side_effect=lambda *args: original(*args)[:-1])))
        with self.assertRaisesRegex(AcceptanceError, "capture_reports_missing"):
            self.run_flow(ObservedLedger(), lambda stack: stack.enter_context(
                patch.object(capture, "sealed_reports", return_value=[])))

    def test_noop_subject_operation_or_repeat_cannot_complete(self):
        for method in ("reject", "proposal"):
            original = getattr(capture.CaptureControls, method)
            def skipped(self, label, *args, _original=original, **kwargs):
                if label.endswith("-structural") or label.endswith("-saved-repeat"):
                    return {"state_unchanged": True}
                return _original(self, label, *args, **kwargs)
            with self.subTest(method=method), self.assertRaisesRegex(AcceptanceError, "capture_subject_not_attempted"):
                self.run_flow(ObservedLedger(), lambda stack: stack.enter_context(
                    patch.object(capture.CaptureControls, method, skipped)))

    def test_missing_capture_and_late_outside_window_entries_cannot_complete(self):
        for field, error in (("no_capture", "capture_missing_closed_process"),
                ("late_subject", "capture_zero_work_failed"),
                ("omit_saved_entry", "capture_revalidation_not_observed"),
                ("dirty_shutdown", "observation_clean_shutdown")):
            with self.subTest(field=field), self.assertRaisesRegex(AcceptanceError, error):
                state = ObservedLedger()
                setattr(state, field, True)
                self.run_flow(state)

    def test_noop_rollback_reactivation_and_retry_cannot_complete(self):
        for field, error in (("no_rollback", "transparent_rollback_tip"),
                             ("no_reactivation", "capture_no_reactivation")):
            with self.subTest(field=field), self.assertRaisesRegex(AcceptanceError, error):
                state = ObservedLedger()
                setattr(state, field, True)
                self.run_flow(state)
        with self.assertRaisesRegex(AcceptanceError, "capture_replay_no_new_block"):
            self.run_flow(ObservedLedger(), lambda stack: stack.enter_context(
                patch.object(capture, "reconcile_saved", return_value={"mined_blocks": []})))

    def test_unrelated_failure_missing_parent_and_wrong_identity_cannot_complete(self):
        for field, error in (("unrelated_rejection", "transparent_wrong_relay_rejection"),
                ("wrong_identity", "capture_fixture_identity"),
                ("missing_parent", "authenticated_funding_output"),
                ("change_on_reject", "capture_control_changed_state")):
            with self.subTest(field=field), self.assertRaisesRegex(AcceptanceError, error):
                state = ObservedLedger()
                setattr(state, field, True)
                self.run_flow(state)

    def test_attempt_receipt_retains_failure_before_rpc_result(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = capture.Attempts(Path(directory) / "attempts.json")
            tx = {"txid": "11" * 32, "auth_digest": "22" * 32, "transaction_sha256": "33" * 32}
            def failure():
                raise AcceptanceError("test_rpc_failure")
            with self.assertRaisesRegex(AcceptanceError, "test_rpc_failure"):
                ledger.call("subject", 0, "proposal", tx, failure)
            row = read_json(ledger.path)[0]
            self.assertFalse(row["complete"])
            self.assertEqual(row["failure"], "test_rpc_failure")
            self.assertEqual(row["identity"], capture.transaction_identity(tx))

    def test_identity_refuses_modified_raw_bytes_before_decoding(self):
        tx = {"transaction_hex": "00", "transaction_sha256": "00" * 32}
        with self.assertRaisesRegex(AcceptanceError, "capture_transaction_hash"):
            capture.identify([], tx)


if __name__ == "__main__":
    unittest.main()
