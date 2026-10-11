"""Causal source-only ledger and capture mocks; no daemon, signer or CLI starts."""
from contextlib import ExitStack
from copy import deepcopy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from common import AcceptanceError, read_json
import nodes
import observation_controls as capture
import observations
import transparent_controls
from test_transparent_controls import FakeNode, Ledger, host_shape, identity

TOKEN = "0123456789abcdef0123456789abcdef"
SOURCE = {"mock_source": "source-only-test"}


class ObservedLedger(Ledger):
    def __init__(self):
        super().__init__()
        self.no_capture = self.no_rollback = self.no_reactivation = False
        self.late_subject = self.wrong_witness = self.unrelated_rejection = False
        self.omit_saved_entry = self.dirty_shutdown = False
        self.proposal_counts = {}
        self.authorizations, self.pid = 0, 40

    def attach(self, binary, directory, miner, *, observation_token):
        assert observation_token == TOKEN
        # A network that drops the opt-in token runs nodes without any capture.
        token = None if self.no_capture else observation_token
        self.nodes = [ObservedNode(self, index, binary, directory, label, miner, token)
                      for index, label in enumerate(("node-a", "node-b"))]
        self.a, self.b = self.nodes
        for node in self.nodes:
            node.start()
        return self

    def launch(self, command, *, stdout, stderr, env):
        """The only process fake: actual ManagedNode start, stop and capture run."""
        node = next(node for node in self.nodes
                    if command == [str(node.binary), "--config", str(node.config), "start"])
        assert stderr == nodes.subprocess.STDOUT
        assert env.get(observations.ENVIRONMENT) == node.observation_token
        node.sequence = 0
        stdout.write(b"mock startup\n")
        stdout.flush()
        self.pid += 1
        process = Mock(pid=self.pid)
        process.poll.return_value = None
        process.wait.return_value = 1 if self.dirty_shutdown else 0
        process.terminate.side_effect = node.shutdown_entries
        return process

    def __exit__(self, *args):
        nodes.Network.__exit__(self, *args)
        self.closed = True

    def restart(self):
        super().restart()
        return nodes.Network.restart(self)

    def metadata(self):
        assert self.closed
        return nodes.Network.metadata(self)

    def mine(self, count=1):
        if self.no_reactivation and self.height == 108 and self.restarts:
            return []
        return super().mine(count)

    def slh(self, _args, keys, _producer, txid, index, _expiry, case):
        assert keys == {self.public: "public mock key"}
        assert capture.zat(self.output(txid, index)["value"]) == 3_000_000
        _, script = capture.policy([self.public], 1)
        return host_shape(self.tx(case, [{"value_zat": 2_000_000, "script_hex": script}], [(txid, index)]),
                          "txid", "auth_digest")

    def host(self, binary, operation, **fields):
        if operation == "classical-spend":
            self.calls.append((operation, deepcopy(fields)))
            recipe = fields["recipe"]
            parent = self.transactions[recipe["parent_hex"]]
            name = "classical-positive" if parent["name"] == "funding" else "classical-funding"
            index = recipe["output_index"]
            outputs = deepcopy(recipe["outputs"])
            outputs.append({"value_zat": parent["outputs"][index]["value_zat"]
                - sum(row["value_zat"] for row in outputs) - recipe["fee_zat"],
                "script_hex": self.classical_script})
            return host_shape(self.tx(name, outputs, [(parent["txid"], index)]), "auth_digest")
        # Authorization controls have unique serialized variants for every
        # original, just as the host does. Preserve pre-existing source fixtures.
        if operation == "control-authorization":
            original = self.transactions[fields["recipe"]["transaction_hex"]]
            prior = dict(self.transactions)
            result = super().host(binary, operation, **fields)
            row = self.transactions.pop(result["transaction_hex"])
            self.transactions.update(prior)
            raw = (row["name"] + ":" + original["name"]).encode().hex()
            result.update(transaction_hex=raw, transaction_sha256=observations.digest(bytes.fromhex(raw)))
            # The first four calls are authorization_variants; later ones are identity witnesses.
            self.authorizations += 1
            if self.wrong_witness and self.authorizations > 4:
                result["positive_auth_digest"] = identity("wrong")
            self.transactions[raw] = dict(row, **result)
        else:
            result = super().host(binary, operation, **fields)
        if operation == "control-block":
            old = self.blocks.pop(result["block_hex"])
            raw = repr((fields["recipe"], result)).encode().hex()
            result.update(block_hex=raw, block_hash=identity(raw))
            self.blocks[raw] = dict(old, **result)
        return result


class ObservedNode(FakeNode, nodes.ManagedNode):
    def __init__(self, ledger, index, binary, directory, label, miner, token):
        nodes.ManagedNode.__init__(self, binary, directory, label, miner, 18000 + index,
                                   observation_token=token)
        FakeNode.__init__(self, ledger)
        self.index, self.sequence = index, 0

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

    def shutdown_entries(self):
        if self.state.late_subject:
            tx = next(tx for tx in self.state.transactions.values() if tx["name"] == "classical-on-slh")
            self.entry(dict(tx, name="saved"))

    def response(self, method, *args):
        if method == "getblockcount":
            return {"result": self.state.height}
        if method == "sendrawtransaction":
            tx = self.state.transactions[args[0]]
            self.entry(tx)
            if self.state.unrelated_rejection and tx["reason"]:
                return {"error": {"code": -25, "message": "missing inputs"}}
        return super().response(method, *args)

    def rpc(self, method, *args):
        assert method != "decoderawtransaction", "pinned node has no decoderawtransaction RPC"
        if method == "getblock" and args[1] == 1:
            block = self.state.blocks[args[0]]
            if block["block_hex"].startswith("generated-"):
                return {"tx": [self.state.transactions[raw]["txid"] for raw in block["raws"]]}
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
            stack.enter_context(patch.object(transparent_controls, "restart_with_backups",
                                             side_effect=state.restart_backed))
            stack.enter_context(patch.object(observations, "source_state", return_value=SOURCE))
            stack.enter_context(patch.object(observations, "validate_build"))
            stack.enter_context(patch.object(nodes.subprocess, "Popen", side_effect=state.launch))
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
        self.assertEqual([len(hashes) for hashes in state.backup_checks], [1, 3])
        self.assertEqual(receipt["reorg"]["backup"]["excluded_block_hashes"], state.backup_checks[0])
        self.assertEqual(receipt["rollback"]["backup"]["excluded_block_hashes"], state.backup_checks[1])
        self.assertEqual(receipt["final_tip"]["height"], 110)
        self.assertEqual(len(reports), 12)
        self.assertEqual([len(node.observation_captures) for node in state.nodes], [3, 3])
        self.assertEqual([row["shutdown_exit_codes"] for row in receipt["nodes"]], [[0, 0, 0]] * 2)
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
        versions = [(operation, fields["recipe"]["transaction_version"]) for operation, fields in state.calls
                    if operation in ("control-funding", "classical-spend", "mixed-prepare", "mixed-assemble")]
        self.assertEqual(sorted(versions), [("classical-spend", 6)] * 2 + [("control-funding", 6)]
                         + [("mixed-assemble", 6)] * 6 + [("mixed-prepare", 6)] * 6)

    def test_rollback_receipt_requires_exact_prior_height_and_hash(self):
        for field, value in (("height", 0), ("hash", identity("wrong-reopened-tip"))):
            def changed(network, block, height):
                return dict(transparent_controls.rollback(network, block, height), **{field: value})
            with self.subTest(field=field), self.assertRaisesRegex(AcceptanceError, "capture_reorg_no_rollback"):
                state = ObservedLedger()
                self.run_flow(state, lambda stack: stack.enter_context(
                    patch.object(capture, "rollback", side_effect=changed)))
            self.assertEqual(state.restarts, [110])

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
                ("dirty_shutdown", "node_shutdown_failed")):
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
                ("wrong_positive_auth", "capture_replay_wrong_bytes"),
                ("corrupt_positive_auth", "transparent_positive_identity_changed"),
                ("wrong_witness", "capture_fixture_identity"),
                ("change_on_reject", "capture_control_changed_state")):
            with self.subTest(field=field), self.assertRaisesRegex(AcceptanceError, error):
                state = ObservedLedger()
                setattr(state, field, True)
                self.run_flow(state)
        # The positive proposals succeed; the funding disappears before the first negative.
        state = ObservedLedger()
        original = capture.CaptureControls.reject
        def parent_removed(control, *args):
            state.missing_parent = True
            return original(control, *args)
        with self.assertRaisesRegex(AcceptanceError, "capture_parent_missing"):
            self.run_flow(state, lambda stack: stack.enter_context(
                patch.object(capture.CaptureControls, "reject", parent_removed)))
        self.assertEqual(state.relays, [])

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

    def test_identity_uses_exact_host_original_and_no_invented_rpc(self):
        raw, changed = "00", "01"
        tx = {"transaction_hex": raw, "transaction_sha256": observations.digest(bytes.fromhex(raw)),
              "txid": "11" * 32, "outputs": []}
        witness = {"transaction_hex": changed, "transaction_sha256": observations.digest(bytes.fromhex(changed)),
            "positive_transaction_sha256": tx["transaction_sha256"], "txid": tx["txid"],
            "auth_digest": "22" * 32, "positive_auth_digest": "33" * 32, "outputs": []}
        for field, bad in (("positive_transaction_sha256", "00" * 32), ("txid", "44" * 32),
                           ("outputs", [{}]), ("transaction_sha256", "00" * 32)):
            with self.subTest(field=field), patch.object(capture, "host_call", return_value=dict(witness, **{field: bad})), \
                    self.assertRaises(AcceptanceError):
                capture.identify(Path("unused-host"), dict(tx), variant="corrupt-slh")
        with patch.object(capture, "host_call", return_value=witness) as call:
            result = dict(tx)
            capture.identify(Path("unused-host"), result, variant="corrupt-slh", input_index=1)
            self.assertEqual(result["auth_digest"], witness["positive_auth_digest"])
            self.assertEqual(call.call_args.kwargs["recipe"]["transaction_hex"], raw)
            self.assertEqual(call.call_args.kwargs["recipe"]["input_index"], 1)

    def test_identity_refuses_modified_raw_bytes_before_decoding(self):
        tx = {"transaction_hex": "00", "transaction_sha256": "00" * 32}
        with self.assertRaisesRegex(AcceptanceError, "capture_transaction_hash"):
            capture.identify(Path("unused-host"), tx)


if __name__ == "__main__":
    unittest.main()
