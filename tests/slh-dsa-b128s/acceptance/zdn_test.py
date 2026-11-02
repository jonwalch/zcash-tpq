"""Offline coordinator tests. No PTY, signing, cloud, node, RPC or build."""
import copy
import hashlib
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

import zdn_flow as flow
from common import AcceptanceError, read_json, write_json


def h(value):
    return hashlib.sha256(value.encode()).hexdigest()


# Synthetic public inputs, not staged or validated by the Rust ZDN CLI.
CONFIG_YAML = "profile: devnet\nnode_count: 2\nblock_interval_seconds: 30\n"
SEMANTIC_CONFIG_SHA256 = h("synthetic ZDN Config::fingerprint")


class JourneyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.run = self.root / "run"
        self.count = 0
        pins = {}
        for role in flow.PIN_ROLES:
            path = self.root / role
            path.write_text(CONFIG_YAML if role == "config" else role)
            pins[role] = flow.reference(path)
        public = self.root / "public"
        public.mkdir()
        artifacts = {}
        for slot in flow.SLOTS:
            path = public / slot
            path.write_text(slot)
            if slot == "wallet-profile.json":
                path.write_bytes((self.root / "profile").read_bytes())
            artifacts[slot] = {key: value for key, value in flow.reference(path).items() if key != "path"}
        request = {"schema": "zdn-external-artifact-set/v1", "configSha256": SEMANTIC_CONFIG_SHA256,
                   "trust": {}, "compiled": {"nativeFingerprint": h("native"), "cargoFeatures": [flow.FEATURE]},
                   "image": {}, "build": None, "nodeCount": 2, "blockIntervalSeconds": 30,
                   "artifacts": artifacts}
        (self.root / "request").unlink()
        write_json(self.root / "request", request)
        pins["request"] = flow.reference(self.root / "request")
        self.plan = {"schema": flow.SCHEMA, "beta_sha256": flow.BETA_SHA256,
                     "binding": {"deployment_id": "aa000000-0000-4000-8000-000000000001",
                                 "request_sha256": pins["request"]["sha256"], "native_fingerprint": h("native")},
                     "pins": pins, "directory": str(public), "state_dir": str(self.root / "zdn-state"),
                     "profile_alias": "devnet", "launch": {"ami_id": "ami-test", "availability_zone": "test-1a",
                                                           "reward_address": "test-reward", "native_port": 18233},
                     "payments": {}}
        for phase, amount, sender, recipient in (("fund", 3_000_000, "seed", "alice"),
                                                ("pay5", 1_000_000, "alice", "bob"),
                                                ("pay6", 400_000, "bob", "alice"),
                                                ("pay-restored", 100_000, "alice", "bob")):
            self.plan["payments"][phase] = {"version": 6 if phase in {"pay6", "pay-restored"} else 5,
                                              "amount": amount, "fee": 21_600, "receiver_script": "5320" + h(recipient) + "c0",
                                              "sender": sender, "recipient": recipient}
        write_json(self.root / "plan-input.json", self.plan)
        self.plan_hash = flow.initialize(self.root / "plan-input.json", self.run)
        self.refs = [flow.reference(self.root / "prepare_receipt"), flow.reference(self.root / "build_receipt")]
        self.runner = Mock(return_value=SimpleNamespace(returncode=0))
        self.transactions = {}
        for phase in flow.PAYMENTS:
            path = self.root / (phase + ".bin")
            # Deliberately not a valid transaction: test only the coordinator's
            # public byte/version binding. No consensus/signature claim.
            path.write_bytes((self.plan["payments"][phase]["version"] | 0x80000000).to_bytes(4, "little")
                             + phase.encode())
            self.transactions[phase] = flow.reference(path)

    def payment(self, phase, completed):
        intent = self.plan["payments"][phase]
        previous = {"pay5": "fund", "pay6": "pay5", "pay-restored": "pay6"}.get(phase)
        before = copy.deepcopy(completed[previous]["data"]["after"]) if previous else {"alice": 0, "bob": 0}
        after = dict(before)
        if phase != "fund":
            after[intent["sender"]] -= intent["amount"] + intent["fee"]
        after[intent["recipient"]] += intent["amount"]
        txid = h("txid-" + phase)
        transaction_hash = self.transactions[phase]["sha256"]
        inputs = [{"txid": h("funding-outpoint"), "index": 0,
                   "value": intent["amount"] + intent["fee"] + 500}]
        if phase == "pay6":
            source = completed["pay5"]["data"]
            inputs = [{"txid": source["txid"], "index": source["output_index"], "value": source["amount"]}]
        return {"proposal_id": None if phase == "fund" else h("proposal-" + phase), "txid": txid, "transaction_sha256": transaction_hash,
                "transaction": self.transactions[phase], "version": intent["version"], "amount": intent["amount"],
                "fee": intent["fee"], "change": sum(row["value"] for row in inputs) - intent["amount"] - intent["fee"],
                "receiver_script": intent["receiver_script"], "inputs": inputs, "output_index": 0,
                "before": before, "after": after,
                "peers": [{"node_id": node, "block_hash": h("block-" + phase), "height": 110,
                           "txid": txid, "transaction_sha256": transaction_hash,
                           "spent_outpoints_authenticated": True, "receiver_output_authenticated": True}
                          for node in ("node-1", "node-2")]}

    def gate(self, phase):
        _, _, completed = flow.load(self.run)
        checks = flow.required_checks(phase)
        data = {}
        if phase.endswith("-review"):
            name = phase.removesuffix("-review")
            data = {"intent": copy.deepcopy(self.plan["payments"][name]),
                    "approved_digest": self.transactions[name]["sha256"] if name == "fund" else h("proposal-" + name)}
        elif phase in flow.PAYMENTS:
            data = self.payment(phase, completed)
        elif phase in flow.AUTOMATED:
            data = {"operation_reference": "ZDN saved original operation", "ready": True}
        elif phase == "uncertain":
            original = completed["pay6"]["data"]
            data = {"original_phase": "pay6", "proposal_id": original["proposal_id"], "txid": original["txid"],
                    "original_bytes_sha256": original["transaction_sha256"], "retry_transaction": self.transactions["pay6"],
                    "retried_bytes_sha256": original["transaction_sha256"]}
        elif phase == "recovery":
            data = {"native_ids_before": ["alice-node", "bob-node"], "native_ids_after": ["alice-node", "bob-node"],
                    "cookie_rotation_receipt": self.refs[0]}
        elif phase == "restore":
            data = {"snapshot_receipt_sha256": self.refs[0]["sha256"], "old_allocator": "retired", "new_allocator": "restored"}
        elif phase == "negatives":
            cases = read_json(Path(flow.__file__).with_name("zdn_cases.json"))["negative_controls"]
            data = {"controls": {row["id"]: {"reason_class": row["reason_class"], "effect": row["effect"],
                                             "evidence": self.refs[0]} for row in cases}}
        elif phase == "audit":
            data = {"kms_deletion": "scheduled-pending"}
        return {"schema": flow.SCHEMA, "phase": phase, "plan_sha256": self.plan_hash,
                "binding": copy.deepcopy(self.plan["binding"]), "reviewer": "independent-human-review",
                "checks": {key: True for key in checks}, "references": copy.deepcopy(self.refs), "data": data}

    def accept_gate(self, gate):
        self.count += 1
        path = self.root / f"gate-{self.count}.json"
        write_json(path, gate)
        return flow.accept(self.run, path)

    def advance(self, stop):
        while True:
            _, _, completed = flow.load(self.run)
            phase = flow.next_phase(completed)
            if phase == stop:
                return
            if phase in flow.AUTOMATED:
                flow.dispatch(self.run, self.plan_hash, runner=self.runner)
            self.accept_gate(self.gate(phase))

    def test_full_mocked_journey_includes_new_restored_payment(self):
        self.advance(None)
        _, _, completed = flow.load(self.run)
        self.assertEqual(set(completed), set(flow.PHASES))
        self.assertEqual(completed["pay6"]["data"]["after"], {"alice": 2_378_400, "bob": 578_400})
        self.assertEqual(completed["pay-restored"]["data"]["after"], {"alice": 2_256_800, "bob": 678_400})
        self.assertEqual(self.runner.call_count, 5)

    def test_manual_gate_cannot_dispatch(self):
        with self.assertRaises(AcceptanceError):
            flow.dispatch(self.run, self.plan_hash, runner=self.runner)
        self.runner.assert_not_called()

    def test_pinned_yaml_comment_and_pretty_json_accept_distinct_semantic_digest(self):
        variants = (CONFIG_YAML, "# Reviewed deployment settings\n" + CONFIG_YAML,
                    '{\n  "profile": "devnet",\n  "node_count": 2,\n'
                    '  "block_interval_seconds": 30\n}\n')
        raw_hashes = set()
        for index, contents in enumerate(variants):
            with self.subTest(index=index):
                path = self.root / f"config-{index}"
                path.write_text(contents)
                plan = copy.deepcopy(self.plan)
                plan["pins"]["config"] = flow.reference(path)
                raw_hashes.add(plan["pins"]["config"]["sha256"])
                self.assertNotEqual(plan["pins"]["config"]["sha256"], SEMANTIC_CONFIG_SHA256)
                plan_path = self.root / f"plan-{index}.json"
                write_json(plan_path, plan)
                flow.initialize(plan_path, self.root / f"variant-{index}")
        self.assertEqual(len(raw_hashes), len(variants))

    def test_comment_change_behind_frozen_config_pin_stops_dispatch(self):
        self.advance("network")
        (self.root / "config").write_text(CONFIG_YAML + "# Added after approval\n")
        with self.assertRaisesRegex(AcceptanceError, "^changed_input$"):
            flow.dispatch(self.run, self.plan_hash, runner=self.runner)
        self.runner.assert_not_called()
        self.assertFalse((self.run / "network.dispatch.json").exists())

    def test_malformed_semantic_digest_and_bad_request_schema_refuse(self):
        changes = [{"configSha256": value} for value in
                   (None, True, 123, [], {}, "", "a" * 63, "a" * 65,
                    "A" * 64, "g" * 64, " " + "a" * 64, "a" * 64 + "\n")]
        changes += [{"schema": value} for value in
                    (None, True, 1, {}, "zdn-external-artifact-set/v2")]
        changes += [{"extra": "unknown field"}]
        for index, change in enumerate(changes):
            with self.subTest(change=change):
                request = read_json(self.root / "request")
                request.update(change)
                path = self.root / f"bad-request-{index}.json"
                write_json(path, request)
                plan = copy.deepcopy(self.plan)
                plan["pins"]["request"] = flow.reference(path)
                plan["binding"]["request_sha256"] = plan["pins"]["request"]["sha256"]
                flow.validate_plan(plan)
                with self.assertRaises(AcceptanceError):
                    flow.check_inputs(plan)

    def test_bad_approval_and_changed_binary_stop_dispatch(self):
        self.advance("network")
        with self.assertRaises(AcceptanceError):
            flow.dispatch(self.run, h("not-reviewed"), runner=self.runner)
        (self.root / "zdn").write_text("changed")
        with self.assertRaises(AcceptanceError):
            flow.dispatch(self.run, self.plan_hash, runner=self.runner)
        self.runner.assert_not_called()

    def test_wrong_binding_pending_and_unknown_fields_never_advance(self):
        for mutate in (lambda row: row["binding"].update(native_fingerprint=h("wrong")),
                       lambda row: row.update(plan_sha256=h("stale")),
                       lambda row: row["checks"].update(pins_reviewed=False),
                       lambda row: row.update(password="not-allowed")):
            gate = self.gate("prepare")
            mutate(gate)
            with self.assertRaises(AcceptanceError):
                self.accept_gate(gate)
            self.assertFalse((self.run / "prepare.json").exists())

    def test_source_inputs_slots_profile_and_feature_bindings_refuse(self):
        for filename in ("config", "profile", "build_receipt"):
            path = self.root / filename
            original = path.read_bytes()
            path.write_bytes(b"wrong")
            with self.assertRaises(AcceptanceError):
                flow.check_inputs(self.plan)
            path.write_bytes(original)
        for field, value in (("nodeCount", True), ("artifacts", {}),
                             ("compiled", {"nativeFingerprint": h("wrong"), "cargoFeatures": [flow.FEATURE]}),
                             ("compiled", {"nativeFingerprint": h("native"), "cargoFeatures": []})):
            request = read_json(self.root / "request")
            request[field] = value
            path = self.root / ("mutated-" + str(self.count))
            self.count += 1
            write_json(path, request)
            plan = copy.deepcopy(self.plan)
            plan["pins"]["request"] = flow.reference(path)
            with self.assertRaises(AcceptanceError):
                flow.check_inputs(plan)

    def test_strict_numeric_and_plan_schema(self):
        for value in (True, 1.0, "3000000", -1):
            plan = copy.deepcopy(self.plan)
            plan["payments"]["fund"]["amount"] = value
            with self.assertRaises(AcceptanceError):
                flow.validate_plan(plan)
        plan = copy.deepcopy(self.plan)
        plan["shell_hook"] = "no hooks"
        with self.assertRaises(AcceptanceError):
            flow.validate_plan(plan)

    def test_failure_timeout_and_success_all_fence_repeat_dispatch(self):
        self.advance("network")
        self.runner.side_effect = subprocess.TimeoutExpired("zdn", 7200)
        with self.assertRaises(AcceptanceError):
            flow.dispatch(self.run, self.plan_hash, runner=self.runner)
        with self.assertRaises(AcceptanceError):
            flow.dispatch(self.run, self.plan_hash, runner=self.runner)
        self.assertEqual(self.runner.call_count, 1)
        self.assertIsNone(read_json(self.run / "network.process.json")["returncode"])
        self.assertEqual(flow.next_phase(flow.load(self.run)[2]), "network")

    def test_successful_process_requires_independent_gate(self):
        self.advance("network")
        flow.dispatch(self.run, self.plan_hash, runner=self.runner)
        self.assertFalse((self.run / "network.json").exists())
        with self.assertRaises(AcceptanceError):
            flow.dispatch(self.run, self.plan_hash, runner=self.runner)

    def test_pending_template_never_approves_or_advances(self):
        path = self.root / "pending.json"
        flow.gate_template(self.run, path)
        self.assertFalse(any(read_json(path)["checks"].values()))
        with self.assertRaises(AcceptanceError):
            flow.accept(self.run, path)
        self.assertEqual(flow.next_phase(flow.load(self.run)[2]), "prepare")

    def test_rotated_native_identity_refuses_recovery(self):
        self.advance("recovery")
        gate = self.gate("recovery")
        gate["data"]["native_ids_after"][1] = "replacement-node"
        with self.assertRaises(AcceptanceError):
            self.accept_gate(gate)

    def test_actual_command_shapes_are_zdn_only(self):
        for phase in flow.AUTOMATED:
            argv = flow.command(self.plan, phase)
            self.assertEqual(argv[0:2], [self.plan["pins"]["zdn"]["path"], "devnet"])
            self.assertNotIn("--shell", argv)
        up = flow.command(self.plan, "network")
        self.assertIn("--external-request-sha256", up)
        self.assertNotIn("--profile", up)  # fresh config.profile is authoritative
        update = flow.command(self.plan, "update")
        self.assertEqual(update[update.index("--node") + 1], "node-2")
        self.assertNotIn("--resume", update)

    def test_wrong_payment_inputs_balances_peers_and_approval_refuse(self):
        self.advance("pay6")
        for mutate in (lambda row: row["data"]["inputs"][0].update(txid=h("not-bobs-output")),
                       lambda row: row["data"]["after"].update(alice=2_378_401),
                       lambda row: row["data"]["peers"][1].update(block_hash=h("other-chain")),
                       lambda row: row["data"].update(proposal_id=h("unapproved")),
                       lambda row: row["data"].update(version=True),
                       lambda row: row["data"].update(change=0)):
            gate = self.gate("pay6")
            mutate(gate)
            with self.assertRaises(AcceptanceError):
                self.accept_gate(gate)

    def test_exact_uncertain_original_bytes_required(self):
        self.advance("uncertain")
        for key in ("retried_bytes_sha256", "proposal_id", "txid"):
            gate = self.gate("uncertain")
            gate["data"][key] = h("replacement")
            with self.assertRaises(AcceptanceError):
                self.accept_gate(gate)

    def test_restore_retires_allocator_and_requires_new_transaction(self):
        self.advance("restore")
        gate = self.gate("restore")
        gate["data"]["new_allocator"] = gate["data"]["old_allocator"]
        with self.assertRaises(AcceptanceError):
            self.accept_gate(gate)
        self.advance("pay-restored")
        gate = self.gate("pay-restored")
        gate["data"]["txid"] = flow.load(self.run)[2]["pay6"]["data"]["txid"]
        for peer in gate["data"]["peers"]:
            peer["txid"] = gate["data"]["txid"]
        with self.assertRaises(AcceptanceError):
            self.accept_gate(gate)

    def test_control_matrix_requires_all_controls_and_explicit_rejection(self):
        self.advance("negatives")
        gate = self.gate("negatives")
        del gate["data"]["controls"]["TPQ-N04"]
        with self.assertRaises(AcceptanceError):
            self.accept_gate(gate)
        gate = self.gate("negatives")
        gate["data"]["controls"]["TPQ-N02"]["reason_class"] = "closed-port"
        with self.assertRaises(AcceptanceError):
            self.accept_gate(gate)

    def test_cleanup_without_companion_and_after_failed_gate(self):
        for role in ("wallet", "devnet"):
            Path(self.plan["pins"][role]["path"]).unlink()
        (Path(self.plan["directory"]) / "host-adapter").unlink()
        flow.dispatch(self.run, self.plan_hash, cleanup=True, runner=self.runner)
        self.assertEqual(self.runner.call_args.args[0][1:3], ["devnet", "destroy"])
        self.assertIn("--delete-data", self.runner.call_args.args[0])
        self.assertEqual(flow.next_phase(flow.load(self.run)[2]), "prepare")

    def test_changed_public_gate_reference_is_not_reused(self):
        self.accept_gate(self.gate("prepare"))
        row = read_json(self.run / "prepare.json")
        Path(row["evidence"]["path"]).write_bytes(b"changed")
        with self.assertRaises(AcceptanceError):
            flow.dispatch(self.run, self.plan_hash, runner=self.runner)
        self.runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
