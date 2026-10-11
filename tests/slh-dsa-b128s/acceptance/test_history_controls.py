"""Offline orchestration mocks; no wallet process, terminal, node or signing."""
import copy
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from common import AcceptanceError, canonical, read_json, write_json
import history_controls as controls
from wallet_live import Participant

TIP = {"height": 111, "hash": "11" * 32}
REVIEW = {"proposal_id": "22" * 32, "input_value": controls.FUNDING_VALUE, "checks": 1}
PREVIEW = dict(REVIEW, proposal_id="33" * 32)


class FakeService:
    def __init__(self, demo, mode):
        self.mode, self.events, self.address = mode, [], "127.0.0.1:2"
        demo.services[self.address] = self
    def clear(self):
        self.mode = "honest"
    def __enter__(self):
        return self
    def __exit__(self, *_):
        pass


class FakeDemo:
    def __init__(self, mutation=None):
        self.services, self.calls = {}, []
        self.mutation, self.export_count, self.preview_count = mutation, 0, 0

    def service(self, _upstream, mode, **_):
        return FakeService(self, mode)

    def participant(self, directory, mode="allocator", fresh=False):
        directory.mkdir(mode=0o700)
        scan = {"checkpoint": None if fresh else TIP, "complete": not fresh, "context": None if fresh else TIP,
                "coins": [] if fresh else [{"value": controls.HISTORY_BALANCE, "outpoint": "funded"}], "undo": []}
        write_json(directory / "state.json", {"format": "ZcashTransparentPQ/watch-state/v2",
            "manifest": {"allocator_id": "public-test"}, "mode": mode,
            "receive_next": 1, "payments": {"change_next": 1, "records": ["saved-authorization"]}, "scan": scan})
        return Participant(directory / "unused-backup", directory, {})

    def cli(self, command, *arguments, secret=False, success=True):
        self.calls.append((command, arguments, secret, success))
        if command == "status":
            value = controls.state(arguments[0])
            scan = value["scan"]
            observed = sum(coin["value"] for coin in scan["coins"])
            return canonical({"mode": value["mode"], "receive_next": value["receive_next"], "scan": {
                "checkpoint": scan["checkpoint"], "complete_at_checkpoint": scan["complete"],
                "confirmed_zatoshis": observed if scan["complete"] else None,
                "immature_coinbase_zatoshis": 0 if scan["complete"] else None,
                "observed_zatoshis": observed, "pq_active_for_next_block": True if scan["complete"] else None}})
        store = arguments[0] if command in ("receive", "sync") else arguments[1]
        value = controls.state(store)
        if command in ("receive", "propose", "sign", "submit") and value["mode"] == "monitor":
            assert not success
            if self.mutation == "monitor-mutates":
                value["receive_next"] += 1
                write_json(store / "state.json", value, fresh=False)
            return controls.MONITOR.encode()
        address = arguments[1] if command == "sync" else arguments[2]
        service = self.services.get(address)
        fault = service and service.mode != "honest"
        if command in ("sync", "propose", "sign"):
            if service and self.mutation != "no-fault-event":
                method = "getblock" if service.mode in ("pruned", "inconsistent-block", "honest") else "getblockchaininfo"
                service.events.append({"method": method, "fault_applied": bool(fault)})
            if fault:
                assert not success
                value["scan"].update(complete=False, context=None)
                if value["scan"]["checkpoint"] is None:
                    value["scan"]["checkpoint"] = {"height": 110, "hash": "10" * 32}
                if self.mutation == "false-current":
                    value["scan"].update(complete=True)
                if self.mutation == "forget-cached-funds":
                    value["scan"]["coins"] = []
                if self.mutation == "change-cached-outpoint":
                    value["scan"]["coins"][0]["outpoint"] = "different-same-value"
                if self.mutation == "authority-change":
                    value["payments"]["change_next"] += 1
                if self.mutation == "published-partials" and command == "sign":
                    arguments[-1].mkdir()
                write_json(store / "state.json", value, fresh=False)
                reason = controls.INCONSISTENT if service.mode in ("inconsistent-tip", "inconsistent-block") else controls.UNAVAILABLE
                return ("unrelated rejection" if self.mutation == "wrong-diagnostic" else reason).encode()
            assert success and command == "sync"
            if arguments[2] == 1 and self.mutation != "bounded-complete":
                value["scan"].update(checkpoint={"height": 0, "hash": "00" * 32},
                    complete=False, context=None)
            else:
                value["scan"].update(checkpoint=TIP, complete=True, context=TIP,
                    coins=[{"value": controls.HISTORY_BALANCE, "outpoint": "funded"}])
                if self.mutation == "promote-after-reconcile":
                    value["mode"] = "allocator"
            write_json(store / "state.json", value, fresh=False)
            return self.cli("status", store)
        if command == "review":
            return canonical(dict(REVIEW, input_value=0) if self.mutation == "ineligible-payment" else REVIEW)
        if command == "propose-preview":
            self.preview_count += 1
            write_json(arguments[-1], {"public": "unreserved-input-proposal"})
            result = dict(PREVIEW)
            if self.mutation == "ineligible-preview":
                result["proposal_id"] = REVIEW["proposal_id"]
            if self.mutation == "changed-preview" and self.preview_count > 1:
                write_json(arguments[-1], {"public": "changed-proposal"}, fresh=False)
            return canonical(result)
        raise AssertionError(command)

    def export(self, _owner, proposal_id, directory):
        assert proposal_id == REVIEW["proposal_id"]
        self.export_count += 1
        directory.mkdir(mode=0o700)
        (directory / "signed-transaction.hex").write_text(
            "changed" if self.mutation == "saved-bytes-change" and self.export_count > 1 else "aabb")
        write_json(directory / "partial-0.json", {"saved": "exact-public-authorization"})
        return directory


class ControlsTests(unittest.TestCase):
    def cached(self, directory, mode="unavailable", mutation=None):
        demo = FakeDemo(mutation)
        participants = [demo.participant(directory / "owner"), demo.participant(directory / "monitor", "monitor"),
                        demo.participant(directory / "unknown", "monitor")]
        payment = {"review": REVIEW, "intent_path": directory / "intent", "proposal_path": directory / "proposal"}
        return demo, controls.cached_fault(demo, participants, payment, "127.0.0.1:1", TIP, mode,
                                           directory / "case", service_factory=demo.service)

    def rescan(self, directory, mode="pruned", mutation=None):
        demo = FakeDemo(mutation)
        participant = demo.participant(directory / "monitor", "monitor", fresh=True)
        payment = {"review": REVIEW, "intent_path": directory / "intent", "proposal_path": directory / "proposal"}
        return demo, controls.rescan_fault(demo, participant, payment, "127.0.0.1:1", TIP, mode,
                                           TIP["hash"], directory / "case", service_factory=demo.service)

    def test_cached_funded_faults_preserve_authority_and_exact_bytes_then_reconcile(self):
        for mode in ("unavailable", "missing-hash", "inconsistent-tip"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                demo, row = self.cached(Path(directory), mode)
                self.assertEqual(row["funded_value"], 6_000_000)
                self.assertEqual(row["monitor_count"], 2)
                self.assertEqual(row["reconciled_tip"], TIP)
                self.assertEqual(sum(e["fault_applied"] for e in row["events"]), 5)
                self.assertEqual(demo.export_count, 3)
                self.assertEqual(demo.preview_count, 2)
                self.assertFalse(any(command == "receive" and arguments[0].name == "owner"
                                     for command, arguments, *_ in demo.calls))

    def test_cached_controls_reject_false_positive_failures_and_authority_changes(self):
        mutations = {"wrong-diagnostic": "wrong_history_refusal_diagnostic", "no-fault-event": "fault_not_exercised",
            "false-current": "advertised_current_balance", "forget-cached-funds": "lost_cached_funds",
            "change-cached-outpoint": "changed_cached_scan",
            "authority-change": "fault_changed_authority", "published-partials": "published_authorization",
            "saved-bytes-change": "changed_saved_payment", "ineligible-payment": "not_otherwise_eligible",
            "ineligible-preview": "proposal_not_otherwise_eligible", "changed-preview": "changed_preview",
            "monitor-mutates": "monitor_refusal_changed_authority"}
        for mutation, reason in mutations.items():
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(AcceptanceError, reason):
                    self.cached(Path(directory), mutation=mutation)

    def test_fresh_monitor_pruned_inconsistent_and_bounded_rescan_reconcile(self):
        for mode in ("pruned", "inconsistent-block", "incomplete"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                demo, row = self.rescan(Path(directory), mode)
                self.assertEqual(row["reconciled_value"], 6_000_000)
                self.assertEqual(row["diagnostic"], None if mode == "incomplete" else
                                 controls.INCONSISTENT if mode == "inconsistent-block" else controls.UNAVAILABLE)
                self.assertEqual(sum(command == "receive" for command, *_ in demo.calls), 3)

    def test_rescan_cannot_promote_monitor_or_hide_diagnostic_and_progress_failures(self):
        for mutation, reason in (("promote-after-reconcile", "rescan_promoted_authority"),
                                 ("wrong-diagnostic", "wrong_history_refusal_diagnostic"),
                                 ("no-fault-event", "fault_not_exercised"),
                                 ("authority-change", "rescan_changed_authority"),
                                 ("false-current", "advertised_current_balance")):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(AcceptanceError, reason):
                    self.rescan(Path(directory), mutation=mutation)
        for mutation, reason in (("no-fault-event", "bounded_scan_no_history"),
                                 ("bounded-complete", "bounded_scan_not_incomplete")):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(AcceptanceError, reason):
                    self.rescan(Path(directory), "incomplete", mutation)

    def test_state_projection_allows_only_scan_and_v3_commit_generation(self):
        value = {"format": "ZcashTransparentPQ/watch-state/v3", "scan": {"complete": True},
                 "mode": "monitor", "payments": {"journal": {"generation": 10, "history": "root"}}, "receive_next": 3}
        changed = copy.deepcopy(value)
        changed["scan"] = {"complete": False}
        changed["payments"]["journal"]["generation"] += 1
        self.assertEqual(controls.authority(value), controls.authority(changed))
        for field in ("history", "new-field"):
            changed["payments"]["journal"][field] = "other"
            self.assertNotEqual(controls.authority(value), controls.authority(changed))
        self.assertEqual(value["payments"]["journal"]["generation"], 10)

    def test_restore_requests_unknown_authority_and_inspects_its_paired_backup(self):
        owner = Participant(Path("root.tpq"), Path("watch"), {"public": "manifest"})
        for snapshot in (None, Path("snapshot")):
            with self.subTest(snapshot=snapshot), patch.object(controls, "fingerprint", return_value="approved"):
                demo = SimpleNamespace(cli=Mock(side_effect=[canonical({"mode": "monitor", "authority": "unknown"}),
                                                               canonical({"restored": "manifest"})]))
                result = controls.restored(demo, owner, Path("destination"), snapshot=snapshot)
                first = demo.cli.call_args_list[0].args
                self.assertEqual(first, ("restore", Path("root.tpq"), "approved", Path("destination")) if snapshot is None
                                 else ("snapshot-restore", Path("snapshot"), Path("destination"), "unknown"))
                self.assertEqual(result.backup, Path("destination/backup-restored.tpq"))
                self.assertEqual(result.manifest, {"restored": "manifest"})
                demo.cli = Mock(return_value=canonical({"mode": "allocator", "authority": "known"}))
                with self.assertRaisesRegex(AcceptanceError, "restore_granted_authority"):
                    controls.restored(demo, owner, Path("destination"), snapshot=snapshot)

    def test_chain_guard_checks_both_real_outpoints_and_rejects_submission(self):
        funding = {"txid": "44" * 32, "outputs": [{"script_hex": "script"}] * 2}
        tip = (TIP["height"], TIP["hash"])
        def guard(tips=(tip, tip), pool=(), change=None):
            """Two independent nodes; `change` alters only the second node's output 1."""
            def node(position):
                def rpc(method, *args):
                    if method == "getrawmempool":
                        return list(pool) if position else []
                    output = {"value": "0.03", "coinbase": False, "confirmations": 1, "scriptPubKey": {"hex": "script"}}
                    return change(output) if change and position and args[1] == 1 else output
                return SimpleNamespace(tip=lambda: tips[position], rpc=Mock(side_effect=rpc))
            network = SimpleNamespace(nodes=[node(0), node(1)])
            controls.unchanged_chain(network, funding, TIP, [[], []])
            return network
        network = guard()
        for node in network.nodes:
            self.assertEqual([call.args for call in node.rpc.call_args_list if call.args[0] == "gettxout"],
                             [("gettxout", funding["txid"], index, False) for index in (0, 1)])
        moved = (TIP["height"] + 1, "12" * 32)
        for arguments, reason in (({"pool": ["unexpected-payment"]}, "history_control_submitted_payment"),
                                  ({"tips": (moved, moved)}, "history_control_changed_chain"),
                                  ({"tips": (tip, moved)}, "nodes_do_not_share_tip"),
                                  ({"change": lambda output: None}, "history_control_changed_funding"),
                                  ({"change": lambda output: dict(output, coinbase=True)}, "history_control_changed_funding"),
                                  ({"change": lambda output: dict(output, confirmations=0)}, "history_control_changed_funding"),
                                  ({"change": lambda output: dict(output, value="0.02")}, "history_control_changed_funding"),
                                  ({"change": lambda output: dict(output, scriptPubKey={"hex": "other"})},
                                   "history_control_changed_funding")):
            with self.subTest(reason=reason, arguments=arguments), self.assertRaisesRegex(AcceptanceError, reason):
                guard(**arguments)


class ReceiptTests(unittest.TestCase):
    def test_main_requires_human_flag_without_launching_anything(self):
        with patch.object(controls, "execute") as execute:
            with self.assertRaisesRegex(AcceptanceError, "human_run_required"):
                controls.main(SimpleNamespace(human_run=False))
            execute.assert_not_called()

    def test_failure_receipt_is_incomplete_and_sanitizes_exception_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = SimpleNamespace(human_run=True, artifacts=root / "artifacts", version=6, classical="single")
            for role in ("node", "cli", "host"):
                setattr(args, role, root / role)
                setattr(args, role + "_build", write_json(root / (role + ".json"), {}))
            with patch.object(controls, "validate_build", return_value={}), \
                    patch.object(controls, "source_state", return_value={}), \
                    patch.object(controls, "execute", side_effect=RuntimeError("secret must not reach receipt")):
                with self.assertRaises(RuntimeError):
                    controls.main(args)
            receipt = read_json(args.artifacts / "execution.json")
            self.assertFalse(receipt["complete"])
            self.assertEqual(receipt["failure"], "RuntimeError")
            self.assertNotIn(b"secret", (args.artifacts / "execution.json").read_bytes())


if __name__ == "__main__":
    unittest.main()
