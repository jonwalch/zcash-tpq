"""Offline mocks only: no real process, node, fixture host or signer is launched."""
import hashlib
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import common
import lifecycle_controls as controls
from common import AcceptanceError

MIXED = "active SLH transparent inputs cannot be mixed with other transparent input types"


class FakeNetwork:
    def __init__(self):
        self.height, self.block_hash = 111, "11" * 32
        self.accepted = False
        self.bad_proposal = False
        self.changed_on_reject = False
        self.relay_error = {"code": -26, "message": MIXED}
        self.mixed_proposal, self.mixed_submit = "transaction-experimentalslhdsab128smixedinputs", "rejected"
        self.mempool, self.template = [], []
        # Raw transaction -> spent outpoints, and block -> raw transactions.
        self.spends, self.blocks, self.spent = {}, {}, set()
        self.spend_error = set()  # Outpoints whose accepted-block spend state is wrong.
        self.calls = []
        self.nodes = [FakeNode(self), FakeNode(self)]
        self.a, self.b = self.nodes


class FakeNode(common.Node):
    """Actual Node.rpc/reject diagnostics over an in-memory JSON-RPC response."""
    def __init__(self, network):
        self.network = network

    def tip(self):
        return self.network.height, self.network.block_hash

    def response(self, method, *arguments):
        state = self.network
        state.calls.append((method, arguments))
        if method == "sendrawtransaction":
            if state.changed_on_reject:
                state.height += 1
            return {"id": 1, "result": None, "error": state.relay_error}
        return {"id": 1, "result": self.result(method, *arguments), "error": None}

    def result(self, method, *arguments):
        state = self.network
        if method == "gettxout":
            return None if tuple(arguments[:2]) in state.spent else {"index": arguments[1], "value": "0.03"}
        if method == "getrawmempool":
            return list(state.mempool)
        if method == "getblocktemplate":
            if not arguments:
                return {"previousblockhash": state.block_hash, "transactions": list(state.template)}
            if arguments[0]["data"] == "mixed-block":
                return state.mixed_proposal
            if arguments[0]["data"] == "65":
                return "wrong-parent" if state.bad_proposal else "block-toomanyexperimentalslhdsab128schecks-limit-64"
            return None
        if method == "submitblock":
            if arguments == ("mixed-block",):
                return state.mixed_submit
            if arguments == ("65",):
                if state.changed_on_reject:
                    state.height += 1
                return "rejected"
            state.accepted, state.height, state.block_hash = True, 112, "64" * 32
            state.spent.update(point for raw in state.blocks[arguments[0]] for point in state.spends[raw])
            state.spent ^= state.spend_error
            return None
        if method == "getblock":
            return "64"
        raise AssertionError(method)


class ControlFlowTests(unittest.TestCase):
    def setUp(self):
        self.args = SimpleNamespace(host=Path("public-host"), signer=Path("public-signer"),
                                    classical="single", version=5)
        self.keys = {"33" * 32: "public fixture key"}
        self.funding = {"transaction_hex": "44", "txid": "55" * 32}

    def mixed_host(self, _host, operation, **fields):
        recipe = fields["recipe"]
        if operation == "control-block":
            self.assertEqual(recipe["transactions"], [{"transaction_hex": "88", "fee_zat": 100_000}])
            return {"block_hex": "mixed-block"}
        self.assertEqual(recipe["classical"]["output_index"], 0)
        self.assertEqual(recipe["slh"]["output_index"], 1)
        self.assertEqual(recipe["classical"]["parent_hex"], "44")
        result = {"slh_input_index": int(recipe["classical_first"]),
                  "public_key_hex": next(iter(self.keys)), "message_hex": "66" * 101}
        if operation == "mixed-assemble":
            self.assertEqual(fields["record"]["signature_hex"], "77")
            result.update(transaction_hex="88", txid="99" * 32, slh_checks=1)
        return result

    def mixed(self, network):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(controls, "host_call", side_effect=self.mixed_host) as host, \
                patch.object(controls, "signer_call", return_value={"public_key": next(iter(self.keys)), "signature": "77"}):
            return controls.mixed_controls(self.args, Path(directory), network, self.funding, self.keys), host

    def test_mixed_both_orders_bind_real_parent_context_and_precise_rejection(self):
        network = FakeNetwork()
        rows, host = self.mixed(network)
        self.assertEqual([row["classical_first"] for row in rows], [True, False])
        self.assertEqual(host.call_count, 6)
        relays = [arguments for method, arguments in network.calls if method == "sendrawtransaction"]
        self.assertEqual(relays, [("88",)] * 4)
        error = hashlib.sha256(common.canonical(network.relay_error)).hexdigest()
        self.assertEqual([observed for row in rows for observed in row["rejections"]],
                         [{"reason_contains": "cannot be mixed", "error_sha256": error}] * 4)

    def test_mixed_controls_refuse_unrelated_or_accepted_mixed_results(self):
        for change, reason in (
                ({"relay_error": {"code": -25, "message": "bad-txns-inputs-missingorspent"}},
                 "unexpected_rejection_reason"),
                ({"relay_error": None}, "unexpected_rejection_reason"),
                ({"mempool": ["99" * 32]}, "mixed_transaction_in_mempool"),
                ({"template": [{"hash": "99" * 32, "data": "88"}]}, "mixed_template_must_be_empty"),
                ({"mixed_proposal": "bad-parent"}, "wrong_mixed_block_proposal_rejection"),
                ({"mixed_proposal": None}, "wrong_mixed_block_proposal_rejection"),
                ({"mixed_submit": None}, "mixed_block_not_rejected")):
            with self.subTest(change=change):
                network = FakeNetwork()
                vars(network).update(change)
                with self.assertRaisesRegex(AcceptanceError, reason):
                    self.mixed(network)

    def test_mixed_rejection_must_preserve_state(self):
        network = FakeNetwork()
        network.changed_on_reject = True
        with self.assertRaisesRegex(AcceptanceError, "rejected_control_changed_tip"):
            self.mixed(network)

    def block_host(self, _host, operation, **fields):
        if operation == "prepare":
            self.assertEqual(fields["recipe"]["inputs"][0]["outpoint"]["index"], 10)
            return {"inputs": [{"message_hex": "66" * 101}]}
        if operation == "assemble":
            outpoint = fields["recipe"]["inputs"][0]["outpoint"]
            self.network.spends["aa"] = [(outpoint["txid_display_hex"], outpoint["index"])]
            return {"transaction_hex": "aa", "expected": {"native_authorization": "accept", "signature_checks": 1}}
        self.assertEqual(operation, "control-block")
        recipe = fields["recipe"]
        count = recipe["nonce"]
        self.templates.append(recipe["template"])
        self.network.blocks[str(count)] = [row["transaction_hex"] for row in recipe["transactions"]]
        self.assertTrue(all(row["fee_zat"] == 1_000_000 for row in recipe["transactions"]))
        return {"block_hex": str(count), "block_hash": str(count) * 32, "height": 112}

    def blocks(self, network):
        self.network, self.templates = network, []
        def signed(_args, _keys, _producer, txid, slots, *_rest):
            # Tag each artifact with the outpoints it spends.
            raw = "".join(f"{slot:02x}" for slot in slots)
            network.spends[raw] = [(txid, slot) for slot in slots]
            return {"transaction_hex": raw, "expected": {"native_authorization": "accept", "signature_checks": 16}}
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(controls, "host_call", side_effect=self.block_host), \
                patch.object(controls, "signed_artifact", side_effect=signed) as self.signed, \
                patch.object(controls, "signer_call", return_value={"public_key": next(iter(self.keys)), "signature": "77"}):
            return controls.block_controls(self.args, Path(directory), network, self.funding, self.keys, {})

    def test_direct_blocks_reject_65_then_accept_exact_64_with_same_parents(self):
        network = FakeNetwork()
        result = self.blocks(network)
        self.assertEqual((result["accepted_checks"], result["rejected_checks"]), (64, 65))
        submits = [params[0] for method, params in network.calls if method == "submitblock"]
        self.assertEqual(submits, ["65", "65", "64"])
        self.assertTrue(network.accepted)
        txid = self.funding["txid"]
        self.assertEqual([call.args[3:] for call in self.signed.call_args_list],
                         [(txid, [2 + 2 * index, 3 + 2 * index], [3_000_000] * 2, [(15, 15), (1, 1)], 5, 131,
                           f"block-control-{index}") for index in range(4)])
        sixteen = ["0203", "0405", "0607", "0809"]
        self.assertEqual(network.blocks, {"64": sixteen, "65": [*sixteen, "aa"]})
        self.assertEqual(self.templates, [{"previousblockhash": "11" * 32, "transactions": []}] * 2)
        self.assertEqual(network.spent, {(txid, index) for index in range(2, 10)})

    def test_accepted_exact_block_must_spend_only_its_inputs(self):
        for outpoint in (("55" * 32, 9), ("55" * 32, 10)):
            with self.subTest(outpoint=outpoint):
                network = FakeNetwork()
                network.spend_error = {outpoint}
                with self.assertRaisesRegex(AcceptanceError, "exact_block_wrong_spends"):
                    self.blocks(network)
                self.assertTrue(network.accepted)

    def test_other_block_failure_cannot_stand_in_for_budget_rejection(self):
        network = FakeNetwork()
        network.bad_proposal = True
        with self.assertRaisesRegex(AcceptanceError, "wrong_excess_block_proposal_rejection"):
            self.blocks(network)
        self.assertFalse(network.accepted)

    def test_rejected_block_cannot_advance_either_node(self):
        network = FakeNetwork()
        network.changed_on_reject = True
        with self.assertRaisesRegex(AcceptanceError, "rejected_control_changed_tip"):
            self.blocks(network)

    def compatibility(self, mutation=None):
        class Comparator:
            def __init__(self, enabled):
                self.enabled, self.height, self.hash = enabled, 111, "11" * 32
                self.spent = False
            def tip(self):
                return self.height, self.hash
            def rpc(self, method, *args):
                if method == "getblocktemplate":
                    if not args:
                        return {"transactions": []}
                    if args[0]["data"] == "fund":
                        return None
                    if self.enabled:
                        return "bad-txns" if mutation == "enabled-proposal-rejected" else None
                    return {"default-proposal-accepted": None,
                            "default-proposal-bad-parent": "bad-parent"}.get(mutation, "transaction-script-invalid")
                if method == "submitblock":
                    if args[0] == "fund":
                        self.height, self.hash = 112, "12" * 32
                        return None
                    if not self.enabled:
                        if mutation == "default-block-accepted":
                            return None
                        if mutation == "default-rejection-spends":
                            self.spent = True
                        if mutation == "default-rejection-advances":
                            self.height, self.hash = 113, "13" * 32
                        return "rejected"
                    self.height, self.hash = 113, "13" * 32
                    self.spent = mutation != "enabled-output-unspent"
                    return None
                if method == "getblock":
                    return "fund" if args[0] == "12" * 32 else "slh"
                if method == "gettxout":
                    return None if self.spent else {"value": "0.03", "scriptPubKey": {"hex": "fixture-script"},
                        "coinbase": False, "confirmations": 1}
                raise AssertionError(method)
        nodes = [Comparator(False), Comparator(True)]
        public = next(iter(self.keys))
        def host(_path, operation, **fields):
            if operation == "classical-spend":
                self.assertEqual(fields["recipe"]["parent_hex"], "actual-parent")
                return {"transaction_hex": "funding-tx", "txid": "14" * 32,
                    "outputs": [{"script_hex": "fixture-script", "value_zat": 3_000_000}]}
            if operation == "control-block":
                raw = "fund" if fields["recipe"]["nonce"] == 700 else "slh"
                return {"block_hex": raw, "block_hash": ("12" if raw == "fund" else "13") * 32}
            if operation == "prepare":
                return {"inputs": [{"message_hex": "66" * 101}]}
            return {"transaction_hex": "spend-tx", "expected": {"native_authorization": "accept", "signature_checks": 1}}
        self.args.root = Path("product")
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(controls, "host_call", side_effect=host), \
                patch.object(controls, "signer_call", return_value={"public_key": public, "secret_key": "public", "signature": "77"}), \
                patch.object(controls, "producer_identity", return_value=({}, {})), \
                patch.object(controls, "authenticate_coinbase", return_value={"parent_hex": "actual-parent", "output_index": 0}):
            return nodes, controls.slh_compatibility(self.args, Path(directory), {"script_hex": "fixture-script"}, nodes)

    def test_identical_slh_spend_accepts_only_with_enabled_consensus(self):
        nodes, result = self.compatibility()
        self.assertEqual(result["common_parent"], {"height": 112, "hash": "12" * 32})
        self.assertEqual(result["default_rejection"], "transaction-script-invalid")
        self.assertEqual(nodes[0].tip(), (112, "12" * 32))
        self.assertEqual(nodes[1].tip(), (113, "13" * 32))
        self.assertFalse(nodes[0].spent)
        self.assertTrue(nodes[1].spent)
        for mutation, reason in (("enabled-proposal-rejected", "enabled_slh_proposal_rejected"),
                                 ("default-proposal-accepted", "disabled_slh_wrong_rejection"),
                                 ("default-proposal-bad-parent", "disabled_slh_wrong_rejection"),
                                 ("default-block-accepted", "disabled_slh_block_accepted"),
                                 ("default-rejection-spends", "disabled_slh_rejection_changed_state"),
                                 ("default-rejection-advances", "disabled_slh_rejection_changed_state"),
                                 ("enabled-output-unspent", "enabled_slh_block_state")):
            with self.subTest(mutation=mutation), self.assertRaisesRegex(AcceptanceError, reason):
                self.compatibility(mutation)


class FilesAndRefusalTests(unittest.TestCase):
    def test_namespace_changes_every_consensus_coordinate(self):
        profiles = [None, (110, 16, 64), (111, 16, 64), (110, 15, 64), (110, 16, 65)]
        self.assertEqual(len({controls.namespace(row) for row in profiles}), 5)
        self.assertEqual(controls.namespace(profiles[1]), "regtest-slh-dsa-b128s-v1-h110-t16-b64")

    def populate(self, root):
        name = controls.namespace((110, 16, 64))
        database = root / "state/v29" / name
        backup = root / "non_finalized_state" / name
        database.mkdir(parents=True)
        backup.mkdir(parents=True)
        (database / "CURRENT").write_text("MANIFEST-000001\n")
        (database / "MANIFEST-000001").write_bytes(b"fixture database")
        (backup / ("11" * 32)).write_bytes(b"\0" * 8 + bytes.fromhex("abcd"))
        return name, backup

    def test_state_inventory_and_exact_ordinary_backup_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            name, backup = self.populate(root)
            files = controls.state_files(root, name)
            self.assertEqual(len(files), 3)
            node = SimpleNamespace(tip=lambda: (3, "11" * 32), rpc=lambda *_: "abcd")
            saved = controls.backup_tip(node, root, name)
            self.assertEqual(saved["raw_block_sha256"], hashlib.sha256(bytes.fromhex("abcd")).hexdigest())
            (backup / ("11" * 32)).write_bytes(b"\0" * 8 + bytes.fromhex("abce"))
            def immediate(action, reason, _timeout):
                controls.require(action(), reason)
            with patch.object(controls, "wait_for", side_effect=immediate):
                with self.assertRaisesRegex(AcceptanceError, "ordinary_backup"):
                    controls.backup_tip(node, root, name)

    def test_state_inventory_refuses_links_and_empty_backups(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            name, backup = self.populate(root)
            target = backup / ("11" * 32)
            target.unlink()
            with self.assertRaisesRegex(AcceptanceError, "namespace_backup_empty"):
                controls.state_files(root, name)
            target.symlink_to(root / "outside")
            with self.assertRaisesRegex(AcceptanceError, "namespace_symlink"):
                controls.state_files(root, name)

    def test_default_refusal_requires_specific_error_before_state_open(self):
        # zakurad/src/commands/start.rs startup refusal for the default build.
        refusal = (b"experimental_slh_dsa_b128s_activation_height requires complete SLH-DSA-B-128s "
                   b"runtime support; this build does not provide it")
        for mutation, reason in ((None, None), ("exit-zero", "default_build_accepted_slh_configuration"),
                                 ("other-error", "wrong_startup_refusal"),
                                 ("oversized-log", "refusal_log_size"),
                                 ("opened-state", "refusal_opened_state")):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                node = SimpleNamespace(directory=root, binary=Path("default-node"), config=root / "node.toml", close=Mock())
                node.config.write_text("public fixture config")
                def stopped(argv, **kwargs):
                    self.assertEqual(argv, ["default-node", "--config", str(node.config), "start"])
                    kwargs["stdout"].write(b"Error: configuration rejected" if mutation == "other-error" else refusal)
                    if mutation == "oversized-log":
                        kwargs["stdout"].write(b"\0" * 1024 * 1024)
                    if mutation == "opened-state":
                        (root / "state").mkdir()
                    return SimpleNamespace(returncode=0 if mutation == "exit-zero" else 1)
                with patch.object(controls, "ManagedNode", return_value=node), \
                        patch.object(controls, "port", return_value=1234), \
                        patch.object(controls.subprocess, "run", side_effect=stopped):
                    if reason is None:
                        result = controls.startup_refusal(SimpleNamespace(node_default=node.binary), root, "fixture")
                        self.assertTrue(result["before_state_initialization"])
                        self.assertEqual(result["exit_code"], 1)
                    else:
                        with self.assertRaisesRegex(AcceptanceError, reason):
                            controls.startup_refusal(SimpleNamespace(node_default=node.binary), root, "fixture")
                node.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
