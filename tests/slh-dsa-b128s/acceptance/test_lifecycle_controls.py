"""Offline mocks only: no real process, node, fixture host or signer is launched."""
import hashlib
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import lifecycle_controls as controls
from common import AcceptanceError


class FakeNetwork:
    def __init__(self):
        self.height, self.block_hash = 111, "11" * 32
        self.accepted = False
        self.bad_proposal = False
        self.changed_on_reject = False
        self.calls = []
        self.nodes = [FakeNode(self), FakeNode(self)]
        self.a, self.b = self.nodes


class FakeNode:
    def __init__(self, network):
        self.network = network

    def tip(self):
        return self.network.height, self.network.block_hash

    def rpc(self, method, *arguments):
        state = self.network
        state.calls.append((method, arguments))
        if method == "gettxout":
            index = arguments[1]
            return None if state.accepted and 2 <= index < 10 else {"index": index, "value": "0.03"}
        if method == "getrawmempool":
            return []
        if method == "getblocktemplate":
            if not arguments:
                return {"transactions": []}
            if arguments[0]["data"] == "mixed-block":
                return "transaction-experimentalslhdsab128smixedinputs"
            if arguments[0]["data"] == "65":
                return "wrong-parent" if state.bad_proposal else "block-toomanyexperimentalslhdsab128schecks-limit-64"
            return None
        if method == "submitblock":
            if arguments == ("mixed-block",):
                return "rejected"
            if arguments == ("65",):
                if state.changed_on_reject:
                    state.height += 1
                return "rejected"
            state.accepted, state.height, state.block_hash = True, 112, "64" * 32
            return None
        if method == "getblock":
            return "64"
        raise AssertionError(method)

    def reject(self, method, reason, raw):
        self.network.calls.append((method, (reason, raw)))
        if self.network.changed_on_reject:
            self.network.height += 1
        return {"reason_contains": reason, "error_sha256": "22" * 32}


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

    def test_mixed_both_orders_bind_real_parent_context_and_precise_rejection(self):
        network = FakeNetwork()
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(controls, "host_call", side_effect=self.mixed_host) as host, \
                patch.object(controls, "signer_call", return_value={"public_key": next(iter(self.keys)), "signature": "77"}):
            rows = controls.mixed_controls(self.args, Path(directory), network, self.funding, self.keys)
        self.assertEqual([row["classical_first"] for row in rows], [True, False])
        self.assertEqual(host.call_count, 6)
        rejections = [entry for entry in network.calls if entry[0] == "sendrawtransaction"]
        self.assertEqual(len(rejections), 4)
        self.assertTrue(all(entry[1][0] == "cannot be mixed" for entry in rejections))

    def test_mixed_rejection_must_preserve_state(self):
        network = FakeNetwork()
        network.changed_on_reject = True
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(controls, "host_call", side_effect=self.mixed_host), \
                patch.object(controls, "signer_call", return_value={"public_key": next(iter(self.keys)), "signature": "77"}):
            with self.assertRaisesRegex(AcceptanceError, "rejected_control_changed_tip"):
                controls.mixed_controls(self.args, Path(directory), network, self.funding, self.keys)

    def block_host(self, _host, operation, **fields):
        if operation == "prepare":
            self.assertEqual(fields["recipe"]["inputs"][0]["outpoint"]["index"], 10)
            return {"inputs": [{"message_hex": "66" * 101}]}
        if operation == "assemble":
            return {"transaction_hex": "aa", "expected": {"native_authorization": "accept", "signature_checks": 1}}
        self.assertEqual(operation, "control-block")
        recipe = fields["recipe"]
        count = recipe["nonce"]
        self.assertEqual(len(recipe["transactions"]), 4 if count == 64 else 5)
        self.assertTrue(all(row["fee_zat"] == 1_000_000 for row in recipe["transactions"]))
        return {"block_hex": str(count), "block_hash": str(count) * 32, "height": 112}

    def blocks(self, network):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(controls, "host_call", side_effect=self.block_host), \
                patch.object(controls, "signed_artifact", return_value={"transaction_hex": "bb",
                    "expected": {"native_authorization": "accept", "signature_checks": 16}}), \
                patch.object(controls, "signer_call", return_value={"public_key": next(iter(self.keys)), "signature": "77"}):
            return controls.block_controls(self.args, Path(directory), network, self.funding, self.keys, {})

    def test_direct_blocks_reject_65_then_accept_exact_64_with_same_parents(self):
        network = FakeNetwork()
        result = self.blocks(network)
        self.assertEqual((result["accepted_checks"], result["rejected_checks"]), (64, 65))
        submits = [params[0] for method, params in network.calls if method == "submitblock"]
        self.assertEqual(submits, ["65", "65", "64"])
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

    def test_identical_slh_spend_accepts_only_with_enabled_consensus(self):
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
                    return None if args[0]["data"] == "fund" or self.enabled else "transaction-script-invalid"
                if method == "submitblock":
                    if args[0] == "fund":
                        self.height, self.hash = 112, "12" * 32
                        return None
                    if not self.enabled:
                        return "rejected"
                    self.height, self.hash, self.spent = 113, "13" * 32, True
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
            result = controls.slh_compatibility(self.args, Path(directory), {"script_hex": "fixture-script"}, nodes)
        self.assertEqual(result["common_parent"], {"height": 112, "hash": "12" * 32})
        self.assertEqual(nodes[0].tip(), (112, "12" * 32))
        self.assertEqual(nodes[1].tip(), (113, "13" * 32))
        self.assertFalse(nodes[0].spent)
        self.assertTrue(nodes[1].spent)


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
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            node = SimpleNamespace(directory=root, binary=Path("default-node"), config=root / "node.toml", close=Mock())
            node.config.write_text("public fixture config")
            def stopped(_argv, **kwargs):
                kwargs["stdout"].write(b"requires complete SLH-DSA-B-128s runtime support")
                return SimpleNamespace(returncode=1)
            with patch.object(controls, "ManagedNode", return_value=node), \
                    patch.object(controls, "port", return_value=1234), \
                    patch.object(controls.subprocess, "run", side_effect=stopped):
                result = controls.startup_refusal(SimpleNamespace(node_default=node.binary), root, "fixture")
            self.assertTrue(result["before_state_initialization"])
            node.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
