"""Offline wallet restart ordering; all CLI, node and RPC work is mocked."""
from decimal import Decimal
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import common
import node_live
import test_node_reentry as backup_model
import wallet_live


class ReachedRollback(Exception):
    """Stop the actual wallet driver just after its recovery/restart boundary."""


class WalletBackupNode(backup_model.BackupNode):
    def __init__(self, model, directory):
        super().__init__(model, directory)
        (self.backup / ("11" * 32)).write_bytes(bytes(8) + b"parent")

    def start(self):
        self.model.events.append("start")
        self.current = ((self.height, "aa" * 32) if (self.backup / ("aa" * 32)).exists()
                        else (self.height - 1, "11" * 32))
        if self.model.mode == "changed-reopen":
            self.current = (self.height - 1, "11" * 32)

    def rpc(self, method, *args):
        if method == "sendrawtransaction":
            return "44" * 32
        if method == "getrawmempool":
            return ["44" * 32]
        if method == "getrawtransaction":
            return "0102"
        if method == "gettxout":
            return {"coinbase": False, "confirmations": 1, "value": Decimal("0.03"),
                    "scriptPubKey": {"hex": "public-funded-output"}}
        if method == "invalidateblock":
            self.model.events.append("rollback")
            raise ReachedRollback
        return super().rpc(method, *args)


class WalletBackupNetwork(backup_model.BackupNetwork):
    def __init__(self, directory, mode="complete"):
        self.events, self.mode, self.invalidated, self.updated = [], mode, (), False
        self.nodes = [WalletBackupNode(self, directory / label) for label in ("a", "b")]
        self.a, self.b = self.nodes

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def bootstrap(self):
        return common.common_tip(self.nodes)

    def mine(self):
        self.events.append("mine")


class WalletRestartTests(unittest.TestCase):
    def execute_until_rollback(self, model, directory, receipt):
        """Run execute itself, with preceding wallet/funding work replaced."""
        args = SimpleNamespace(host=Path("unused-host"), node=Path("unused-node"),
            cli=Path("unused-cli"), classical="single", threshold=2, participants=3,
            inputs=1, version=5, missing_required_key=False)
        entry = {"role": 0, "policy_hex": "01f70101" + "22" * 32,
                 "origins": [{"wallet_id": "owner", "index": 0}]}
        owner = SimpleNamespace(backup=Path("unused-backup"), store=Path("unused-watch"),
                                manifest={"wallet_id": "owner", "entries": [entry]})
        demo = Mock()
        demo.group.return_value = [owner] * 3
        demo.oracle.receiver.return_value = "first"
        demo.cli.side_effect = [b"recipient", b"first", b"second", b"", b"", b"third", b""]
        demo.sync.return_value = {"scan": {"confirmed_zatoshis": wallet_live.FUNDING_VALUE}}
        demo.payment.return_value = {"review": {"tip": common.common_tip(model.nodes)}}
        demo.recover.return_value = ([owner] * 2, [])

        def local_recovery(*args):
            # Completing local operations cannot advance a separate backup task.
            model.events.extend(["wallet-control"] * 20)
            return {}

        demo.recovery_controls.side_effect = local_recovery
        information = {"material": "public-test-only", "slh_checks": 0,
                       "address": "public-address", "script_hex": "public-script"}
        parent = {"parent_hex": "public-parent", "output_index": 0, "txid": "33" * 32}
        funding = {"slh_checks": 0, "outpoint": {"txid_display_hex": parent["txid"]},
                   "transaction_hex": "0102", "transaction_sha256": "55" * 32,
                   "txid": "44" * 32, "outputs": [{"script_hex": "public-funded-output"}]}
        artifacts = directory / "artifacts"
        artifacts.mkdir()
        with patch.object(wallet_live, "Network", return_value=model), \
                patch.object(wallet_live, "Demo", return_value=demo), \
                patch.object(wallet_live, "host_call", side_effect=[information, funding]), \
                patch.object(wallet_live, "authenticate_coinbase", return_value=parent), \
                patch.object(wallet_live, "wait_for", side_effect=lambda predicate, reason:
                             common.require(predicate(), reason)), \
                backup_model.BackupRestartTests().backup_waits(model):
            wallet_live.execute(args, artifacts, receipt)

    def test_wallet_waits_for_backup_before_exact_tip_restart(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            model, receipt = WalletBackupNetwork(directory), {}
            with self.assertRaises(ReachedRollback):
                self.execute_until_rollback(model, directory, receipt)
            self.assertEqual(receipt["restart"]["height"], 2)
            self.assertEqual(receipt["restart"]["hash"], "aa" * 32)
            self.assertEqual(receipt["restart"]["backup"]["excluded_block_hashes"], [])
            self.assertEqual([row["blocks"] for row in receipt["restart"]["backup"]["canonical"]], [2, 2])
            self.assertEqual(model.events, ["mine"] * 2 + ["wallet-control"] * 20
                             + ["backup-update", "stop", "stop", "start", "start", "rollback"])

    def test_old_direct_restart_loses_tip_despite_completed_wallet_controls(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            model = WalletBackupNetwork(directory)
            # Remove only the observation, recreating the old direct call.
            with patch.object(node_live, "restart_with_backups", side_effect=lambda network: network.restart()), \
                    self.assertRaisesRegex(common.AcceptanceError, "restart_tip"):
                self.execute_until_rollback(model, directory, {})
            self.assertEqual(model.events.count("wallet-control"), 20)
            self.assertNotIn("backup-update", model.events)
            self.assertNotIn("rollback", model.events)

    def test_invalid_backup_or_changed_reopen_cannot_reach_rollback(self):
        for mode, reason in (("wrong-tip-bytes", "ordinary_backup_did_not_preserve_tip"),
                             ("changed-reopen", "restart_tip")):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                model = WalletBackupNetwork(directory, mode)
                with self.assertRaisesRegex(common.AcceptanceError, reason):
                    self.execute_until_rollback(model, directory, {})
                self.assertNotIn("rollback", model.events)
                if mode == "wrong-tip-bytes":
                    self.assertNotIn("stop", model.events)


if __name__ == "__main__":
    unittest.main()
