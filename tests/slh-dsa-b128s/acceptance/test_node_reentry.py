"""Offline model of inherited RPC rejected-transaction retries; no processes."""
import contextlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import common
import node_live
from nodes import Network


class BackupNode:
    """Only public block bytes and an asynchronous ordinary-backup model."""
    def __init__(self, model, directory, height=2):
        self.model, self.directory, self.height = model, directory, height
        self.current = (height, "aa" * 32)
        self.backup = directory / "state/non_finalized_state/regtest-slh-dsa-b128s-v1-h110-t16-b64"
        self.backup.mkdir(parents=True)
        for block_hash in model.invalidated:
            (self.backup / block_hash).write_bytes(bytes(8) + b"old")

    def tip(self):
        return self.current

    def rpc(self, method, *args):
        if method == "getblockhash":
            return "aa" * 32 if args[0] == self.height else "11" * 32
        if method == "getblock":
            return (b"tip" if args[0] == "aa" * 32 else b"parent").hex()
        raise AssertionError(method)

    def stop(self):
        self.model.events.append("stop")

    def start(self):
        self.model.events.append("start")
        self.current = (self.height, "bb" * 32 if (self.backup / ("bb" * 32)).exists() else "aa" * 32)
        if self.model.mode == "changed-reopen":
            self.current = (self.height - 1, "11" * 32)


class BackupNetwork:
    restart = Network.restart

    def __init__(self, directory, mode="complete", height=2, invalidated=("bb" * 32,)):
        self.events, self.mode = [], mode
        self.invalidated = invalidated
        self.nodes = [BackupNode(self, directory / label, height) for label in ("a", "b")]
        self.a, self.b = self.nodes
        self.updated = False

    def wait(self, predicate, reason, timeout=60):
        if predicate():
            return
        self.events.append("backup-update")
        if not self.updated:
            self.updated = True
            for node in self.nodes:
                (node.backup / ("aa" * 32)).write_bytes(bytes(8) +
                    (b"wrong" if self.mode == "wrong-tip-bytes" else b"tip"))
                if self.mode != "missing-parent":
                    (node.backup / ("11" * 32)).write_bytes(bytes(8) + b"parent")
                if self.mode != "orphan-retained":
                    for block_hash in self.invalidated:
                        (node.backup / block_hash).unlink()
        common.require(predicate(), reason)


class BackupRestartTests(unittest.TestCase):
    def backup_waits(self, model):
        import crash_controls
        import lifecycle_controls
        import shielded_spend_controls
        stack = contextlib.ExitStack()
        for module in (crash_controls, lifecycle_controls, shielded_spend_controls):
            stack.enter_context(patch.object(module, "wait_for", side_effect=model.wait))
        return stack

    def test_old_immediate_restart_loses_tip_but_observed_restart_preserves_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            old = BackupNetwork(Path(temporary) / "old")
            with self.assertRaisesRegex(common.AcceptanceError, "restart_tip"):
                old.restart()
            self.assertNotIn("backup-update", old.events)
            current = BackupNetwork(Path(temporary) / "current")
            with self.backup_waits(current):
                result = node_live.restart_with_backups(current, excluded=("bb" * 32,))
            self.assertEqual(result["height"], 2)
            self.assertEqual(result["hash"], "aa" * 32)
            self.assertEqual(result["backup"]["excluded_block_hashes"], ["bb" * 32])
            self.assertEqual([row["blocks"] for row in result["backup"]["canonical"]], [2, 2])
            self.assertEqual(current.events, ["backup-update", "stop", "stop", "start", "start"])

    def test_every_invalidated_backup_is_excluded_before_restart(self):
        invalidated = ("bb" * 32, "cc" * 32, "dd" * 32)
        with tempfile.TemporaryDirectory() as temporary:
            model = BackupNetwork(Path(temporary), invalidated=invalidated)
            with self.backup_waits(model):
                result = node_live.restart_with_backups(model, excluded=invalidated)
            self.assertEqual(result["backup"]["excluded_block_hashes"], list(invalidated))
            self.assertTrue(all(not (node.backup / block_hash).exists()
                                for node in model.nodes for block_hash in invalidated))

    def test_missing_or_wrong_backup_and_retained_invalidated_block_prevent_shutdown(self):
        for mode, reason in (("wrong-tip-bytes", "ordinary_backup_did_not_preserve_tip"),
                             ("missing-parent", "crash_incomplete_backup"),
                             ("orphan-retained", "spend_invalidated_backup_present")):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                model = BackupNetwork(Path(temporary), mode)
                with self.backup_waits(model), self.assertRaisesRegex(common.AcceptanceError, reason):
                    node_live.restart_with_backups(model, excluded=("bb" * 32,))
                self.assertNotIn("stop", model.events)

    def test_ready_backup_does_not_excuse_a_changed_reopened_tip(self):
        with tempfile.TemporaryDirectory() as temporary:
            model = BackupNetwork(Path(temporary), "changed-reopen")
            with self.backup_waits(model), self.assertRaisesRegex(common.AcceptanceError, "restart_tip"):
                node_live.restart_with_backups(model, excluded=("bb" * 32,))

    def test_long_replay_reuses_tip_backup_without_widening_short_history_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            model = BackupNetwork(Path(temporary), height=1114)
            expected = {"height": 1114, "hash": "aa" * 32}
            with self.backup_waits(model):
                result = node_live.restart_replayed(model.a, expected)
            self.assertEqual((result["height"], result["hash"]), (1114, "aa" * 32))
            self.assertEqual(model.events, ["backup-update", "stop", "start"])
            with self.backup_waits(model), self.assertRaisesRegex(common.AcceptanceError, "crash_history_bound"):
                node_live.restart_with_backups(model)

    def test_long_replay_refuses_wrong_tip_backup_and_reopen(self):
        for mode, reason in (("wrong-tip-bytes", "ordinary_backup_did_not_preserve_tip"),
                             ("changed-reopen", "replay_restart")):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                model = BackupNetwork(Path(temporary), mode, height=1114)
                with self.backup_waits(model), self.assertRaisesRegex(common.AcceptanceError, reason):
                    node_live.restart_replayed(model.a, {"height": 1114, "hash": "aa" * 32})
                if mode == "wrong-tip-bytes":
                    self.assertNotIn("stop", model.events)


class QueuedNetwork:
    def __init__(self):
        self.height = 108
        self.queue, self.mempool, self.confirmed, self.known = {}, {}, {}, {}
        self.submissions = []
        self.race_on_submit = False
        self.nodes = [QueuedNode(self), QueuedNode(self)]
        self.a, self.b = self.nodes

    def retry(self):
        if self.height + 1 >= 110:
            self.mempool.update({key: raw for key, raw in self.queue.items() if key not in self.confirmed})

    def mine(self):
        self.retry()
        self.height += 1
        self.confirmed.update(self.mempool)
        self.mempool.clear()
        return [f"{self.height:064x}"]


class QueuedNode:
    def __init__(self, network):
        self.network = network

    def tip(self):
        return self.network.height, f"{self.network.height:064x}"

    def rpc(self, method, *args):
        if method == "getrawmempool":
            return list(self.network.mempool)
        raise AssertionError(method)

    def response(self, method, *args):
        network = self.network
        if method == "getrawtransaction":
            txid = args[0]
            if txid not in network.known:
                return {"error": {"code": -5, "message": "Transaction not found in mempool or best chain"}}
            return {"result": {"hex": network.known[txid],
                               "confirmations": 1 if txid in network.confirmed else 0}}
        if method == "sendrawtransaction":
            raw = args[0]
            txid = raw * 32
            network.submissions.append(raw)
            # Model the actual ordering: queue receives the raw bytes BEFORE
            # activation validation rejects the synchronous RPC call.
            network.queue[txid] = raw
            network.known[txid] = raw
            if network.height + 1 < 110:
                return {"error": {"code": -26, "message": "before activation"}}
            if network.race_on_submit:
                network.retry()
            if txid in network.mempool or txid in network.confirmed:
                return {"error": {"code": -27, "message": "already known"}}
            network.mempool[txid] = raw
            return {"result": txid}
        raise AssertionError(method)


class ReentryTests(unittest.TestCase):
    def transaction(self, raw="ab"):
        return {"txid": raw * 32, "raw": raw}

    def test_failed_request_is_retried_then_reconciled_in_mempool_or_chain(self):
        for mined_before_reentry in (False, True):
            with self.subTest(mined=mined_before_reentry):
                network = QueuedNetwork()
                transaction = self.transaction()
                self.assertIn("error", network.a.response("sendrawtransaction", transaction["raw"]))
                self.assertIn(transaction["txid"], network.queue)
                self.assertFalse(network.mempool)
                network.mine()  # candidate109: still rejected
                network.retry()  # candidate110: queue can accept before our driver
                if mined_before_reentry:
                    network.mine()
                receipt = node_live.reconcile_saved(network, [transaction], 1)
                self.assertEqual(receipt["initial_states"][transaction["txid"]],
                                 "confirmed" if mined_before_reentry else "mempool")
                self.assertEqual(network.submissions, [transaction["raw"]])
                self.assertEqual(network.confirmed[transaction["txid"]], transaction["raw"])
                self.assertEqual(len(receipt["mined_blocks"]), 0 if mined_before_reentry else 1)

    def test_orphan_lookup_is_not_active_acceptance_and_racing_retry_is_authenticated(self):
        network = QueuedNetwork()
        transaction = self.transaction()
        network.a.response("sendrawtransaction", transaction["raw"])
        self.assertEqual(node_live.transaction_state(network.a, transaction), "absent")
        network.height = 110
        network.race_on_submit = True
        receipt = node_live.reconcile_saved(network, [transaction], 1)
        self.assertEqual(receipt["initial_states"][transaction["txid"]], "absent")
        self.assertEqual(network.submissions, [transaction["raw"]] * 2)
        self.assertIn(transaction["txid"], network.confirmed)

    def test_unexpected_rpc_error_and_mismatched_saved_bytes_fail(self):
        network = QueuedNetwork()
        transaction = self.transaction()
        network.known[transaction["txid"]] = "different bytes"
        with self.assertRaisesRegex(common.AcceptanceError, "saved_transaction_bytes"):
            node_live.reconcile_saved(network, [transaction], 1)
        network.a.response = lambda *args: {"error": {"code": -1, "message": "backend unavailable"}}
        with self.assertRaisesRegex(common.AcceptanceError, "saved_transaction_lookup"):
            node_live.reconcile_saved(network, [transaction], 1)


if __name__ == "__main__":
    unittest.main()
