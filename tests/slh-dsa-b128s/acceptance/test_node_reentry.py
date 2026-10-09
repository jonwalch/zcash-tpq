"""Offline model of inherited RPC rejected-transaction retries; no processes."""
import unittest

import common
import node_live


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
