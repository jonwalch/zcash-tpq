"""Offline driver mocks: no host, signer, daemon, or live process is launched."""
from contextlib import ExitStack
from copy import deepcopy
from decimal import Decimal
import hashlib
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from common import AcceptanceError
import transparent_controls as controls


def identity(value):
    return hashlib.sha256(value.encode()).hexdigest()


class Ledger:
    """Small independent chain/UTXO model; fixture operations are mocked only."""
    public = "33" * 32
    classical_script = "a914" + "22" * 20 + "87"

    def __init__(self):
        self.height = 0
        self.chain = {0: "genesis"}
        self.blocks, self.transactions, self.known, self.pool = {}, {}, {}, []
        self.calls, self.restarts, self.mixed_recipes = [], [], []
        self.serial = 0
        self.nodes = [FakeNode(self), FakeNode(self)]
        self.a, self.b = self.nodes
        self.closed = False
        self.wrong_proposal = self.change_on_reject = self.missing_parent = False
        self.wrong_raw = self.wrong_block_order = self.corrupt_positive_auth = False
        self.wrong_signer = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.closed = True

    def tx(self, name, outputs, spends=(), *, txid=None, reason=None):
        raw = name.encode().hex()
        result = {"transaction_hex": raw, "transaction_sha256": identity(name),
            "txid": txid or identity("effects:" + name), "auth_digest": identity("auth:" + name),
            "outputs": [dict(row, output_index=index) for index, row in enumerate(outputs)]}
        self.transactions[raw] = dict(result, spends=list(spends), reason=reason, name=name)
        return result

    def mined(self):
        return {raw: height for height, block in self.chain.items()
                for raw in self.blocks.get(block, {}).get("raws", [])}

    def output(self, txid, index):
        mined = self.mined()
        found = [(raw, tx) for raw, tx in self.transactions.items()
                 if tx["txid"] == txid and raw in mined]
        if not found or any((txid, index) in self.transactions[raw]["spends"] for raw in mined):
            return None
        if self.missing_parent and self.transactions[found[0][0]]["name"] == "funding":
            return None
        raw, tx = found[0]
        row = tx["outputs"][index]
        return {"value": Decimal(row["value_zat"]) / 100_000_000,
            "scriptPubKey": {"hex": row["script_hex"]}, "coinbase": tx["name"].startswith("coinbase"),
            "confirmations": self.height - mined[raw] + 1}

    def commit(self, block):
        self.height = block["height"]
        self.chain[self.height] = block["block_hash"]
        self.blocks[block["block_hash"]] = block
        for raw in block["raws"]:
            self.known[self.transactions[raw]["txid"]] = raw
        self.pool.clear()

    def mine(self, count=1):
        hashes = []
        for _ in range(count):
            self.serial += 1
            height = self.height + 1
            coinbase = self.tx(f"coinbase-{height}-{self.serial}", [
                {"value_zat": 100_000_000, "script_hex": self.classical_script}])
            raws = [coinbase["transaction_hex"], *self.pool]
            block_hash = identity(f"generated:{self.serial}:{height}")
            self.commit({"block_hash": block_hash, "height": height, "raws": raws,
                         "block_hex": f"generated-{self.serial}"})
            hashes.append(block_hash)
        return hashes

    def restart(self):
        self.pool.clear()
        self.restarts.append(self.height)
        return {"height": self.height, "hash": self.chain[self.height]}

    def metadata(self):
        assert self.closed
        return {"mock_stopped": True}

    def coinbase(self, _nodes, height, script):
        assert script == self.classical_script and self.height - height + 1 >= 100
        raw = self.blocks[self.chain[height]]["raws"][0]
        tx = self.transactions[raw]
        assert self.output(tx["txid"], 0) is not None
        return {"parent_hex": raw, "txid": tx["txid"], "output_index": 0}

    def signer(self, _binary, operation, **fields):
        if operation == "keygen":
            return {"public_key": self.public, "secret_key": "public mock key"}
        assert operation == "sign" and fields["secret_key"] == "public mock key"
        return {"public_key": "44" * 32 if self.wrong_signer else self.public,
                "signature": "mock signature"}

    def slh(self, _args, keys, _producer, txid, index, _expiry, _case):
        assert keys == {self.public: "public mock key"} and index == 1
        _, script = controls.policy([self.public], 1)
        return self.tx("slh-positive", [{"value_zat": 2_000_000, "script_hex": script}], [(txid, index)])

    def host(self, _binary, operation, **fields):
        self.calls.append((operation, deepcopy(fields)))
        if operation == "classical-info":
            assert fields["kind"] == "multisig"
            return {"ecdsa_checks": 2, "address": "public fixture", "script_hex": self.classical_script}
        recipe = fields["recipe"]
        if operation in ("classical-spend", "control-funding"):
            parent = self.transactions[recipe["parent_hex"]]
            index = recipe["output_index"]
            assert self.output(parent["txid"], index) is not None
            outputs = deepcopy(recipe["outputs"])
            change = parent["outputs"][index]["value_zat"] - sum(o["value_zat"] for o in outputs) - recipe["fee_zat"]
            outputs.append({"value_zat": change, "script_hex": self.classical_script})
            name = "funding" if operation == "control-funding" else (
                "dust" if outputs[0]["value_zat"] == 2402 else "classical-positive")
            return self.tx(name, outputs, [(parent["txid"], index)])
        if operation == "control-authorization":
            original = self.transactions[recipe["transaction_hex"]]
            name = recipe["variant"]
            donor = recipe["donor_transaction_hex"]
            assert bool(donor) == (name in ("slh-on-classical", "classical-on-slh"))
            reason = "script" if "classical" in name and name != "classical-on-slh" else (
                "encoding" if name == "classical-on-slh" else "signature")
            result = self.tx(name, original["outputs"], original["spends"], txid=original["txid"], reason=reason)
            result.update(variant=name, positive_transaction_sha256=original["transaction_sha256"],
                positive_auth_digest=identity("wrong") if self.corrupt_positive_auth else original["auth_digest"],
                expected_consensus_reason=reason)
            return result
        if operation in ("mixed-prepare", "mixed-assemble"):
            expected = {"multisig": 2, "unsupported51": 4, "unsupported52": 5}[recipe["kind"]]
            assert recipe["classical"]["output_index"] == expected
            assert recipe["slh"]["output_index"] == 3
            assert recipe["classical"]["parent_hex"] == recipe["slh"]["parent_hex"]
            parent = self.transactions[recipe["slh"]["parent_hex"]]
            assert self.output(parent["txid"], expected) and self.output(parent["txid"], 3)
            prepared = {"slh_input_index": int(recipe["classical_first"]), "public_key_hex": self.public,
                        "message_hex": identity(str(sorted(recipe.items())))}
            if operation == "mixed-prepare":
                self.mixed_recipes.append(deepcopy(recipe))
                return prepared
            assert fields["record"]["signature_hex"] == "mock signature"
            result = self.tx(f'mixed-{recipe["kind"]}-{recipe["classical_first"]}',
                [{"value_zat": 5_900_000, "script_hex": self.classical_script}],
                [(parent["txid"], expected), (parent["txid"], 3)], reason="mixed")
            result.update(prepared, slh_checks=1, ecdsa_checks=2 if expected == 2 else 0)
            return result
        assert operation == "control-block"
        assert recipe["template"]["height"] == self.height + 1
        raws = [tx["transaction_hex"] for tx in recipe["transactions"]]
        assert all(self.output(txid, index) is not None
                   for raw in raws for txid, index in self.transactions[raw]["spends"])
        block_hash = identity(str(recipe["nonce"]))
        result = {"block_hash": block_hash, "block_hex": "block-" + str(recipe["nonce"]),
            "height": self.height + 1, "txids": [self.transactions[raw]["txid"] for raw in raws],
            "aggregate_fee_zat": sum(tx["fee_zat"] for tx in recipe["transactions"])}
        self.blocks[result["block_hex"]] = dict(result, raws=raws)
        return result


class FakeNode:
    def __init__(self, ledger):
        self.state = ledger

    def tip(self):
        return self.state.height, self.state.chain[self.state.height]

    def response(self, method, *args):
        state = self.state
        if method == "getrawtransaction":
            raw = state.known.get(args[0])
            if raw is None:
                return {"error": {"code": -5, "message": "No such transaction found; not found"}}
            return {"result": {"hex": raw, "confirmations": state.height - state.mined()[raw] + 1
                               if raw in state.mined() else 0}}
        assert method == "sendrawtransaction"
        tx = state.transactions[args[0]]
        name, active = tx["name"], state.height + 1 >= 110
        if name.startswith("mixed"):
            message = ("active SLH transparent inputs cannot be mixed with other transparent input types"
                       if active else "mempool transaction input 0 has a 8000 byte scriptSig, above the 1650 byte standardness limit")
        elif name == "funding" and not active:
            message = "mempool transaction output 1 uses SLH before activation"
        elif name == "dust":
            message = "mempool transaction output 0 is below the SLH dust threshold"
        elif name == "slh-on-classical":
            message = "mempool transaction input 0 has a 8000 byte scriptSig, above the 1650 byte standardness limit"
        elif name == "classical-on-slh":
            message = "mempool transaction has non-standard transparent inputs"
        elif name == "missing-classical-quorum":
            message = "could not verify a transparent script: INVALID_STACK_OPERATION"
        elif name == "corrupt-slh":
            message = "experimental SLH-DSA-B-128s authorization failed for transparent input 0: signature"
        else:
            assert not tx["reason"] and active
            state.known[tx["txid"]] = args[0]
            if args[0] not in state.pool:
                state.pool.append(args[0])
            return {"result": tx["txid"]}
        if state.change_on_reject:
            state.mine()
        return {"error": {"code": -25, "message": message}}

    def rpc(self, method, *args):
        state = self.state
        if method == "gettxout":
            return state.output(args[0], args[1])
        if method == "getrawmempool":
            return [state.transactions[raw]["txid"] for raw in state.pool]
        if method == "getblockhash":
            return state.chain[args[0]]
        if method == "getrawtransaction":
            result = self.response(method, *args)["result"]
            return dict(result, hex="different bytes") if state.wrong_raw else result
        if method == "invalidateblock":
            if args[0] in state.chain.values():
                height = next(h for h, value in state.chain.items() if value == args[0])
                state.chain = {h: value for h, value in state.chain.items() if h < height}
                state.height = height - 1
            return None
        if method == "getblock":
            block = state.blocks[args[0]]
            if args[1] == 0:
                return block["block_hex"]
            txids = [state.transactions[raw]["txid"] for raw in block["raws"]]
            return {"tx": ["coinbase", *(reversed(txids) if state.wrong_block_order else txids)]}
        if method == "getblocktemplate" and not args:
            return {"transactions": [{"data": raw} for raw in state.pool], "height": state.height + 1}
        assert method in ("submitblock", "getblocktemplate"), method
        raw = args[0] if method == "submitblock" else args[0]["data"]
        block = state.blocks[raw]
        reasons = [state.transactions[tx]["reason"] for tx in block["raws"]]
        reason = next((value for value in reasons if value), None)
        if reason:
            if method == "submitblock":
                return "rejected"
            if state.wrong_proposal:
                return "transaction-expired"
            if reason == "mixed":
                return "transaction-experimentalslhdsab128smixedinputs" if state.height + 1 >= 110 else "transaction-script-invalid"
            return "transaction-script-invalid" if reason == "script" else (
                "transaction-experimentalslhdsab128s-input-index-0-reason-" + reason)
        if method == "submitblock":
            state.commit(block)
        return None


class TransparentDriverTests(unittest.TestCase):
    def run_flow(self, state):
        args = SimpleNamespace(host=Path("public-host"), signer=Path("public-signer"),
                               node=Path("public-node"), root=Path("product"), version=5)
        receipt = {}
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            for name, replacement in {"Network": lambda *_: state, "host_call": state.host,
                    "signer_call": state.signer, "authenticate_coinbase": state.coinbase,
                    "single_artifact": state.slh, "producer_identity": lambda *_: ({}, {})}.items():
                stack.enter_context(patch.object(controls, name, side_effect=replacement))
            controls.execute(args, Path(directory), receipt)
        return receipt

    def test_real_driver_runs_funded_controls_and_saved_byte_reentry_through_both_rollbacks(self):
        state = Ledger()
        receipt = self.run_flow(state)
        self.assertEqual(receipt["preactivation_funding_block"]["height"], 108)
        self.assertEqual(receipt["dust_block"]["height"], 111)
        self.assertEqual(len(receipt["separate_transactions_same_block"]["txids"]), 2)
        self.assertFalse(receipt["positive_preflight"]["published"])
        self.assertEqual(state.restarts, [111, 108])
        self.assertEqual(receipt["final_tip"]["height"], 110)
        self.assertEqual([(r["kind"], r["classical_first"]) for r in state.mixed_recipes],
            [(kind, first) for kind in ("multisig", "unsupported51", "unsupported52") for first in (True, False)])
        for key in ("mixed_active", "mixed_after_reorg", "mixed_before_activation", "mixed_reactivation"):
            self.assertEqual(len(receipt[key]), 6)
            self.assertTrue(all(row["parents_present"] and row["tip_and_utxos_unchanged"] for row in receipt[key]))
        for key in ("authorization", "authorization_after_reorg", "authorization_reactivation"):
            self.assertEqual(len(receipt[key]), 4)
        self.assertEqual({row["tip"]["height"] for row in receipt["mixed_before_activation"]}, {108})
        self.assertEqual({row["tip"]["height"] for row in receipt["mixed_reactivation"]}, {109})
        self.assertEqual(set(receipt["same_txid_reentry"]["initial_states"].values()), {"absent"})
        self.assertEqual(set(receipt["reactivated_saved_bytes"]["initial_states"].values()), {"absent"})
        positive_raws = {raw for raw, tx in state.transactions.items()
                         if tx["name"] in ("classical-positive", "slh-positive")}
        for key in ("same_txid_reentry", "reactivated_saved_bytes"):
            mined = receipt[key]["mined_blocks"]
            self.assertEqual(len(mined), 1)
            self.assertEqual(set(state.blocks[mined[0]]["raws"][1:]), positive_raws)

    def test_wrong_reason_changed_state_wrong_bytes_and_wrong_identity_fail_closed(self):
        for field, diagnostic in (("wrong_proposal", "transparent_wrong_proposal_rejection"),
                ("change_on_reject", "rejected_control_changed_tip"),
                ("wrong_raw", "transparent_positive_transaction_bytes"),
                ("corrupt_positive_auth", "transparent_positive_identity_changed"),
                ("wrong_signer", "transparent_mixed_signer")):
            with self.subTest(field=field):
                state = Ledger()
                setattr(state, field, True)
                with self.assertRaisesRegex(AcceptanceError, diagnostic):
                    self.run_flow(state)

    def test_direct_block_checks_order_and_missing_funding_is_not_a_valid_negative(self):
        for field, diagnostic in (("wrong_block_order", "transparent_positive_block_bytes"),
                                  ("missing_parent", "authenticated_funding_output")):
            with self.subTest(field=field):
                state = Ledger()
                setattr(state, field, True)
                with self.assertRaisesRegex(AcceptanceError, diagnostic):
                    self.run_flow(state)

    def test_unrelated_rpc_errors_and_proposal_failures_cannot_count_as_controls(self):
        for error in ({"code": -25, "message": "missing inputs"}, {"code": -25, "message": "expired"},
                      {"code": -32603, "message": "could not verify a transparent script"},
                      {"code": True, "message": "could not verify a transparent script"}):
            node = SimpleNamespace(response=lambda *_: {"error": error})
            with self.assertRaises(AcceptanceError):
                controls.reject_relay(node, "public", controls.CLASSICAL_SCRIPT)
        for result in (None, {}, "wrong-parent", "transaction-expired", "transaction-script-invalid"):
            with self.assertRaises(AcceptanceError):
                controls.proposal_rejection(result, "mixed")


if __name__ == "__main__":
    unittest.main()
