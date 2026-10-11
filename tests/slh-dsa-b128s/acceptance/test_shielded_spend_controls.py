"""Offline trusted-history and causal-state models; no proofs, signing or nodes."""
from contextlib import ExitStack
from copy import deepcopy
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from common import AcceptanceError
import nodes
import shielded_spend_controls as controls
from test_shielded_controls import SCRIPT, identity, row


def wait(predicate, reason, *_):
    if not predicate():
        raise AcceptanceError(reason)


def fixture(pools=("sapling", "orchard", "ironwood"), version=6):
    pools = list(pools)
    parent = dict(txid=identity("parent"), parent_hex="abcd", output_index=0,
                  value_zat=3_000_000, script_hex=SCRIPT)
    tree = dict(height=113, hash=identity("anchor-block"), **{p: {"commitments": {"finalRoot": identity(p)}} for p in controls.POOLS})
    history = dict(blocks=["ab"], treestate=tree)
    recipe = dict(human_run=True, transaction_version=version, pools=pools, parent_hex="abcd",
        output_index=0, expiry_height=210, authorization="slh", public_key_hex="33"*32,
        sapling_parameters=None, history=history, funding_txids=[dict(pool=p, txid=identity("funding"+p)) for p in pools])
    positive = row("positive", pools)
    positive["outputs"][0]["value_zat"] = 3_000_000 + 50000*len(pools) - 100000
    components = {p: dict(spend_auth=[True]*(1 if p == "sapling" else 2), binding=True,
                          proof=None if p == "sapling" else True) for p in pools}
    result = dict(material="public-test-only", version=version, pools=pools, parent_txid=parent["txid"], parent_index=0,
        parent_value_zat=3_000_000, parent_script_hex=SCRIPT, parent_transaction_sha256=hashlib.sha256(bytes.fromhex("abcd")).hexdigest(),
        fee_zat=100000, withdrawal_zat=50000*len(pools), deposit_zat=0, orchard_value_zat=50000*int("orchard" in pools),
        proof_profile="real-spend-post-nu6.3", parameters=None, history_sha256=controls.digest(history),
        anchor_height=113, anchor_block_hash=tree["hash"], positive=positive, positive_pool_valid=dict.fromkeys(pools, True),
        positive_components=components, notes=[], variants=[])
    for p in pools:
        result["notes"].append(dict(pool=p, funding_txid=identity("funding"+p), funding_height=111,
            funding_output_index=0, position=0, value_zat=50000, anchor=identity(p), nullifier=identity("nf"+p),
            commitment=identity("cm"+p), commitment_count=4, real_spend_index=0 if p == "sapling" else 1))
        for mutation in ("spend_auth", "binding", "proof"):
            variant = row(p+mutation, pools)
            variant["outputs"] = deepcopy(positive["outputs"])
            detail = deepcopy(components)
            if mutation == "spend_auth": detail[p]["spend_auth"][0 if p == "sapling" else 1] = False
            elif mutation == "binding": detail[p]["binding"] = False
            elif p != "sapling": detail[p]["proof"] = False
            result["variants"].append(dict(variant, pool=p, mutation=mutation,
                pool_valid={other: other != p for other in pools}, components=detail))
    return recipe, parent, result


class HistoryNode:
    def __init__(self):
        self.hashes = [controls.GENESIS, identity("block1"), identity("block2")]
        self.raws = ["00", "01", "02"]
        self.calls = []
        self.parent = dict(txid=identity("parent"), output_index=0, value_zat=3_000_000, script_hex=SCRIPT)
        self.funding = dict(txid=identity("funding"), transaction_hex="cdef")
        self.chain = "test"
        self.change_tip = self.spent = self.wrong_link = self.wrong_funding = False
        self.root = "ab"*32

    def tip(self):
        return 2, self.hashes[-1]

    def rpc(self, method, *params):
        self.calls.append((method, params))
        if method == "getblockchaininfo":
            return dict(chain=self.chain, blocks=2, bestblockhash=self.hashes[-1])
        if method == "z_gettreestate":
            return dict(height=2, hash=identity("changed") if self.change_tip and sum(m == "z_gettreestate" for m, _ in self.calls) > 1 else self.hashes[-1],
                **{p: {"commitments": {"finalRoot": self.root}} for p in controls.POOLS})
        if method == "getblockhash": return self.hashes[params[0]]
        if method == "getblock":
            index = self.hashes.index(params[0])
            if params[1] == 0: return self.raws[index]
            return dict(hash=params[0], height=index, previousblockhash=(identity("wrong") if self.wrong_link else self.hashes[index-1]), tx=[self.funding["txid"]])
        if method == "gettxout":
            return None if self.spent else dict(confirmations=10, value=Decimal("0.03"), coinbase=False, scriptPubKey={"hex": SCRIPT})
        if method == "getrawtransaction":
            return dict(hex="aaaa" if self.wrong_funding else self.funding["transaction_hex"], confirmations=1, blockhash=self.hashes[1])
        raise AssertionError((method, params))


class Model:
    def __init__(self, pools=("sapling", "orchard", "ironwood")):
        self.pools = list(pools)
        self.args = SimpleNamespace(host="host", classical="single", pools=self.pools)
        _, parent, fixture_row = fixture(pools)
        self.parents = [parent, dict(parent, output_index=1)]
        self.positive = dict(fixture_row["positive"], fee_zat=100000)
        self.duplicate = deepcopy(self.positive)
        self.duplicate.update(transaction_hex="1234", transaction_sha256=hashlib.sha256(bytes.fromhex("1234")).hexdigest(),
            txid=identity("duplicate"), message_hex="02"*101, auth_digest=identity("duplicate-auth"))
        self.variants = [dict({k: r[k] for k in controls.outputs.WIRE}, pool=r["pool"], mutation=r["mutation"], fee_zat=100000) for r in fixture_row["variants"]]
        self.txs = {tx["transaction_hex"]: tx for tx in [self.positive, self.duplicate, *self.variants]}
        self.nodes = [StateNode(self, i) for i in range(2)]
        self.a, self.b = self.nodes
        self.blocks = {}
        self.calls = []
        self.nonce = 0
        self.no_rollback = self.no_reconsider = self.no_reentry = self.no_relay = self.no_mining = False
        self.wrong_reason = self.wrong_proposal = self.no_tree = self.bad_parent = False
        self.skip_replacement = False
        self.refuse_reentry = self.duplicate_reentry = False
        self.wrong_reentry_block = self.wrong_reentry_transaction = self.unconfirmed_reentry = False
        self.wrong_reentry_membership = self.wrong_reentry_transaction_block = False
        self.anchor = dict(block_hash=identity("anchor-block"), block_hex="aabb", height=113)
        self.anchor["block_sha256"] = hashlib.sha256(bytes.fromhex("aabb")).hexdigest()
        self.spent_hash = None

    def host(self, _, op, **fields):
        assert op == "shielded-spend-block"
        self.nonce += 1
        recipe = fields["recipe"]
        tx = self.txs[recipe["transactions"][0]["transaction_hex"]]
        raw = str(self.nonce).encode().hex()
        result = dict(block_hex=raw, block_sha256=hashlib.sha256(bytes.fromhex(raw)).hexdigest(),
            block_hash=identity(raw), height=self.a.height+1, txids=[tx["txid"]], aggregate_fee_zat=tx["fee_zat"])
        self.blocks[raw] = dict(result, tx=tx)
        return result

    def restart(self):
        self.calls.append("restart")
        for node in self.nodes:
            node.pool = []
            node.invalidated.clear()

    def mine(self, count=1):
        hashes = []
        for _ in range(count):
            tx = self.txs[self.a.pool[0]] if self.a.pool else None
            if tx:
                assert tx is self.positive
                assert all(n.negative == {(p,m) for p in self.pools for m in ("spend_auth","binding","proof")} and n.valid_after for n in self.nodes), "skipped subject authorization operations"
                if self.spent_hash:
                    assert self.a.height >= 115, "missing replacement branch"
            self.nonce += 1
            raw = ("mined"+str(self.nonce)).encode().hex()
            block = dict(block_hash=identity(raw), block_hex=raw, height=self.a.height+1, tx=tx)
            self.blocks[raw] = block
            hashes.append(block["block_hash"])
            if not self.no_mining and not (self.skip_replacement and tx is None):
                for node in self.nodes:
                    node.height, node.hash = block["height"], block["block_hash"]
                    node.chain[node.height] = node.hash
                    if tx: node.stage = 2; node.saved = tx
                    node.pool = []
            if tx: self.spent_hash = block["block_hash"]
        return hashes


class StateNode:
    def __init__(self, model, index):
        self.model, self.index = model, index
        self.height, self.hash, self.stage = 113, identity("anchor-block"), 1
        self.chain = {112: identity("baseline"), 113: self.hash}
        self.pool = []
        self.saved = None
        self.valid_before = False
        self.valid_after = False
        self.negative = set()
        self.negative_submitted = set()
        self.anchor_rejected = False
        self.duplicate_preflight = False
        self.invalidated = set()
        self.reentry_block = None

    def tip(self): return self.height, self.hash

    def failure(self, tx):
        if self.stage == 0: return f"unknown {self.model.pools[0]} anchor", "unknown"+self.model.pools[0]+"anchor"
        if tx is self.model.duplicate and self.stage == 2:
            # Unrelated refusals replace only the targeted duplicate-nullifier reason.
            if self.model.wrong_reason: return "missing transparent input", "missinginput"
            return (f"{self.model.pools[0]} double-spend: duplicate nullifier",
                    "missinginput" if self.model.wrong_proposal else "duplicate"+self.model.pools[0]+"nullifier")
        if "pool" in tx:
            return (("sapling proof or signature verification failed", "saplingverificationfailed") if tx["pool"] == "sapling" else
                    ("orchard or ironwood halo2 proof verification failed", "halo2verificationfailed"))
        return None

    def response(self, method, *params):
        if method == "getrawtransaction":
            tx = next(t for t in self.model.txs.values() if t["txid"] == params[0])
            if self.saved or tx["transaction_hex"] in self.pool:
                replay_peer = self.index == 1 and self.reentry_block
                raw = "ffff" if replay_peer and self.model.wrong_reentry_transaction else tx["transaction_hex"]
                confirmed = self.stage == 2 and not (replay_peer and self.model.unconfirmed_reentry)
                blockhash = identity("wrong-block") if replay_peer and self.model.wrong_reentry_transaction_block else self.hash
                return {"result": {"hex": raw, "confirmations": int(confirmed), "blockhash": blockhash}}
            return {"error": {"code": -5, "message": "transaction not found"}}
        assert method == "sendrawtransaction"
        tx = self.model.txs[params[0]]
        fail = self.failure(tx)
        if fail:
            if "pool" in tx: assert self.valid_before, "missing positive preflight"
            if tx is self.model.duplicate: assert self.duplicate_preflight, "missing duplicate positive control"
            if self.stage == 0: self.anchor_rejected = True
            self.model.calls.append((self.index, "reject-relay", tx["transaction_hex"]))
            return {"error": {"code": -25, "message": fail[0]}}
        assert self.valid_after and self.negative == self.negative_submitted, "skipped final positive or negative submissions"
        if not self.model.no_relay and not (self.model.no_reentry and self.model.spent_hash):
            for node in self.model.nodes: node.pool = [params[0]]
        self.model.calls.append((self.index, "relay", params[0]))
        return {"result": tx["txid"]}

    def rpc(self, method, *params):
        model = self.model
        if method == "getblockchaininfo":
            return dict(blocks=self.height, bestblockhash=self.hash,
                valuePools=[dict(id=p, chainValueZat=(50000 + (50000 if self.stage>0 and p!="orchard" else 0) - (50000 if self.stage==2 else 0)) if p in model.pools else 0) for p in controls.POOLS])
        if method == "z_gettreestate":
            return dict(height=self.height, hash=self.hash, **{p: {"commitments": {"finalRoot": identity(p+str(0 if model.no_tree else self.stage if p in model.pools else 0))}} for p in controls.POOLS})
        if method == "gettxout":
            if params[0] == model.parents[0]["txid"]:
                if self.stage == 2 and (params[1] == 0 or model.bad_parent): return None
                return dict(value=Decimal("0.03"), scriptPubKey={"hex": SCRIPT}, confirmations=10, coinbase=False)
            if self.stage == 2 and params[0] == model.positive["txid"]:
                return dict(value=Decimal(model.positive["outputs"][0]["value_zat"])/100_000_000,
                    scriptPubKey={"hex": SCRIPT}, confirmations=1, coinbase=False)
            return None
        if method == "getrawmempool": return [model.txs[raw]["txid"] for raw in self.pool]
        if method == "getblocktemplate":
            if not params: return {"transactions": [{"hash": model.txs[raw]["txid"], "data": raw} for raw in self.pool]}
            tx = model.blocks[params[0]["data"]]["tx"]
            failure = self.failure(tx)
            if failure:
                if "pool" in tx: self.negative.add((tx["pool"],tx["mutation"]))
                return "context-"+failure[1]
            if tx is model.duplicate: self.duplicate_preflight = True
            else:
                self.valid_before = True
                if self.negative: self.valid_after = True
            return None
        if method == "submitblock":
            tx = model.blocks[params[0]]["tx"]
            if self.failure(tx):
                if "pool" in tx: self.negative_submitted.add((tx["pool"], tx["mutation"]))
                model.calls.append((self.index, "reject-block", tx["transaction_hex"]))
                return "rejected"
            assert tx is model.positive and model.spent_hash and self.height == 115
            assert all(n.valid_after and n.negative == n.negative_submitted ==
                       {(p,m) for p in model.pools for m in ("spend_auth","binding","proof")}
                       for n in model.nodes), "skipped replacement authorization bracket"
            model.calls.append((self.index, "accept-block", params[0]))
            if model.refuse_reentry and self.index == 1: return "rejected"
            if not model.no_reentry:
                block = model.blocks[params[0]]
                self.height, self.hash, self.stage = block["height"], block["block_hash"], 2
                self.chain[self.height] = self.hash
                self.saved, self.pool, self.reentry_block = tx, [], self.hash
            return "duplicate" if model.duplicate_reentry else None
        if method == "invalidateblock":
            self.invalidated.add(params[0])
            if not model.no_rollback:
                if params[0] == model.anchor["block_hash"]: self.height,self.hash,self.stage = 112,identity("baseline"),0
                else:
                    assert self.stage == 2
                    self.height,self.hash,self.stage = 113,identity("anchor-block"),1
                    self.valid_before = self.valid_after = False
                    self.negative.clear(); self.negative_submitted.clear()
            return None
        if method == "reconsiderblock":
            # Inherited invalidated-block records are memory-only; the RPC rejects unknown records.
            if params[0] not in self.invalidated: raise AcceptanceError("rpc_rejected_reconsiderblock")
            assert self.anchor_rejected, "unknown-anchor subject skipped"
            if not model.no_reconsider: self.height,self.hash,self.stage = 113,identity("anchor-block"),1
            return None
        if method == "getblockhash": return self.chain[params[0]]
        if method == "getblock":
            block = model.anchor if params[0] == model.anchor["block_hash"] else next(b for b in model.blocks.values() if b["block_hash"] == params[0])
            replay_peer = self.index == 1 and self.reentry_block
            if params[1] == 0:
                return "ffff" if replay_peer and model.wrong_reentry_block else block["block_hex"]
            return {"tx": ["coinbase", identity("wrong-tx") if replay_peer and model.wrong_reentry_membership else model.positive["txid"]]}
        if method == "getrawtransaction": return self.response(method, *params)["result"]
        raise AssertionError((method, params))


class PendingRelayNetwork:
    """Model independent RPC admission and delayed or absent peer propagation."""
    def __init__(self):
        self.tx = row("funding", ("orchard",))
        self.mined = self.never_arrives = self.wrong_bytes = self.wrong_template = self.refused = False
        self.no_gossip = self.peer_refused = self.already_in_mempool = self.observed_peer = False
        self.no_admission = self.peer_wrong_template = self.peer_empty_template = False
        self.nodes = [PendingRelayNode(self, index) for index in range(2)]
        self.a, self.b = self.nodes
        self.block_hash = identity("funding-block")

    def mine(self):
        assert all(node.raw == self.tx["transaction_hex"] and node.template_seen for node in self.nodes)
        self.mined = True
        return [self.block_hash]


class PendingRelayNode:
    def __init__(self, network, index):
        self.network, self.index = network, index
        self.raw, self.pending, self.template_seen = None, False, False
        self.lookups = 0
        self.submissions = []

    def response(self, method, *params):
        tx = self.network.tx
        if method == "sendrawtransaction":
            self.submissions.append(params[0])
            if self.index == 1:
                if self.network.peer_refused:
                    return {"error": {"code": -25, "message": "invalid proof"}}
                if self.network.no_gossip:
                    if not self.network.no_admission:
                        self.raw = "ffff" if self.network.wrong_bytes else params[0]
                    return {"result": tx["txid"]}
                if self.network.already_in_mempool:
                    self.raw = tx["transaction_hex"]
                    return {"error": {"code": -1, "message": "transaction already exists in mempool"}}
                return {"error": {"code": -1, "message": "transaction dropped because it is already queued for download"}}
            if self.network.refused:
                return {"error": {"code": -25, "message": "invalid proof"}}
            assert params == (tx["transaction_hex"],)
            self.raw = params[0]
            self.network.b.pending = not self.network.no_gossip
            if self.network.observed_peer: self.network.b.raw = params[0]
            return {"result": tx["txid"]}
        assert method == "getrawtransaction" and params == (tx["txid"], 1)
        self.lookups += 1
        if self.pending and self.lookups >= 3 and not self.network.never_arrives:
            self.raw = "ffff" if self.network.wrong_bytes else tx["transaction_hex"]
        if self.raw is None:
            return {"error": {"code": -5, "message": "transaction not found"}}
        return {"result": {"hex": self.raw, "confirmations": int(self.network.mined)}}

    def rpc(self, method, *params):
        tx = self.network.tx
        if method == "getrawmempool":
            return [tx["txid"]] if self.raw and not self.network.mined else []
        if method == "getblocktemplate":
            self.template_seen = True
            if self.index == 1 and self.network.peer_empty_template:
                return {"transactions": []}
            wrong = self.network.wrong_template or (self.index == 1 and self.network.peer_wrong_template)
            return {"transactions": [{"hash": tx["txid"], "data": "ffff" if wrong else self.raw}]}
        if method == "getblock":
            assert params[0] == self.network.block_hash
            return "aabb" if params[1] == 0 else {"tx": [tx["txid"]]}
        if method == "gettxout":
            assert self.network.mined and params == (tx["txid"], 0, False)
            output = tx["outputs"][0]
            return dict(value=Decimal(output["value_zat"])/100_000_000,
                        scriptPubKey={"hex": output["script_hex"]}, confirmations=1, coinbase=False)
        raise AssertionError((method, params))

    def tip(self):
        return (102, self.network.block_hash) if self.network.mined else (101, identity("funding-parent-block"))


class ExecuteNetwork:
    """Funding-order recorder around the actual execute driver; lifecycle is tested separately."""
    def __init__(self, directory, pools):
        self.pools, self.height, self.events, self.lifecycle = list(pools), 0, [], None
        self.proofs, self.finalized, self.signed = {}, [], []
        self.duplicate_note = self.change_history = self.change_signed = self.change_state = False
        self.directory, self.script = directory, controls.policy(["33"*32], 1)[1]
        self.nodes = [SimpleNamespace(tip=lambda: (self.height, identity(str(self.height))),
                                      config=directory / f"node-{index}.toml") for index in range(2)]
        for node in self.nodes: node.config.write_text("public config")

    def __call__(self, binary, artifacts, miner, *, activation_heights):
        self.events.append(("network", activation_heights))
        return self

    def __enter__(self): return self

    def __exit__(self, *_): self.events.append("closed")

    def metadata(self): return [{"mock": True}]

    def mine_to(self, network, height):
        assert network is self and self.height <= height
        self.events.append(("mine_to", height)); self.height = height

    def coinbase(self, nodes, height, script):
        assert nodes is self.nodes and script == SCRIPT
        self.events.append(("coinbase", height))
        return dict(txid=identity(f"coinbase{height}"), parent_hex=f"{height:02x}", output_index=0, value_zat=625_000_000, script_hex=SCRIPT)

    def orchard_deposit(self, args, network, artifacts, parent):
        self.events.append(("orchard-funding", self.height, parent["txid"])); self.height += 1
        return {"txid": identity("orchard-note")}

    def output_deposit(self, args, network, artifacts, parent, pools, label):
        self.events.append((label, self.height, parent["txid"], list(pools))); self.height += 1
        return {"txid": identity(label)}, {"block_hash": identity(label + "-block"), "height": self.height}

    def publish(self, network, tx, artifacts, label):
        self.events.append((label, tx["txid"], tx["fee_zat"])); self.height += 1

    def observe(self, nodes, parents, spent=()):
        assert nodes is self.nodes and spent == ()
        return {"tip": {"height": self.height}, "parents": [p["output_index"] for p in parents]}

    def collect_history(self, nodes, parents, funding):
        self.events.append(("history", [p["output_index"] for p in parents], [tx["txid"] for tx in funding]))
        return fixture(self.pools)[0]["history"]

    def host(self, _, op, **fields):
        if op == "classical-info":
            return dict(address="public", script_hex=SCRIPT)
        if op == "classical-spend":
            recipe = fields["recipe"]
            self.events.append(("bank-recipe", recipe["parent_hex"], recipe["outputs"]))
            raw = b"bank".hex()
            return dict(transaction_hex=raw, transaction_sha256=hashlib.sha256(b"bank").hexdigest(), txid=identity("bank"),
                        outputs=[dict(row, output_index=index) for index, row in enumerate(recipe["outputs"])])
        assert op == "shielded-spend-finalize"
        original = self.proofs[fields["transaction_hex"]]
        self.finalized.append((original["label"], fields["record"]))
        result = {k: original[k] for k in controls.outputs.WIRE}
        result["transaction_hex"] += "ff"
        result.update(transaction_sha256=hashlib.sha256(bytes.fromhex(result["transaction_hex"])).hexdigest(),
                      auth_digest=identity(result["transaction_hex"]), slh_checks=1, ecdsa_checks=0, fee_zat=100000,
                      withdrawal_zat=50000*len(self.pools), deposit_zat=0)
        return result

    def signer(self, _, op, **fields):
        if op == "keygen":
            return dict(public_key="33"*32, secret_key="PUBLIC")
        assert op == "sign" and fields["secret_key"] == "PUBLIC"
        self.signed.append(fields["message"])
        return dict(public_key="33"*32, signature=fields["message"][:2] * 7856)

    def proof(self, host, op, recipe):
        assert op == "shielded-spend-prepare"
        label = "primary" if recipe["output_index"] == 0 else "duplicate"
        self.events.append(("proof", label, [(row["pool"], row["txid"]) for row in recipe["funding_txids"]]))
        _, _, result = fixture(recipe["pools"], recipe["transaction_version"])
        effects = dict(txid=identity(label), message_hex=("01" if label == "primary" else "02") * 101,
                       outputs=[dict(output_index=0, script_hex=self.script, value_zat=3_000_000 + 50000*len(self.pools) - 100000)])
        for item in [result["positive"], *result["variants"]]:
            raw = (label + ":").encode().hex() + item["transaction_hex"]
            item.update(effects, transaction_hex=raw, transaction_sha256=hashlib.sha256(bytes.fromhex(raw)).hexdigest(),
                        auth_digest=identity(raw))
            self.proofs[raw] = dict(item, label=label)
        result.update(parent_txid=identity("bank"), parent_index=recipe["output_index"], parent_script_hex=self.script,
                      parent_transaction_sha256=hashlib.sha256(b"bank").hexdigest(), parameters=recipe["sapling_parameters"])
        for note, source in zip(result["notes"], recipe["funding_txids"]):
            note["funding_txid"] = source["txid"]
        if label == "duplicate":
            if self.duplicate_note: result["notes"][0]["nullifier"] = identity("other-note")
            if self.change_history: (self.directory / "artifacts" / "history.json").write_text("{}")
            if self.change_signed == "preparation": (self.directory / "artifacts" / "primary-signed.json").write_text("{}")
            if self.change_state: self.height += 1
        return result

    def record_lifecycle(self, control, *args):
        self.lifecycle = (control, *args)
        if self.change_signed == "lifecycle":
            (self.directory / "artifacts" / "primary-signed.json").write_text("{}")


class SpendTests(unittest.TestCase):
    @staticmethod
    def poll_relay(predicate, reason, *_):
        for _ in range(5):
            if predicate():
                return
        raise AcceptanceError(reason)

    def test_publication_queued_peer_requires_eventual_exact_presence(self):
        network = PendingRelayNetwork()
        with tempfile.TemporaryDirectory() as temp, patch.object(controls,"wait_for",self.poll_relay):
            block = controls.publish(network, network.tx, Path(temp), "funding")
            receipt = json.loads((Path(temp) / "funding-relay.json").read_text())
        self.assertEqual(block["height"], 102)
        self.assertTrue(network.mined)
        self.assertGreaterEqual(network.b.lookups, 3)
        self.assertEqual(network.a.submissions, [network.tx["transaction_hex"]])
        self.assertEqual(network.b.submissions, [network.tx["transaction_hex"]])
        self.assertEqual(receipt["mode"], "per-node-rpc-or-observed")
        self.assertEqual(receipt["txid"], network.tx["txid"])
        self.assertEqual(receipt["transaction_sha256"], network.tx["transaction_sha256"])
        self.assertEqual(receipt["nodes"][0], dict(node_index=0, initial_state="absent",
            response={"result": network.tx["txid"]}, exact_mempool_and_template=True))
        self.assertEqual(receipt["nodes"][1], dict(node_index=1, initial_state="absent",
            response={"error": {"code": -1, "message": "transaction dropped because it is already queued for download"}},
            exact_mempool_and_template=True))

    def test_publication_direct_peer_admission_without_gossip(self):
        network = PendingRelayNetwork()
        network.no_gossip = True
        with tempfile.TemporaryDirectory() as temp, patch.object(controls,"wait_for",self.poll_relay):
            controls.publish(network, network.tx, Path(temp), "funding")
            receipt = json.loads((Path(temp) / "funding-relay.json").read_text())
        self.assertTrue(network.mined)
        for index, node in enumerate(network.nodes):
            self.assertEqual(node.submissions, [network.tx["transaction_hex"]])
            self.assertEqual(receipt["nodes"][index]["response"], {"result": network.tx["txid"]})
            self.assertTrue(receipt["nodes"][index]["exact_mempool_and_template"])

    def test_publication_observed_peer_and_mempool_race_are_authenticated(self):
        for field in ("observed_peer", "already_in_mempool"):
            network = PendingRelayNetwork()
            setattr(network, field, True)
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temp, \
                    patch.object(controls,"wait_for",self.poll_relay):
                controls.publish(network, network.tx, Path(temp), "funding")
                receipt = json.loads((Path(temp) / "funding-relay.json").read_text())
            peer = receipt["nodes"][1]
            self.assertTrue(peer["exact_mempool_and_template"])
            if field == "observed_peer":
                self.assertEqual(network.b.submissions, [])
                self.assertEqual(peer["initial_state"], "mempool")
                self.assertIsNone(peer["response"])
            else:
                self.assertEqual(network.b.submissions, [network.tx["transaction_hex"]])
                self.assertEqual(peer["response"]["error"]["message"], "transaction already exists in mempool")

    def test_publication_never_mines_absent_changed_or_refused_transactions(self):
        for field, reason in (("never_arrives", "spend_positive_mempool"), ("wrong_bytes", "saved_transaction_bytes"),
                              ("wrong_template", "spend_positive_template"), ("refused", "spend_positive_relay"),
                              ("peer_refused", "spend_positive_relay"), ("peer_empty_template", "spend_positive_template"),
                              ("peer_wrong_template", "spend_positive_template"), ("no_admission", "spend_positive_mempool")):
            network = PendingRelayNetwork()
            setattr(network, field, True)
            if field == "no_admission": network.no_gossip = True
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temp, \
                    patch.object(controls,"wait_for",self.poll_relay):
                with self.assertRaisesRegex(AcceptanceError, reason):
                    controls.publish(network, network.tx, Path(temp), "funding")
                self.assertFalse(network.mined)
                receipt = json.loads((Path(temp) / "funding-relay.json").read_text())
                if field in ("refused", "peer_refused"):
                    self.assertEqual(receipt["nodes"][-1]["response"]["error"]["message"], "invalid proof")
                self.assertFalse(receipt["nodes"][-1]["exact_mempool_and_template"])

    def test_publication_unrelated_reply_cannot_be_excused_by_later_presence(self):
        replies = [
            {"error": {"code": -25, "message": "invalid proof"}},
            {"error": {"code": -25, "message": "transaction already exists in mempool"}},
            {"error": {"code": -1, "message": "unrecognized queue condition"}},
            {"result": identity("wrong-txid")},
        ]
        for reply in replies:
            network = PendingRelayNetwork()
            original = network.b.response
            def respond(method, *params):
                if method == "sendrawtransaction":
                    network.b.raw = network.tx["transaction_hex"]
                    return reply
                return original(method, *params)
            with self.subTest(reply=reply), tempfile.TemporaryDirectory() as temp, \
                    patch.object(controls,"wait_for",self.poll_relay), patch.object(network.b,"response",respond):
                with self.assertRaisesRegex(AcceptanceError, "spend_positive_relay"):
                    controls.publish(network, network.tx, Path(temp), "funding")
                self.assertFalse(network.mined)

    def test_bounded_stable_history_and_exact_dual_node_bytes(self):
        nodes = [HistoryNode(), HistoryNode()]
        result = controls.collect_history(nodes, [nodes[0].parent], [nodes[0].funding])
        self.assertEqual(result["blocks"], ["00", "01", "02"])
        self.assertEqual(result["treestate"]["hash"], nodes[0].hashes[-1])
        for node in nodes:
            self.assertIn(("gettxout", (node.parent["txid"], 0, False)), node.calls)

    def test_changed_forged_disconnected_history_and_absent_parent_fail(self):
        for field in ("change_tip", "spent", "wrong_link", "wrong_funding"):
            nodes = [HistoryNode(), HistoryNode()]
            for node in nodes: setattr(node, field, True)
            with self.subTest(field=field), self.assertRaises(AcceptanceError):
                controls.collect_history(nodes, [nodes[0].parent], [nodes[0].funding])
        for change in (lambda n:n.raws.__setitem__(1,"abcd"), lambda n:n.hashes.__setitem__(0,"00"*32),
                       lambda n:setattr(n,"root","ff"*32), lambda n:setattr(n,"chain","main")):
            nodes=[HistoryNode(),HistoryNode()];change(nodes[1])
            with self.assertRaises(AcceptanceError): controls.collect_history(nodes,[nodes[0].parent],[nodes[0].funding])

    def test_all_ten_host_shapes_and_each_identity_component(self):
        for version in (5,6):
            for mask in range(1,4 if version==5 else 8):
                pools=[p for i,p in enumerate(controls.POOLS) if mask&(1<<i)]
                recipe,parent,result=fixture(pools,version)
                self.assertIs(controls.validate_prepared(result,recipe,parent),result)
        recipe,parent,result=fixture()
        changes=[lambda r:r.update(history_sha256="00"*32),lambda r:r.update(anchor_height=112),
            lambda r:r["notes"][0].update(position=4),lambda r:r["notes"][0].update(anchor="00"*32),
            lambda r:r["notes"][0].update(value_zat=49999),lambda r:r["variants"][0].update(message_hex="02"*101),
            lambda r:r["variants"][0].update(txid="11"*32),lambda r:r["variants"][0].update(auth_digest=r["positive"]["auth_digest"]),
            lambda r:r["variants"][0]["components"]["sapling"].update(binding=False),lambda r:r.update(withdrawal_zat=0),
            lambda r:r["positive"]["outputs"][0].update(value_zat=3_000_000),lambda r:r.update(variants=r["variants"][:-1])]
        for change in changes:
            bad=deepcopy(result);change(bad)
            with self.assertRaises(AcceptanceError):controls.validate_prepared(bad,recipe,parent)

    def run_lifecycle(self, model, replaced=None):
        with tempfile.TemporaryDirectory() as temp, patch.object(controls,"host_call",model.host), \
                patch.object(controls,"wait_for",wait),patch("node_live.wait_for",wait), \
                patch.object(controls,"backup_ready",return_value={"mock":True}):
            control=controls.SpendControls(model.args,Path(temp),model)
            anchored=controls.observe(model.nodes,model.parents)
            for node in model.nodes:node.height,node.hash,node.stage=112,identity("baseline"),0
            baseline=controls.observe(model.nodes,model.parents)
            for node in model.nodes:node.height,node.hash,node.stage=113,identity("anchor-block"),1
            receipt={}
            if replaced:
                with replaced:controls.lifecycle(control,model.positive,model.duplicate,model.variants,model.parents,baseline,model.anchor,anchored,receipt)
            else:controls.lifecycle(control,model.positive,model.duplicate,model.variants,model.parents,baseline,model.anchor,anchored,receipt)
            return receipt

    def test_complete_causal_lifecycle_all_subsets(self):
        for mask in range(1,8):
            pools=[p for i,p in enumerate(controls.POOLS) if mask&(1<<i)]
            model=Model(pools)
            receipt=self.run_lifecycle(model)
            self.assertEqual(len(receipt["authorization"]),2+3*len(pools))
            self.assertEqual(receipt["remined"]["values"],receipt["mined"]["state"]["values"])
            self.assertEqual(len(receipt["saved_reentry"]["mined_blocks"]),1)
            self.assertEqual(receipt["saved_reentry"]["mode"], "direct-saved-block")
            self.assertEqual(receipt["saved_reentry"]["initial_peer_states"], ["absent", "absent"])
            self.assertEqual(receipt["saved_reentry"]["positive_proposals"], 2)
            self.assertEqual(receipt["saved_reentry"]["transaction_sha256"], model.positive["transaction_sha256"])
            # Reentry submits the saved block; it never needs a fresh transaction relay.
            self.assertEqual(receipt["saved_reentry"]["submitblock_results"], [None, None])
            self.assertEqual(len([c for c in model.calls if isinstance(c,tuple) and c[1] == "relay"]), 1)
            for index in (0,1):
                self.assertEqual(len([c for c in model.calls if isinstance(c,tuple) and c[:2]==(index,"reject-relay")]),2+6*len(pools))
                self.assertEqual(len([c for c in model.calls if isinstance(c,tuple) and c[:2]==(index,"accept-block")]),1)

    def test_saved_block_reentry_requires_both_nodes_exact_confirmed_best_chain(self):
        for field, reason in (("refuse_reentry", "spend_reentry_block_rejected"),
                              ("wrong_reentry_block", "spend_reentry_block_bytes"),
                              ("wrong_reentry_membership", "spend_reentry_block_bytes"),
                              ("wrong_reentry_transaction", "spend_reentry_transaction"),
                              ("unconfirmed_reentry", "spend_reentry_transaction"),
                              ("wrong_reentry_transaction_block", "spend_reentry_transaction")):
            model = Model()
            setattr(model, field, True)
            with self.subTest(field=field), self.assertRaisesRegex(AcceptanceError, reason):
                self.run_lifecycle(model)

    def test_duplicate_block_response_requires_actual_reentry(self):
        model = Model()
        model.duplicate_reentry = True
        receipt = self.run_lifecycle(model)
        self.assertEqual(receipt["saved_reentry"]["submitblock_results"], ["duplicate", "duplicate"])
        model = Model()
        model.duplicate_reentry = model.no_reentry = True
        with self.assertRaisesRegex(AcceptanceError, "spend_reentry_tip"):
            self.run_lifecycle(model)

    def test_noop_wrong_failure_and_parent_confounders_cannot_pass(self):
        for field,reason in (("no_rollback","spend_rollback_tip"),("no_reconsider","spend_anchor_reconsider_tip"),
                             ("no_reentry","spend_reentry_tip"),("no_relay","spend_positive_mempool"),
                             ("no_mining","spend_mined_membership"),("no_tree","spend_anchor_not_new"),
                             ("skip_replacement","spend_replacement_branch")):
            model=Model();setattr(model,field,True)
            with self.subTest(field=field),self.assertRaisesRegex(AcceptanceError,reason):
                self.run_lifecycle(model)
        # Missing parents, expiry and unrelated errors cannot substitute for the duplicate-nullifier refusal.
        duplicate_relays=lambda model:[c for c in model.calls if isinstance(c,tuple) and c[2]==model.duplicate["transaction_hex"]]
        for field,reason,relays in (("bad_parent","spend_parent_unavailable",0),("expired","spend_expired",0),
                                    ("wrong_reason","transparent_wrong_relay_rejection",1),
                                    ("wrong_proposal","spend_wrong_proposal_rejection",2)):
            model=Model()
            with self.subTest(field=field),self.assertRaisesRegex(AcceptanceError,reason):
                if field=="expired":
                    # The duplicate is first submitted at tip 114, after the published spend.
                    with patch.object(controls,"EXPIRY",114):self.run_lifecycle(model)
                else:
                    setattr(model,field,True);self.run_lifecycle(model)
            self.assertEqual(len(duplicate_relays(model)),relays)
            self.assertEqual(model.a.stage,2)
        # Self-checks of the fake oracle: the flow test fails if lifecycle skips these steps.
        for function,error,message in (("authorization_round",AssertionError,"skipped final positive or negative submissions"),
                                       ("preflight",AssertionError,"missing positive preflight"),
                                       ("reject",AssertionError,"unknown-anchor subject skipped"),
                                       ("reenter_saved_block",AcceptanceError,"spend_reentry_mining")):
            model=Model()
            with self.subTest(function=function),self.assertRaisesRegex(error,message):
                self.run_lifecycle(model,patch.object(controls,function,return_value=[]))

    def test_slh_signs_final_message_once_per_effects_and_reuses_for_mutants(self):
        recipe,parent,prepared=fixture()
        signed=[];records=[]
        def signer(_,op,**fields):
            self.assertEqual(op,"sign");self.assertEqual(fields["message"],prepared["positive"]["message_hex"])
            signed.append(fields)
            return dict(public_key=recipe["public_key_hex"],signature="ab"*7856)
        def host(_,op,**fields):
            self.assertEqual(op,"shielded-spend-finalize");records.append(fields["record"])
            original=next(r for r in [prepared["positive"],*prepared["variants"]] if r["transaction_hex"]==fields["transaction_hex"])
            row={k:original[k] for k in controls.outputs.WIRE}
            row["transaction_hex"]+="ff"
            row.update(transaction_sha256=hashlib.sha256(bytes.fromhex(row["transaction_hex"])).hexdigest(),auth_digest=identity(row["transaction_hex"]),
                slh_checks=1,ecdsa_checks=0,fee_zat=100000,withdrawal_zat=150000,deposit_zat=0)
            return row
        with patch.object(controls,"signer_call",signer),patch.object(controls,"host_call",host):
            controls.finalize(SimpleNamespace(host="host",signer="signer"),recipe,prepared,{"secret_key":"PUBLIC"},"primary")
        self.assertEqual(len(signed),1);self.assertEqual(len(records),10)
        self.assertTrue(all(record==records[0] for record in records))

    def test_restart_loses_inherited_invalidated_anchor_record(self):
        # Lifecycle must not reopen between anchor invalidation and reconsideration.
        original = controls.rollback
        def restarted(network, block, expected, *, restart=True):
            return original(network, block, expected, restart=True)
        model = Model()
        with self.assertRaisesRegex(AcceptanceError, "rpc_rejected_reconsiderblock"):
            self.run_lifecycle(model, patch.object(controls, "rollback", side_effect=restarted))
        self.assertEqual(model.calls.count("restart"), 1)
        self.assertTrue(all(node.anchor_rejected for node in model.nodes))

    def test_backup_restart_gate_requires_removed_orphan_absence(self):
        model = Model()
        with tempfile.TemporaryDirectory() as temp:
            for index, node in enumerate(model.nodes):
                node.directory = Path(temp) / str(index)
                directory = node.directory / "state" / "non_finalized_state" / controls.namespace((110,16,64))
                directory.mkdir(parents=True)
                (directory / model.anchor["block_hash"]).write_bytes(b"stale")
            with patch.object(controls,"backup_observed",return_value={"complete":True}), \
                    patch.object(controls,"export_chain",return_value=[{"height":113}]),patch.object(controls,"wait_for",wait):
                with self.assertRaisesRegex(AcceptanceError,"invalidated_backup_present"):
                    controls.backup_ready(model,excluded=(model.anchor["block_hash"],))
                for node in model.nodes:
                    (node.directory / "state" / "non_finalized_state" / controls.namespace((110,16,64)) / model.anchor["block_hash"]).unlink()
                receipt = controls.backup_ready(model,excluded=(model.anchor["block_hash"],))
                self.assertEqual(receipt["excluded_block_hashes"],[model.anchor["block_hash"]])
                self.assertEqual(len(receipt["canonical"]),2)

    def test_inactive_ironwood_is_explicit_only_before_nu6_3(self):
        tip = {"height": 101, "hash": identity("preactivation")}
        tree = dict(tip, **{p: {"commitments": {"finalRoot": identity(p)}} for p in controls.POOLS})
        tree["ironwood"] = {"commitments": {}}
        roots = controls.root_fields(tree, tip, inactive_ironwood=True)
        self.assertIsNone(roots["ironwood"])
        for height in (104, 110):
            changed_tip = dict(tip, height=height)
            with self.assertRaises(AcceptanceError):
                controls.root_fields(dict(tree, height=height), changed_tip, inactive_ironwood=True)

    def run_execute(self, network):
        args = SimpleNamespace(host="host", signer="signer", node=Path("node"), classical="single",
                               authorization="slh", version=6, pools=network.pools, parameters=None)
        artifacts = network.directory / "artifacts"
        artifacts.mkdir()
        receipt = {}
        replacements = {"Network": network, "mine_to": network.mine_to, "coinbase": network.coinbase,
            "orchard_deposit": network.orchard_deposit, "output_deposit": network.output_deposit,
            "publish": network.publish, "observe": network.observe, "collect_history": network.collect_history,
            "host_call": network.host, "signer_call": network.signer, "proof_call": network.proof,
            "lifecycle": network.record_lifecycle}
        with ExitStack() as stack:
            for name, replacement in replacements.items():
                stack.enter_context(patch.object(controls, name, side_effect=replacement))
            controls.execute(args, artifacts, receipt)
        return receipt

    def test_execute_funds_in_order_and_signs_each_effect_once(self):
        for pools in (("orchard",), ("sapling", "ironwood"), ("sapling", "orchard", "ironwood")):
            with self.subTest(pools=pools), tempfile.TemporaryDirectory() as temp:
                network = ExecuteNetwork(Path(temp), pools)
                receipt = self.run_execute(network)
                new_pools = [p for p in pools if p != "orchard"]
                script = network.script
                bank_outputs = [{"value_zat": 3_000_000, "script_hex": script}] * 2
                funding = (["orchard-note"] if "orchard" in pools else []) + (["note-funding"] if new_pools else [])
                notes = [(p, identity("orchard-note" if p == "orchard" else "note-funding")) for p in pools]
                expected = [("network", nodes.SPEND_ACTIVATION_HEIGHTS), ("mine_to", 101)]
                if "orchard" in pools:
                    expected += [("coinbase", 1), ("orchard-funding", 101, identity("coinbase1"))]
                expected += [("mine_to", 110)]
                if new_pools:
                    expected += [("coinbase", 3), ("note-funding", 110, identity("coinbase3"), new_pools)]
                expected += [("coinbase", 2), ("bank-recipe", "02", bank_outputs), ("transparent-funding", identity("bank"), 20000),
                             ("coinbase", 4), ("anchor-funding", 111 + bool(new_pools), identity("coinbase4"), list(pools)),
                             ("history", [0, 1], [identity(name) for name in funding]),
                             ("proof", "primary", notes), ("proof", "duplicate", notes), "closed"]
                self.assertEqual(network.events, expected)
                # Distinct effects: one signature per message, reused for that effect's mutants only.
                self.assertEqual(network.signed, ["01"*101, "02"*101])
                records = {label: {r["signature_hex"] for l, r in network.finalized if l == label} for label in ("primary", "duplicate")}
                self.assertEqual([len(records["primary"]), len(records["duplicate"])], [1, 1])
                self.assertNotEqual(records["primary"], records["duplicate"])
                self.assertEqual(len(network.finalized), 2 * (1 + 3 * len(pools)))
                _, positive, duplicate, variants, parents, baseline, anchor_block, anchored, actual = network.lifecycle
                self.assertIs(actual, receipt)
                self.assertEqual((positive["txid"], duplicate["txid"]), (identity("primary"), identity("duplicate")))
                self.assertEqual({tx["txid"] for tx in variants}, {identity("primary")})
                self.assertEqual(len(variants), 3 * len(pools))
                self.assertEqual([(p["txid"], p["output_index"], p["script_hex"]) for p in parents],
                                 [(identity("bank"), 0, script), (identity("bank"), 1, script)])
                self.assertEqual(anchor_block["block_hash"], identity("anchor-funding-block"))
                self.assertEqual(anchored["tip"]["height"], baseline["tip"]["height"] + 1)
                self.assertEqual([row["pool"] for row in receipt["notes"]], list(pools))
                self.assertEqual(set(receipt["saved_authorization_sha256"]), {"primary", "duplicate"})

    def test_execute_refuses_changed_notes_history_signed_bytes_or_state(self):
        for field, value, reason in (("duplicate_note", True, "spend_duplicate_note_identity"),
                                     ("change_history", True, "spend_saved_history_changed"),
                                     ("change_signed", "preparation", "spend_saved_authorization_changed"),
                                     ("change_state", True, "spend_preparation_changed_state"),
                                     ("change_signed", "lifecycle", "spend_saved_authorization_changed")):
            with self.subTest(field=field, value=value), tempfile.TemporaryDirectory() as temp:
                network = ExecuteNetwork(Path(temp), ("sapling", "orchard"))
                setattr(network, field, value)
                with self.assertRaisesRegex(AcceptanceError, reason):
                    self.run_execute(network)
                # Only the final saved-authorization recheck runs after lifecycle.
                self.assertEqual(network.lifecycle is not None, value == "lifecycle")

    def test_orchard_funding_uses_legal_height_and_actual_parent(self):
        _, parent, _ = fixture(("orchard",))
        args = SimpleNamespace(host="host", classical="single")
        network = SimpleNamespace(nodes=[object(), object()])
        before = {"tip": {"height": 101, "hash": identity("101")},
                  "roots": {"sapling": identity("s"), "orchard": identity("o"), "ironwood": None},
                  "values": dict.fromkeys(controls.POOLS, 0)}
        after = deepcopy(before)
        after["tip"] = {"height": 102, "hash": identity("102")}
        after["roots"]["orchard"] = identity("funded")
        after["values"]["orchard"] = 50000
        tx = row("orchard-pre", ("orchard",))
        del tx["message_hex"]
        tx["outputs"][0]["value_zat"] = parent["value_zat"] - 150000
        tx.update(material="public-test-only", version=5, parent_txid=parent["txid"], parent_index=0,
                  parent_value_zat=parent["value_zat"], parent_script_hex=SCRIPT,
                  parent_transaction_sha256=hashlib.sha256(bytes.fromhex(parent["parent_hex"])).hexdigest(),
                  fee_zat=100000, deposit_zat=50000, orchard_value_zat=50000,
                  proof_profile="orchard-pre-nu6.3", pool_valid={"orchard": True}, ecdsa_checks=1, slh_checks=0)
        def proof(_, op, recipe):
            self.assertEqual(op, "shielded-spend-funding")
            self.assertEqual(recipe["expiry_height"], 103)
            self.assertEqual(recipe["parent_hex"], parent["parent_hex"])
            return deepcopy(tx)
        with tempfile.TemporaryDirectory() as temp, patch.object(controls,"common_tip",return_value=before["tip"]), \
                patch.object(controls,"observe",side_effect=[before,before,after]), \
                patch.object(controls,"proof_call",side_effect=proof), \
                patch.object(controls,"publish",return_value={"height":102}) as publish:
            actual = controls.orchard_deposit(args,network,Path(temp),parent)
            self.assertEqual(actual,tx)
            self.assertEqual(publish.call_count,1)
        with tempfile.TemporaryDirectory() as temp, patch.object(controls,"common_tip",return_value={"height":104}), \
                patch.object(controls,"proof_call") as proof, self.assertRaises(AcceptanceError):
            controls.orchard_deposit(args,network,Path(temp),parent)
        proof.assert_not_called()

    def test_transport_deadline_and_strict_envelope(self):
        recipe,_,prepared=fixture()
        reply=dict(schema_version=1,contract=controls.CONTRACT,public_fixture=True,op="shielded-spend-prepare",ok=True,result=prepared)
        with patch.object(controls,"invoke",return_value=reply) as invoke:
            self.assertEqual(controls.proof_call("host","shielded-spend-prepare",recipe),prepared)
            self.assertEqual(invoke.call_args.kwargs,{"timeout":1800})
        for key,value in (("schema_version",True),("public_fixture",False),("op","shielded-prepare"),("ok",False)):
            with patch.object(controls,"invoke",return_value=dict(reply,**{key:value})),self.assertRaises(AcceptanceError):
                controls.proof_call("host","shielded-spend-prepare",recipe)


if __name__ == "__main__":
    unittest.main()
