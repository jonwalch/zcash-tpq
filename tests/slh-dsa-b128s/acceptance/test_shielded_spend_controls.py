"""Offline trusted-history and causal-state models; no proofs, signing or nodes."""
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
        self.wrong_reason = self.no_tree = self.bad_parent = self.expired = False
        self.skip_replacement = False
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

    def tip(self): return self.height, self.hash

    def failure(self, tx):
        if self.model.wrong_reason: return "missing transparent input", "missinginput"
        if self.stage == 0: return f"unknown {self.model.pools[0]} anchor", "unknown"+self.model.pools[0]+"anchor"
        if tx is self.model.duplicate and self.stage == 2:
            return f"{self.model.pools[0]} double-spend: duplicate nullifier", "duplicate"+self.model.pools[0]+"nullifier"
        if "pool" in tx:
            return (("sapling proof or signature verification failed", "saplingverificationfailed") if tx["pool"] == "sapling" else
                    ("orchard or ironwood halo2 proof verification failed", "halo2verificationfailed"))
        return None

    def response(self, method, *params):
        if method == "getrawtransaction":
            tx = next(t for t in self.model.txs.values() if t["txid"] == params[0])
            if self.saved or tx["transaction_hex"] in self.pool:
                return {"result": {"hex": tx["transaction_hex"], "confirmations": int(self.stage == 2)}}
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
            return dict(blocks=211 if model.expired else self.height, bestblockhash=self.hash,
                valuePools=[dict(id=p, chainValueZat=(50000 + (50000 if self.stage>0 and p!="orchard" else 0) - (50000 if self.stage==2 else 0)) if p in model.pools else 0) for p in controls.POOLS])
        if method == "z_gettreestate":
            return dict(height=self.height, hash=self.hash, **{p: {"commitments": {"finalRoot": identity(p+str(0 if model.no_tree else self.stage if p in model.pools else 0))}} for p in controls.POOLS})
        if method == "gettxout":
            if params[0] == model.parents[0]["txid"]:
                if (self.stage == 2 and params[1] == 0) or model.bad_parent: return None
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
            assert self.failure(tx), "invalid block should be tested"
            if "pool" in tx: self.negative_submitted.add((tx["pool"], tx["mutation"]))
            model.calls.append((self.index, "reject-block", tx["transaction_hex"]))
            return "rejected"
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
            assert params[0] in self.invalidated, "restart lost the memory-only invalidated block"
            assert self.anchor_rejected, "unknown-anchor subject skipped"
            if not model.no_reconsider: self.height,self.hash,self.stage = 113,identity("anchor-block"),1
            return None
        if method == "getblockhash": return self.chain[params[0]]
        if method == "getblock":
            block = model.anchor if params[0] == model.anchor["block_hash"] else next(b for b in model.blocks.values() if b["block_hash"] == params[0])
            return block["block_hex"] if params[1] == 0 else {"tx": ["coinbase", model.positive["txid"]]}
        if method == "getrawtransaction": return self.response(method, *params)["result"]
        raise AssertionError((method, params))


class PendingRelayNetwork:
    """Peer lookup remains absent while gossip verification is in flight."""
    def __init__(self):
        self.tx = row("funding", ("orchard",))
        self.mined = self.never_arrives = self.wrong_bytes = self.wrong_template = self.refused = False
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
                return {"error": {"code": -1, "message": "transaction dropped because it is already queued for download"}}
            if self.network.refused:
                return {"error": {"code": -25, "message": "invalid proof"}}
            assert params == (tx["transaction_hex"],)
            self.raw = params[0]
            self.network.b.pending = True
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
            return {"transactions": [{"hash": tx["txid"], "data": "ffff" if self.network.wrong_template else self.raw}]}
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


class SpendTests(unittest.TestCase):
    @staticmethod
    def poll_relay(predicate, reason, *_):
        for _ in range(5):
            if predicate():
                return
        raise AcceptanceError(reason)

    def test_publication_waits_for_exact_peer_gossip_without_duplicate_submit(self):
        network = PendingRelayNetwork()
        with tempfile.TemporaryDirectory() as temp, patch.object(controls,"wait_for",self.poll_relay):
            block = controls.publish(network, network.tx, Path(temp), "funding")
            receipt = json.loads((Path(temp) / "funding-relay.json").read_text())
        self.assertEqual(block["height"], 102)
        self.assertTrue(network.mined)
        self.assertGreaterEqual(network.b.lookups, 3)
        self.assertEqual(network.a.submissions, [network.tx["transaction_hex"]])
        self.assertEqual(network.b.submissions, [])
        self.assertEqual(receipt, dict(txid=network.tx["txid"],
            transaction_sha256=network.tx["transaction_sha256"], response={"result": network.tx["txid"]}))

    def test_publication_never_mines_missing_or_changed_bytes_or_refused_origin(self):
        for field, reason in (("never_arrives", "spend_positive_mempool"), ("wrong_bytes", "saved_transaction_bytes"),
                              ("wrong_template", "spend_positive_template"), ("refused", "spend_positive_relay")):
            network = PendingRelayNetwork()
            setattr(network, field, True)
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temp, \
                    patch.object(controls,"wait_for",self.poll_relay):
                with self.assertRaisesRegex(AcceptanceError, reason):
                    controls.publish(network, network.tx, Path(temp), "funding")
                self.assertFalse(network.mined)
                self.assertEqual(network.b.submissions, [])
                receipt = json.loads((Path(temp) / "funding-relay.json").read_text())
                if field == "refused":
                    self.assertEqual(receipt["response"]["error"]["message"], "invalid proof")

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
            for index in (0,1):
                self.assertEqual(len([c for c in model.calls if isinstance(c,tuple) and c[:2]==(index,"reject-relay")]),2+6*len(pools))

    def test_noop_wrong_failure_and_parent_confounders_cannot_pass(self):
        for field in ("no_rollback","no_reconsider","no_reentry","no_relay","no_mining","wrong_reason",
                      "no_tree","bad_parent","expired","skip_replacement"):
            model=Model();setattr(model,field,True)
            with self.subTest(field=field),self.assertRaises((AcceptanceError,AssertionError)):
                self.run_lifecycle(model)
        for function in ("authorization_round","preflight","reject"):
            model=Model()
            with self.subTest(function=function),self.assertRaises((AcceptanceError,AssertionError)):
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
        model = Model()
        for node in model.nodes:
            node.rpc("invalidateblock", model.anchor["block_hash"])
            node.anchor_rejected = True
        model.restart()
        for node in model.nodes:
            with self.assertRaisesRegex(AssertionError, "memory-only"):
                node.rpc("reconsiderblock", model.anchor["block_hash"])

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
