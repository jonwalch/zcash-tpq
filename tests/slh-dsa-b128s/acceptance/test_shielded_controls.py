"""Offline causal models only: no signer, proof generator or node is launched."""
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from decimal import Decimal
import hashlib
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from common import AcceptanceError
import shielded_controls as controls


def identity(value):
    return hashlib.sha256(value.encode()).hexdigest()


SCRIPT = "a914" + "22" * 20 + "87"


def row(label, pools, *, signed=False):
    raw = (label + ("-signed" if signed else "")).encode().hex()
    return dict(transaction_hex=raw, transaction_sha256=hashlib.sha256(bytes.fromhex(raw)).hexdigest(),
        txid=identity("effects"), auth_digest=identity(raw), message_hex="01" * 101,
        outputs=[dict(output_index=0, value_zat=3_000_000 - 100000 - 50000 * len([p for p in pools if p != "orchard"]),
                      script_hex=SCRIPT)], sapling_outputs=2 * ("sapling" in pools),
        orchard_actions=2 * ("orchard" in pools), ironwood_actions=2 * ("ironwood" in pools))


def objects(pools=("sapling","orchard","ironwood"), version=6, authorization="single"):
    parameters = dict(spend_path="/public/spend",spend_sha256="11"*32,
                      output_path="/public/output",output_sha256="22"*32) if "sapling" in pools else None
    recipe = dict(human_run=True, transaction_version=version, pools=list(pools), parent_hex="abcd",
        output_index=0, expiry_height=210, authorization=authorization,
        public_key_hex="33"*32 if authorization=="slh" else None, sapling_parameters=parameters)
    parent = dict(parent_hex="abcd",txid="55"*32,output_index=0,value_zat=3_000_000,script_hex=SCRIPT)
    prepared = dict(material="public-test-only",version=version,pools=list(pools),
        parent_txid=parent["txid"],parent_index=0,parent_value_zat=3_000_000,parent_script_hex=SCRIPT,
        parent_transaction_sha256=hashlib.sha256(bytes.fromhex("abcd")).hexdigest(),fee_zat=100000,
        deposit_zat=50000*len([p for p in pools if p!="orchard"]),orchard_value_zat=0,
        proof_profile="output-only-post-nu6.3",parameters=parameters,positive=row("positive",pools),
        positive_pool_valid=dict.fromkeys(pools,True),variants=[])
    for pool in pools:
        for mutation in ("binding","proof"):
            prepared["variants"].append(dict(row(pool+mutation,pools),pool=pool,mutation=mutation,
                                             pool_valid={p:p!=pool for p in pools}))
    return recipe,parent,prepared


class Ledger:
    def __init__(self,pools,version=6):
        self.recipe,self.parent,self.prepared=objects(pools,version)
        self.pools=pools
        self.nodes=[FakeNode(self,0),FakeNode(self,1)]
        self.tx={}
        self.blocks={}
        self.calls=[]
        self.serial=0
        self.skip_relay=self.skip_mining=self.wrong_reason=self.corrupt_artifact=False
        self.change_parent=self.no_tree_change=False

    @contextmanager
    def pair(self,*_):
        yield self.nodes
        for node in self.nodes:
            node.stops=[0]

    def host(self,_,op,**fields):
        if op=="classical-info":
            return dict(address="public",script_hex=SCRIPT)
        if op=="shielded-finalize":
            original=next(r for r in [self.prepared["positive"],*self.prepared["variants"]]
                          if r["transaction_hex"]==fields["transaction_hex"])
            result={k:deepcopy(original[k]) for k in controls.WIRE}
            result["transaction_hex"] += "ff"
            result["transaction_sha256"]=hashlib.sha256(bytes.fromhex(result["transaction_hex"])).hexdigest()
            result["auth_digest"]=identity(result["transaction_hex"])
            result.update(slh_checks=int(fields["record"] is not None),ecdsa_checks=0 if fields["record"] else 1,
                          fee_zat=100000,deposit_zat=self.prepared["deposit_zat"])
            self.tx[result["transaction_hex"]]=dict(result,positive=original is self.prepared["positive"],
                pool=original.get("pool"),mutation=original.get("mutation"))
            if self.corrupt_artifact:
                result["outputs"][0]["value_zat"]+=1
            return result
        if op in ("shielded-block","control-block"):
            self.serial+=1
            tx=self.tx[fields["recipe"]["transactions"][0]["transaction_hex"]]
            result=dict(block_hex=f"block{self.serial}".encode().hex(), block_sha256=identity(str(self.serial)),
                block_hash=identity("block"+str(self.serial)),height=111,
                txids=[tx["txid"]],aggregate_fee_zat=tx["fee_zat"])
            self.blocks[result["block_hex"]]=dict(result,tx=tx)
            return result
        raise AssertionError(op)


class FakeNode:
    def __init__(self,ledger,index):
        self.ledger,self.index=ledger,index
        self.height=110
        self.tip_hash="66"*32
        self.pool=[]
        self.spent=False
        self.accepted=None
        self.preflight=False
        self.negative=set()
        self.stops=[]
        self.config=Path("public-config")

    def tip(self):
        return self.height,self.tip_hash

    def response(self,method,raw):
        assert method=="sendrawtransaction"
        tx=self.ledger.tx[raw]
        assert not tx["positive"]
        assert self.preflight,"negative requires successful positive preflight"
        self.ledger.calls.append((self.index,"reject-relay",tx["pool"],tx["mutation"]))
        text="missing input" if self.ledger.wrong_reason else (
            "sapling proof or signature verification failed" if tx["pool"]=="sapling" else
            "orchard or ironwood halo2 proof verification failed")
        if self.ledger.change_parent:
            self.spent=True
        return {"error":{"code":-25,"message":text}}

    def rpc(self,method,*params):
        ledger=self.ledger
        if method=="getblockcount": return self.height
        if method=="getbestblockhash": return self.tip_hash
        if method=="z_gettreestate":
            return dict(height=self.height,hash=self.tip_hash,**{p:{"commitments":{"finalRoot":identity(p + ("-accepted" if self.accepted and not ledger.no_tree_change and p in ledger.pools else ""))}} for p in controls.POOLS})
        if method=="gettxout":
            if params[0]==ledger.parent["txid"]:
                if self.spent:return None
                return dict(value=Decimal("0.03"),scriptPubKey={"hex":SCRIPT},coinbase=True,confirmations=110)
            assert self.accepted and params[0]==self.accepted["txid"]
            output=self.accepted["outputs"][0]
            return dict(value=Decimal(output["value_zat"])/100_000_000,scriptPubKey={"hex":SCRIPT},
                        coinbase=False,confirmations=1)
        if method=="getrawmempool":return [ledger.tx[raw]["txid"] for raw in self.pool]
        if method=="getblocktemplate":
            if not params:return {"transactions":[{"hash":ledger.tx[raw]["txid"],"data":raw} for raw in self.pool]}
            block=ledger.blocks[params[0]["data"]]
            tx=block["tx"]
            ledger.calls.append((self.index,"proposal",tx["pool"],tx["mutation"]))
            if tx["positive"]:
                self.preflight=True
                return None
            self.negative.add((tx["pool"],tx["mutation"]))
            return "transaction-saplingverificationfailed" if tx["pool"]=="sapling" else "transaction-halo2verificationfailed"
        if method=="sendrawtransaction":
            tx=ledger.tx[params[0]]
            assert tx["positive"]
            assert self.preflight
            assert self.negative=={(p,m) for p in ledger.pools for m in ("binding","proof")},"skipped negative operations"
            ledger.calls.append((self.index,"positive-relay",None,None))
            if not ledger.skip_relay:self.pool=[params[0]]
            return tx["txid"]
        if method=="generate":
            assert params==(1,)
            assert self.pool
            raw=self.pool[0]
            tx=ledger.tx[raw]
            ledger.serial+=1
            block=dict(block_hex="abcdff",block_hash=identity("accepted"),height=111,tx=tx)
            ledger.blocks[block["block_hex"]]=block
            if not ledger.skip_mining:self.commit(block)
            return [block["block_hash"]]
        if method=="submitblock":
            block=ledger.blocks[params[0]]
            if not block["tx"]["positive"]:
                ledger.calls.append((self.index,"reject-block",block["tx"]["pool"],block["tx"]["mutation"]))
                return "rejected"
            self.commit(block)
            return None
        if method=="getblock":
            block=next(b for b in ledger.blocks.values() if b["block_hash"]==params[0])
            return block["block_hex"] if params[1]==0 else {"tx":["coinbase",block["tx"]["txid"]]}
        if method=="getrawtransaction":
            assert self.accepted
            return {"hex":self.accepted["transaction_hex"],"confirmations":1}
        raise AssertionError((method,params))

    def commit(self,block):
        self.height,self.tip_hash=block["height"],block["block_hash"]
        self.accepted=block["tx"]
        self.spent=True
        self.pool=[]


class ShieldedTests(unittest.TestCase):
    def test_all_ten_shapes_and_mismatched_artifacts(self):
        for version in (5,6):
            for mask in range(1,4 if version==5 else 8):
                pools=[p for index,p in enumerate(controls.POOLS) if mask&(1<<index)]
                recipe,parent,prepared=objects(pools,version)
                self.assertIs(controls.validate_prepared(prepared,recipe,parent),prepared)
        recipe,parent,prepared=objects()
        mutations=[lambda p:p.update(extra=1),lambda p:p.update(parent_value_zat=3_000_001),
            lambda p:p.update(variants=p["variants"][:-1]),lambda p:p["positive"].update(transaction_sha256="00"*32),
            lambda p:p["variants"][0].update(message_hex="02"*101),lambda p:p["variants"][0].update(txid="00"*32),
            lambda p:p["variants"][0].update(auth_digest=p["positive"]["auth_digest"]),
            lambda p:p["variants"][0].update(pool_valid=dict.fromkeys(controls.POOLS,True)),
            lambda p:p["positive"]["outputs"][0].update(value_zat=123456),
            lambda p:p.update(parameters=None),lambda p:p.update(orchard_value_zat=50000),
            lambda p:p["positive"].update(sapling_outputs=4000)]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                changed=deepcopy(prepared); mutate(changed)
                with self.assertRaises(AcceptanceError):
                    controls.validate_prepared(changed,recipe,parent)

    def execute_mock(self,ledger,extra=None):
        args=SimpleNamespace(host=Path("host"),signer=Path("signer"),authorization="single",classical="single",
            version=ledger.recipe["transaction_version"],pools=list(ledger.pools),parameters=ledger.recipe["sapling_parameters"])
        def wait(predicate,label,*_):
            if not predicate():raise AcceptanceError(label)
        with tempfile.TemporaryDirectory() as temp,ExitStack() as stack:
            for name,replacement in [("pair",ledger.pair),("host_call",ledger.host),
                ("proof_call",lambda *_:deepcopy(ledger.prepared)),
                ("authenticate_coinbase",lambda *_:deepcopy(ledger.parent)),
                ("sha256",lambda _:"11"*32),("wait_for",wait)]:
                stack.enter_context(patch.object(controls,name,replacement))
            stack.enter_context(patch("lifecycle_controls.wait_for",wait))
            if extra:stack.enter_context(extra)
            receipt={}
            controls.execute(args,Path(temp),receipt)
            return receipt

    def test_complete_causal_flow_for_all_pool_combinations(self):
        for version in (5,6):
            for mask in range(1,4 if version==5 else 8):
                pools=tuple(p for i,p in enumerate(controls.POOLS) if mask&(1<<i))
                ledger=Ledger(pools,version)
                receipt=self.execute_mock(ledger)
                self.assertEqual(len(receipt["negative_controls"]),len(pools)*2)
                self.assertTrue(receipt["accepted"]["parent_spent"])
                for index in (0,1):
                    calls=[call for call in ledger.calls if call[0]==index]
                    self.assertEqual(len([c for c in calls if c[1]=="reject-relay"]),len(pools)*2)
                    self.assertEqual(len([c for c in calls if c[1]=="reject-block"]),len(pools)*2)

    def test_noop_and_unrelated_failures_cannot_complete(self):
        for attribute in ("skip_relay","skip_mining","wrong_reason","change_parent","corrupt_artifact","no_tree_change"):
            ledger=Ledger(("sapling","orchard","ironwood"));setattr(ledger,attribute,True)
            with self.subTest(attribute=attribute),self.assertRaises((AcceptanceError,AssertionError)):
                self.execute_mock(ledger)
        for function in ("preflight","negative_controls"):
            with self.subTest(function=function),self.assertRaises(AssertionError):
                self.execute_mock(Ledger(("orchard",)),patch.object(controls,function,return_value=[]))

    def test_slh_signs_final_effects_once_and_reuses_exact_record_for_auth_mutations(self):
        ledger=Ledger(("orchard","ironwood"))
        ledger.recipe["authorization"]="slh";ledger.recipe["public_key_hex"]="33"*32
        signed=[];records=[]
        def signer(_,op,**fields):
            self.assertEqual(op,"sign");self.assertEqual(fields["message"],ledger.prepared["positive"]["message_hex"])
            signed.append(fields)
            return dict(public_key="33"*32,signature="44"*7856)
        def host(*args,**kwargs):
            records.append(kwargs["record"])
            return ledger.host(*args,**kwargs)
        with patch.object(controls,"signer_call",signer),patch.object(controls,"host_call",host):
            positive,variants=controls.finalize(SimpleNamespace(host="host",signer="signer"),ledger.recipe,
                                              ledger.prepared,{"secret_key":"PUBLIC"})
        self.assertEqual(len(signed),1)
        self.assertEqual(len(records),5)
        self.assertTrue(all(record==records[0] for record in records))
        self.assertEqual({tx["txid"] for tx in [positive,*variants]},{positive["txid"]})
        self.assertEqual(len({tx["auth_digest"] for tx in [positive,*variants]}),5)

    def test_proof_transport_rejects_wrong_envelope_and_uses_finite_deadline(self):
        recipe,_,prepared=objects(("orchard",))
        response=dict(schema_version=1,contract=controls.CONTRACT,public_fixture=True,
                      op="shielded-prepare",ok=True,result=prepared)
        with patch.object(controls,"invoke",return_value=response) as invoke:
            self.assertEqual(controls.proof_call("host",recipe),prepared)
            self.assertEqual(invoke.call_args.kwargs,{"timeout":1800})
        for key,value in (("schema_version",True),("public_fixture",False),("op","prepare"),("ok",False)):
            with patch.object(controls,"invoke",return_value=dict(response,**{key:value})):
                with self.assertRaises(AcceptanceError):controls.proof_call("host",recipe)


if __name__=="__main__":unittest.main()
