# SPDX-License-Identifier: MIT OR Apache-2.0
"""Causal isolated chain/process mocks. No daemon, signer, signal or socket runs."""
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import signal
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from common import AcceptanceError
import build
import common
import crash_controls as crash
import lifecycle_controls
import node_live
import observation_controls
import transparent_controls
from test_transparent_controls import FakeNode, Ledger, identity


def immediate(check, reason, *_):
    if not check():
        raise AcceptanceError(reason)


class World(Ledger):
    def __init__(self, *, persist_mined=False):
        super().__init__()
        self.all_nodes, self.next_pid, self.signatures, self.kills = [], 100, 0, []
        self.persist_mined = persist_mined
        self.no_kill = self.wrong_exit = self.stale_pid = self.no_restart = False
        self.no_replay = self.no_reorg = self.partial = self.wrong_auth = self.changed_raw = False
        self.wrong_source = self.wrong_config = self.wrong_saved = self.unrelated = False
        self.drop_backup_ancestor = False
        self.blocks[identity("genesis")] = {"block_hash": identity("genesis"), "height": 0,
                                           "block_hex": b"genesis".hex(), "raws": []}

    def node(self, binary, directory, label, _miner, _port):
        node = DiskNode(self, binary, directory, label)
        self.all_nodes.append(node)
        return node

    def signer(self, *_args, **_fields):
        self.signatures += 1
        return {"public_key": self.public, "secret_key": "public mock key"}

    def slh(self, _args, keys, _producer, txid, index, _expiry, _case):
        assert keys == {self.public: "public mock key"} and index == 1
        self.signatures += 1
        _, script = crash.policy([self.public], 1)
        return self.tx("slh-positive", [{"value_zat": 2_000_000, "script_hex": script}], [(txid, index)])

    def host(self, _binary, operation, **fields):
        if operation == "classical-info":
            return {"ecdsa_checks": 2, "address": "public fixture", "script_hex": self.classical_script}
        recipe = fields["recipe"]
        if operation == "classical-spend":
            parent = self.transactions[recipe["parent_hex"]]
            index = recipe["output_index"]
            outputs = deepcopy(recipe["outputs"])
            outputs.append({"value_zat": parent["outputs"][index]["value_zat"]
                - sum(row["value_zat"] for row in outputs) - recipe["fee_zat"],
                "script_hex": self.classical_script})
            return self.tx("funding" if parent["name"].startswith("coinbase") else "classical-positive",
                           outputs, [(parent["txid"], index)])
        if operation == "control-authorization":
            original = self.transactions[recipe["transaction_hex"]]
            name = recipe["variant"]
            # Unique bytes per original, while the inherited fake verifier uses the variant name.
            old = dict(self.transactions)
            result = super().host(_binary, operation, **fields)
            row = self.transactions[result["transaction_hex"]]
            self.transactions.update(old)
            raw = (name + ":" + original["name"]).encode().hex()
            result.update(transaction_hex=raw, transaction_sha256=hashlib.sha256(bytes.fromhex(raw)).hexdigest())
            self.transactions[raw] = dict(row, **result)
            return result
        assert operation == "control-block", operation
        # Match the actual host controls.rs boundary, including empty rejection.
        if not 1 <= len(recipe["transactions"]) <= 5:
            raise AcceptanceError("control_block_shape")
        node = self.all_nodes[recipe["template"]["mock_node"]]
        raws = [tx["transaction_hex"] for tx in recipe["transactions"]]
        for raw in raws:
            for txid, index in self.transactions[raw]["spends"]:
                assert node.state.output(txid, index) is not None
        return self.block(node, raws, sum(tx["fee_zat"] for tx in recipe["transactions"]))

    def block(self, node, raws, fee=0):
        self.serial += 1
        raw = f"block:{self.serial}:{node.tip()}:{raws}".encode().hex()
        block_hash = identity(raw)
        block = {"block_hash": block_hash, "block_hex": raw, "height": node.tip()[0] + 1,
                 "txids": [self.transactions[item]["txid"] for item in raws], "aggregate_fee_zat": fee,
                 "raws": list(raws), "parent": node.tip()[1]}
        self.blocks[raw] = self.blocks[block_hash] = block
        return {key: value for key, value in block.items() if key not in ("raws", "parent")}

    def backed(self, node, cache, name):
        directory = cache / "non_finalized_state" / name
        directory.mkdir(parents=True, exist_ok=True)
        for height, block_hash in node.state.chain.items():
            if height == 0 or self.drop_backup_ancestor and height == 50:
                continue
            (directory / block_hash).write_bytes(b"\0" * 8 + bytes.fromhex(self.blocks[block_hash]["block_hex"]))
        node.durable = dict(node.state.chain)
        height, block_hash = node.tip()
        return {"height": height, "hash": block_hash,
                "raw_block_sha256": hashlib.sha256(bytes.fromhex(self.blocks[block_hash]["block_hex"])).hexdigest()}


class Process:
    def __init__(self, node, pid):
        self.node, self.pid, self.status = node, pid, None

    def poll(self):
        return self.status

    def send_signal(self, value):
        assert value == signal.SIGKILL
        world = self.node.world
        world.kills.append((self.pid, value))
        self.node.kill_count += 1
        self.status = 0 if world.no_kill or world.wrong_exit else -signal.SIGKILL
        if self.node.kill_count % 3 == 2 and world.persist_mined:
            self.node.durable = dict(self.node.state.chain)
        if world.wrong_config:
            self.node.config.write_text("changed config")
        if world.wrong_saved:
            (self.node.directory.parent / "slh.json").write_text("{}")

    def wait(self, timeout):
        assert timeout == 10
        return self.status


class DiskNode(FakeNode):
    def __init__(self, world, binary, directory, label):
        state = Ledger()
        state.transactions, state.blocks = world.transactions, world.blocks
        state.chain = {0: identity("genesis")}
        super().__init__(state)
        self.world, self.binary, self.directory = world, binary, directory / label
        self.directory.mkdir()
        self.config = self.directory / "node.toml"
        self.config.write_text("ordinary isolated test config")
        self.address, self.observation_token = label, None
        self.process, self.log, self.stops, self.kill_count = None, None, [], 0
        self.durable = dict(state.chain)
        self.events = (self.directory / "rpc.jsonl").open("wb")
        self.last_process = None

    def start(self):
        assert self.process is None
        self.world.next_pid += 1
        self.process = (self.last_process if self.world.no_restart and self.last_process else
                        Process(self, self.world.next_pid))
        if self.world.stale_pid and self.last_process:
            self.process.pid = self.last_process.pid
        self.log = (self.directory / "node.log").open("ab")
        self.state.chain = dict(self.durable)
        self.state.height = max(self.state.chain)
        self.state.pool.clear()
        self.state.known = {self.world.transactions[raw]["txid"]: raw for raw in self.state.mined()}
        self.last_process = self.process

    def stop(self):
        if self.process:
            self.process = None
            self.log.close()
            self.stops.append(0)

    def close(self):
        self.stop()
        self.events.close()

    def response(self, method, *args):
        if self.world.unrelated and method == "sendrawtransaction":
            tx = self.world.transactions[args[0]]
            if tx["reason"]:
                return {"error": {"code": -25, "message": "missing inputs"}}
        result = super().response(method, *args)
        if method == "getrawtransaction" and result.get("result") is not None:
            tx = self.world.transactions[result["result"]["hex"]]
            result["result"].update(txid=tx["txid"], authdigest=(identity("wrong")
                if self.world.wrong_auth and self.kill_count else tx["auth_digest"]))
            if self.world.changed_raw and self.kill_count:
                result["result"]["hex"] = "00"
        return result

    def rpc(self, method, *args):
        assert method != "decoderawtransaction", "pinned RPC does not exist"
        if method == "getpeerinfo":
            return []
        if method == "generate":
            results = []
            for _ in range(args[0]):
                coinbase = self.world.tx(f"coinbase-{self.tip()}-{self.world.serial}",
                    [{"value_zat": 100_000_000, "script_hex": self.world.classical_script}])
                candidate = self.world.block(self, [coinbase["transaction_hex"], *self.state.pool])
                self.commit(self.world.blocks[candidate["block_hash"]])
                results.append(candidate["block_hash"])
            return results
        if method == "getblocktemplate" and not args:
            return {"height": self.tip()[0] + 1, "mock_node": self.world.all_nodes.index(self),
                    "transactions": [{"hash": self.world.transactions[raw]["txid"], "data": raw}
                                     for raw in self.state.pool]}
        if method == "getblock" and args[1] == 1:
            block = self.world.blocks[args[0]]
            txids = [self.world.transactions[raw]["txid"] for raw in block["raws"]]
            return {"height": block["height"], "tx": txids if txids and
                self.world.transactions[block["raws"][0]]["name"].startswith("coinbase") else ["coinbase", *txids]}
        if method == "getrawtransaction":
            result = self.response(method, *args)["result"]
            return result["hex"] if args[1] == 0 else result
        if method == "gettxout":
            result = super().rpc(method, *args)
            if self.world.partial and self.kill_count == 2 and result is not None:
                result = dict(result, confirmations=result["confirmations"] + 1)
            return result
        if method == "submitblock":
            block = self.world.blocks[args[0]]
            if any(self.world.transactions[raw]["reason"] for raw in block["raws"]):
                return "rejected"
            if self.world.no_replay and self.kill_count == 2:
                return None
            if self.world.no_reorg and block["height"] > self.tip()[0] and block["parent"] != self.tip()[1]:
                return None
            self.commit(block)
            return None
        return super().rpc(method, *args)

    def commit(self, block):
        if block["height"] <= self.tip()[0]:
            return  # retain equal-work competing block until it becomes longer
        chain = {block["height"]: block["block_hash"]}
        cursor = block
        while cursor["height"]:
            cursor = self.world.blocks[cursor["parent"]]
            chain[cursor["height"]] = cursor["block_hash"]
        self.state.chain, self.state.height = chain, max(chain)
        self.state.known.update({self.world.transactions[raw]["txid"]: raw for raw in self.state.mined()})
        self.state.pool.clear()


class CrashTests(unittest.TestCase):
    def flow(self, world, inject=None, version=5):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory)
            binary = root / "node-binary"
            binary.write_bytes(b"source-only mock binary")
            args = SimpleNamespace(node=binary, host=Path("host"), signer=Path("signer"),
                                   root=root, version=version)
            for module in (crash, lifecycle_controls, node_live, transparent_controls):
                stack.enter_context(patch.object(module, "wait_for", immediate))
            for module in (crash, transparent_controls, observation_controls):
                stack.enter_context(patch.object(module, "host_call", world.host))
            stack.enter_context(patch.object(crash, "ManagedNode", world.node))
            stack.enter_context(patch.object(crash, "port", return_value=1234))
            stack.enter_context(patch.object(crash, "backup_tip", world.backed))
            stack.enter_context(patch.object(crash, "producer_identity", return_value=({"public": True}, {})))
            stack.enter_context(patch.object(crash, "signer_call", world.signer))
            stack.enter_context(patch.object(crash, "single_artifact", world.slh))
            stack.enter_context(patch.object(crash, "source_state", side_effect=lambda:
                {"source": "changed" if world.wrong_source and world.kills else "original"}))
            stack.enter_context(patch.object(crash, "authenticate_coinbase", side_effect=lambda nodes, height, script:
                nodes[0].state.coinbase(nodes, height, script)))
            if inject:
                inject(stack, root)
            receipt = {}
            crash.execute(args, root, receipt)
            # Public process receipts contain negative Unix signal exit codes;
            # the fixture request parser intentionally accepts unsigned tokens only.
            return receipt, json.loads((root / "checkpoints.json").read_bytes())

    def test_both_versions_and_both_legal_mined_recovery_states(self):
        for version in (5, 6):
            for persisted in (False, True):
                with self.subTest(version=version, persisted=persisted):
                    world = World(persist_mined=persisted)
                    receipt, rows = self.flow(world, version=version)
                    self.assertEqual([(r["kind"], r["stage"]) for r in rows], crash.CHECKPOINTS)
                    self.assertEqual(len(world.kills), 12)
                    self.assertEqual(world.signatures, 2)
                    self.assertTrue(all(row["complete"] for row in rows))
                    for row in (rows[1], rows[4]):
                        self.assertEqual([r["state"] for r in row["after"]], ["new" if persisted else "old"] * 2)
                    self.assertEqual([s["kind"] for s in receipt["subjects"]], ["classical", "slh"])
                    self.assertEqual(receipt["final_tip"]["height"], 117)

    def test_missing_kill_wrong_exit_stale_pid_and_noop_restart_fail(self):
        for flag, reason in (("no_kill", "crash_wrong_exit"), ("wrong_exit", "crash_wrong_exit"),
                             ("stale_pid", "crash_restart_not_fresh"), ("no_restart", "crash_restart_not_fresh")):
            with self.subTest(flag=flag):
                world = World()
                setattr(world, flag, True)
                with self.assertRaisesRegex(AcceptanceError, reason):
                    self.flow(world)

    def test_noop_replay_noop_reorg_and_partial_recovery_fail(self):
        for flag, reason in (("no_replay", "crash_replay_no_progress"),
                             ("no_reorg", "crash_reorg_no_progress"),
                             ("partial", "crash_recovery_not_old_or_complete_new")):
            with self.subTest(flag=flag):
                world = World()
                setattr(world, flag, True)
                with self.assertRaisesRegex(AcceptanceError, reason):
                    self.flow(world)

    def test_changed_source_config_saved_authorization_and_identity_fail(self):
        for flag, reason in (("wrong_source", "crash_binding_changed"),
                             ("wrong_config", "crash_binding_changed"),
                             ("wrong_saved", "crash_binding_changed"),
                             ("wrong_auth", "crash_transaction_identity"),
                             ("changed_raw", "saved_transaction_bytes")):
            with self.subTest(flag=flag):
                world = World()
                setattr(world, flag, True)
                with self.assertRaisesRegex(AcceptanceError, reason):
                    self.flow(world)

    def test_unrelated_refusal_and_incomplete_backup_fail(self):
        for flag, reason in (("unrelated", "transparent_wrong_relay_rejection"),
                             ("drop_backup_ancestor", "crash_incomplete_backup")):
            with self.subTest(flag=flag):
                world = World()
                setattr(world, flag, True)
                with self.assertRaisesRegex(AcceptanceError, reason):
                    self.flow(world)

    def test_skipped_checkpoint_and_skipped_reentry_fail(self):
        def skip_checkpoint(stack, _root):
            original = crash.CrashJournal.checkpoint
            def call(journal, network, kind, stage, *args):
                if stage == "admitted-unmined":
                    return None
                return original(journal, network, kind, stage, *args)
            stack.enter_context(patch.object(crash.CrashJournal, "checkpoint", call))
        with self.assertRaisesRegex(AcceptanceError, "crash_checkpoint_order"):
            self.flow(World(), skip_checkpoint)
        def skip_retry(stack, _root):
            original = crash.submit_saved
            def call(network, tx):
                if network.a.kill_count == 3:
                    return []
                return original(network, tx)
            stack.enter_context(patch.object(crash, "submit_saved", call))
        with self.assertRaisesRegex(AcceptanceError, "saved_transaction_relay"):
            self.flow(World(), skip_retry)

    def test_stale_process_before_kill_is_not_signalled(self):
        world = World()
        def replace_process(stack, _root):
            original = crash.CrashJournal.flush
            def call(journal):
                original(journal)
                if journal.rows and len(journal.rows[-1]["processes"]) == 2 and not world.kills:
                    world.all_nodes[0].process = Process(world.all_nodes[0], 9999)
            stack.enter_context(patch.object(crash.CrashJournal, "flush", call))
        with self.assertRaisesRegex(AcceptanceError, "crash_stale_pid"):
            self.flow(world, replace_process)
        self.assertFalse(world.kills)

    def test_retry_changed_cached_bytes_and_empty_journal_fail(self):
        tx = {"txid": identity("tx"), "transaction_hex": "00", "transaction_sha256": identity("original")}
        with self.assertRaisesRegex(AcceptanceError, "crash_cached_bytes_changed"):
            crash.submit_saved(None, tx)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(AcceptanceError, "crash_incomplete_matrix"):
                crash.CrashJournal(Path(directory) / "checkpoints.json").finish()

    def test_main_requires_real_supported_build_receipts_before_execution(self):
        for fault in (None, "unsupported-kind", "wrong-command", "changed-binary"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                args = SimpleNamespace(human_run=True, version=5, artifacts=root / "run")
                for role, kind in (("node", "node-slh"), ("host", "host"), ("signer", "signer")):
                    binary = root / role
                    binary.write_bytes(("inert:" + role).encode())
                    argv, _name, features = build.command(kind, root / (role + "-target"))
                    record = {"schema_version": 1, "contract": common.CONTRACT, "kind": kind,
                        "complete": True, "source": {}, "command": argv, "features": features,
                        "binary_sha256": common.sha256(binary), "identity":
                            common.identity_expected(True, True) if role == "node" else None,
                        "rustc": "mock", "cargo": "mock", "environment": {}}
                    if role == "signer":
                        if fault == "unsupported-kind":
                            record["kind"] = "fixture-signer"
                        elif fault == "wrong-command":
                            record["command"] += ["--ignored"]
                        elif fault == "changed-binary":
                            binary.write_bytes(b"changed")
                    record_path = common.write_json(root / (role + ".json"), record)
                    setattr(args, role, binary)
                    setattr(args, role + "_build", record_path)
                with patch.object(common, "source_state", return_value={}), \
                        patch.object(crash, "source_state", return_value={}), \
                        patch.object(crash, "execute") as execute:
                    if fault is None:
                        crash.main(args)
                        execute.assert_called_once()
                    else:
                        with self.assertRaises(AcceptanceError):
                            crash.main(args)
                        execute.assert_not_called()
                receipt = common.read_json(args.artifacts / "execution.json")
                self.assertEqual(receipt["complete"], fault is None)

if __name__ == "__main__":
    unittest.main()
