#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Explicit live-run adapter: isolated SLH process interruption and exact retry.

Reuse research history/replay through existing product lifecycle helpers. Imports
are inert. SIGKILL is at an acknowledged RPC boundary, never a write failpoint.
"""
import argparse
import hashlib
from pathlib import Path
import secrets
import signal

from common import (ROOT, CONTRACT, AcceptanceError, canonical, common_tip, read_json,
                    require, sha256, source_state, validate_build, wait_for, write_json, zat)
from generate_transactions import host_call, producer_identity, seed, signer_call
from lifecycle_controls import backup_tip, copy_blocks, namespace, single_artifact
from node_live import authenticated_outputs, policy, reconcile_saved, transaction_state
from nodes import (ManagedNode, Network, SLH_HEIGHT, TX_LIMIT, BLOCK_LIMIT,
                   authenticate_coinbase, port)
from observation_controls import identify
from transparent_controls import AUTHORIZATION_RELAY, Controls, fee

MAX_HEIGHT = 128
CHECKPOINTS = [(kind, stage) for kind in ("classical", "slh")
               for stage in ("admitted-unmined", "mined-unbacked", "reorg-backed")]


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


class IsolatedNetwork(Network):
    """Keep shared clean-stop behavior; transport only explicitly saved blocks."""
    def __init__(self, binary, directory, miner):
        self.nodes = [ManagedNode(binary, directory, label, miner, port())
                      for label in ("node-a", "node-b")]
        self.a, self.b = self.nodes

    def __enter__(self):
        try:
            for node in self.nodes:
                node.start()
                require(node.rpc("getpeerinfo") == [], "crash_node_has_peers")
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def mine(self, count=1):
        require(type(count) is int and 1 <= count <= 25, "crash_mining_batch")
        require(self.a.tip()[0] + count <= MAX_HEIGHT, "crash_height_bound")
        common_tip(self.nodes)
        hashes = self.a.rpc("generate", count)
        require(len(hashes) == count, "crash_mining_count")
        copy_blocks(self.a, self.b, hashes)
        return hashes


def saved(tx):
    return {"txid": tx["txid"], "raw": tx["transaction_hex"]}


def observed(node, tx):
    state = transaction_state(node, saved(tx))
    if state != "absent":
        value = node.rpc("getrawtransaction", tx["txid"], 1)
        require(value["hex"] == tx["transaction_hex"] and value["txid"] == tx["txid"]
                and value["authdigest"] == tx["auth_digest"], "crash_transaction_identity")
    return state


def snapshot(node, transactions):
    require(node.rpc("getpeerinfo") == [], "crash_node_has_peers")
    height, block_hash = node.tip()
    require(0 < height <= MAX_HEIGHT, "crash_height_bound")
    rows, states = [], {}
    for tx in transactions:
        states[tx["txid"]] = observed(node, tx)
        for index, expected in enumerate(tx["outputs"]):
            output = node.rpc("gettxout", tx["txid"], index, False)
            row = None
            if output is not None:
                require(not output["coinbase"] and type(output["confirmations"]) is int
                        and output["confirmations"] > 0
                        and output["scriptPubKey"]["hex"] == expected["script_hex"]
                        and zat(output["value"]) == expected["value_zat"], "crash_utxo_identity")
                row = {"value_zat": zat(output["value"]), "script_hex": output["scriptPubKey"]["hex"],
                       "confirmations": output["confirmations"], "coinbase": False}
            rows.append({"txid": tx["txid"], "index": index, "utxo": row})
    pool = node.rpc("getrawmempool")
    require(len(pool) == len(set(pool)) and set(pool) <= set(states), "crash_unexpected_mempool")
    require(set(pool) == {txid for txid, state in states.items() if state == "mempool"},
            "crash_mempool_identity")
    raw = node.rpc("getblock", block_hash, 0)
    return {"chain": {"height": height, "hash": block_hash,
        "block_sha256": hashlib.sha256(bytes.fromhex(raw)).hexdigest(), "utxos": rows},
        "transactions": states, "mempool": sorted(pool)}


def snapshots(network, transactions):
    result = [snapshot(node, transactions) for node in network.nodes]
    require(result[0] == result[1], "crash_peer_snapshot_disagreement")
    return result[0]


def export_chain(node, height):
    require(type(height) is int and 1 <= height <= node.tip()[0] <= MAX_HEIGHT, "crash_history_bound")
    return [{"height": index, "hash": node.rpc("getblockhash", index),
             "raw": node.rpc("getblock", node.rpc("getblockhash", index), 0)}
            for index in range(1, height + 1)]


def backup_observed(node, blocks):
    """Observe ordinary backup bytes, without requesting or forcing a flush."""
    cache = node.directory / "state"
    name = namespace((SLH_HEIGHT, TX_LIMIT, BLOCK_LIMIT))
    tip = backup_tip(node, cache, name)
    require((tip["height"], tip["hash"]) == (blocks[-1]["height"], blocks[-1]["hash"]),
            "crash_backup_tip_changed")
    directory = cache / "non_finalized_state" / name
    def complete():
        for block in blocks:
            path = directory / block["hash"]
            if not path.exists():
                return False
            require(path.is_file() and not path.is_symlink(), "crash_backup_file")
            expected = bytes.fromhex(block["raw"])
            with path.open("rb") as stream:
                value = stream.read(len(expected) + 9)
            if len(value) != len(expected) + 8 or value[8:] != expected:
                return False
        return True
    wait_for(complete, "crash_incomplete_backup", 30)
    return {"tip": tip, "blocks": len(blocks), "canonical_blocks_sha256": digest(blocks),
            "scope": "ordinary-nonfinalized-backup-visible-to-running-os"}


def binding(network, artifact_files):
    return {"source_sha256": digest(source_state()),
            "nodes": [{"binary_sha256": sha256(node.binary), "config_sha256": sha256(node.config),
                       "directory": str(node.directory.resolve())} for node in network.nodes],
            "saved_files": {str(path): sha256(path) for path in artifact_files}}


class CrashJournal:
    def __init__(self, path):
        self.path, self.rows = path, []
        self.initial_binding = None

    def flush(self):
        write_json(self.path, self.rows, fresh=not self.path.exists())

    def checkpoint(self, network, kind, stage, transactions, allowed, files):
        """A persisted controller handshake binds the observed RPC checkpoint."""
        require(len(self.rows) < len(CHECKPOINTS)
                and (kind, stage) == CHECKPOINTS[len(self.rows)], "crash_checkpoint_order")
        expected = binding(network, files)
        if self.initial_binding is None:
            self.initial_binding = expected
        require(expected["source_sha256"] == self.initial_binding["source_sha256"]
                and expected["nodes"] == self.initial_binding["nodes"]
                and all(expected["saved_files"].get(path) == value
                        for path, value in self.initial_binding["saved_files"].items()), "crash_binding_changed")
        row = {"kind": kind, "stage": stage, "token": secrets.token_hex(24), "complete": False,
               "binding": expected, "before": snapshots(network, transactions),
               "allowed_chain_sha256": {key: digest(value["chain"]) for key, value in allowed.items()},
               "processes": [], "after": []}
        self.rows.append(row)
        self.flush()
        processes = []
        for node in network.nodes:
            process = node.process
            require(process is not None and type(process.pid) is int and process.pid > 0
                    and process.poll() is None and node.observation_token is None, "crash_process_not_live")
            processes.append(process)
            row["processes"].append({"pid": process.pid, "signal": "SIGKILL", "sent": False})
        require(len({process.pid for process in processes}) == len(processes), "crash_duplicate_pid")
        self.flush()  # Full acknowledged state and exact PIDs precede every kill.
        for index, (node, process) in enumerate(zip(network.nodes, processes)):
            require(node.process is process and process.pid == row["processes"][index]["pid"]
                    and process.poll() is None, "crash_stale_pid")
            require(binding(network, files) == expected, "crash_binding_changed")
            require(snapshot(node, transactions) == row["before"], "crash_checkpoint_changed")
            event = row["processes"][index]
            process.send_signal(signal.SIGKILL)
            event["sent"] = True
            self.flush()
            status = process.wait(timeout=10)
            event["exit_code"] = status
            require(status == -signal.SIGKILL and process.poll() == status, "crash_wrong_exit")
            node.process = None
            node.log.close()
            self.flush()
        for index, node in enumerate(network.nodes):
            require(binding(network, files) == expected, "crash_binding_changed")
            node.start()
            require(node.process is not None and node.process is not processes[index]
                    and node.process.pid not in {p.pid for p in processes}
                    and node.process.poll() is None, "crash_restart_not_fresh")
            event = row["processes"][index]
            event["reopened_pid"] = node.process.pid
            after = snapshot(node, transactions)
            matches = [key for key, candidate in allowed.items() if after["chain"] == candidate["chain"]]
            require(len(matches) == 1, "crash_recovery_not_old_or_complete_new")
            selected = matches[0]
            prior = allowed[selected]["transactions"]
            subject = transactions[1 if kind == "classical" else 2]["txid"]
            require(all((state == "confirmed") == (prior[txid] == "confirmed")
                        and (txid == subject or state == prior[txid])
                        for txid, state in after["transactions"].items()), "crash_partial_transaction_state")
            row["after"].append({"state": selected, "snapshot": after})
            self.flush()
        require(binding(network, files) == expected, "crash_binding_changed")
        row["complete"] = True
        self.flush()
        return row

    def finish(self):
        require([(row["kind"], row["stage"]) for row in self.rows] == CHECKPOINTS
                and all(row["complete"] and len(row["after"]) == 2 and
                    all(p["sent"] and p["exit_code"] == -signal.SIGKILL and "reopened_pid" in p
                        for p in row["processes"]) for row in self.rows), "crash_incomplete_matrix")


def submit_saved(network, tx):
    """Submit only cached bytes to both isolated nodes; authenticate retry races."""
    require(hashlib.sha256(bytes.fromhex(tx["transaction_hex"])).hexdigest() == tx["transaction_sha256"],
            "crash_cached_bytes_changed")
    result = []
    for node in network.nodes:
        before = observed(node, tx)
        reply = node.response("sendrawtransaction", tx["transaction_hex"])
        require(reply.get("error") is None and reply.get("result") == tx["txid"]
                or observed(node, tx) != "absent", "crash_saved_submission")
        result.append({"before": before, "request_sha256": tx["transaction_sha256"],
                       "acknowledged": reply.get("error") is None})
    wait_for(lambda: all(observed(node, tx) != "absent" for node in network.nodes), "crash_saved_not_admitted")
    return result


def replay_block(node, block):
    require(node.tip() == (block["height"] - 1, block["parent"]), "crash_replay_wrong_parent")
    require(node.rpc("submitblock", block["raw"]) is None, "crash_replay_rejected")
    wait_for(lambda: node.tip() == (block["height"], block["hash"]), "crash_replay_no_progress")
    require(node.rpc("getblock", block["hash"], 0) == block["raw"], "crash_replay_changed_bytes")


def reorg(args, artifacts, network, miner, ancestor, orphan, transactions, label):
    """Build a genuinely longer competing branch by exact bounded fresh replay."""
    fork = ManagedNode(args.node, artifacts, label + "-fork", miner, port())
    rows = []
    try:
        fork.start()
        require(fork.tip()[0] == 0 and fork.rpc("getpeerinfo") == [], "crash_fork_not_fresh")
        require(all(network.a.rpc("getblock", block["hash"], 0) == block["raw"] for block in ancestor),
                "crash_saved_ancestor_changed")
        copy_blocks(network.a, fork, [block["hash"] for block in ancestor])
        require(fork.tip() == (ancestor[-1]["height"], ancestor[-1]["hash"]), "crash_fork_replay_no_progress")
        require(all(fork.rpc("getblockhash", block["height"]) == block["hash"]
                    and fork.rpc("getblock", block["hash"], 0) == block["raw"] for block in ancestor),
                "crash_fork_replay_bytes")
        require(fork.rpc("getrawmempool") == [], "crash_fork_mempool")
        hashes = fork.rpc("generate", 2)
        require(type(hashes) is list and len(hashes) == 2 and len(set(hashes)) == 2,
                "crash_fork_mining_count")
        for index, block_hash in enumerate(hashes):
            height = ancestor[-1]["height"] + index + 1
            require(fork.rpc("getblockhash", height) == block_hash
                    and len(fork.rpc("getblock", block_hash, 1)["tx"]) == 1, "crash_fork_not_empty")
            rows.append({"height": height, "hash": block_hash,
                         "raw": fork.rpc("getblock", block_hash, 0),
                         "parent": ancestor[-1]["hash"] if index == 0 else hashes[index - 1]})
        require(fork.tip() == (rows[-1]["height"], rows[-1]["hash"]), "crash_fork_mining_no_progress")
        require(rows[0]["hash"] != orphan["hash"] and rows[-1]["height"] == orphan["height"] + 1,
                "crash_not_competing_longer_branch")
        for node in network.nodes:
            require(node.tip() == (orphan["height"], orphan["hash"]), "crash_reorg_wrong_start")
            for block in rows:
                require(node.rpc("submitblock", block["raw"]) is None, "crash_reorg_rejected")
            wait_for(lambda: node.tip() == (rows[-1]["height"], rows[-1]["hash"]), "crash_reorg_no_progress")
            for block in rows:
                require(node.rpc("getblockhash", block["height"]) == block["hash"]
                        and node.rpc("getblock", block["hash"], 0) == block["raw"], "crash_reorg_bytes")
        result = snapshots(network, transactions)
        return rows, result
    finally:
        fork.close()


def run_subject(args, artifacts, network, miner, journal, files, transactions, tx, mutant, kind, index):
    control = Controls(args, artifacts, network)
    before = snapshots(network, transactions)
    parent = transactions[0]
    require(network.a.rpc("gettxout", parent["txid"], index, False) is not None
            and observed(network.a, tx) == "absent", "crash_subject_ineligible")
    ancestor = export_chain(network.a, before["chain"]["height"])
    write_json(artifacts / (kind + "-ancestor.json"), ancestor)
    backed = [backup_observed(node, ancestor) for node in network.nodes]
    # Positive proposals surround a causal malformed-authorization refusal.
    value = fee(tx, [3_000_000])
    control.accept(kind + "-positive-before", [tx], [value], publish=False)
    negative = control.reject(kind + "-negative", mutant, value, parent["txid"], [index],
        AUTHORIZATION_RELAY[mutant["variant"]], mutant["expected_consensus_reason"])
    control.accept(kind + "-positive-after", [tx], [value], publish=False)
    submit_saved(network, tx)
    admitted = snapshots(network, transactions)
    require(admitted["chain"] == before["chain"] and admitted["transactions"][tx["txid"]] == "mempool",
            "crash_admission_checkpoint_missing")
    journal.checkpoint(network, kind, "admitted-unmined", transactions, {"same-chain": before}, files)
    retries = submit_saved(network, tx)
    progress = reconcile_saved(network, [saved(tx)], 1)
    mined = snapshots(network, transactions)
    require(mined["chain"]["height"] == before["chain"]["height"] + 1
            and mined["transactions"][tx["txid"]] == "confirmed"
            and len(progress["mined_blocks"]) == 1, "crash_mining_no_progress")
    block = {"height": mined["chain"]["height"], "hash": mined["chain"]["hash"],
             "raw": network.a.rpc("getblock", mined["chain"]["hash"], 0), "parent": before["chain"]["hash"]}
    block_path = write_json(artifacts / (kind + "-saved-block.json"), block)
    outcome = journal.checkpoint(network, kind, "mined-unbacked", transactions,
                                 {"old": before, "new": mined}, [*files, block_path])
    replayed = []
    for node, result in zip(network.nodes, outcome["after"]):
        if result["state"] == "old":
            replay_block(node, read_json(block_path))
            replayed.append(node.address)
    require(snapshots(network, transactions)["chain"] == mined["chain"], "crash_replay_not_reconciled")
    replacement, restored = reorg(args, artifacts, network, miner, ancestor, block, transactions, kind)
    require(restored["transactions"][tx["txid"]] != "confirmed"
            and all(node.rpc("gettxout", parent["txid"], index, False) is not None
                    and all(node.rpc("gettxout", tx["txid"], output, False) is None
                            for output in range(len(tx["outputs"]))) for node in network.nodes),
            "crash_reorg_utxos_not_restored")
    replacement_path = write_json(artifacts / (kind + "-replacement.json"), replacement)
    durable = [backup_observed(node, [*ancestor, *replacement]) for node in network.nodes]
    journal.checkpoint(network, kind, "reorg-backed", transactions,
                       {"complete-replacement": restored}, [*files, block_path, replacement_path])
    reentry_before = common_tip(network.nodes)
    retries_after_reorg = submit_saved(network, tx)
    reentry = reconcile_saved(network, [saved(tx)], 1)
    require(common_tip(network.nodes)["height"] == reentry_before["height"] + 1
            and len(reentry["mined_blocks"]) == 1, "crash_reentry_no_progress")
    authenticated_outputs(network.nodes, tx["txid"], tx["outputs"])
    require(all(node.rpc("gettxout", parent["txid"], index, False) is None for node in network.nodes),
            "crash_reentry_parent_not_spent")
    return {"kind": kind, "txid": tx["txid"], "ancestor_backup": backed, "negative": negative,
            "admission_retry": retries, "mining": progress, "old_block_replayed_nodes": replayed,
            "replacement_backup": durable, "reorg_retry": retries_after_reorg, "reentry": reentry,
            "final": snapshots(network, transactions)}


def execute(args, artifacts, receipt):
    info = host_call(args.host, "classical-info", kind="multisig")
    require(info["ecdsa_checks"] == 2, "crash_classical_control")
    producer, _ = producer_identity(args.root, args.host, args.signer)
    generated = signer_call(args.signer, "keygen", seed=seed(0))
    keys = {generated["public_key"]: generated["secret_key"]}
    journal = CrashJournal(artifacts / "checkpoints.json")
    try:
        _, script = policy(list(keys), 1)
        with IsolatedNetwork(args.node, artifacts, info["address"]) as network:
            receipt["bootstrap_tip"] = network.bootstrap()
            parent = authenticate_coinbase(network.nodes, 1, info["script_hex"])
            funding = host_call(args.host, "classical-spend", recipe={"kind": "multisig",
                "transaction_version": args.version, "lock_time": 0, "expiry_height": 210,
                "parent_hex": parent["parent_hex"], "output_index": parent["output_index"],
                "outputs": [{"value_zat": 3_000_000, "script_hex": raw}
                            for raw in (info["script_hex"], script)], "fee_zat": 20_000})
            identify(args.host, funding, variant="missing-classical-quorum")
            submit_saved(network, funding)
            reconcile_saved(network, [saved(funding)], 1)
            authenticated_outputs(network.nodes, funding["txid"], funding["outputs"])
            classical = host_call(args.host, "classical-spend", recipe={"kind": "multisig",
                "transaction_version": args.version, "lock_time": 0, "expiry_height": 210,
                "parent_hex": funding["transaction_hex"], "output_index": 0,
                "outputs": [{"value_zat": 2_000_000, "script_hex": info["script_hex"]}], "fee_zat": 20_000})
            slh = single_artifact(args, keys, producer, funding["txid"], 1, 210, "crash-saved-slh")
            keys.clear()  # No signer call exists in any checkpoint/retry path.
            variants = [identify(args.host, tx, variant=variant) for tx, variant in
                ((classical, "missing-classical-quorum"), (slh, "corrupt-slh"))]
            transactions = [funding, classical, slh]
            files = [write_json(artifacts / (label + ".json"), tx) for label, tx in
                     zip(("funding", "classical", "slh", "bad-classical", "bad-slh"),
                         [*transactions, *variants])]
            receipt["producer"], receipt["subjects"] = producer, []
            for index, (kind, tx, mutant) in enumerate(zip(("classical", "slh"), transactions[1:], variants)):
                receipt["subjects"].append(run_subject(args, artifacts, network, info["address"],
                    journal, files, transactions, tx, mutant, kind, index))
            journal.finish()
            receipt["final_tip"] = common_tip(network.nodes)
        receipt["nodes"] = network.metadata()
    finally:
        keys.clear()


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--human-run", action="store_true", required=True)
    for role in ("node", "host", "signer"):
        result.add_argument("--" + role, type=Path, required=True)
        result.add_argument("--" + role + "-build", type=Path, required=True)
    result.add_argument("--version", type=int, choices=(5, 6), required=True)
    result.add_argument("--artifacts", type=Path, required=True)
    return result


def main(args):
    require(args.human_run, "human_run_required")
    args.root = ROOT
    artifacts = args.artifacts.resolve()
    artifacts.mkdir(mode=0o700, parents=False, exist_ok=False)
    receipt = {"schema_version": 1, "contract": CONTRACT, "complete": False,
               "case": {"driver": "crash-controls", "version": args.version, "classical": "multisig"}}
    write_json(artifacts / "execution.json", receipt)
    try:
        receipt["builds"] = {role: validate_build(read_json(getattr(args, role + "_build")),
            getattr(args, role), kind, runtime_required=role == "node") for role, kind in
            (("node", "node-slh"), ("host", "host"), ("signer", "signer"))}
        before = source_state()
        execute(args, artifacts, receipt)
        require(source_state() == before, "source_changed_during_acceptance")
        for role in ("node", "host", "signer"):
            require(sha256(getattr(args, role)) == receipt["builds"][role]["binary_sha256"],
                    "binary_changed_during_acceptance")
        receipt["complete"] = True
    except BaseException as error:
        receipt["failure"] = str(error) if isinstance(error, AcceptanceError) else type(error).__name__
        raise
    finally:
        receipt["artifacts"] = [{"path": str(path.relative_to(artifacts)), "sha256": sha256(path)}
            for path in sorted(artifacts.rglob("*")) if path.is_file() and not path.is_symlink()
            and path != artifacts / "execution.json" and "state" not in path.relative_to(artifacts).parts]
        write_json(artifacts / "execution.json", receipt, fresh=False)


if __name__ == "__main__":
    main(parser().parse_args())
