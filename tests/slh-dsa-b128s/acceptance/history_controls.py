#!/usr/bin/env python3
"""HUMAN ONLY: funded wallet refusal and recovery with uncertain chain history.

Adapted from pinned recovery_controls.py::late_receipt_and_offline and
monitor_rejections, using the existing SLH Demo/Network and authenticated raw
block discovery. Importing this module launches nothing; unit tests use mocks.
"""
import argparse
import copy
import hashlib
from pathlib import Path
import secrets
import tempfile

from common import (CONTRACT, AcceptanceError, canonical, common_tip, fingerprint,
                    object_output, read_json, require, sha256, source_state,
                    validate_build, wait_for, write_json, zat)
from generate_transactions import host_call
from history_service import HistoryService
from nodes import Network, authenticate_coinbase
from wallet_live import Demo, FUNDING_VALUE, Participant, entry_at, lock_script, profile

UNAVAILABLE = "trusted node or required chain history is unavailable; scan is incomplete"
INCONSISTENT = "chain changed or returned inconsistent block data; retry synchronization"
MONITOR = "this watcher does not own the receiver allocator"
STATE_LIMIT = 32 * 1024 * 1024 + 16384
HISTORY_BALANCE = 2 * FUNDING_VALUE


def state(store):
    return read_json(store / "state.json", STATE_LIMIT)


def authority(value):
    """Only cached scan data and v3's scan-commit generation may differ.

    All manifest, allocator, cursor, active capability and journal root fields
    remain exact. The fixture normally stays v2; no migration is induced here.
    """
    result = copy.deepcopy(value)
    del result["scan"]
    if result["format"] == "ZcashTransparentPQ/watch-state/v3":
        del result["payments"]["journal"]["generation"]
    return result


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def cached_scan(value):
    """Context faults precede rollback: cached coins, undo and tip stay exact."""
    return {key: data for key, data in value["scan"].items() if key not in ("complete", "context")}


def status(demo, store):
    return object_output(demo.cli("status", store))


def uncertain(value, observed=None):
    scan = value["scan"]
    require(scan["complete_at_checkpoint"] is False and scan["confirmed_zatoshis"] is None
            and scan["immature_coinbase_zatoshis"] is None
            and scan["pq_active_for_next_block"] is None, "uncertain_history_advertised_current_balance")
    require(observed is None or scan["observed_zatoshis"] == observed, "uncertain_history_lost_cached_funds")


def reject(demo, reason, command, *arguments, secret=False):
    output = demo.cli(command, *arguments, secret=secret, success=False)
    require(reason.encode("ascii") in output, "wrong_history_refusal_diagnostic")


def monitor_refusals(demo, participant, payment, address, directory):
    """Exact state and output checks around monitor-only commands, as in research."""
    directory.mkdir(mode=0o700)
    before = state(participant.store)
    require(before["mode"] == "monitor", "restored_monitor_promoted")
    proposal, partials = directory / "proposal.json", directory / "partials"
    reject(demo, MONITOR, "receive", participant.store)
    reject(demo, MONITOR, "propose", participant.backup, participant.store, address,
           payment["intent_path"], proposal, secret=True)
    reject(demo, MONITOR, "sign", participant.backup, participant.store, address,
           payment["intent_path"], payment["proposal_path"], payment["review"]["proposal_id"], partials, secret=True)
    reject(demo, MONITOR, "submit", participant.backup, participant.store, address,
           payment["review"]["proposal_id"], secret=True)
    require(not proposal.exists() and not partials.exists() and state(participant.store) == before,
            "monitor_refusal_changed_authority")


def restored(demo, owner, destination, *, snapshot=None):
    if snapshot is None:
        output = demo.cli("restore", owner.backup, fingerprint(owner.manifest), destination, secret=True)
    else:
        output = demo.cli("snapshot-restore", snapshot, destination, "unknown", secret=True)
    response = object_output(output)
    require(response["mode"] == "monitor" and response["authority"] == "unknown", "restore_granted_authority")
    backup = destination / "backup-restored.tpq"
    manifest = object_output(demo.cli("inspect", backup, secret=True))
    return Participant(backup, destination / "watch", manifest)


def reconciled(demo, participant, address, tip):
    response = object_output(demo.cli("sync", participant.store, address, 1000))
    require(response == status(demo, participant.store), "reopened_history_status_changed")
    scan = response["scan"]
    require(scan["complete_at_checkpoint"] is True and scan["checkpoint"] == tip
            and scan["confirmed_zatoshis"] == scan["observed_zatoshis"] == HISTORY_BALANCE
            and scan["immature_coinbase_zatoshis"] == 0
            and scan["pq_active_for_next_block"] is True, "history_reconciliation_incomplete")
    return response


def exported(demo, owner, payment, directory):
    path = demo.export(owner, payment["review"]["proposal_id"], directory)
    files = sorted(path.iterdir())
    require(1 <= len(files) <= 32 and all(p.is_file() and not p.is_symlink()
            and p.stat().st_size <= 262144 for p in files), "history_export_bounds")
    return {p.name: sha256(p) for p in files}


def cached_fault(demo, participants, payment, upstream, tip, mode, directory,
                 *, service_factory=HistoryService):
    """A valid funded pending payment before/after makes failure causal."""
    directory.mkdir(mode=0o700)
    owner = participants[0]
    require(state(owner.store)["mode"] == "allocator", "history_positive_allocator")
    for participant in participants:
        reconciled(demo, participant, upstream, tip)
    reviewed = object_output(demo.cli("review", owner.backup, owner.store, upstream,
                                    payment["intent_path"], payment["proposal_path"], secret=True))
    require(reviewed == payment["review"] and reviewed["input_value"] == FUNDING_VALUE
            and reviewed["checks"] == 1, "history_payment_not_otherwise_eligible")
    preview_path = directory / "eligible-preview.json"
    preview = object_output(demo.cli("propose-preview", owner.backup, owner.store, upstream,
                                    payment["intent_path"], preview_path, secret=True))
    require(preview["input_value"] == FUNDING_VALUE and preview["checks"] == 1
            and preview["proposal_id"] != reviewed["proposal_id"], "history_proposal_not_otherwise_eligible")
    saved = exported(demo, owner, payment, directory / "before-export")
    before = [state(p.store) for p in participants]
    reason = INCONSISTENT if mode == "inconsistent-tip" else UNAVAILABLE
    with service_factory(upstream, mode, height=tip["height"]) as service:
        for index, participant in enumerate(participants):
            first = len(service.events)
            reject(demo, reason, "sync", participant.store, service.address, 1000)
            require(any(e["fault_applied"] for e in service.events[first:]), "history_fault_not_exercised")
            uncertain(status(demo, participant.store), HISTORY_BALANCE)
            if index:
                monitor_refusals(demo, participant, payment, service.address, directory / f"monitor-{index}")
        proposal, partials = directory / "rejected-proposal.json", directory / "rejected-partials"
        for command, arguments in (
            ("propose", (payment["intent_path"], proposal)),
            ("sign", (payment["intent_path"], payment["proposal_path"], payment["review"]["proposal_id"], partials))):
            first = len(service.events)
            reject(demo, reason, command, owner.backup, owner.store, service.address, *arguments, secret=True)
            require(any(e["fault_applied"] for e in service.events[first:]), "history_payment_fault_not_exercised")
        require(not proposal.exists() and not partials.exists(), "history_refusal_published_authorization")
        after = [state(p.store) for p in participants]
        require([authority(s) for s in before] == [authority(s) for s in after], "history_fault_changed_authority")
        require([cached_scan(s) for s in before] == [cached_scan(s) for s in after], "history_fault_changed_cached_scan")
        require(exported(demo, owner, payment, directory / "uncertain-export") == saved,
                "history_fault_changed_saved_payment")
        service.clear()
        for index, participant in enumerate(participants):
            reconciled(demo, participant, service.address, tip)
            if index:
                monitor_refusals(demo, participant, payment, service.address, directory / f"reconciled-{index}")
        require(object_output(demo.cli("review", owner.backup, owner.store, service.address,
                payment["intent_path"], payment["proposal_path"], secret=True)) == reviewed,
                "history_reconciliation_changed_payment")
        after_preview = directory / "reconciled-preview.json"
        require(object_output(demo.cli("propose-preview", owner.backup, owner.store, service.address,
                payment["intent_path"], after_preview, secret=True)) == preview
                and sha256(after_preview) == sha256(preview_path), "history_reconciliation_changed_preview")
        final = [state(p.store) for p in participants]
        require([authority(s) for s in before] == [authority(s) for s in final],
                "history_reconciliation_changed_authority")
        require([cached_scan(s) for s in before] == [cached_scan(s) for s in final],
                "history_reconciliation_changed_cached_scan")
        require(exported(demo, owner, payment, directory / "after-export") == saved,
                "history_reconciliation_changed_saved_payment")
        return {"fault": mode, "diagnostic": reason, "funded_value": HISTORY_BALANCE,
                "state_before_sha256": [digest(s) for s in before],
                "state_uncertain_sha256": [digest(s) for s in after],
                "state_reconciled_sha256": [digest(s) for s in final],
                "authority_sha256": [digest(authority(s)) for s in before],
                "saved_payment_files": saved, "eligible_preview_sha256": sha256(preview_path),
                "monitor_count": len(participants) - 1,
                "reconciled_tip": tip, "events": service.events}


def rescan_fault(demo, participant, payment, upstream, tip, mode, block_hash, directory,
                 *, service_factory=HistoryService):
    """Fresh monitors must fetch history, unlike an already caught-up watcher."""
    directory.mkdir(mode=0o700)
    before = state(participant.store)
    require(before["mode"] == "monitor" and status(demo, participant.store)["scan"]["checkpoint"] is None,
            "history_rescan_not_fresh_monitor")
    monitor_refusals(demo, participant, payment, upstream, directory / "before")
    reason = INCONSISTENT if mode == "inconsistent-block" else UNAVAILABLE
    with service_factory(upstream, "honest" if mode == "incomplete" else mode, block_hash=block_hash) as service:
        if mode == "incomplete":
            response = object_output(demo.cli("sync", participant.store, service.address, 1))
            require(response == status(demo, participant.store), "reopened_history_status_changed")
            require(response["scan"]["checkpoint"] is not None
                    and response["scan"]["checkpoint"]["height"] < tip["height"], "bounded_scan_not_incomplete")
            require(any(e["method"] == "getblock" for e in service.events), "bounded_scan_no_history")
        else:
            reject(demo, reason, "sync", participant.store, service.address, 1000)
            require(any(e["fault_applied"] for e in service.events), "history_fault_not_exercised")
        uncertain(status(demo, participant.store))
        uncertain_state = state(participant.store)
        require(authority(before) == authority(uncertain_state), "history_rescan_changed_authority")
        monitor_refusals(demo, participant, payment, service.address, directory / "uncertain")
        service.clear()
        reconciled(demo, participant, service.address, tip)
        require(authority(before) == authority(state(participant.store)), "history_rescan_promoted_authority")
        monitor_refusals(demo, participant, payment, service.address, directory / "after")
        return {"fault": mode, "diagnostic": None if mode == "incomplete" else reason,
                "state_before_sha256": digest(before), "state_uncertain_sha256": digest(uncertain_state),
                "state_reconciled_sha256": digest(state(participant.store)),
                "authority_sha256": digest(authority(before)), "reconciled_tip": tip,
                "reconciled_value": HISTORY_BALANCE, "events": service.events}


def unchanged_chain(network, funding, tip, pools):
    require(common_tip(network.nodes) == tip, "history_control_changed_chain")
    require([node.rpc("getrawmempool") for node in network.nodes] == pools, "history_control_submitted_payment")
    for node in network.nodes:
        for index in range(2):
            output = node.rpc("gettxout", funding["txid"], index, False)
            require(output is not None and not output["coinbase"] and output["confirmations"] >= 1
                    and zat(output["value"]) == FUNDING_VALUE
                    and output["scriptPubKey"]["hex"] == funding["outputs"][index]["script_hex"],
                    "history_control_changed_funding")


def execute(args, artifacts, receipt):
    information = host_call(args.host, "classical-info", kind=args.classical)
    require(information["material"] == "public-test-only" and information["slh_checks"] == 0,
            "classical_host_identity")
    with Network(args.node, artifacts, information["address"]) as network:
        receipt["bootstrap_tip"] = network.bootstrap()
        with tempfile.TemporaryDirectory(prefix="slh-history-acceptance-") as temporary:
            private = Path(temporary)
            private.chmod(0o700)
            profile_path = write_json(private / "profile.json", profile(network.a.rpc("getblockhash", 0)))
            receipt["profile_sha256"] = sha256(profile_path)
            demo = Demo(args.cli, profile_path, private, network.nodes, secrets.token_hex(24).encode("ascii"))
            owner = demo.group(private / "owner", 1, 1)[0]
            recipient = demo.group(private / "recipient", 1, 1)[0]
            receiver = demo.cli("receive", recipient.store).decode("ascii").strip()
            issued = demo.cli("receive", owner.store).decode("ascii").strip()
            require(issued == demo.oracle.receiver(bytes.fromhex(entry_at(owner.manifest, 0, 0)["policy_hex"])),
                    "history_funding_receiver")
            monitor = Participant(owner.backup, demo.monitor(owner, private / "monitor"), owner.manifest)
            parent = authenticate_coinbase(network.nodes, 1, information["script_hex"])
            funding = host_call(args.host, "classical-spend", recipe={"kind": args.classical,
                "transaction_version": args.version, "lock_time": 0, "expiry_height": network.a.tip()[0] + 20,
                "parent_hex": parent["parent_hex"], "output_index": parent["output_index"],
                "outputs": [{"value_zat": FUNDING_VALUE, "script_hex": lock_script(entry_at(owner.manifest, 0, 0))}
                            for _ in range(2)],
                "fee_zat": 20_000})
            require(funding["slh_checks"] == 0 and funding["outpoint"]["txid_display_hex"] == parent["txid"],
                    "classical_funding_context")
            require(network.a.rpc("sendrawtransaction", funding["transaction_hex"]) == funding["txid"],
                    "classical_funding_submission")
            wait_for(lambda: funding["txid"] in network.b.rpc("getrawmempool"), "classical_peer_relay")
            network.mine()
            tip = common_tip(network.nodes)
            pools = [node.rpc("getrawmempool") for node in network.nodes]
            require(pools == [[], []], "history_setup_pool_not_empty")
            unchanged_chain(network, funding, tip, pools)
            for node in network.nodes:
                require(node.rpc("getrawtransaction", funding["txid"], 0) == funding["transaction_hex"],
                        "classical_funding_bytes")
            write_json(artifacts / "funding.json", funding)
            payment = demo.payment([owner], receiver, args.version, 1, private / "payment")
            snapshot = private / "snapshot"
            demo.cli("snapshot-save", owner.backup, owner.store, snapshot, secret=True)
            unknown = restored(demo, owner, private / "unknown", snapshot=snapshot)
            receipt["cached_faults"] = []
            for mode in ("unavailable", "missing-hash", "inconsistent-tip"):
                row = cached_fault(demo, [owner, monitor, unknown], payment, network.a.address,
                                   tip, mode, private / mode)
                unchanged_chain(network, funding, tip, pools)
                receipt["cached_faults"].append(row)
            receipt["rescan_faults"] = []
            # Fresh stores are essential: a cached tip need not request pruned blocks.
            for kind in ("public-monitor", "inventory-restore"):
                for mode in ("pruned", "inconsistent-block", "incomplete"):
                    label = kind + "-" + mode
                    destination = private / (label + "-store")
                    participant = (restored(demo, owner, destination) if kind == "inventory-restore" else
                        Participant(owner.backup, demo.monitor(owner, destination), owner.manifest))
                    row = rescan_fault(demo, participant, payment, network.a.address, tip, mode,
                                       tip["hash"], private / label)
                    unchanged_chain(network, funding, tip, pools)
                    receipt["rescan_faults"].append(dict(row, recovery=kind))
            receipt["final_tip"] = tip
        receipt["private_material_deleted"] = True
    receipt["nodes"] = network.metadata()


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--human-run", action="store_true", required=True)
    for role in ("node", "cli", "host"):
        result.add_argument("--" + role, type=Path, required=True)
        result.add_argument("--" + role + "-build", type=Path, required=True)
    result.add_argument("--version", type=int, choices=(5, 6), required=True)
    result.add_argument("--classical", choices=("single", "multisig"), default="single")
    result.add_argument("--artifacts", type=Path, required=True)
    return result


def main(args):
    require(args.human_run, "human_run_required")
    artifacts = args.artifacts.resolve()
    artifacts.mkdir(mode=0o700, parents=False, exist_ok=False)
    receipt = {"schema_version": 1, "contract": CONTRACT, "complete": False,
               "case": {"version": args.version, "classical": args.classical, "driver": "history-controls"}}
    write_json(artifacts / "execution.json", receipt)
    try:
        receipt["builds"] = {role: validate_build(read_json(getattr(args, role + "_build")),
            getattr(args, role), kind, runtime_required=role == "node") for role, kind in
            (("node", "node-slh"), ("cli", "wallet-slh"), ("host", "host"))}
        before = source_state()
        execute(args, artifacts, receipt)
        require(source_state() == before, "source_changed_during_acceptance")
        for role in ("node", "cli", "host"):
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
