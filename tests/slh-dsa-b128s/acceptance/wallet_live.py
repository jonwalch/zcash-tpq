#!/usr/bin/env python3
"""HUMAN ONLY: funded SLH CLI, relay, restart and coherent recovery acceptance.

Reuses the pinned research separate-cosigner payment/recovery command flow and
terminal adapter. Generates disposable private roots in a temporary directory.
No password, backup, operational snapshot or terminal transcript is retained.
"""
import argparse
from dataclasses import dataclass
import hashlib
import importlib.util
import json
from pathlib import Path
import secrets
import shutil
import tempfile

from common import (ROOT, CONTRACT, AcceptanceError, canonical, common_tip, fingerprint,
                    object_output, read_json, require, sha256, source_state, validate_build,
                    wait_for, write_json, zat)
from generate_transactions import host_call
from nodes import (BLOCK_LIMIT, NU7_HEIGHT, SLH_HEIGHT, TX_LIMIT, Network,
                   authenticate_coinbase)
from terminal import new_password, run

FUNDING_VALUE = 3_000_000
PARTIAL_FORMAT = "ZcashTransparentPQ/experimental/slh-dsa-b-128s/partial/v1"
KEY_DOMAIN = b"ZcashTransparentPQ/experimental/slh-dsa-b-128s/key/v1\0"
POLICY_DOMAIN = b"ZcashTransparentPQ/experimental/slh-dsa-b-128s/policy/v1\0"


def reference():
    path = ROOT / "tests/slh-dsa-b128s/wallet/formats/reference.py"
    spec = importlib.util.spec_from_file_location("slh_acceptance_independent_formats", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def profile(genesis_hash):
    return {"genesis_hash": genesis_hash, "max_block_pq_checks": BLOCK_LIMIT,
            "max_tx_pq_checks": TX_LIMIT, "network": 2, "nu7_activation_height": NU7_HEIGHT,
            "nu7_branch_id": "77190ad9", "pq_activation_height": SLH_HEIGHT}


def key_commitment(public_key):
    require(len(public_key) == 32, "public_key_size")
    return hashlib.sha256(KEY_DOMAIN + b"\xf7" + public_key).digest()


def lock_script(entry):
    descriptor = bytes.fromhex(entry["policy_hex"])
    require(descriptor[:2] == b"\x01\xf7", "slh_policy")
    return "5320" + hashlib.sha256(POLICY_DOMAIN + descriptor).hexdigest() + "c0"


def entry_at(manifest, role, index):
    rows = [entry for entry in manifest["entries"] if entry["role"] == role
            and any(origin["wallet_id"] == manifest["wallet_id"] and origin["index"] == index
                    for origin in entry["origins"])]
    require(len(rows) == 1, "wallet_coordinate")
    return rows[0]


def partials_match(files, proposal, proposal_id, wallet_id):
    require(len(files) == len(proposal["inputs"]), "partial_input_count")
    seen = set()
    for path in files:
        partial = read_json(path, 16384)
        index, slot = partial["input_index"], partial["signer_index"]
        require(type(index) is int and 0 <= index < len(proposal["inputs"]) and index not in seen,
                "partial_input_index")
        seen.add(index)
        entry = proposal["inputs"][index]["entry"]
        require(type(slot) is int and 0 <= slot < len(entry["origins"])
                and entry["origins"][slot]["wallet_id"] == wallet_id, "partial_owner")
        require(partial["format"] == PARTIAL_FORMAT and partial["proposal_id"] == proposal_id
                and len(bytes.fromhex(partial["signature_hex"])) == 7856, "partial_contract")
        commitment = key_commitment(bytes.fromhex(partial["public_key_hex"]))
        require(bytes.fromhex(entry["policy_hex"])[4 + 32 * slot:4 + 32 * (slot + 1)] == commitment,
                "partial_commitment")


@dataclass
class Participant:
    backup: Path
    store: Path
    manifest: dict


class Demo:
    def __init__(self, binary, profile_path, directory, nodes, password):
        self.binary, self.profile_path, self.directory = binary, profile_path, directory
        self.nodes, self.password = nodes, password
        self.oracle = reference()

    def cli(self, command, *arguments, secret=False, success=True, prompts=None):
        if prompts is None:
            prompts = [(b"Backup password: ", self.password)] if secret else []
        return run(self.binary, [command, self.profile_path, *arguments], prompts, success)

    def group(self, directory, threshold, participants):
        directory.mkdir(mode=0o700)
        originals, roots = [], []
        for index in range(participants):
            child = directory / f"signer-{index}"
            child.mkdir(mode=0o700)
            root = child / "root.tpq"
            self.cli("create-slh-exp", root, 0, prompts=new_password(self.password))
            originals.append(object_output(self.cli("inspect", root, secret=True)))
            roots.append(root)
        require(len({row["wallet_id"] for row in originals}) == participants, "independent_cosigners")
        entries = []
        inventories = []
        current = list(originals)
        for root in roots:
            public = root.parent / "inventory-0.json"
            self.cli("export", root, public, secret=True)
            inventories.append(public)
        generation = 0
        for role in (0, 1):
            for index in range(2):
                keys = []
                exchanges = []
                role_name = "receive" if role == 0 else "change"
                for root, original in zip(roots, originals):
                    key_path = root.parent / f"key-{role}-{index}.json"
                    exported = object_output(self.cli("key-export", root, role_name, index, key_path, secret=True))
                    public = exported["exchange"]
                    expected_fingerprint = hashlib.sha256(
                        b"ZcashTransparentPQ/experimental/slh-dsa-b-128s/key-exchange/v1\0"
                        + canonical(public)).hexdigest()
                    require(exported["fingerprint"] == expected_fingerprint
                            and key_path.read_bytes() == canonical(public), "key_exchange_binding")
                    require(public["wallet_id"] == original["wallet_id"]
                            and public["role"] == role and public["index"] == index, "derived_owner")
                    keys.append((key_commitment(bytes.fromhex(public["public_key_hex"])),
                                 {"account": 0, "index": index, "wallet_id": public["wallet_id"]}))
                    exchanges.extend([key_path, expected_fingerprint])
                keys.sort(key=lambda item: item[0])
                require(len(set(key for key, _ in keys)) == participants, "distinct_cosigner_keys")
                entries.append({"role": role, "origins": [origin for _, origin in keys],
                    "policy_hex": (bytes([1, 247, threshold, participants])
                                   + b"".join(key for key, _ in keys)).hex()})
                generation += 1
                for slot, root in enumerate(roots):
                    candidate = dict(current[slot], entries=list(entries), revision=generation)
                    candidate["receive_end" if role == 0 else "change_end"] = index + 1
                    self.oracle.check_manifest(candidate)
                    destination = root.parent / f"inventory-{generation}.json"
                    prepared = object_output(self.cli("enroll-prepare", inventories[slot], role_name,
                                                      threshold, destination, *exchanges))
                    require(prepared["inventory"] == candidate and destination.read_bytes() == canonical(candidate)
                            and prepared["fingerprint"] == fingerprint(candidate), "prepared_enrollment")
                    enrolled = root.parent / f"wallet-{generation}.tpq"
                    self.cli("enroll", root, destination, fingerprint(candidate), enrolled, secret=True)
                    root.unlink()
                    roots[slot] = enrolled
                    current[slot], inventories[slot] = candidate, destination
        group = []
        for root, inventory, public in zip(roots, current, inventories):
            backup = root
            store = root.parent / "watch"
            self.cli("watch-create", public, fingerprint(inventory), store, "allocator")
            actual = object_output(self.cli("inspect", backup, secret=True))
            require(actual == inventory, "enrollment_bytes")
            group.append(Participant(backup, store, inventory))
        return group

    def monitor(self, participant, destination):
        inventory = write_json(destination.with_suffix(".json"), participant.manifest)
        require(b"root_hex" not in inventory.read_bytes(), "secret_in_inventory")
        self.cli("watch-create", inventory, fingerprint(participant.manifest), destination, "monitor")
        self.cli("receive", destination, success=False)
        return destination

    def replenish_receive(self, group):
        """Use the public exchange/enrollment flow to extend the finite range."""
        index = group[0].manifest["receive_end"]
        exchanges, keys = [], []
        for signer in group:
            key_path = signer.backup.parent / "replenishment-key.json"
            response = object_output(self.cli("key-export", signer.backup, "receive", index, key_path, secret=True))
            key = response["exchange"]
            digest = hashlib.sha256(b"ZcashTransparentPQ/experimental/slh-dsa-b-128s/key-exchange/v1\0"
                                    + canonical(key)).hexdigest()
            require(response["fingerprint"] == digest, "replenishment_key_fingerprint")
            exchanges.extend([key_path, digest])
            keys.append((key_commitment(bytes.fromhex(key["public_key_hex"])),
                         {"account": 0, "index": index, "wallet_id": key["wallet_id"]}))
        keys.sort(key=lambda row: row[0])
        policy = bytes.fromhex(group[0].manifest["entries"][0]["policy_hex"])
        entry = {"role": 0, "origins": [origin for _, origin in keys],
                 "policy_hex": (bytes([1, 247, policy[2], policy[3]]) + b"".join(key for key, _ in keys)).hex()}
        for signer in group:
            current = write_json(signer.backup.parent / "before-replenishment.json", signer.manifest)
            candidate = signer.backup.parent / "replenished.json"
            response = object_output(self.cli("enroll-prepare", current, "receive", policy[2], candidate, *exchanges))
            expected = dict(signer.manifest, receive_end=index + 1, revision=signer.manifest["revision"] + 1,
                            entries=sorted([*signer.manifest["entries"], entry], key=lambda item: (item["role"],
                                next(origin["index"] for origin in item["origins"]
                                     if origin["wallet_id"] == signer.manifest["wallet_id"]))))
            require(response["inventory"] == expected and response["fingerprint"] == fingerprint(expected),
                    "replenishment_policy")
            self.oracle.check_manifest_update(signer.manifest, expected)
            backup = signer.backup.parent / "replenished.tpq"
            self.cli("enroll", signer.backup, candidate, fingerprint(expected), backup, secret=True)
            self.cli("watch-import", signer.store, candidate, fingerprint(expected))
            signer.backup, signer.manifest = backup, expected

    def refresh(self, group, payment, directory):
        """Pinned tip-only refresh flow; old bytes survive renewed local approval."""
        directory.mkdir(mode=0o700)
        owner = group[0]
        old_id = payment["review"]["proposal_id"]
        proposal = directory / "refreshed.json"
        review = object_output(self.cli("refresh-propose", owner.backup, owner.store,
                                        self.nodes[0].address, old_id, proposal, secret=True))
        decoded = read_json(proposal, 262144)
        require(review["proposal_id"] != old_id
                and decoded["transaction_hex"] == payment["proposal"]["transaction_hex"]
                and review["expiry_height"] == payment["review"]["expiry_height"], "tip_only_refresh")
        collected = directory / "partials"
        collected.mkdir(mode=0o700)
        for index, signer in enumerate(group):
            endpoint = self.nodes[index % 2].address
            before = self.export(signer, old_id, directory / f"before-{index}")
            independent = object_output(self.cli("refresh-review", signer.backup, signer.store,
                                                endpoint, old_id, proposal, secret=True))
            require({key: value for key, value in independent.items() if key != "local_change"}
                    == {key: value for key, value in review.items() if key != "local_change"}, "refresh_review")
            self.cli("refresh-approve", signer.backup, signer.store, endpoint, old_id, proposal,
                     old_id, secret=True, success=False)
            approved = object_output(self.cli("refresh-approve", signer.backup, signer.store, endpoint,
                                             old_id, proposal, review["proposal_id"], secret=True))
            require(approved == independent, "refresh_approval")
            partials = directory / f"signed-{index}"
            self.cli("sign", signer.backup, signer.store, endpoint, payment["intent_path"], proposal,
                     review["proposal_id"], partials, secret=True)
            for path in partials.iterdir():
                original, updated = read_json(before / path.name), read_json(path)
                require(dict(original, proposal_id=review["proposal_id"]) == updated, "refresh_cached_partial_bytes")
                shutil.copyfile(path, collected / path.name)
                (collected / path.name).chmod(0o600)
        self.cli("assemble", owner.backup, owner.store, self.nodes[0].address, payment["intent_path"],
                 proposal, collected, secret=True)
        exported = self.export(owner, review["proposal_id"], directory / "export")
        require((exported / "signed-transaction.hex").read_text() == payment["raw"], "refresh_saved_transaction")
        payment.update(review=review, proposal=decoded, proposal_path=proposal)
        return {"old_id": old_id, "new_id": review["proposal_id"], "exact_bytes": True}

    def sync(self, store, node=0):
        response = object_output(self.cli("sync", store, self.nodes[node].address, 1000))
        require(response["scan"]["complete_at_checkpoint"], "incomplete_scan")
        require(response["scan"]["checkpoint"]["hash"] == self.nodes[node].tip()[1], "scan_tip")
        return response

    def export(self, participant, proposal_id, directory):
        self.cli("payment-history-export", participant.store, proposal_id, directory)
        require(read_json(directory / "complete.json") == {"format": "ZcashTransparentPQ/payment-export/v1"},
                "incomplete_payment_export")
        return directory

    def payment(self, group, recipient, version, inputs, directory, *, all_value=None, reject=False, incomplete_quorum=False):
        directory.mkdir(mode=0o700)
        threshold = bytes.fromhex(group[0].manifest["entries"][0]["policy_hex"])[2]
        participants = bytes.fromhex(group[0].manifest["entries"][0]["policy_hex"])[3]
        auth = self.oracle.authorization_bytes(threshold, participants)
        input_size = 36 + len(self.oracle.compact_size(auth)) + auth + 4
        fee = 400 * max(2, (input_size * inputs + 149) // 150)
        amount = inputs * FUNDING_VALUE - fee - 500_000 if all_value is None else all_value - fee
        intent = write_json(directory / "intent.json", {"amount": amount, "max_fee": fee,
            "receiver": recipient, "remainder": "reject", "version": version})
        proposal_path = directory / "proposal.json"
        owner = group[0]
        response = self.cli("propose", owner.backup, owner.store, self.nodes[0].address,
                            intent, proposal_path, secret=True, success=not reject)
        if reject:
            require(b"insufficient eligible funds within the payment limits" in response,
                    "unexpected_budget_rejection")
            require(not proposal_path.exists(), "rejected_budget_published_proposal")
            return {"rejected_checks": threshold * inputs, "transaction_limit": TX_LIMIT}
        review = object_output(response)
        proposal = read_json(proposal_path, 262144)
        require(len(proposal["inputs"]) == inputs and review["checks"] == threshold * inputs
                and review["fee"] == review["conventional_fee"] == fee, "payment_capacity_fee")
        expected_size = self.oracle.transaction_bytes(version, [(threshold, participants)] * inputs,
                                                     2 if all_value is None else 1)
        require(review["final_bytes"] == expected_size, "payment_exact_size")
        require(all(record["entry"]["policy_hex"][:4] == "01f7" for record in proposal["inputs"]),
                "payment_suite")
        collected = directory / "collected"
        collected.mkdir(mode=0o700)
        signed = []
        for index, signer in enumerate(group[:threshold]):
            endpoint = self.nodes[index % 2].address
            independently_reviewed = object_output(self.cli("review", signer.backup, signer.store, endpoint,
                                                            intent, proposal_path, secret=True))
            require({key: value for key, value in independently_reviewed.items() if key != "local_change"}
                    == {key: value for key, value in review.items() if key != "local_change"},
                    "independent_approval")
            local = independently_reviewed["local_change"]
            if all_value is None:
                entry = proposal["outputs"][1]["entry"]
                origin = next(origin for origin in entry["origins"]
                              if origin["wallet_id"] == signer.manifest["wallet_id"])
                require(local is not None and local["local_index"] == origin["index"]
                        and local["advancement"] is None, "independent_local_change")
            else:
                require(local is None, "unexpected_no_change_advancement")
            refused = directory / f"refused-{index}"
            rejected = self.cli("sign", signer.backup, signer.store, endpoint, intent, proposal_path,
                                "00" * 32, refused, secret=True, success=False)
            require(b"proposal, approved intent or partial authorization does not match" in rejected,
                    "unexpected_approval_rejection")
            require(not refused.exists(), "unapproved_signature_export")
            partial_dir = directory / f"signed-{index}"
            self.cli("sign", signer.backup, signer.store, endpoint, intent, proposal_path,
                     review["proposal_id"], partial_dir, secret=True)
            files = sorted(partial_dir.iterdir())
            partials_match(files, proposal, review["proposal_id"], signer.manifest["wallet_id"])
            retry = directory / f"retry-{index}"
            self.cli("sign", signer.backup, signer.store, endpoint, intent, proposal_path,
                     review["proposal_id"], retry, secret=True)
            require({path.name: path.read_bytes() for path in retry.iterdir()}
                    == {path.name: path.read_bytes() for path in files}, "saved_partial_retry")
            for path in files:
                target = collected / path.name
                require(not target.exists(), "duplicate_partial_file")
                shutil.copyfile(path, target)
                target.chmod(0o600)
            signed.append(signer)
        insufficient = directory / "subquorum"
        insufficient.mkdir(mode=0o700)
        for path in sorted(collected.iterdir())[:max(0, threshold - 1)]:
            shutil.copyfile(path, insufficient / path.name)
            (insufficient / path.name).chmod(0o600)
        rejected = self.cli("assemble", owner.backup, owner.store, self.nodes[0].address, intent, proposal_path,
                            insufficient, secret=True, success=False)
        require(b"not enough distinct partials for every input threshold" in rejected,
                "unexpected_subquorum_rejection")
        rejected_export = self.export(owner, review["proposal_id"], directory / "subquorum-export")
        require(not (rejected_export / "signed-transaction.hex").exists(), "subquorum_assembled_transaction")
        if incomplete_quorum:
            require(len(group) < threshold, "missing_key_control_has_quorum")
            return {"threshold": threshold, "available_private_roots": len(group), "assembled": False,
                    "diagnostic": "not enough distinct partials for every input threshold"}
        self.cli("assemble", owner.backup, owner.store, self.nodes[0].address, intent, proposal_path,
                 collected, secret=True)
        exported = self.export(owner, review["proposal_id"], directory / "export")
        raw = (exported / "signed-transaction.hex").read_text()
        require(len(bytes.fromhex(raw)) == expected_size, "assembled_size")
        return {"review": review, "raw": raw, "proposal": proposal,
                "intent_path": intent, "proposal_path": proposal_path, "signers": signed}

    def recover(self, group, payment, directory):
        """Capture latest test authority, remove working roots, restore both modes."""
        directory.mkdir(mode=0o700)
        receipts, snapshots = [], []
        saved = []
        for index, signer in enumerate(group[:len(payment["signers"])]):
            snapshot = directory / f"snapshot-{index}"
            receipt = object_output(self.cli("snapshot-save", signer.backup, signer.store, snapshot, secret=True))
            receipts.append(receipt)
            snapshots.append(snapshot)
            if index < len(payment["signers"]):
                exported = self.export(signer, payment["review"]["proposal_id"], directory / f"before-{index}")
                saved.append({path.name: path.read_bytes() for path in exported.iterdir()
                              if path.name != "payment.json"})
        # Inventory alone has no complete payment authority. Keep monitor-only,
        # even after a trusted full scan and reopening through another process.
        inventory_restore = directory / "inventory-restored"
        response = object_output(self.cli("restore", group[0].backup, fingerprint(group[0].manifest),
                                         inventory_restore, secret=True))
        require(response["mode"] == "monitor" and response["authority"] == "unknown", "inventory_authority")
        self.sync(inventory_restore / "watch")
        self.cli("receive", inventory_restore / "watch", success=False)
        unknown = directory / "unknown-restored"
        response = object_output(self.cli("snapshot-restore", snapshots[0], unknown, "unknown", secret=True))
        require(response["mode"] == "monitor" and response["authority"] == "unknown", "unknown_authority")
        self.sync(unknown / "watch")
        self.cli("receive", unknown / "watch", success=False)
        rejected = self.cli("submit", unknown / "backup-restored.tpq", unknown / "watch",
                            self.nodes[0].address, payment["review"]["proposal_id"], secret=True, success=False)
        require(b"this watcher does not own the receiver allocator" in rejected, "unknown_authority_submission")
        # The receipts above were retained independently in this driver before
        # destroying the only test working copies. No later signing occurs.
        for signer in group:
            shutil.rmtree(signer.backup.parent)
        restored = []
        for index, (original, snapshot, receipt) in enumerate(zip(group, snapshots, receipts)):
            target = directory / f"known-{index}"
            response = object_output(self.cli("snapshot-restore", snapshot, target, "known",
                receipt["receipt_fingerprint"], "--retired-old-allocators", secret=True))
            require(response["mode"] == "allocator" and response["authority"] == "known", "known_authority")
            backup = target / "backup-restored.tpq"
            manifest = object_output(self.cli("inspect", backup, secret=True))
            expected = dict(original.manifest, allocator_id=manifest["allocator_id"],
                revision=original.manifest["revision"] + 1,
                retired_receive_end=original.manifest["receive_end"],
                retired_change_end=original.manifest["change_end"])
            require(manifest == expected and manifest["allocator_id"] != original.manifest["allocator_id"],
                    "restored_inventory")
            participant = Participant(backup, target / "watch", manifest)
            if index < len(saved):
                exported = self.export(participant, payment["review"]["proposal_id"], directory / f"after-{index}")
                require({path.name: path.read_bytes() for path in exported.iterdir() if path.name != "payment.json"}
                        == saved[index], "restored_authorization_bytes")
            self.sync(participant.store, index % 2)
            self.cli("receive", participant.store, success=False)  # old ranges retired
            restored.append(participant)
        return restored, [{"receipt_fingerprint": receipt["receipt_fingerprint"],
                           "generation": receipt["receipt"]["journal"]["generation"]} for receipt in receipts]

    def recovery_controls(self, snapshot, directory):
        directory.mkdir(mode=0o700)
        backup = snapshot / "backup.tpq"
        response = self.cli("inspect", backup, prompts=[(b"Backup password: ", b"deliberately-wrong-password")],
                            success=False)
        require(b"backup authentication failed" in response, "wrong_password_control")
        corrupt = directory / "corrupted.tpq"
        raw = bytearray(backup.read_bytes())
        require(bool(raw), "empty_backup")
        raw[-1] ^= 1
        corrupt.write_bytes(raw)
        corrupt.chmod(0o600)
        response = self.cli("inspect", corrupt, secret=True, success=False)
        require(b"backup authentication failed" in response, "corrupted_backup_control")
        missing = directory / "missing-state"
        shutil.copytree(snapshot, missing)
        (missing / "watch/state.json").unlink()
        destination = directory / "rejected-missing"
        response = self.cli("snapshot-restore", missing, destination, "unknown", secret=True, success=False)
        require(b"wallet storage operation failed" in response and not destination.exists(),
                "missing_snapshot_state_control")
        destination = directory / "rejected-trust"
        response = self.cli("snapshot-restore", snapshot, destination, "known", "00" * 32,
                            "--retired-old-allocators", secret=True, success=False)
        require(b"inventory fingerprint does not match the independently approved fingerprint" in response
                and not destination.exists(), "wrong_snapshot_trust_control")
        destination = directory / "existing"
        destination.mkdir(mode=0o700)
        marker = destination / "keep"
        marker.write_bytes(b"existing state must survive")
        response = self.cli("snapshot-restore", snapshot, destination, "unknown", secret=True, success=False)
        require(b"wallet storage operation failed" in response
                and marker.read_bytes() == b"existing state must survive", "restore_no_clobber_control")
        return {"wrong_password": True, "corrupted_backup": True, "missing_state": True,
                "untrusted_receipt": True, "existing_destination_preserved": True}

    def missing_required_key(self, group, directory):
        """Lose one required all-of-n root before any authorization exists."""
        directory.mkdir(mode=0o700)
        snapshots = []
        for index, signer in enumerate(group[:-1]):
            require(json.loads(self.cli("payments", signer.store, self.nodes[index % 2].address)) == [],
                    "missing_key_control_has_saved_authority")
            source = directory / f"snapshot-{index}"
            receipt = object_output(self.cli("snapshot-save", signer.backup, signer.store, source, secret=True))
            snapshots.append((source, receipt["receipt_fingerprint"]))
        for signer in group:
            shutil.rmtree(signer.backup.parent)
        restored = []
        for index, (source, trusted) in enumerate(snapshots):
            destination = directory / f"restored-{index}"
            response = object_output(self.cli("snapshot-restore", source, destination, "known", trusted,
                                             "--retired-old-allocators", secret=True))
            require(response["mode"] == "allocator", "missing_key_restore_authority")
            backup = destination / "backup-restored.tpq"
            manifest = object_output(self.cli("inspect", backup, secret=True))
            participant = Participant(backup, destination / "watch", manifest)
            self.sync(participant.store, index % 2)
            restored.append(participant)
        return restored


def submit(demo, network, owner, payment, *, snapshot=None):
    proposal_id, raw = payment["review"]["proposal_id"], payment["raw"]
    output = demo.cli("submit", owner.backup, owner.store, network.a.address, proposal_id, secret=True)
    txid = output.decode("ascii").split()[-1]
    require(len(txid) == 64, "submitted_txid")
    wait_for(lambda: txid in network.b.rpc("getrawmempool"), "peer_transaction_relay", 60)
    for node in network.nodes:
        require(node.rpc("getrawtransaction", txid, 0) == raw, "relayed_bytes")
        entries = node.rpc("getblocktemplate")["transactions"]
        require(any(row["hash"] == txid and row["data"] == raw for row in entries), "template_bytes")
    captured = None
    if snapshot is not None:
        captured = object_output(demo.cli("snapshot-save", owner.backup, owner.store, snapshot, secret=True))
    network.mine()
    for node in network.nodes:
        confirmed = node.rpc("getrawtransaction", txid, 1)
        require(confirmed["confirmations"] >= 1 and confirmed["hex"] == raw, "mined_bytes")
    rows = json.loads(demo.cli("payments", owner.store, network.a.address))
    require(any(row["proposal_id"] == proposal_id and row["state"] == "confirmed" for row in rows),
            "wallet_confirmation")
    if snapshot is not None:
        restored = snapshot.with_name(snapshot.name + "-unknown")
        response = object_output(demo.cli("snapshot-restore", snapshot, restored, "unknown", secret=True))
        require(response["mode"] == "monitor", "submitted_snapshot_authority")
        participant = Participant(restored / "backup-restored.tpq", restored / "watch", {})
        exported = demo.export(participant, proposal_id, snapshot.with_name(snapshot.name + "-export"))
        require((exported / "signed-transaction.hex").read_text() == raw, "submitted_snapshot_exact_bytes")
        demo.sync(participant.store)
    return {"txid": txid, "transaction_sha256": hashlib.sha256(bytes.fromhex(raw)).hexdigest(),
            "fee": payment["review"]["fee"], "final_bytes": len(bytes.fromhex(raw)),
            "checks": payment["review"]["checks"], "tip": common_tip(network.nodes),
            "submitted_snapshot": None if captured is None else captured["receipt_fingerprint"]}


def late_receipt_reorg(demo, network, group, monitor, recipient, original_funding, args, private, artifacts):
    """Spend a receipt arriving at a retired address after controlled recovery."""
    index = args.inputs  # the classical helper's final change output
    expected = original_funding["outputs"][index]
    for node in network.nodes:
        output = node.rpc("gettxout", original_funding["txid"], index, False)
        require(output is not None and output["confirmations"] >= 1 and not output["coinbase"]
                and output["scriptPubKey"]["hex"] == expected["script_hex"]
                and zat(output["value"]) == expected["value_zat"], "late_classical_change_context")
        require(node.rpc("getrawtransaction", original_funding["txid"], 0) == original_funding["transaction_hex"],
                "late_parent_bytes")
    manifest = group[0].manifest
    require(manifest["retired_receive_end"] == manifest["receive_end"], "late_range_not_retired")
    entry = entry_at(manifest, 0, manifest["receive_end"] - 1)
    funding = host_call(args.host, "classical-spend", recipe={"kind": args.classical,
        "transaction_version": args.version, "lock_time": 0, "expiry_height": network.a.tip()[0] + 20,
        "parent_hex": original_funding["transaction_hex"], "output_index": index,
        "outputs": [{"value_zat": 1_000_000, "script_hex": lock_script(entry)}], "fee_zat": 20_000})
    require(network.a.rpc("sendrawtransaction", funding["transaction_hex"]) == funding["txid"], "late_funding_submission")
    wait_for(lambda: funding["txid"] in network.b.rpc("getrawmempool"), "late_funding_relay")
    block = network.mine()[0]
    tip = common_tip(network.nodes)
    require(demo.sync(group[0].store)["scan"]["confirmed_zatoshis"] == 1_000_000
            and demo.sync(monitor)["scan"]["confirmed_zatoshis"] == 1_000_000, "retired_receipt_discovery")
    for node in network.nodes:
        node.rpc("invalidateblock", block)
    wait_for(lambda: all(node.tip()[0] == tip["height"] - 1 for node in network.nodes), "watch_reorg_tip")
    require(demo.sync(group[0].store)["scan"]["confirmed_zatoshis"] == 0
            and demo.sync(monitor)["scan"]["confirmed_zatoshis"] == 0, "watch_reorg_undo")
    for node in network.nodes:
        node.rpc("reconsiderblock", block)
    wait_for(lambda: all(node.tip() == (tip["height"], tip["hash"]) for node in network.nodes), "watch_reconsider_tip")
    require(demo.sync(group[0].store)["scan"]["confirmed_zatoshis"] == 1_000_000
            and demo.sync(monitor)["scan"]["confirmed_zatoshis"] == 1_000_000, "watch_reorg_recovery")
    write_json(artifacts / "late-funding.json", funding)
    payment = demo.payment(group, recipient, args.version, 1, private / "late-payment", all_value=1_000_000)
    return {"funding_txid": funding["txid"], "retired_receive_index": manifest["receive_end"] - 1,
            "reorg_undo_and_reconsider": True, "subsequent_spend": submit(demo, network, group[0], payment)}


def execute(args, artifacts, receipt):
    information = host_call(args.host, "classical-info", kind=args.classical)
    require(information["material"] == "public-test-only" and information["slh_checks"] == 0,
            "classical_host_identity")
    with Network(args.node, artifacts, information["address"]) as network:
        receipt["bootstrap_tip"] = network.bootstrap()
        with tempfile.TemporaryDirectory(prefix="slh-wallet-acceptance-") as temporary:
            private = Path(temporary)
            private.chmod(0o700)
            password = secrets.token_hex(24).encode("ascii")
            profile_path = write_json(private / "profile.json", profile(network.a.rpc("getblockhash", 0)))
            receipt["profile_sha256"] = sha256(profile_path)
            demo = Demo(args.cli, profile_path, private, network.nodes, password)
            group = demo.group(private / "owners", args.threshold, args.participants)
            recipient_group = demo.group(private / "recipient", 1, 1)
            recipient = demo.cli("receive", recipient_group[0].store).decode("ascii").strip()
            monitor = demo.monitor(group[0], private / "monitor")
            issued = demo.cli("receive", group[0].store).decode("ascii").strip()
            require(issued == demo.oracle.receiver(bytes.fromhex(entry_at(group[0].manifest, 0, 0)["policy_hex"])),
                    "issued_receiver")
            second_receiver = demo.cli("receive", group[0].store).decode("ascii").strip()
            require(second_receiver != issued, "durable_receiver_allocation")
            demo.cli("receive", group[0].store, success=False)
            demo.replenish_receive(group)
            updated_inventory = write_json(private / "monitor-update.json", group[0].manifest)
            demo.cli("watch-import", monitor, updated_inventory, fingerprint(group[0].manifest))
            replenished_receiver = demo.cli("receive", group[0].store).decode("ascii").strip()
            require(replenished_receiver not in (issued, second_receiver), "replenished_receiver")
            demo.cli("receive", group[0].store, success=False)
            receipt["watch_issuance"] = {"finite_range_exhaustion": True, "backed_up_replenishment": True}
            parent = authenticate_coinbase(network.nodes, 1, information["script_hex"])
            funding = host_call(args.host, "classical-spend", recipe={
                "kind": args.classical, "transaction_version": args.version,
                "lock_time": 0, "expiry_height": network.a.tip()[0] + 20,
                "parent_hex": parent["parent_hex"], "output_index": parent["output_index"],
                "outputs": [{"value_zat": FUNDING_VALUE,
                             "script_hex": lock_script(entry_at(group[0].manifest, 0, 0))}
                            for _ in range(args.inputs)], "fee_zat": 20_000})
            require(funding["slh_checks"] == 0 and funding["outpoint"]["txid_display_hex"] == parent["txid"],
                    "classical_funding_context")
            require(network.a.rpc("sendrawtransaction", funding["transaction_hex"]) == funding["txid"],
                    "classical_funding_submission")
            wait_for(lambda: funding["txid"] in network.b.rpc("getrawmempool"), "classical_peer_relay")
            network.mine()
            for node in network.nodes:
                require(node.rpc("getrawtransaction", funding["txid"], 0) == funding["transaction_hex"],
                        "classical_funding_bytes")
                for index in range(args.inputs):
                    output = node.rpc("gettxout", funding["txid"], index, False)
                    require(output is not None and not output["coinbase"] and output["confirmations"] >= 1
                            and zat(output["value"]) == FUNDING_VALUE
                            and output["scriptPubKey"]["hex"] == funding["outputs"][index]["script_hex"],
                            "funded_outpoint")
            receipt["funding"] = {"kind": args.classical, "coinbase": parent,
                "txid": funding["txid"], "transaction_sha256": funding["transaction_sha256"],
                "slh_checks_structural": 0, "primitive_entry_measurement": None}
            receipt["funding"]["coinbase"].pop("parent_hex")
            write_json(artifacts / "funding.json", funding)
            for index, signer in enumerate(group):
                require(demo.sync(signer.store, index % 2)["scan"]["confirmed_zatoshis"]
                        == args.inputs * FUNDING_VALUE, "funded_wallet_balance")
            require(demo.sync(monitor)["scan"]["confirmed_zatoshis"] == args.inputs * FUNDING_VALUE,
                    "watch_balance_parity")
            network.mine()  # forkable proposal tip after the confirmed funding
            over = args.threshold * args.inputs > TX_LIMIT
            if args.missing_required_key:
                group = demo.missing_required_key(group, private / "missing-key")
                receipt["missing_required_key"] = demo.payment(group, recipient, args.version, 1,
                    private / "subquorum-payment", all_value=FUNDING_VALUE, incomplete_quorum=True)
                receipt["working_roots_deleted"] = args.participants
            elif over:
                payment = demo.payment(group, recipient, args.version, args.inputs, private / "payment", reject=True)
                receipt["budget_rejection"] = payment
            else:
                payment = demo.payment(group, recipient, args.version, args.inputs, private / "payment")
                group, receipt["recovery"] = demo.recover(group, payment, private / "recovery")
                receipt["recovery_controls"] = demo.recovery_controls(private / "recovery/snapshot-0",
                                                                       private / "recovery-controls")
                receipt["quorum"] = {"participants": args.participants, "surviving_roots": len(group),
                                     "working_roots_deleted": args.participants}
                receipt["restart"] = network.restart()
                old_tip = payment["review"]["tip"]
                for node in network.nodes:
                    node.rpc("invalidateblock", old_tip["hash"])
                wait_for(lambda: all(node.tip()[0] == old_tip["height"] - 1 for node in network.nodes),
                         "wallet_proposal_tip_rollback")
                replacement = network.mine()[0]
                require(replacement != old_tip["hash"], "wallet_replacement_tip")
                demo.cli("submit", group[0].backup, group[0].store, network.a.address,
                         payment["review"]["proposal_id"], secret=True, success=False)
                receipt["refresh"] = demo.refresh(group, payment, private / "refresh")
                receipt["payment"] = submit(demo, network, group[0], payment, snapshot=private / "submitted-snapshot")
                proposal_id = payment["review"]["proposal_id"]
                demo.cli("payment-archive", group[0].backup, group[0].store,
                         network.a.address, proposal_id, secret=True)
                archived = demo.export(group[0], proposal_id, private / "archived-export")
                require((archived / "signed-transaction.hex").read_text() == payment["raw"], "archived_exact_bytes")
                archived_snapshot = private / "archived-snapshot"
                captured = object_output(demo.cli("snapshot-save", group[0].backup, group[0].store,
                                                   archived_snapshot, secret=True))
                restored_archive = private / "archived-unknown"
                response = object_output(demo.cli("snapshot-restore", archived_snapshot, restored_archive,
                                                 "unknown", secret=True))
                require(response["mode"] == "monitor", "archived_snapshot_authority")
                archive_monitor = Participant(restored_archive / "backup-restored.tpq", restored_archive / "watch", {})
                archived_again = demo.export(archive_monitor, proposal_id, private / "archive-restored-export")
                require((archived_again / "signed-transaction.hex").read_text() == payment["raw"],
                        "archived_snapshot_exact_bytes")
                demo.cli("payment-resume", group[0].backup, group[0].store,
                         network.a.address, proposal_id, secret=True)
                resumed = demo.export(group[0], proposal_id, private / "resumed-export")
                require((resumed / "signed-transaction.hex").read_text() == payment["raw"], "resumed_exact_bytes")
                receipt["archive_resume"] = {"proposal_id": proposal_id, "exact_bytes": True,
                                              "snapshot_receipt": captured["receipt_fingerprint"]}
                balance = demo.sync(group[0].store)["scan"]["confirmed_zatoshis"]
                require(balance == payment["review"]["change_value"], "restored_change_balance")
                following = demo.payment(group, recipient, args.version, 1, private / "after-recovery", all_value=balance)
                receipt["post_recovery_payment"] = submit(demo, network, group[0], following)
                require(demo.sync(group[0].store)["scan"]["confirmed_zatoshis"] == 0, "post_recovery_balance")
                require(demo.sync(monitor)["scan"]["confirmed_zatoshis"] == 0, "watch_post_recovery_parity")
                receipt["late_receipt"] = late_receipt_reorg(demo, network, group, monitor, recipient,
                    funding, args, private, artifacts)
            receipt["final_tip"] = common_tip(network.nodes)
        receipt["private_material_deleted"] = True
    receipt["nodes"] = network.metadata()


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--human-run", action="store_true", required=True)
    for role in ("node", "cli", "host"):
        result.add_argument("--" + role, type=Path, required=True)
        result.add_argument("--" + role + "-build", type=Path, required=True)
    result.add_argument("--artifacts", type=Path, required=True)
    result.add_argument("--threshold", type=int, required=True)
    result.add_argument("--participants", type=int, required=True)
    result.add_argument("--inputs", type=int, default=1)
    result.add_argument("--version", type=int, choices=(5, 6), required=True)
    result.add_argument("--classical", choices=("single", "multisig"), default="single")
    result.add_argument("--missing-required-key", action="store_true",
                        help="all-of-n only: lose one root before signing, restore n-1 and require subquorum refusal")
    return result


def main(args):
    require(1 <= args.threshold <= args.participants <= 15 and 1 <= args.inputs <= 15, "case_shape")
    require(not args.missing_required_key or (args.inputs == 1 and 2 <= args.threshold == args.participants),
            "missing_key_case_shape")
    artifacts = args.artifacts.resolve()
    artifacts.mkdir(mode=0o700, parents=False, exist_ok=False)
    receipt = {"schema_version": 1, "contract": CONTRACT, "complete": False,
               "case": {key: getattr(args, key) for key in ("threshold", "participants", "inputs", "version", "classical", "missing_required_key")}}
    write_json(artifacts / "execution.json", receipt)
    try:
        receipt["builds"] = {role: validate_build(read_json(getattr(args, role + "_build")),
            getattr(args, role), kind, runtime_required=role == "node") for role, kind in
            (("node", "node-slh"), ("cli", "wallet-slh"), ("host", "host"))}
        before = source_state()
        execute(args, artifacts, receipt)
        require(source_state() == before, "source_changed_during_acceptance")
        for role in ("node", "cli", "host"):
            require(sha256(getattr(args, role)) == receipt["builds"][role]["binary_sha256"], "binary_changed_during_acceptance")
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
