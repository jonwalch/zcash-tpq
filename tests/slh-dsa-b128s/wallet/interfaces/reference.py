#!/usr/bin/env python3
"""Independent public enrollment and snapshot identities; no production calls.

Reuses the separately implemented format oracle and immutable public H1/L1
answers. See sources.json and NOTICE for source mappings and scope.
"""

import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
FORMATS = HERE.parent / "formats"
CORPUS = HERE / "vectors.json"
SOURCE_RECORD = HERE / "sources.json"
KEY_FORMAT = "ZcashTransparentPQ/experimental/slh-dsa-b-128s/key-exchange/v1"
RECEIPT_FORMAT = "ZcashTransparentPQ/operational-snapshot-receipt/v1"


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def dependencies():
    sources = json.loads(SOURCE_RECORD.read_bytes())
    root = HERE.parents[3]
    for item in sources["oracle_inputs"]:
        if sha256((root / item["path"]).read_bytes()) != item["sha256"]:
            raise ValueError("independent oracle input changed: " + item["path"])
    spec = importlib.util.spec_from_file_location("slh_wallet_formats", FORMATS / "reference.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, json.loads((FORMATS / "vectors.json").read_bytes())


F, L1 = dependencies()


def exchange(raw):
    value = F.canonical(raw, 4096)
    F.fields(value, "format index profile public_key_hex role suite wallet_id")
    F.require(value["format"] == KEY_FORMAT, "exchange format")
    F.number(value["index"])
    F.number(value["role"], 1)
    F.require(type(value["suite"]) is int and value["suite"] == 247, "exchange suite")
    F.hexadecimal(value["public_key_hex"], 32)
    F.hexadecimal(value["wallet_id"], 16)
    F.check_profile(value["profile"])
    return value


def identity(format_, value):
    return sha256((format_ + "\0").encode() + F.j(value))


def enroll(previous, role, threshold, exchanges):
    """Compose one policy from independently paired keys, then check old rules."""
    F.check_manifest(previous)
    keys = [exchange(F.j(key)) for key in exchanges]
    F.number(role, 1)
    F.require(all(key["role"] == role and key["profile"] == previous["profile"]
                  for key in keys), "cosigner context")
    participants = [key["wallet_id"] for key in keys]
    F.require(len(set(participants)) == len(participants), "duplicate participant")
    local = [key for key in keys if key["wallet_id"] == previous["wallet_id"]]
    end = ("receive_end", "change_end")[role]
    F.require(len(local) == 1 and local[0]["index"] == previous[end], "local origin")
    F.require(threshold <= previous["profile"]["max_tx_pq_checks"] and
              threshold <= previous["profile"]["max_block_pq_checks"], "budget")
    descriptor = F.policy(threshold, [bytes.fromhex(key["public_key_hex"]) for key in keys])
    ordered = sorted(keys, key=lambda key: F.key_commitment(bytes.fromhex(key["public_key_hex"])))
    entry = dict(role=role, policy_hex=descriptor.hex(), origins=[
        dict(account=0, index=key["index"], wallet_id=key["wallet_id"]) for key in ordered])
    F.check_origin_mapping(entry, {
        (key["wallet_id"], role, 0, key["index"]): bytes.fromhex(key["public_key_hex"])
        for key in keys})
    result = copy.deepcopy(previous)
    result[end] += 1
    result["revision"] += 1
    result["entries"].append(entry)
    result["entries"].sort(key=lambda e: (e["role"], next(
        o["index"] for o in e["origins"] if o["wallet_id"] == result["wallet_id"])))
    F.check_manifest(result)
    F.check_manifest_update(previous, result)
    return result


def receipt(raw):
    value = F.canonical(raw, 4096)
    F.fields(value, "backup_sha256 change_next format inventory_fingerprint journal profile "
                   "receive_next state_sha256 suite wallet_id")
    F.require(value["format"] == RECEIPT_FORMAT and type(value["suite"]) is int
              and value["suite"] == 247, "receipt format/suite")
    for key in ("backup_sha256", "inventory_fingerprint", "state_sha256"):
        F.hexadecimal(value[key], 32)
    F.hexadecimal(value["wallet_id"], 16)
    F.number(value["receive_next"], 2**32)
    F.number(value["change_next"], 2**32)
    F.check_profile(value["profile"])
    journal = value["journal"]
    F.fields(journal, "generation journal_id reachable_objects retained_bytes retained_objects root_fingerprint")
    F.require((journal["generation"] is None) == (journal["journal_id"] is None), "journal identity pair")
    if journal["generation"] is not None:
        F.number(journal["generation"], 2**64 - 1)
        F.hexadecimal(journal["journal_id"], 16)
    for key in ("reachable_objects", "retained_bytes", "retained_objects"):
        F.number(journal[key], 2**64 - 1)
    F.hexadecimal(journal["root_fingerprint"], 32)
    return value


def make_corpus():
    manifest = json.loads(L1["inventory_json"])
    empty = copy.deepcopy(manifest)
    empty.update(entries=[], receive_end=0, change_end=0)
    # Actual independent H1 public keys. Public synthetic participant identities
    # do not assert separate ownership or a successful funded quorum.
    answers = F.key_answers()["cases"]
    enrollments = []
    current = empty
    for role, threshold, n, local_index in [(0, 2, 3, 0), (1, 1, 1, 0), (0, 3, 3, 1)]:
        selected = [next(a for a in answers if a["role"] == role and a["index"] == local_index)]
        selected += [a for a in answers if a not in selected][:n-1]
        keys = [dict(format=KEY_FORMAT, index=local_index if i == 0 else 2**32 - i,
                     profile=manifest["profile"], public_key_hex=a["public_key"], role=role,
                     suite=247, wallet_id=manifest["wallet_id"] if i == 0 else bytes([i] * 16).hex())
                for i, a in enumerate(selected)]
        result = enroll(current, role, threshold, keys)
        enrollments.append(dict(role=role, threshold=threshold, previous_json=F.j(current).decode(),
                                keys=[dict(json=F.j(key).decode(), fingerprint=identity(KEY_FORMAT, key))
                                      for key in reversed(keys)],
                                inventory_json=F.j(result).decode(),
                                inventory_fingerprint=F.identifier("wallet-inventory", result)))
        current = result
    state = dict(format="ZcashTransparentPQ/watch-state/v2", manifest=manifest, mode="allocator",
                 payments=dict(change_next=0, records=[]), receive_next=1,
                 scan=dict(checkpoint=None, coins=[], complete=False, context=None, undo=[]))
    # A watch state legitimately contains a boolean. The older inventory-only
    # canonical helper deliberately excludes booleans; encode this literal state
    # with the same standard-library sorted/compact JSON rules.
    state_raw = json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
    retained = b"public retained snapshot test object"
    snapshot = dict(backup_sha256=sha256(bytes.fromhex(L1["backup"]["file_hex"])),
                    change_next=0, format=RECEIPT_FORMAT, inventory_fingerprint=L1["inventory_id"],
                    journal=dict(generation=None, journal_id=None, reachable_objects=0,
                                 retained_bytes=len(retained), retained_objects=1,
                                 root_fingerprint=sha256(b"ZcashTransparentPQ/wallet-journal-root-receipt/v1\0" + state_raw)),
                    profile=manifest["profile"], receive_next=1, state_sha256=sha256(state_raw),
                    suite=247, wallet_id=manifest["wallet_id"])
    receipt(F.j(snapshot))
    bindings = []
    for path, replacement in [
        (("backup_sha256",), "11" * 32), (("state_sha256",), "22" * 32),
        (("inventory_fingerprint",), "33" * 32), (("wallet_id",), "44" * 16),
        (("receive_next",), 2**32), (("change_next",), 2**32),
        (("profile", "max_block_pq_checks"), 65),
        (("journal", "root_fingerprint"), "55" * 32),
        (("journal", "reachable_objects"), 1), (("journal", "retained_objects"), 2),
        (("journal", "retained_bytes"), len(retained) + 1),
    ]:
        changed = copy.deepcopy(snapshot)
        parent = changed if len(path) == 1 else changed[path[0]]
        parent[path[-1]] = replacement
        receipt(F.j(changed))
        bindings.append(dict(field=".".join(path), json=F.j(changed).decode(),
                             fingerprint=identity(RECEIPT_FORMAT, changed)))
    v3 = copy.deepcopy(snapshot)
    v3["journal"].update(generation=2**64 - 1, journal_id="66" * 16)
    receipt(F.j(v3))
    bindings.append(dict(field="journal identity boundary (syntax only)", json=F.j(v3).decode(),
                         fingerprint=identity(RECEIPT_FORMAT, v3)))
    invalid = []
    for path, replacement in [(("suite",), 1), (("receive_next",), 2**32 + 1),
                               (("journal", "generation"), 0),
                               (("journal", "journal_id"), "66" * 16),
                               (("profile", "network"), 1)]:
        changed = copy.deepcopy(snapshot)
        parent = changed if len(path) == 1 else changed[path[0]]
        parent[path[-1]] = replacement
        invalid.append(dict(reason=".".join(path), json=F.j(changed).decode()))
    raw = F.j(snapshot).decode()
    invalid += [dict(reason="trailing newline", json=raw + "\n"),
                dict(reason="duplicate field", json=raw.replace('"suite":247', '"suite":247,"suite":247')),
                dict(reason="unknown field", json=raw[:-1] + ',"zzz":0}'),
                dict(reason="byte limit", json=" " * 4097)]
    return dict(format="slh-wallet-interface-answers-v1", material="PUBLIC TEST MATERIAL ONLY",
                profile_json=F.j(manifest["profile"]).decode(), enrollments=enrollments,
                snapshot=dict(state_json=state_raw.decode(), retained_object_hex=retained.hex(),
                              receipt_json=raw, fingerprint=identity(RECEIPT_FORMAT, snapshot),
                              valid_identity_mutations=bindings, invalid_receipts=invalid))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="create a NEW corpus; never overwrite")
    args = parser.parse_args()
    raw = (json.dumps(make_corpus(), indent=2, sort_keys=True) + "\n").encode()
    if args.write:
        with CORPUS.open("xb") as output:
            output.write(raw)
    elif raw != CORPUS.read_bytes():
        raise ValueError("independent interface answers differ")
    print("Independent interface answers match: 3 enrollments, v2 snapshot companions, 12 identity controls.")


if __name__ == "__main__":
    main()
