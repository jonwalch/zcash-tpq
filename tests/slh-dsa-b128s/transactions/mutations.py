# SPDX-License-Identifier: MIT OR Apache-2.0
"""Bounded negative controls with explicit expectations, never native-derived."""

import copy

import oracle
import wire


def refresh(artifact, tx, *, decode_records=True):
    """Rebuild all redundant claims using only independent wire/codec code."""
    raw = wire.serialize(tx)
    artifact["transaction_hex"] = raw.hex()
    artifact["transaction_sha256"] = oracle.sha256(raw)
    artifact["transaction_version"] = tx["version"]
    artifact["consensus_branch_id"] = tx["branch"]
    previous = [{"value": item["spent_output"]["value_zat"], "script": bytes.fromhex(item["spent_output"]["script_hex"])} for item in artifact["inputs"]]
    for index, (item, actual) in enumerate(zip(artifact["inputs"], tx["inputs"])):
        item["input_index"] = index
        item["sequence"] = actual["sequence"]
        item["outpoint"] = {"txid_display_hex": actual["outpoint"][:32][::-1].hex(),
                            "index": int.from_bytes(actual["outpoint"][32:], "little"), "wire_hex": actual["outpoint"].hex()}
        digest, message = oracle.message(tx, artifact["network"], previous, index)
        item["sighash_all_digest_hex"], item["message_hex"] = digest.hex(), message.hex()
        if decode_records:
            try:
                descriptor, records = oracle.decode_authorization(actual["script"])
                item["descriptor_hex"], item["records"] = descriptor.hex(), records
            except oracle.NativeFailure:
                pass
    artifact["outputs"] = [{"output_index": index, "value_zat": output["value"], "script_hex": output["script"].hex()} for index, output in enumerate(tx["outputs"])]
    artifact["artifact_sha256"] = oracle.artifact_hash(artifact)
    return artifact


def controls(artifacts):
    cases = []
    def add(name, artifact, outcome=None, failure=None, raw=None):
        if outcome is not None:
            artifact["expected"] = outcome
        artifact["artifact_sha256"] = oracle.artifact_hash(artifact)
        cases.append({"name": name, "raw": oracle.canonical(artifact) if raw is None else raw,
                      "outcome": outcome, "interface_stage": failure})
    def fresh(case="v5-1of1"):
        a = copy.deepcopy(artifacts[case])
        return a, wire.parse_transaction(bytes.fromhex(a["transaction_hex"]))
    def rejected(reason, index=0, count=None, stage="authorization"):
        return oracle.observation(stage, reason, index, count)
    # All cryptographic controls preserve wire/metadata correspondence and alter
    # the actual context or public bytes while retaining now-stale signatures.
    for offset in (0, 16, 2927, 2928, 3488, 7855):
        a, tx = fresh()
        descriptor, records = oracle.decode_authorization(tx["inputs"][0]["script"])
        signature = bytearray.fromhex(records[0]["signature_hex"])
        signature[offset] ^= 1
        records[0]["signature_hex"] = signature.hex()
        tx["inputs"][0]["script"] = oracle.encode_authorization(descriptor, records)
        add(f"signature-region-{offset}", refresh(a, tx), rejected("signature", count=1, stage="signature"))
    for change in ("network", "outpoint", "amount", "sequence", "output", "lock-time", "expiry"):
        a, tx = fresh()
        if change == "network":
            a["network"] = "Testnet"
        elif change == "outpoint":
            outpoint = bytearray(tx["inputs"][0]["outpoint"])
            outpoint[0] ^= 1
            tx["inputs"][0]["outpoint"] = bytes(outpoint)
        elif change == "amount":
            a["inputs"][0]["spent_output"]["value_zat"] += 1
        elif change == "sequence":
            tx["inputs"][0]["sequence"] -= 1
        elif change == "output":
            tx["outputs"][0]["value"] += 1
        elif change == "lock-time":
            tx["lock_time"] += 1
        else:
            tx["expiry"] += 1
        add("coherent-" + change, refresh(a, tx), rejected("signature", count=1, stage="signature"))
    a, tx = fresh()
    tx["branch"] = 0x37a5165b  # Known v5/v6 NU6.3, distinct from trusted NU7.
    add("wrong-branch", refresh(a, tx), oracle.observation("context", "consensus_branch"))
    for change in ("template", "policy-commitment", "key-commitment", "nonsigning-participant"):
        a, tx = fresh("v5-2of3" if change == "nonsigning-participant" else "v5-1of1")
        descriptor, records = oracle.decode_authorization(tx["inputs"][0]["script"])
        if change in ("template", "policy-commitment"):
            script = bytearray.fromhex(a["inputs"][0]["spent_output"]["script_hex"])
            script[0 if change == "template" else 2] ^= 1
            a["inputs"][0]["spent_output"]["script_hex"] = script.hex()
            reason, count, stage = ("output_template" if change == "template" else "output_commitment"), None, "authorization"
        elif change == "key-commitment":
            key = bytearray.fromhex(records[0]["public_key_hex"])
            key[0] ^= 1
            records[0]["public_key_hex"] = key.hex()
            tx["inputs"][0]["script"] = oracle.encode_authorization(descriptor, records)
            reason, count, stage = "key_commitment", None, "authorization"
        else:
            # Selected indices0/1 stay fixed; the non-signing commitment remains
            # sorted and changes the policy, spent script, and signed digest.
            descriptor = descriptor[:-32] + b"\xff" * 32
            tx["inputs"][0]["script"] = oracle.encode_authorization(descriptor, records)
            a["inputs"][0]["spent_output"]["script_hex"] = oracle.lock_script(descriptor).hex()
            reason, count, stage = "signature", 2, "signature"
        add(change, refresh(a, tx), rejected(reason, count=count, stage=stage))
    for change, reason in (("nonminimal-key-push", "encoding"), ("trailing", "encoding"),
                           ("sighash-suffix", "encoding"), ("descriptor-version", "unsupported_policy"),
                           ("descriptor-suite", "unsupported_policy"), ("threshold-zero", "threshold"),
                           ("missing-record", "signature_count"), ("signer-index", "signer_index")):
        a, tx = fresh()
        script = tx["inputs"][0]["script"]
        descriptor, records = oracle.decode_authorization(script)
        if change == "nonminimal-key-push":
            script = script[:1] + b"\x4c\x20" + script[2:]
        elif change == "trailing":
            script += b"\x00"
        elif change == "sighash-suffix":
            # A 7857-byte signature push, including an old-style suffix.
            script = script[:35] + b"\xb1\x1e" + script[37:7893] + b"\x01" + script[7893:]
        elif change.startswith("descriptor-") or change == "threshold-zero":
            descriptor = bytearray(descriptor)
            descriptor[{"descriptor-version": 0, "descriptor-suite": 1, "threshold-zero": 2}[change]] = 0
            script = oracle.encode_authorization(bytes(descriptor), records)
        elif change == "missing-record":
            script = oracle.push(descriptor)
        else:
            script = b"\x51" + script[1:]
        tx["inputs"][0]["script"] = script
        add(change, refresh(a, tx), rejected(reason))
    for change, reason in (("signer-order", "signer_index"), ("duplicate-commitment", "key_order")):
        a, tx = fresh("v5-2of3")
        descriptor, records = oracle.decode_authorization(tx["inputs"][0]["script"])
        if change == "signer-order":
            records.reverse()
        else:
            descriptor = descriptor[:36] + descriptor[4:36] + descriptor[68:]
        tx["inputs"][0]["script"] = oracle.encode_authorization(descriptor, records)
        add(change, refresh(a, tx), rejected(reason))
    a, tx = fresh("v6-16checks")
    # Move original input1 into position0 with its correctly associated UTXO;
    # stale signatures bind both all-input order and the explicit new position.
    tx["inputs"].reverse()
    a["inputs"].reverse()
    add("input-position-and-order", refresh(a, tx), rejected("signature", count=16, stage="signature"))
    # Deliberately inconsistent metadata must fail before reference crypto.
    for change in ("outpoint-display", "digest", "message", "old-domain-message", "record", "input-index", "output-value"):
        a, _ = fresh()
        if change == "outpoint-display":
            a["inputs"][0]["outpoint"]["txid_display_hex"] = "00" * 32
        elif change == "digest":
            a["inputs"][0]["sighash_all_digest_hex"] = "00" * 32
        elif change == "message":
            a["inputs"][0]["message_hex"] = "00" * 101
        elif change == "old-domain-message":
            framed = bytes.fromhex(a["inputs"][0]["message_hex"])
            a["inputs"][0]["message_hex"] = framed.replace(b"/message/v1\0", b"/message/v0\0", 1).hex()
        elif change == "record":
            signature = bytearray.fromhex(a["inputs"][0]["records"][0]["signature_hex"])
            signature[0] ^= 1
            a["inputs"][0]["records"][0]["signature_hex"] = signature.hex()
        elif change == "input-index":
            a["inputs"][0]["input_index"] = 1
        else:
            a["outputs"][0]["value_zat"] += 1
        add("mismatch-" + change, a, failure="correspondence")
    a, tx = fresh()
    tx["inputs"][0]["script"] = b"\0" * 131073
    add("authorization-over-guard", refresh(a, tx), failure="correspondence")
    a, _ = fresh()
    raw = bytes.fromhex(a["transaction_hex"])
    a["transaction_hex"] = (raw[:20] + b"\xfd\x01\x00" + raw[21:]).hex()
    a["transaction_sha256"] = oracle.sha256(bytes.fromhex(a["transaction_hex"]))
    add("nonminimal-compactsize", a, failure="correspondence")
    for change in ("duplicate-key", "unknown-key", "float", "negative-zero", "boolean-integer", "uppercase-hex", "non-ascii", "u64-overflow", "depth"):
        a, _ = fresh()
        if change == "unknown-key":
            a["producer"]["secret_key"] = "never-accepted"
        elif change == "boolean-integer":
            a["schema_version"] = True
        elif change == "uppercase-hex":
            a["transaction_hex"] = a["transaction_hex"].upper()
        elif change == "non-ascii":
            a["case_id"] = "\u00e9"
        encoded = oracle.canonical(a)
        if change == "duplicate-key":
            encoded = b'{"schema_version":1,' + encoded[1:]
        elif change == "float":
            encoded = encoded.replace(b'"schema_version":1', b'"schema_version":1e0')
        elif change == "negative-zero":
            encoded = encoded.replace(b'"input_index":0', b'"input_index":-0')
        elif change == "u64-overflow":
            encoded = encoded.replace(b'"schema_version":1', b'"schema_version":18446744073709551616')
        elif change == "depth":
            encoded = b"[" * 17 + b"0" + b"]" * 17
        add("schema-" + change, a, failure="schema", raw=encoded)
    for field in ("native_rejection", "signature_checks", "profile-stage", "rejection-input-index"):
        a, _ = fresh()
        if field == "profile-stage":
            del a["expected"]["functional_profile"]["stage"]
        elif field == "rejection-input-index":
            a["expected"] = oracle.observation("context", "consensus_branch")
            del a["expected"]["native_rejection"]["input_index"]
        else:
            del a["expected"][field]
        add("schema-missing-" + field, a, failure="schema")
    for kind, value in (("array", []), ("object", {})):
        a, _ = fresh()
        a["expected"] = oracle.observation("context", "consensus_branch")
        a["expected"]["native_rejection"]["reason"] = value
        add("schema-reason-" + kind, a, failure="schema")
    a, _ = fresh()
    a["artifact_sha256"] = "00" * 32
    add("artifact-hash", a, failure="integrity", raw=oracle.canonical(a))
    a, _ = fresh()
    a["transaction_sha256"] = "00" * 32
    add("transaction-hash", a, failure="integrity")
    assert len(cases) <= 60 and len({case["name"] for case in cases}) == len(cases)
    return cases
