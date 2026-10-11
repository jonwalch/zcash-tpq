#!/usr/bin/env python3
"""Independent SLH wallet format oracle for PUBLIC TEST MATERIAL ONLY.

Adapted from the separately implemented Transparent PQ Python format reference;
see sources.json and NOTICE. No production serializer, signer, Rust invocation,
node, wallet file I/O, or network request is used to compute expectations.
Bech32m arithmetic follows BIP 173/350 (Pieter Wuille and Greg Maxwell).
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

import cryptography
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

HERE = Path(__file__).resolve().parent
CORPUS = HERE / "vectors.json"
KEY_CORPUS = HERE.parent / "vectors.json"
KEY_CORPUS_SHA256 = "a4791aeef33d859bcb57fc14fc460946bde9ef78462989edcf1687845028eafd"
PREFIX = "ZcashTransparentPQ/"
SLH_PREFIX = PREFIX + "experimental/slh-dsa-b-128s/"
ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
GENERATORS = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
SUITE = 0xF7
MAX_PLAINTEXT = 8 * 1024 * 1024
MAX_ENTRIES = 4096
MAX_PARTIAL = 16384
MAX_TRANSACTION = 262144
MAX_PROPOSAL = 262144
MAX_INPUTS = 15
PUBLIC_WALLET_ID = bytes(range(160, 176)).hex()


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def number(value, maximum=0xFFFFFFFF):
    require(type(value) is int and 0 <= value <= maximum, "integer")


def hexadecimal(value, length):
    require(isinstance(value, str) and len(value) == 2 * length
            and re.fullmatch("[0-9a-f]*", value) is not None, "hex")
    return bytes.fromhex(value)


def fields(value, names):
    require(isinstance(value, dict) and set(value) == set(names.split()), "fields")


def j(value):
    def walk(item, depth):
        require(depth <= 16, "depth")
        if isinstance(item, dict):
            for key, child in item.items():
                require(isinstance(key, str), "object key")
                walk(key, depth + 1)
                walk(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                walk(child, depth + 1)
        elif isinstance(item, str):
            require(all(32 <= ord(c) <= 126 and c not in '\\"' for c in item), "string")
        elif item is not None:
            number(item, 2**64 - 1)
    walk(value, 0)
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def canonical(raw, maximum):
    require(isinstance(raw, bytes) and len(raw) <= maximum, "size")
    # Bound nesting before json.loads recurses/allocates. All format arrays have
    # separate schema limits; this reference is not a streaming product parser.
    depth, string = 0, False
    for byte in raw:
        require(32 <= byte <= 126 and byte != 92, "ASCII/no escapes")
        if byte == 34:
            string = not string
        elif not string and byte in (91, 123):
            depth += 1
            require(depth <= 16, "depth")
        elif not string and byte in (93, 125):
            depth -= 1
            require(depth >= 0, "depth")
    require(depth == 0 and not string, "JSON shape")

    def pairs(items):
        require(len({key for key, _ in items}) == len(items), "duplicate field")
        return dict(items)

    value = json.loads(raw, object_pairs_hook=pairs)
    require(j(value) == raw, "canonical JSON")
    return value


def identifier(domain, value):
    return hashlib.sha256((PREFIX + domain + "/v1\0").encode() + j(value)).hexdigest()


def polymod(values):
    state = 1
    for digit in values:
        carry = state >> 25
        state = ((state & 0x1FFFFFF) << 5) ^ digit
        for bit, generator in enumerate(GENERATORS):
            if carry & (1 << bit):
                state ^= generator
    return state


def encode_words(words, hrp="tpqreg", constant=0x2BC830A3):
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    checksum = polymod(expanded + words + [0] * 6) ^ constant
    digits = words + [(checksum >> shift) & 31 for shift in range(25, -1, -5)]
    return hrp + "1" + "".join(ALPHABET[x] for x in digits)


def encode(payload, hrp="tpqreg", constant=0x2BC830A3):
    bits = "".join(f"{byte:08b}" for byte in payload)
    bits += "0" * (-len(bits) % 5)
    return encode_words([int(bits[i:i+5], 2) for i in range(0, len(bits), 5)], hrp, constant)


def decode(receiver):
    require(isinstance(receiver, str) and len(receiver) == 69
            and receiver.startswith("tpqreg1"), "receiver shape")
    require(all(c in ALPHABET for c in receiver[7:]), "alphabet")
    words = [ALPHABET.index(c) for c in receiver[7:]]
    expanded = [ord(c) >> 5 for c in "tpqreg"] + [0] + [ord(c) & 31 for c in "tpqreg"]
    require(polymod(expanded + words) == 0x2BC830A3, "checksum")
    bits = "".join(f"{word:05b}" for word in words[:-6])
    payload = int(bits, 2).to_bytes(35, "big")
    require(payload[:3] == b"\x01\x02\xf7", "receiver context")
    return payload[3:]


def commitment(descriptor):
    return hashlib.sha256((SLH_PREFIX + "policy/v1\0").encode() + descriptor).digest()


def receiver(descriptor):
    return encode(b"\x01\x02\xf7" + commitment(descriptor))


def check_profile(profile):
    fields(profile, "network genesis_hash nu7_branch_id nu7_activation_height "
           "pq_activation_height max_tx_pq_checks max_block_pq_checks")
    require(type(profile["network"]) is int and profile["network"] == 2, "network")
    hexadecimal(profile["genesis_hash"], 32)
    require(profile["nu7_branch_id"] == "77190ad9", "branch")
    for key in ("nu7_activation_height", "pq_activation_height", "max_tx_pq_checks",
                "max_block_pq_checks"):
        number(profile[key])
    require(profile["pq_activation_height"] > profile["nu7_activation_height"], "activation")
    require(0 < profile["max_tx_pq_checks"] <= profile["max_block_pq_checks"], "budget")


def check_entry(entry):
    fields(entry, "role policy_hex origins")
    number(entry["role"], 1)
    require(isinstance(entry["policy_hex"], str), "descriptor")
    require(isinstance(entry["origins"], list), "origins array")
    n = len(entry["origins"])
    require(1 <= n <= 15, "origin count")
    descriptor = hexadecimal(entry["policy_hex"], 4 + 32 * n)
    require(descriptor[:2] == b"\x01\xf7" and 1 <= descriptor[2] <= descriptor[3] <= 15
            and descriptor[3] == n, "policy")
    hashes_ = [descriptor[i:i+32] for i in range(4, len(descriptor), 32)]
    require(hashes_ == sorted(set(hashes_)), "commitment order")
    identities = []
    for origin in entry["origins"]:
        fields(origin, "wallet_id account index")
        hexadecimal(origin["wallet_id"], 16)
        require(type(origin["account"]) is int and origin["account"] == 0, "account")
        number(origin["index"])
        identities.append(origin["wallet_id"])
    require(len(set(identities)) == n, "participants")
    return descriptor


def check_manifest(manifest):
    fields(manifest, "format derivation_version suite wallet_id allocator_id revision profile "
           "birthday_height receive_end change_end retired_receive_end retired_change_end entries")
    require(manifest["format"] == PREFIX + "inventory/v1", "format")
    require(type(manifest["derivation_version"]) is int and manifest["derivation_version"] == 1
            and type(manifest["suite"]) is int and manifest["suite"] == SUITE, "suite/version")
    for key in ["wallet_id", "allocator_id"]:
        hexadecimal(manifest[key], 16)
    for key in ["revision", "birthday_height"]:
        number(manifest[key])
    check_profile(manifest["profile"])
    for role in ["receive", "change"]:
        number(manifest[role + "_end"], 2**32)
        number(manifest["retired_" + role + "_end"], manifest[role + "_end"])
    require(isinstance(manifest["entries"], list), "entries array")
    expected = manifest["receive_end"] + manifest["change_end"]
    require(expected <= MAX_ENTRIES and expected == len(manifest["entries"]), "coverage")
    coordinates, policies = [], set()
    for entry in manifest["entries"]:
        descriptor = check_entry(entry)
        local = [o for o in entry["origins"] if o["wallet_id"] == manifest["wallet_id"]]
        require(len(local) == 1, "local origin")
        coordinates.append((entry["role"], local[0]["index"]))
        policies.add(commitment(descriptor))
    require(coordinates == [(role, i) for role, end in enumerate(
        [manifest["receive_end"], manifest["change_end"]]) for i in range(end)], "coordinates")
    require(len(policies) == expected and len(j(manifest)) <= MAX_PLAINTEXT, "policies/size")


def inventory_entries(manifest):
    """Index an already validated inventory by its local derivation coordinates."""
    return {(entry["role"], next(origin["index"] for origin in entry["origins"]
                                if origin["wallet_id"] == manifest["wallet_id"])): entry
            for entry in manifest["entries"]}


def check_manifest_update(previous, candidate):
    """Check cumulative snapshot compatibility, not authentication or durable state."""
    check_manifest(previous)
    check_manifest(candidate)
    if candidate["revision"] == previous["revision"]:
        require(j(candidate) == j(previous), "conflicting revision")
        return
    require(candidate["revision"] > previous["revision"], "revision rollback")
    for field in ["format", "derivation_version", "suite", "wallet_id", "profile"]:
        require(candidate[field] == previous[field], "inventory identity")
    require(candidate["birthday_height"] <= previous["birthday_height"], "birthday advanced")
    for role in ["receive", "change"]:
        end, retired = role + "_end", "retired_" + role + "_end"
        require(candidate[end] >= previous[end], "coverage rollback")
        require(candidate[retired] >= previous[retired], "retirement rollback")
        if candidate["allocator_id"] != previous["allocator_id"]:
            require(candidate[retired] >= previous[end], "allocator rotation coverage")
    entries = inventory_entries(candidate)
    for coordinate, entry in inventory_entries(previous).items():
        require(entries.get(coordinate) == entry, "entry history changed")


def password_check(password):
    require(isinstance(password, bytes) and 1 <= len(password) <= 1024, "password length")
    password.decode("utf-8")


def backup_key(password, salt):
    password_check(password)
    return Argon2id(salt=salt, length=32, iterations=3, lanes=4,
                    memory_cost=65536, ad=None, secret=None).derive(password)


def backup_header(salt, nonce, ciphertext_length):
    return (b"TPQBACK\0\x01\x01\x01\x13" + struct.pack("<III", 65536, 3, 4)
            + salt + nonce + struct.pack("<I", ciphertext_length))


def decrypt_backup(blob, password, kdf=backup_key):
    require(isinstance(blob, bytes) and len(blob) >= 56, "header")
    require(blob[:24] == backup_header(bytes(16), bytes(12), 16)[:24], "parameters")
    size, = struct.unpack("<I", blob[52:56])
    require(16 <= size <= MAX_PLAINTEXT + 16 and len(blob) == 56 + size, "length")
    password_check(password)
    key = kdf(password, blob[24:40])
    try:
        plaintext = ChaCha20Poly1305(key).decrypt(blob[40:52], blob[56:], blob[:56])
    except InvalidTag as error:
        raise ValueError("authentication") from error
    recovery = canonical(plaintext, MAX_PLAINTEXT)
    check_recovery(recovery)
    # Root-to-public-key regeneration is checked separately by both Rust backends.
    return recovery


def key_commitment(public_key):
    require(isinstance(public_key, bytes) and len(public_key) == 32, "public key")
    return hashlib.sha256((SLH_PREFIX + "key/v1\0").encode() + bytes([SUITE]) + public_key).digest()


def policy(threshold, public_keys):
    number(threshold, 15)
    require(1 <= threshold <= len(public_keys) <= 15, "policy shape")
    hashes = sorted(key_commitment(key) for key in public_keys)
    require(len(set(hashes)) == len(hashes), "duplicate keys")
    return bytes([1, SUITE, threshold, len(hashes)]) + b"".join(hashes)


def check_origin_mapping(entry, enrolled_keys):
    """Check an independently approved public enrollment mapping, not ownership.

    enrolled_keys maps (wallet_id, role, account, index) to full public keys.
    The descriptor and origins alone cannot prove that an origin maps to a key.
    """
    descriptor = check_entry(entry)
    for slot, origin in enumerate(entry["origins"]):
        coordinate = (origin["wallet_id"], entry["role"], origin["account"], origin["index"])
        require(coordinate in enrolled_keys, "unapproved origin")
        require(key_commitment(enrolled_keys[coordinate]) == descriptor[4 + 32 * slot:36 + 32 * slot],
                "origin commitment")


def check_partial(partial):
    fields(partial, "format input_index proposal_id public_key_hex signature_hex signer_index")
    require(partial["format"] == SLH_PREFIX + "partial/v1", "partial suite")
    number(partial["input_index"], 14)
    number(partial["signer_index"], 14)
    hexadecimal(partial["proposal_id"], 32)
    hexadecimal(partial["public_key_hex"], 32)
    hexadecimal(partial["signature_hex"], 7856)
    require(len(j(partial)) <= MAX_PARTIAL, "partial size")
    # Authorization requires approved inputs, policy slots and real verification.


def read_partial(raw):
    value = canonical(raw, MAX_PARTIAL)
    check_partial(value)
    return value


def script(descriptor):
    return b"\x53\x20" + commitment(descriptor) + b"\xc0"


def check_proposal_envelope(proposal):
    """Public envelope checks only; transaction effects/trust/signatures are L2."""
    fields(proposal, "format inputs outputs profile tip transaction_hex")
    require(proposal["format"] == PREFIX + "proposal/v1", "proposal format")
    check_profile(proposal["profile"])
    fields(proposal["tip"], "height hash")
    number(proposal["tip"]["height"])
    hexadecimal(proposal["tip"]["hash"], 32)
    require(isinstance(proposal["inputs"], list) and 1 <= len(proposal["inputs"]) <= MAX_INPUTS,
            "proposal inputs")
    require(isinstance(proposal["outputs"], list) and 1 <= len(proposal["outputs"]) <= 2,
            "proposal outputs")
    raw = proposal["transaction_hex"]
    require(isinstance(raw, str) and 0 < len(raw) <= MAX_TRANSACTION * 2 and len(raw) % 2 == 0,
            "transaction size")
    hexadecimal(raw, len(raw) // 2)
    for item in proposal["inputs"]:
        fields(item, "entry spent_output_hex")
        descriptor = check_entry(item["entry"])
        output = hexadecimal(item["spent_output_hex"], 44)
        require(output[8:] == b"\x23" + script(descriptor), "spent output policy")
    for index, item in enumerate(proposal["outputs"]):
        fields(item, "entry kind receiver")
        c = decode(item["receiver"])
        if index == 0:
            require(item["kind"] == "payment" and item["entry"] is None, "payment output")
        else:
            require(item["kind"] == "change" and item["entry"] is not None, "change output")
            descriptor = check_entry(item["entry"])
            require(item["entry"]["role"] == 1 and commitment(descriptor) == c, "change policy")
    require(len(j(proposal)) <= MAX_PROPOSAL, "proposal size")


def sample_proposal(version, manifest):
    """Encode an unsigned transparent-only NU7 fixture without Rust serialization."""
    require(version in (5, 6), "version")
    receive_entry, change_entry = manifest["entries"][0], manifest["entries"][2]
    receive_policy, change_policy = check_entry(receive_entry), check_entry(change_entry)
    # Header, one synthetic outpoint with empty authorization/final sequence,
    # recipient/change outputs, then three/four empty shielded vectors.
    group = {5: 0x26A7270A, 6: 0xD884B698}[version]
    header = struct.pack("<IIIII", 0x80000000 | version, group, 0x77190AD9, 0, 140)
    tx_input = bytes.fromhex("11" * 32) + struct.pack("<I", 0) + b"\x00" + b"\xff" * 4
    output = lambda value, descriptor: struct.pack("<Q", value) + b"\x23" + script(descriptor)
    tx = header + b"\x01" + tx_input + b"\x02" + output(20000, receive_policy) + output(30000, change_policy)
    tx += bytes(3 if version == 5 else 4)
    return dict(format=PREFIX + "proposal/v1", profile=manifest["profile"],
                tip=dict(height=120, hash="22" * 32), transaction_hex=tx.hex(),
                inputs=[dict(entry=receive_entry, spent_output_hex=output(100000, receive_policy).hex())],
                outputs=[dict(kind="payment", entry=None, receiver=receiver(receive_policy)),
                         dict(kind="change", entry=change_entry, receiver=receiver(change_policy))])


def check_recovery(recovery):
    fields(recovery, "format root_hex manifest")
    require(recovery["format"] == PREFIX + "recovery/v1", "recovery format")
    hexadecimal(recovery["root_hex"], 32)
    check_manifest(recovery["manifest"])
    require(len(j(recovery)) <= MAX_PLAINTEXT, "recovery size")
    # Regenerating roots is a separate H1 check. This is not operational recovery.


def encrypt_backup(recovery, password, salt, nonce, kdf=backup_key):
    check_recovery(recovery)
    password_check(password)
    require(len(salt) == 16 and len(nonce) == 12, "salt/nonce")
    plaintext = j(recovery)
    header = backup_header(salt, nonce, len(plaintext) + 16)
    key = kdf(password, salt)
    return header + ChaCha20Poly1305(key).encrypt(nonce, plaintext, header)


def compact_size(value):
    number(value, 2**64 - 1)
    if value < 253:
        return bytes([value])
    for maximum, tag, fmt in [(65535, 253, "<H"), (2**32 - 1, 254, "<I"), (2**64 - 1, 255, "<Q")]:
        if value <= maximum:
            return bytes([tag]) + struct.pack(fmt, value)
    raise AssertionError("bounded CompactSize")


def push(data):
    size = len(data)
    if size <= 75:
        return bytes([size]) + data
    if size <= 255:
        return b"\x4c" + bytes([size]) + data
    require(size <= 65535, "push length")
    return b"\x4d" + struct.pack("<H", size) + data


def authorization_bytes(threshold, participants):
    number(threshold, 15)
    number(participants, 15)
    require(1 <= threshold <= participants <= 15, "policy shape")
    descriptor_length = 4 + 32 * participants
    return threshold * (1 + 1 + 32 + 3 + 7856) + len(push(bytes(descriptor_length)))


def transaction_bytes(version, shapes, output_count=2):
    require(type(version) is int and version in (5, 6), "version")
    require(1 <= len(shapes) <= 15 and output_count in (1, 2), "transaction shape")
    # Header: version, group, branch, lock, expiry; then transparent vectors;
    # empty Sapling spend/output and Orchard vectors, plus Ironwood for v6.
    size = 20 + len(compact_size(len(shapes))) + len(compact_size(output_count))
    for threshold, participants in shapes:
        authorization = authorization_bytes(threshold, participants)
        size += 36 + len(compact_size(authorization)) + authorization + 4
    size += output_count * (8 + len(compact_size(35)) + 35)
    return size + (3 if version == 5 else 4)


def check_payment_capacity(version, shapes, transaction_limit=16, block_limit=64):
    number(transaction_limit)
    number(block_limit)
    require(0 < transaction_limit <= block_limit, "check limits")
    size = transaction_bytes(version, shapes)
    require(size <= MAX_TRANSACTION, "transaction size")
    checks = sum(threshold for threshold, _ in shapes)
    require(checks <= transaction_limit and checks <= block_limit, "check limit")
    return size, checks


def synthetic_keys(count):
    """Public format-only bytes. These are not generated SLH public roots."""
    return [hashlib.sha256(b"SLH wallet format fixture\0" + bytes([i])).digest() for i in range(count)]


def sample_entry(threshold, participants, role=0, index=0xFFFFFFFF):
    keys = synthetic_keys(participants)
    rows = sorted((key_commitment(key), dict(account=0, index=index, wallet_id=f"{i + 1:032x}"), key)
                  for i, key in enumerate(keys))
    entry = dict(role=role, policy_hex=policy(threshold, keys).hex(), origins=[row[1] for row in rows])
    enrolled = {(row[1]["wallet_id"], role, 0, index): row[2] for row in rows}
    return entry, enrolled


def key_answers():
    raw = KEY_CORPUS.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == KEY_CORPUS_SHA256, "H1 key corpus changed")
    return json.loads(raw)


def sample_manifest():
    keys = key_answers()
    entries = []
    for row in keys["cases"]:
        if row["index"] <= 1:
            descriptor = policy(1, [bytes.fromhex(row["public_key"])])
            entries.append(dict(role=row["role"], policy_hex=descriptor.hex(), origins=[
                dict(account=0, index=row["index"], wallet_id=PUBLIC_WALLET_ID)]))
    profile = dict(network=2, genesis_hash="00" * 32, nu7_branch_id="77190ad9",
                   nu7_activation_height=105, pq_activation_height=110,
                   max_tx_pq_checks=16, max_block_pq_checks=64)
    return dict(format=PREFIX + "inventory/v1", derivation_version=1, suite=SUITE,
                wallet_id=PUBLIC_WALLET_ID, allocator_id="dd" * 16, revision=0,
                profile=profile, birthday_height=0, receive_end=2, change_end=2,
                retired_receive_end=0, retired_change_end=0, entries=entries)


def make_corpus():
    require(cryptography.__version__ == "48.0.1", "reference library version")
    manifest = sample_manifest()
    check_manifest(manifest)
    recovery = dict(format=PREFIX + "recovery/v1", root_hex=key_answers()["root"], manifest=manifest)
    password, salt, nonce = b"public-slh-wallet-format-password", bytes(range(16)), bytes(range(16, 28))
    key = backup_key(password, salt)
    blob = encrypt_backup(recovery, password, salt, nonce, lambda *_: key)
    require(decrypt_backup(blob, password, lambda *_: key) == recovery, "envelope round trip")
    partial = dict(format=SLH_PREFIX + "partial/v1", input_index=14, proposal_id="12" * 32,
                   public_key_hex="34" * 32, signature_hex="56" * 7856, signer_index=14)
    check_partial(partial)
    policies = []
    for participants in range(1, 16):
        for threshold in range(1, participants + 1):
            entry, enrolled = sample_entry(threshold, participants)
            descriptor = check_entry(entry)
            check_origin_mapping(entry, enrolled)
            c = commitment(descriptor)
            policies.append(dict(threshold=threshold, participants=participants,
                                 policy_hex=descriptor.hex(), commitment_hex=c.hex(),
                                 receiver=receiver(descriptor), script_hex=(b"\x53\x20" + c + b"\xc0").hex(),
                                 authorization_bytes=authorization_bytes(threshold, participants)))
    cases = [(1, 1, 1), (1, 15, 15), (8, 2, 3), (9, 2, 3), (2, 15, 15)]
    maximum_entry = sample_entry(15, 15)[0]
    proposals = []
    for version in (5, 6):
        proposal = sample_proposal(version, manifest)
        check_proposal_envelope(proposal)
        proposals.append(dict(transaction_version=version, proposal_json=j(proposal).decode(),
                              proposal_id=identifier("wallet-proposal", proposal)))
    return dict(
        format=SLH_PREFIX + "wallet-format-corpus/v1",
        material="PUBLIC TEST MATERIAL ONLY; synthetic policies, signatures and profile; no live funds",
        key_corpus_sha256=KEY_CORPUS_SHA256, policies=policies, proposals=proposals,
        inventory_json=j(manifest).decode(), inventory_id=identifier("wallet-inventory", manifest),
        profile_id=identifier("wallet-profile", manifest["profile"]),
        recovery_json=j(recovery).decode(),
        backup=dict(password_utf8_hex=password.hex(), key_hex=key.hex(), header_hex=blob[:56].hex(), file_hex=blob.hex()),
        partial_json=j(partial).decode(),
        capacity=dict(partial_bytes=len(j(partial)), partial_cap=MAX_PARTIAL,
                      maximum_entry_json=j(maximum_entry).decode(), maximum_entry_bytes=len(j(maximum_entry)),
                      maximum_entry_array_bytes=2 + MAX_ENTRIES * len(j(maximum_entry)) + MAX_ENTRIES - 1,
                      inventory_entries_cap=MAX_ENTRIES, inventory_bytes_cap=MAX_PLAINTEXT,
                      encrypted_backup_bytes_cap=56 + MAX_PLAINTEXT + 16,
                      journal_capability_bytes_cap=1048576, watch_v2_bytes_cap=33554432,
                      watch_v3_metadata_bytes_cap=16384, journal_commit_bytes_cap=67108864),
        transactions=[dict(inputs=count, threshold=m, participants=n, checks=count * m,
                           v5_bytes=transaction_bytes(5, [(m, n)] * count),
                           v6_bytes=transaction_bytes(6, [(m, n)] * count),
                           fits_16_checks=count * m <= 16) for count, m, n in cases])


def corpus_bytes(corpus):
    return (json.dumps(corpus, indent=2, sort_keys=True) + "\n").encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="create a new public corpus; never overwrite")
    args = parser.parse_args()
    expected = corpus_bytes(make_corpus())
    if args.write:
        with CORPUS.open("xb") as file:
            file.write(expected)
    else:
        require(CORPUS.read_bytes() == expected, "retained corpus bytes differ")
    print("Checked 120 policy/receiver answers, four H1 inventory entries, profile/inventory IDs, "
          "two v1 proposal IDs, one v1 encrypted backup, one maximum partial and 10 transaction size answers. "
          "No production comparison or live recovery was run.")


if __name__ == "__main__":
    main()
