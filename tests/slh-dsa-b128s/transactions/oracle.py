# SPDX-License-Identifier: MIT OR Apache-2.0
"""Independent strict artifact, codec and transparent digest reconstruction.

No production implementation is imported. The required verification callback is
supplied by the separately pinned Python/portable-C reference in check.py.
"""

import hashlib
import json
import re

import wire

CONTRACT = "slh-dsa-b-128s-exp-v1"
NU7 = 0x77190AD9
MAX_JSON = 16 * 1024 * 1024
MONEY = 2_100_000_000_000_000
KEY_DOMAIN = b"ZcashTransparentPQ/experimental/slh-dsa-b-128s/key/v1\0"
POLICY_DOMAIN = b"ZcashTransparentPQ/experimental/slh-dsa-b-128s/policy/v1\0"
MESSAGE_DOMAIN = b"ZcashTransparentPQ/experimental/slh-dsa-b-128s/message/v1\0"
NETWORKS = {"Mainnet": 0, "Testnet": 1, "Regtest": 2}
TOP = "schema_version contract public_fixture case_id context_provenance producer network transaction_version consensus_branch_id transaction_hex transaction_sha256 inputs outputs expected artifact_sha256"
INPUT = "input_index outpoint sequence spent_output descriptor_hex sighash_all_digest_hex message_hex context_hex records"
PRODUCER = "zakura_revision algorithm_revision blake3_version host_source_inventory_sha256 host_lock_sha256 host_binary_sha256 signer_source_inventory_sha256 signer_lock_sha256 signer_binary_sha256"
CONTEXT_ERRORS = {"transaction_version", "backend_unavailable", "consensus_branch", "input_context", "sighash"}
AUTH_ERRORS = {"input_context", "output_template", "authorization_size", "encoding", "unsupported_policy", "threshold", "key_order", "output_commitment", "signature_count", "signer_index", "key_commitment", "verification_budget"}


class InterfaceFailure(ValueError):
    def __init__(self, stage, reason):
        self.stage, self.reason = stage, reason
        super().__init__(f"{stage}/{reason}")


class NativeFailure(ValueError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def require(condition, stage, reason):
    if not condition:
        raise InterfaceFailure(stage, reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def artifact_hash(artifact):
    return sha256(canonical({key: value for key, value in artifact.items() if key != "artifact_sha256"}))


def strict_json(raw):
    """Bound depth before JSON parsing and reject ambiguous numeric spellings."""
    require(isinstance(raw, bytes) and len(raw) <= MAX_JSON, "transport", "size")
    depth, quoted, escaped = 0, False, False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            require(depth <= 16, "schema", "nesting")
        elif byte in (93, 125):
            depth -= 1
    def integer(token):
        require(re.fullmatch(r"0|[1-9][0-9]*", token) is not None and len(token) <= 20, "schema", "integer")
        number = int(token)
        require(number <= 2**64 - 1, "schema", "integer")
        return number
    def forbidden(_):
        raise InterfaceFailure("schema", "number")
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "schema", "duplicate_key")
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_int=integer,
                           parse_float=forbidden, parse_constant=forbidden)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as error:
        raise InterfaceFailure("schema", "json") from error
    def ascii_values(item):
        if isinstance(item, str):
            require(item.isascii(), "schema", "ascii")
        elif isinstance(item, dict):
            for key, child in item.items():
                ascii_values(key)
                ascii_values(child)
        elif isinstance(item, list):
            for child in item:
                ascii_values(child)
    ascii_values(value)
    return value


def fields(value, names):
    require(type(value) is dict and set(value) == set(names.split()), "schema", "fields")


def number(value, maximum=2**32-1):
    require(type(value) is int and 0 <= value <= maximum, "schema", "range")


def hexadecimal(value, *, size=None, maximum=None):
    require(type(value) is str and len(value) % 2 == 0, "schema", "hex")
    if size is not None:
        require(len(value) == 2 * size, "schema", "hex_length")
    if maximum is not None:
        require(len(value) <= 2 * maximum, "schema", "hex_length")
    require(re.fullmatch(r"[0-9a-f]*", value) is not None, "schema", "hex")
    return bytes.fromhex(value)


def array(value, low, high):
    require(type(value) is list and low <= len(value) <= high, "schema", "array")


def expected_schema(value, input_count=32):
    fields(value, "native_authorization native_rejection signature_checks functional_profile")
    require(value["native_authorization"] in ("accept", "reject"), "schema", "native_result")
    rejection = value["native_rejection"]
    if rejection is not None:
        fields(rejection, "stage reason input_index")
        stage, reason = rejection["stage"], rejection["reason"]
        require(type(stage) is str and type(reason) is str, "schema", "native_rejection")
        require((stage == "context" and reason in CONTEXT_ERRORS)
                or (stage == "authorization" and reason in AUTH_ERRORS)
                or (stage == "signature" and reason == "signature"), "schema", "native_rejection")
        if rejection["input_index"] is not None:
            number(rejection["input_index"], 31)
    require((rejection is None) == (value["native_authorization"] == "accept"), "schema", "native_result")
    if value["signature_checks"] is not None:
        number(value["signature_checks"], 480)
    profile = value["functional_profile"]
    fields(profile, "transaction_limit block_limit result stage")
    require(type(profile["transaction_limit"]) is int and profile["transaction_limit"] == 16
            and type(profile["block_limit"]) is int and profile["block_limit"] == 64, "schema", "profile")
    require((profile["result"], profile["stage"]) in (("accept", None), ("not_evaluated", None),
                                                    ("reject", "transaction_budget")), "schema", "profile")
    if rejection is None:
        require(value["signature_checks"] is not None and profile["result"] in ("accept", "reject"), "schema", "expected")
    else:
        require(profile["result"] == "not_evaluated" and profile["stage"] is None, "schema", "expected")
        index, count = rejection["input_index"], value["signature_checks"]
        if rejection["stage"] == "context":
            require(index is None and count is None, "schema", "native_rejection")
        else:
            require(type(index) is int and 0 <= index < input_count, "schema", "native_rejection")
            require((count is not None) == (rejection["stage"] == "signature"), "schema", "native_rejection")


def validate_schema(a):
    fields(a, TOP)
    require(type(a["schema_version"]) is int and a["schema_version"] == 1
            and a["contract"] == CONTRACT and a["public_fixture"] is True, "schema", "contract")
    require(type(a["case_id"]) is str and re.fullmatch(r"[a-z0-9_-]{1,64}", a["case_id"]) is not None, "schema", "case_id")
    require(a["context_provenance"] == "synthetic-public-fixture", "schema", "provenance")
    p = a["producer"]
    fields(p, PRODUCER)
    hexadecimal(p["zakura_revision"], size=20)
    hexadecimal(p["algorithm_revision"], size=20)
    require(p["zakura_revision"] in {"9b175e9d3d46a6aa4cfb5552517c3d828852ecbc",
                                     "24a17b3f0e7d88513688d607054f018ab6f15af2",
                                     "e33dc43089acca2fe2c6516927932f2b7618b8bc",
                                     "3f36c35031126a8f8cd52865ef0be9e5dc494b8d"}
            and p["algorithm_revision"] == "b392fe82d2d9770142477a576a758a233888bc0a"
            and p["blake3_version"] == "1.8.5", "schema", "producer_pin")
    for name in p:
        if name.endswith("sha256"):
            hexadecimal(p[name], size=32)
    require(type(a["network"]) is str and a["network"] in NETWORKS, "schema", "network")
    require(type(a["transaction_version"]) is int and a["transaction_version"] in (5, 6), "schema", "version")
    number(a["consensus_branch_id"])
    hexadecimal(a["transaction_hex"], maximum=2_000_000)
    hexadecimal(a["transaction_sha256"], size=32)
    hexadecimal(a["artifact_sha256"], size=32)
    array(a["inputs"], 1, 32)
    for item in a["inputs"]:
        fields(item, INPUT)
        number(item["input_index"])
        number(item["sequence"])
        fields(item["outpoint"], "txid_display_hex index wire_hex")
        hexadecimal(item["outpoint"]["txid_display_hex"], size=32)
        hexadecimal(item["outpoint"]["wire_hex"], size=36)
        number(item["outpoint"]["index"])
        fields(item["spent_output"], "value_zat script_hex")
        number(item["spent_output"]["value_zat"], MONEY)
        hexadecimal(item["spent_output"]["script_hex"], maximum=10000)
        hexadecimal(item["descriptor_hex"], maximum=484)
        hexadecimal(item["sighash_all_digest_hex"], size=32)
        hexadecimal(item["message_hex"], size=101)
        require(item["context_hex"] == "", "schema", "context")
        array(item["records"], 0, 15)
        for record in item["records"]:
            fields(record, "signer_index public_key_hex signature_hex")
            number(record["signer_index"], 14)
            hexadecimal(record["public_key_hex"], size=32)
            hexadecimal(record["signature_hex"], size=7856)
    array(a["outputs"], 1, 64)
    for item in a["outputs"]:
        fields(item, "output_index value_zat script_hex")
        number(item["output_index"])
        number(item["value_zat"], MONEY)
        hexadecimal(item["script_hex"], maximum=10000)
    require(sum(i["spent_output"]["value_zat"] for i in a["inputs"]) <= MONEY, "schema", "input_sum")
    require(sum(i["value_zat"] for i in a["outputs"]) <= MONEY, "schema", "output_sum")
    expected_schema(a["expected"], len(a["inputs"]))


def key_commitment(key):
    return hashlib.sha256(KEY_DOMAIN + b"\xf7" + key).digest()


def lock_script(descriptor):
    return b"\x53\x20" + hashlib.sha256(POLICY_DOMAIN + descriptor).digest() + b"\xc0"


def decode_policy(data):
    if len(data) < 4:
        raise NativeFailure("encoding")
    if data[:2] != b"\x01\xf7":
        raise NativeFailure("unsupported_policy")
    m, n = data[2:4]
    if not 1 <= m <= n <= 15:
        raise NativeFailure("threshold")
    if len(data) != 4 + 32 * n:
        raise NativeFailure("encoding")
    keys = [data[offset:offset+32] for offset in range(4, len(data), 32)]
    if any(left >= right for left, right in zip(keys, keys[1:])):
        raise NativeFailure("key_order")
    return m, keys


def push(data):
    length = len(data)
    if length <= 75:
        prefix = bytes([length])
    elif length <= 255:
        prefix = b"\x4c" + bytes([length])
    elif length <= 65535:
        prefix = b"\x4d" + length.to_bytes(2, "little")
    else:
        raise ValueError("field push cap")
    return prefix + data


def decode_authorization(data):
    if len(data) > 131072:
        raise NativeFailure("authorization_size")
    reader = wire.Reader(data)
    def take_push(maximum):
        try:
            opcode = reader.take(1)[0]
            if 1 <= opcode <= 75:
                length = opcode
            elif opcode == 0x4c:
                length = reader.take(1)[0]
                if length < 76:
                    raise ValueError("nonminimal")
            elif opcode == 0x4d:
                length = int.from_bytes(reader.take(2), "little")
                if length < 256:
                    raise ValueError("nonminimal")
            else:
                raise ValueError("push opcode")
            if length > maximum:
                raise ValueError("push bound")
            return reader.take(length)
        except ValueError as error:
            raise NativeFailure("encoding") from error
    records = []
    while reader.pos < len(data) and (data[reader.pos] == 0 or 0x51 <= data[reader.pos] <= 0x5e):
        if len(records) == 15:
            raise NativeFailure("signature_count")
        opcode = reader.take(1)[0]
        index = 0 if opcode == 0 else opcode - 0x50
        key, signature = take_push(32), take_push(7856)
        if len(key) != 32 or len(signature) != 7856:
            raise NativeFailure("encoding")
        records.append({"signer_index": index, "public_key_hex": key.hex(), "signature_hex": signature.hex()})
    descriptor = take_push(484)
    if reader.pos != len(data):
        raise NativeFailure("encoding")
    threshold, commitments = decode_policy(descriptor)
    if len(records) != threshold:
        raise NativeFailure("signature_count")
    indices = [record["signer_index"] for record in records]
    if any(index >= len(commitments) for index in indices) or any(left >= right for left, right in zip(indices, indices[1:])):
        raise NativeFailure("signer_index")
    return descriptor, records


def encode_authorization(descriptor, records):
    out = bytearray()
    for record in records:
        index = record["signer_index"]
        out.append(0 if index == 0 else 0x50 + index)
        out.extend(push(bytes.fromhex(record["public_key_hex"])))
        out.extend(push(bytes.fromhex(record["signature_hex"])))
    return bytes(out) + push(descriptor)


def message(tx, network, previous, index):
    digest = wire.input_digest(tx, previous, index)
    framed = MESSAGE_DOMAIN + bytes([0xf7, NETWORKS[network], tx["version"]]) + wire.le32(tx["branch"]) + wire.le32(index) + digest
    assert len(framed) == 101
    return digest, framed


def observation(stage=None, reason=None, index=None, count=None):
    rejected = stage is not None
    profile_result = "not_evaluated" if rejected else ("accept" if count <= 16 else "reject")
    return {
        "native_authorization": "reject" if rejected else "accept",
        "native_rejection": {"stage": stage, "reason": reason, "input_index": index} if rejected else None,
        "signature_checks": count,
        "functional_profile": {"transaction_limit": 16, "block_limit": 64, "result": profile_result,
                               "stage": "transaction_budget" if profile_result == "reject" else None},
    }


def evaluate(raw, verify_signature):
    """Return (artifact, independent observation); verifier callback is mandatory."""
    a = strict_json(raw)
    validate_schema(a)
    require(artifact_hash(a) == a["artifact_sha256"], "integrity", "artifact_hash")
    encoded = bytes.fromhex(a["transaction_hex"])
    require(sha256(encoded) == a["transaction_sha256"], "integrity", "transaction_hash")
    try:
        tx = wire.parse_transaction(encoded)
    except ValueError as error:
        raise InterfaceFailure("correspondence", "transaction_decode") from error
    require(tx["version"] == a["transaction_version"] and tx["branch"] == a["consensus_branch_id"], "correspondence", "transaction_header")
    require(len(tx["inputs"]) == len(a["inputs"]) and len(tx["outputs"]) == len(a["outputs"]), "correspondence", "counts")
    for index, (item, actual) in enumerate(zip(a["inputs"], tx["inputs"])):
        outpoint = item["outpoint"]
        displayed = bytes.fromhex(outpoint["txid_display_hex"])[::-1] + wire.le32(outpoint["index"])
        require(item["input_index"] == index and bytes.fromhex(outpoint["wire_hex"]) == displayed == actual["outpoint"]
                and item["sequence"] == actual["sequence"], "correspondence", "input")
    for index, (item, actual) in enumerate(zip(a["outputs"], tx["outputs"])):
        require(item["output_index"] == index and item["value_zat"] == actual["value"]
                and bytes.fromhex(item["script_hex"]) == actual["script"], "correspondence", "output")
    context_failure = tx["branch"] != NU7
    previous = [{"value": item["spent_output"]["value_zat"], "script": bytes.fromhex(item["spent_output"]["script_hex"])} for item in a["inputs"]]
    parsed, first_failure = [], None
    for index, (item, actual, spent) in enumerate(zip(a["inputs"], tx["inputs"], previous)):
        framed = None
        if not context_failure:
            digest, framed = message(tx, a["network"], previous, index)
            require(digest.hex() == item["sighash_all_digest_hex"] and framed.hex() == item["message_hex"], "correspondence", "digest_message")
        decoded, parse_error = None, None
        try:
            decoded = decode_authorization(actual["script"])
        except NativeFailure as error:
            parse_error = error
        if decoded is not None:
            descriptor, records = decoded
            require(descriptor.hex() == item["descriptor_hex"] and records == item["records"], "correspondence", "authorization")
        # Raw authorization fields remain computable when native context fails.
        # Only their correspondence matters here; context still precedes native
        # structural failures and signature verification.
        if context_failure:
            continue
        try:
            script = spent["script"]
            if len(script) != 35 or script[:2] != b"\x53\x20" or script[-1:] != b"\xc0":
                raise NativeFailure("output_template")
            if parse_error is not None:
                raise parse_error
            descriptor, records = decoded
            if script != lock_script(descriptor):
                raise NativeFailure("output_commitment")
            _, commitments = decode_policy(descriptor)
            if any(key_commitment(bytes.fromhex(record["public_key_hex"])) != commitments[record["signer_index"]] for record in records):
                raise NativeFailure("key_commitment")
            parsed.append((index, records, framed))
        except NativeFailure as error:
            if first_failure is None:
                first_failure = observation("authorization", error.reason, index)
    if context_failure:
        return a, observation("context", "consensus_branch")
    if first_failure is not None:
        return a, first_failure
    count = sum(len(records) for _, records, _ in parsed)
    for index, records, framed in parsed:
        for record in records:
            if not verify_signature(bytes.fromhex(record["public_key_hex"]), bytes.fromhex(record["signature_hex"]), framed, b""):
                return a, observation("signature", "signature", index, count)
    return a, observation(count=count)
