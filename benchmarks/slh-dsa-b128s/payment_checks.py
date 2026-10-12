#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Independent, bounded checks for newly produced public payment artifacts.

Uses the existing independent ZIP-244/229 wire oracle and pinned Python/portable-C
SLH reference. The small public-data secp256k1 verifier below shares no production
crypto code. It is a benchmark checker, not a wallet or general Script interpreter.
"""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import types

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
TRANSACTIONS = ROOT / "tests/slh-dsa-b128s/transactions"
REFERENCE = ROOT / "tests/slh-dsa-b128s/reference"
WALLET_FORMATS = ROOT / "tests/slh-dsa-b128s/wallet/formats/reference.py"
MAX_ARTIFACT = 2 * 1024 * 1024
FIELDS = set("schema_version algorithm version policy input_count inventory offline_fixture trusted_utxos node_acceptance transaction_hex unsigned_transaction_hex previous_outputs_hex messages wallet".split())


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def load(path, name, imports=None):
    previous = {key: sys.modules.get(key) for key in (imports or {})}
    try:
        sys.modules.update(imports or {})
        raw = bounded_file(path)
        module = types.ModuleType(name)
        module.__file__ = str(path)
        exec(compile(raw, str(path), "exec"), module.__dict__)
        return module
    finally:
        for key, value in previous.items():
            if value is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = value


def bounded_file(path, maximum=MAX_ARTIFACT):
    path = Path(os.path.abspath(path))
    # Reject symlinked parents as well as the final component. No artifact path
    # is read from JSON, and all reference paths come from the pinned inventory.
    require(not any(parent.is_symlink() for parent in (path, *path.parents)), "symlink input")
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_size <= maximum, "bounded regular file required")
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    require(len(raw) <= maximum, "input grew beyond bound")
    return raw


WIRE = load(TRANSACTIONS / "wire.py", "tpq_payment_wire")
ORACLE = load(TRANSACTIONS / "oracle.py", "tpq_payment_oracle", {"wire": WIRE})
FORMATS = load(WALLET_FORMATS, "tpq_payment_wallet_formats")


def reference_identity(inputs):
    """Validate all pinned inputs without compiling, importing crypto or signing."""
    inputs = Path(inputs)
    source_raw = bounded_file(REFERENCE / "sources.json", 65536)
    sources = ORACLE.strict_json(source_raw)
    build_raw = bounded_file(inputs / "hash-build.json", 65536)
    build = ORACLE.strict_json(build_raw)
    require(type(build) is dict and build.get("schema_version") == 1, "reference build schema")
    require(build.get("sources_sha256") == sha256(source_raw), "reference source inventory changed")
    require(build.get("shim_sha256") == sha256(bounded_file(REFERENCE / "hash_shim.c")), "reference shim changed")
    library = build.get("library_name")
    require(library in ("libslh_reference_blake3.dylib", "libslh_reference_blake3.so"), "reference library name")
    library_hash = sha256(bounded_file(inputs / library, 16 * 1024 * 1024))
    require(build.get("library_sha256") == library_hash, "reference library changed")
    inventory = {}
    for group in ("reference", "blake3_c"):
        for item in sources[group]["files"]:
            relative = Path(item["path"])
            require(not relative.is_absolute() and ".." not in relative.parts, "reference path")
            key = group + "/" + relative.as_posix()
            actual = sha256(bounded_file(inputs / group / relative, 4 * 1024 * 1024))
            require(actual == item["sha256"], "reference source changed: " + key)
            inventory[key] = actual
    expected = {item["path"] for item in sources["reference"]["files"] if item["path"].endswith(".py")}
    actual = {p.relative_to(inputs / "reference").as_posix()
              for p in (inputs / "reference/slhdsa/lowlevel").rglob("*.py")}
    require(actual == expected, "reference Python inventory changed")
    return {"hash_build_sha256": sha256(build_raw), "library_sha256": library_hash,
            "sources_sha256": sha256(source_raw), "source_files": inventory}


def checker_identity():
    paths = [HERE / "payment_checks.py", TRANSACTIONS / "wire.py", TRANSACTIONS / "oracle.py",
             REFERENCE / "reference.py", REFERENCE / "prepare.py", REFERENCE / "sources.json",
             REFERENCE / "hash_shim.c", WALLET_FORMATS]
    identity = {p.relative_to(ROOT).as_posix(): sha256(bounded_file(p)) for p in paths}
    # The reused wallet format oracle imports cryptography for its unrelated
    # backup functions. Bind every loaded package module, including extensions,
    # even though these public envelope checks never call its cipher or KDF.
    package = Path(FORMATS.cryptography.__file__).resolve().parent
    for name, module in list(sys.modules.items()):
        if (name == "cryptography" or name.startswith("cryptography.")) and getattr(module, "__file__", None):
            path = Path(module.__file__).resolve()
            relative = path.relative_to(package).as_posix()
            identity["python-package/cryptography/" + relative] = sha256(bounded_file(path, 64 * 1024 * 1024))
    return identity


def make_reference(inputs):
    prepare = load(REFERENCE / "prepare.py", "tpq_payment_prepare")
    module = load(REFERENCE / "reference.py", "tpq_payment_reference", {"prepare": prepare})
    return module.Reference(Path(inputs))


# SEC 2 secp256k1 domain constants. All arithmetic below is public verification;
# this variable-time reference must never be used for secret scalars or signing.
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def point_add(left, right):
    if left is None:
        return right
    if right is None:
        return left
    x, y = left
    u, v = right
    if x == u:
        if (y + v) % P == 0:
            return None
        slope = 3 * x * x * pow(2 * y, -1, P) % P
    else:
        slope = (v - y) * pow(u - x, -1, P) % P
    out = (slope * slope - x - u) % P
    return out, (slope * (x - out) - y) % P


def point_multiply(scalar, point):
    require(type(scalar) is int and 0 <= scalar < N, "scalar bound")
    result = None
    while scalar:
        if scalar & 1:
            result = point_add(result, point)
        scalar >>= 1
        point = point_add(point, point)
    return result


def compressed_key(raw):
    require(len(raw) == 33 and raw[0] in (2, 3), "compressed secp256k1 key")
    x = int.from_bytes(raw[1:], "big")
    require(x < P, "secp256k1 x range")
    y = pow((pow(x, 3, P) + 7) % P, (P + 1) // 4, P)
    require(y * y % P == (x * x * x + 7) % P, "secp256k1 curve")
    if y % 2 != raw[0] % 2:
        y = P - y
    return x, y


def strict_der(raw):
    require(8 <= len(raw) <= 72 and raw[0] == 0x30 and raw[1] == len(raw) - 2, "DER sequence")
    values, cursor = [], 2
    for _ in range(2):
        require(cursor + 2 <= len(raw) and raw[cursor] == 2, "DER integer tag")
        size = raw[cursor + 1]
        cursor += 2
        require(1 <= size <= 33 and cursor + size <= len(raw), "DER integer length")
        value = raw[cursor:cursor + size]
        cursor += size
        require(value[0] < 128 and not (len(value) > 1 and value[0] == 0 and value[1] < 128), "DER integer minimality")
        values.append(int.from_bytes(value, "big"))
    require(cursor == len(raw) and 1 <= values[0] < N and 1 <= values[1] <= N // 2, "DER scalar range/low S")
    return values


def verify_ecdsa(public, signature, message):
    try:
        require(len(message) == 32, "ECDSA digest size")
        point = compressed_key(public)
        r, s = strict_der(signature)
        inverse = pow(s, -1, N)
        result = point_add(point_multiply(int.from_bytes(message, "big") * inverse % N, G),
                           point_multiply(r * inverse % N, point))
        return result is not None and result[0] % N == r
    except ValueError:
        return False


def pushes(raw):
    reader, values = WIRE.Reader(raw), []
    while reader.pos < len(raw):
        opcode = reader.take(1)[0]
        if 1 <= opcode <= 75:
            size = opcode
        elif opcode == 0x4c:
            size = reader.take(1)[0]
            require(size >= 76, "nonminimal classical PUSHDATA1")
        else:
            raise ValueError("classical push opcode")
        require(size <= 255, "classical push bound")
        values.append(reader.take(size))
        require(len(values) <= 4, "classical stack bound")
    return values


def classical_authorization(raw, multisig, previous):
    if multisig:
        require(raw[:1] == b"\0", "classical multisig dummy")
        raw = raw[1:]
    stack = pushes(raw)
    threshold = 2 if multisig else 1
    require(len(stack) == threshold + 1, "classical signature count")
    signatures, redeem = stack[:-1], stack[-1]
    if multisig:
        require(len(redeem) == 105 and redeem[:1] == b"\x52" and redeem[-2:] == b"\x53\xae", "classical 2of3 template")
        keys = [redeem[2 + 34 * i:35 + 34 * i] for i in range(3)]
        require(all(redeem[1 + 34 * i] == 33 for i in range(3)), "classical compressed pushes")
    else:
        require(len(redeem) == 35 and redeem[:1] == b"\x21" and redeem[-1:] == b"\xac", "classical single template")
        keys = [redeem[1:34]]
    require(len(set(keys)) == len(keys), "classical duplicate participant")
    for key in keys:
        compressed_key(key)
    commitment = hashlib.new("ripemd160", hashlib.sha256(redeem).digest()).digest()
    require(previous["script"] == b"\xa9\x14" + commitment + b"\x87", "classical P2SH commitment")
    for signature in signatures:
        require(signature[-1:] == b"\x01", "classical SIGHASH_ALL")
        strict_der(signature[:-1])
    return [(key, signature[:-1]) for key, signature in zip(keys[:threshold], signatures)]


def evaluate(artifact, verify_slh):
    """Check one bounded payment; callback is the independent reference only.

    Unit tests can replace the callback to inspect structural rejection. Such
    calls produce no reference receipt or claim of independent crypto evidence.
    """
    require(type(artifact) is dict and set(artifact) == FIELDS, "payment artifact fields")
    a = artifact
    require(type(a["schema_version"]) is int and a["schema_version"] == 1, "payment schema version")
    require(a["algorithm"] in ("slh-dsa-b128s", "ecdsa-secp256k1"), "payment algorithm")
    require(a["inventory"] in ("cached", "generated") and a["policy"] in ("single", "multisig"), "payment dimensions")
    require(type(a["version"]) is int and a["version"] in (5, 6), "payment version")
    require(type(a["input_count"]) is int and a["input_count"] in (1, 2, 5), "payment input count")
    require(a["offline_fixture"] is True and a["trusted_utxos"] is False
            and a["node_acceptance"] is False, "offline trust boundary")
    require(type(a["wallet"]) is dict, "wallet evidence object")
    raw = ORACLE.hexadecimal(a["transaction_hex"], maximum=100_000)
    unsigned_raw = ORACLE.hexadecimal(a["unsigned_transaction_hex"], maximum=100_000)
    tx, unsigned = WIRE.parse_transaction(raw), WIRE.parse_transaction(unsigned_raw)
    require(WIRE.serialize(tx) == raw and WIRE.serialize(unsigned) == unsigned_raw, "canonical transaction size")
    effects = copy.deepcopy(tx)
    for entry in effects["inputs"]:
        entry["script"] = b""
    require(effects == unsigned, "signed/unsigned payment effects")
    require(tx["version"] == a["version"] and tx["branch"] == ORACLE.NU7
            and tx["lock_time"] == 0 and tx["expiry"] == 130, "payment header")
    count = a["input_count"]
    require(len(tx["inputs"]) == count and len(tx["outputs"]) == 2, "payment shape")
    require(all(item["sequence"] == 0xffffffff for item in tx["inputs"]), "payment sequence")
    require(type(a["previous_outputs_hex"]) is list and len(a["previous_outputs_hex"]) == count, "ordered previous outputs")
    previous = []
    for encoded in a["previous_outputs_hex"]:
        raw_output = ORACLE.hexadecimal(encoded, maximum=10032)
        reader = WIRE.Reader(raw_output)
        output = WIRE.parse_output(reader)
        require(reader.pos == len(raw_output) and WIRE.output_bytes(output) == raw_output, "canonical previous output")
        require(output["value"] == 10_000_000, "matched input amount")
        previous.append(output)
    require(type(a["messages"]) is list and len(a["messages"]) == count, "payment messages")
    payment = count * 10_000_000 - 5_000_000
    require(tx["outputs"][0]["value"] == payment, "matched recipient amount")
    fee = count * 10_000_000 - sum(item["value"] for item in tx["outputs"])
    input_bytes = sum(36 + len(WIRE.compact(len(i["script"]))) + len(i["script"]) + 4 for i in tx["inputs"])
    output_bytes = sum(len(WIRE.output_bytes(o)) for o in tx["outputs"])
    actions = max(2, (input_bytes + 149) // 150, (output_bytes + 33) // 34)
    require(fee == 400 * actions and tx["outputs"][1]["value"] == 5_000_000 - fee, "actual-size conventional fee/change")
    multisig, checks, signature_bytes = a["policy"] == "multisig", 0, 0
    mutation_checks = 0
    for index, (entry, spent, declared) in enumerate(zip(tx["inputs"], previous, a["messages"])):
        require(type(declared) is dict and set(declared) == {"input_index", "message_hex"}
                and type(declared["input_index"]) is int and declared["input_index"] == index, "message order")
        digest = WIRE.input_digest(tx, previous, index)
        if a["algorithm"] == "slh-dsa-b128s":
            _, message = ORACLE.message(tx, "Regtest", previous, index)
            descriptor, records = ORACLE.decode_authorization(entry["script"])
            require(ORACLE.encode_authorization(descriptor, records) == entry["script"], "canonical authorization")
            threshold, commitments = ORACLE.decode_policy(descriptor)
            require((threshold, len(commitments)) == ((2, 3) if multisig else (1, 1)), "matched SLH policy")
            require(spent["script"] == ORACLE.lock_script(descriptor), "SLH policy commitment")
            pairs = []
            for record in records:
                public = bytes.fromhex(record["public_key_hex"])
                require(ORACLE.key_commitment(public) == commitments[record["signer_index"]], "SLH key commitment")
                pairs.append((public, bytes.fromhex(record["signature_hex"])))
            verifier = lambda pk, sig, msg: verify_slh(pk, sig, msg, b"")
        else:
            message = digest
            pairs = classical_authorization(entry["script"], multisig, spent)
            verifier = verify_ecdsa
        require(ORACLE.hexadecimal(declared["message_hex"], size=len(message)) == message, "transaction-derived message mismatch")
        for public, signature in pairs:
            require(verifier(public, signature, message) is True, "independent signature rejection")
            checks += 1
            signature_bytes += len(signature)
        # Two bounded controls per input bind actual verification to this
        # artifact. Same-length corruption cannot pass a stub accepting all.
        public, signature = pairs[-1]
        corrupt = signature[:-1] + bytes([signature[-1] ^ 1])
        changed_message = message[:-1] + bytes([message[-1] ^ 1])
        require(verifier(public, corrupt, message) is False, "signature mutation unexpectedly accepted")
        require(verifier(public, signature, changed_message) is False, "message mutation unexpectedly accepted")
        mutation_checks += 2
        if index == count - 1:
            changed_previous = copy.deepcopy(previous)
            changed_previous[index]["value"] += 1
            changed_recipient = copy.deepcopy(tx)
            changed_recipient["outputs"][0]["value"] += 1
            if a["algorithm"] == "slh-dsa-b128s":
                prev_message = ORACLE.message(tx, "Regtest", changed_previous, index)[1]
                output_message = ORACLE.message(changed_recipient, "Regtest", previous, index)[1]
            else:
                prev_message = WIRE.input_digest(tx, changed_previous, index)
                output_message = WIRE.input_digest(changed_recipient, previous, index)
            require(verifier(public, signature, prev_message) is False, "previous-output amount mutation accepted")
            require(verifier(public, signature, output_message) is False, "recipient amount mutation accepted")
            mutation_checks += 2
    expected_script = b"\x53\x20" if a["algorithm"] == "slh-dsa-b128s" else b"\xa9\x14"
    require(all(output["script"].startswith(expected_script) and len(output["script"]) == (35 if len(expected_script) == 2 and expected_script[0] == 0x53 else 23)
                and output["script"][-1:] == (b"\xc0" if expected_script[0] == 0x53 else b"\x87")
                for output in tx["outputs"]), "payment output templates")
    require(tx["outputs"][1]["script"] == previous[0]["script"] or a["algorithm"] == "slh-dsa-b128s", "classical change destination")
    wallet_checked = False
    if a["algorithm"] == "slh-dsa-b128s":
        proposal = a["wallet"].get("proposal")
        FORMATS.check_proposal_envelope(proposal)
        require(proposal["transaction_hex"] == a["unsigned_transaction_hex"], "wallet proposal transaction")
        require([item["spent_output_hex"] for item in proposal["inputs"]] == a["previous_outputs_hex"], "wallet proposal previous-output order")
        for proposal_input, tx_input in zip(proposal["inputs"], tx["inputs"]):
            descriptor, _ = ORACLE.decode_authorization(tx_input["script"])
            require(FORMATS.check_entry(proposal_input["entry"]) == descriptor, "wallet proposal policy")
        for proposed, output in zip(proposal["outputs"], tx["outputs"]):
            require(output["script"] == b"\x53\x20" + FORMATS.decode(proposed["receiver"]) + b"\xc0", "wallet proposal receiver")
        require(len(proposal["outputs"]) == len(tx["outputs"]), "wallet proposal output count")
        wallet_checked = True
    return {"algorithm": a["algorithm"], "version": a["version"], "policy": a["policy"],
            "inventory": a["inventory"], "input_count": count, "transaction_bytes": len(raw),
            "unsigned_transaction_bytes": len(unsigned_raw), "signature_bytes": signature_bytes,
            "authorization_bytes": sum(len(i["script"]) for i in tx["inputs"]),
            "signature_checks": checks, "mutation_checks": mutation_checks,
            "conventional_actions": actions, "fee_zat": fee, "payment_zat": payment,
            "change_zat": tx["outputs"][1]["value"], "wallet_proposal_checked": wallet_checked,
            "trusted_utxos": False, "node_acceptance": False}


def check_artifact(path, repo_root, reference_inputs):
    require(Path(repo_root).resolve() == ROOT, "checker repo root mismatch")
    raw = bounded_file(path)
    artifact = ORACLE.strict_json(raw)
    before = checker_identity()
    reference_before = reference_identity(reference_inputs)
    reference = make_reference(reference_inputs)
    checked = evaluate(artifact, reference.verify)
    require(checker_identity() == before and reference_identity(reference_inputs) == reference_before,
            "checker/reference inputs changed")
    return {"schema_version": 1, "complete": True, "scope": "offline payment codec/digest/signatures; no full Script, wallet durability or node acceptance",
            "artifact_sha256": sha256(raw), "checker_sha256": before, "reference": reference_before,
            **checked}


def classical_known_answer():
    # Exact public algebraic answer d=k=z=1: Q=G, r=G.x, s=1+r.
    # s is already low. This is a verification control, never a signing API.
    r = G[0].to_bytes(32, "big")
    s = (G[0] + 1).to_bytes(32, "big")
    signature = b"\x30\x44\x02\x20" + r + b"\x02\x20" + s
    public = b"\x02" + r
    digest = bytes(31) + b"\x01"
    require(verify_ecdsa(public, signature, digest), "classical known answer")
    require(not verify_ecdsa(public, signature, bytes(32)), "classical message control")
    return 2


def preflight(repo_root, reference_inputs):
    require(Path(repo_root).resolve() == ROOT, "checker repo root mismatch")
    before, ref_before = checker_identity(), reference_identity(reference_inputs)
    reference = make_reference(reference_inputs)
    vectors = reference.hash_vectors(Path(reference_inputs))
    require(vectors == 105, "official BLAKE3 vector count")
    fixture_path = ROOT / "tests/slh-dsa-b128s/fixtures/data/v5-1of1.json"
    fixture = bounded_file(fixture_path)
    def strict_verify(*args):
        result = reference.verify(*args)
        require(type(result) is bool, "SLH reference result must be boolean")
        return result
    artifact, result = ORACLE.evaluate(fixture, strict_verify)
    require(result["native_authorization"] == "accept", "retained SLH preflight")
    record = artifact["inputs"][0]["records"][0]
    public, signature, message = (bytes.fromhex(value) for value in
                                 (record["public_key_hex"], record["signature_hex"], artifact["inputs"][0]["message_hex"]))
    require(reference.verify(public, signature[:-1] + bytes([signature[-1] ^ 1]), message, b"") is False, "SLH signature negative control")
    require(reference.verify(public, signature, message[:-1] + bytes([message[-1] ^ 1]), b"") is False, "SLH message negative control")
    classical_checks = classical_known_answer()
    require(checker_identity() == before and reference_identity(reference_inputs) == ref_before,
            "checker/reference inputs changed")
    return {"schema_version": 1, "complete": True, "scope": "independent verifier readiness; no benchmark execution",
            "checker_sha256": before, "reference": ref_before, "fixture_sha256": sha256(fixture),
            "official_blake3_controls": vectors, "slh_positive_checks": 1,
            "slh_mutation_checks": 2, "classical_known_answer_checks": classical_checks}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--artifact", type=Path)
    mode.add_argument("--preflight", action="store_true")
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--reference-inputs", type=Path, required=True)
    args = parser.parse_args()
    result = preflight(args.repo_root, args.reference_inputs) if args.preflight else check_artifact(args.artifact, args.repo_root, args.reference_inputs)
    print(json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError) as error:
        print("payment-check: " + str(error), file=sys.stderr)
        raise SystemExit(1)
