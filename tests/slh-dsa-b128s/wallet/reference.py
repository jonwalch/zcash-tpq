#!/usr/bin/env python3
"""Bounded independent public wallet key/signature answers; no production imports.

HKDF uses Python's stdlib HMAC/SHA256. SLH uses the pinned independent Python
implementation and portable C BLAKE3 loaded by the existing checked G reference.
All roots, seeds and randomness in these vectors are deliberately public tests.
"""

import argparse
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
REFERENCE = HERE.parent / "reference"
SALT = b"ZcashTransparentPQ/wallet-root/v1\0"
KEY_DOMAIN = b"ZcashTransparentPQ/wallet-key/v1\0"
MESSAGE_DOMAIN = b"ZcashTransparentPQ/experimental/slh-dsa-b-128s/message/v1\0"
COORDINATES = [(role, index) for role in (0, 1) for index in (0, 1, 0xffffffff)]


def expand(root, salt, info):
    """Return extract PRK and the first two full HKDF-SHA256 expansion blocks."""
    prk = hmac.digest(salt, root, "sha256")
    first = hmac.digest(prk, info + b"\x01", "sha256")
    second = hmac.digest(prk, first + info + b"\x02", "sha256")
    return prk, first, second


def derive(root, role, index, suite=0xf7):
    if len(root) != 32 or role not in (0, 1) or not 0 <= index <= 0xffffffff:
        raise ValueError("wallet derivation bounds")
    info = KEY_DOMAIN + bytes([1, 2, suite]) + bytes(4) + bytes([role]) + index.to_bytes(4, "little")
    prk, first, second = expand(root, SALT, info)
    return {
        "info": info.hex(), "prk": prk.hex(),
        "t1": first.hex(), "t2": second.hex(), "seed": (first + second[:16]).hex(),
    }


def checked_reference(inputs):
    sys.path.insert(0, str(REFERENCE))
    spec = importlib.util.spec_from_file_location("slh_checked_reference", REFERENCE / "reference.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.Reference(inputs)


def keygen(reference, seed):
    chunks = iter((seed[:16], seed[16:32], seed[32:]))
    original = reference.scheme.token_bytes

    def public_entropy(length):
        if length != 16:
            raise ValueError("unexpected keygen entropy request")
        return next(chunks)

    reference.scheme.token_bytes = public_entropy
    try:
        secret, public = reference.scheme.keygen(reference.profile)
        if next(chunks, None) is not None:
            raise ValueError("independent keygen did not consume every seed component")
        return secret, b"".join(public)
    finally:
        reference.scheme.token_bytes = original


def sign(reference, secret, message, randomness):
    requests = []
    original = reference.scheme.token_bytes

    def public_entropy(length):
        requests.append(length)
        if requests != [16]:
            raise ValueError("unexpected signing entropy request")
        return randomness

    reference.scheme.token_bytes = public_entropy
    try:
        signature = reference.scheme.sign(reference.frame(message, b""), secret, reference.profile, randomize=True)
        if requests != [16]:
            raise ValueError("independent signing skipped prescribed randomness")
        return signature
    finally:
        reference.scheme.token_bytes = original


def vectors(reference):
    root = bytes(range(32))
    cases = []
    for role, index in COORDINATES:
        material = derive(root, role, index)
        secret, public = keygen(reference, bytes.fromhex(material["seed"]))
        case = {"role": role, "index": index, **material, "public_key": public.hex()}
        # Two complete signatures cover both derivation branches and index bounds.
        if (role, index) in ((0, 0), (1, 0xffffffff)):
            randomness = bytes(range(16 * role, 16 * role + 16))
            message = MESSAGE_DOMAIN + bytes([0xf7, 2, 5]) + (0x77190ad9).to_bytes(4, "little") + index.to_bytes(4, "little") + bytes(range(32))
            assert len(message) == 101
            signature = sign(reference, secret, message, randomness)
            if not reference.verify(public, signature, message):
                raise ValueError("independent signature failed self-verification")
            case.update(message=message.hex(), randomness=randomness.hex(), signature=signature.hex())
        cases.append(case)
    return {
        "schema_version": 1,
        "material": "public-test-only",
        "root": root.hex(), "salt": SALT.hex(), "suite": 0xf7,
        "cases": cases,
        "suite_separation": [dict(suite=suite, **derive(root, 0, 0, suite)) for suite in (0, 0xf6, 0xf8)],
    }


def mutations(reference, data):
    controls = 0
    for case in data["cases"]:
        if "signature" not in case:
            continue
        public, signature, message = (bytes.fromhex(case[key]) for key in ("public_key", "signature", "message"))
        for offset in (0, 16, 2928, 7855):
            changed = bytearray(signature)
            changed[offset] ^= 1
            if reference.verify(public, bytes(changed), message):
                raise ValueError("signature mutation accepted")
            controls += 1
        if reference.verify(public, signature, b"\0\0" + message):
            raise ValueError("double Pure framing accepted")
        controls += 1
    return controls


def retain(destination, encoded, write):
    """Bind receipts to exact retained bytes and never overwrite expectations."""
    if write:
        with destination.open("xb") as stream:
            stream.write(encoded)
    elif destination.read_bytes() != encoded:
        raise ValueError("independent expected wallet answers changed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", required=True, type=Path)
    parser.add_argument("--write", action="store_true", help="create a new public answer file; refuses to overwrite")
    args = parser.parse_args()
    reference = checked_reference(args.inputs)
    hash_controls = reference.hash_vectors(args.inputs)
    actual = vectors(reference)
    encoded = (json.dumps(actual, indent=2, sort_keys=True) + "\n").encode()
    destination = HERE / "vectors.json"
    retain(destination, encoded, args.write)
    count = mutations(reference, actual)
    print(json.dumps({"roots": len(actual["cases"]), "signatures": 2, "mutations": count,
                      "hash_controls": hash_controls, "vectors_sha256": hashlib.sha256(encoded).hexdigest()}))


if __name__ == "__main__":
    main()
