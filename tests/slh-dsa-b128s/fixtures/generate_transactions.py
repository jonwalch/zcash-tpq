#!/usr/bin/env python3
"""Produce the fixed 18-case public SLH corpus. Never supply operational keys."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import time

CONTRACT = "slh-dsa-b-128s-exp-v1"
UPSTREAM = "9b175e9d3d46a6aa4cfb5552517c3d828852ecbc"
ALGORITHM = "b392fe82d2d9770142477a576a758a233888bc0a"
MAX_HOST = 16 * 1024 * 1024
MAX_SIGNER = 32768
MAX_DEPTH = 16
ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent


class FixtureError(Exception):
    """A fixed diagnostic which must not include subprocess or key material."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def strict_json(data, bound):
    if len(data) > bound:
        raise FixtureError("response_size")

    def pairs(entries):
        result = {}
        for key, value in entries:
            if key in result:
                raise FixtureError("duplicate_key")
            result[key] = value
        return result

    def integer(token):
        if not token.isascii() or not token.isdecimal() or int(token) > 2**64 - 1:
            raise FixtureError("numeric_token")
        return int(token)

    def invalid(_):
        raise FixtureError("numeric_token")

    def validate(value, depth=0):
        if depth > MAX_DEPTH:
            raise FixtureError("nesting")
        if isinstance(value, str) and not value.isascii():
            raise FixtureError("non_ascii")
        if isinstance(value, dict):
            for key, child in value.items():
                validate(key, depth)
                validate(child, depth + 1)
        elif isinstance(value, list):
            for child in value:
                validate(child, depth + 1)

    # Bound parser recursion before json.loads, including malicious nesting.
    quoted = escaped = False
    depth = 0
    for byte in data:
        if byte > 127:
            raise FixtureError("non_ascii")
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
            if depth > MAX_DEPTH:
                raise FixtureError("nesting")
        elif byte in (93, 125):
            depth -= 1
    try:
        value = json.loads(data, object_pairs_hook=pairs, parse_int=integer,
                           parse_float=invalid, parse_constant=invalid)
        validate(value)
        return value
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise FixtureError("invalid_json") from None


def hex_field(value, length):
    if not isinstance(value, str) or len(value) != length * 2 or any(
            c not in "0123456789abcdef" for c in value):
        raise FixtureError("hex_field")
    return value


def invoke(binary, request, bound, timeout=300):
    """Bound input, concurrent pipe output and elapsed time without logging pipes."""
    payload = canonical(request) + b"\n"
    if len(payload) > bound:
        raise FixtureError("request_size")
    process = None
    try:
        process = subprocess.Popen([str(binary)], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = bytearray()
        error_size = 0
        offset = 0
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            for stream, events in ((process.stdin, selectors.EVENT_WRITE),
                                   (process.stdout, selectors.EVENT_READ),
                                   (process.stderr, selectors.EVENT_READ)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, events)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise FixtureError("subprocess_timeout")
                events = selector.select(remaining)
                if not events:
                    raise FixtureError("subprocess_timeout")
                for key, _ in events:
                    stream = key.fileobj
                    if stream is process.stdin:
                        try:
                            offset += os.write(stream.fileno(), payload[offset:offset + 8192])
                        except BrokenPipeError:
                            raise FixtureError("subprocess_failed") from None
                        if offset == len(payload):
                            selector.unregister(stream)
                            stream.close()
                    else:
                        chunk = os.read(stream.fileno(), 8192)
                        if not chunk:
                            selector.unregister(stream)
                            stream.close()
                        elif stream is process.stdout:
                            if len(output) + len(chunk) > bound:
                                raise FixtureError("response_size")
                            output.extend(chunk)
                        else:
                            error_size += len(chunk)
                            if error_size > MAX_SIGNER:
                                raise FixtureError("stderr_size")
        if process.wait(timeout=max(0.001, deadline - time.monotonic())) != 0:
            raise FixtureError("subprocess_failed")
        return strict_json(bytes(output), bound)
    except (OSError, subprocess.TimeoutExpired):
        raise FixtureError("subprocess_failed") from None
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait()
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()


def host_call(binary, op, **fields):
    request = dict(schema_version=1, contract=CONTRACT, public_fixture=True, op=op, **fields)
    response = invoke(binary, request, MAX_HOST)
    if (not isinstance(response, dict) or set(response) != {
            "schema_version", "contract", "public_fixture", "op", "ok", "result"}
            or type(response["schema_version"]) is not int or response["schema_version"] != 1
            or response["contract"] != CONTRACT or response["public_fixture"] is not True
            or response["op"] != op or response["ok"] is not True):
        raise FixtureError("host_rejected")
    return response["result"]


def signer_call(binary, op, **fields):
    response = invoke(binary, dict(version=1, contract=CONTRACT, public_fixture=True,
                                   op=op, **fields), MAX_SIGNER)
    required = {"version", "contract", "public_fixture", "material", "backend", "public_key"}
    required |= {"secret_key"} if op == "keygen" else {"signature", "locally_verified"}
    if (not isinstance(response, dict) or set(response) != required
            or type(response["version"]) is not int or response["version"] != 1
            or response["contract"] != CONTRACT or response["public_fixture"] is not True
            or response["material"] != "public-test-only"
            or response["backend"] != {"repository": "https://github.com/PQC-Suite-B/signatures",
                                       "revision": ALGORITHM, "blake3": "1.8.5"}):
        raise FixtureError("signer_identity")
    hex_field(response["public_key"], 32)
    if op == "keygen":
        hex_field(response["secret_key"], 64)
    else:
        hex_field(response["signature"], 7856)
        if response["locally_verified"] is not True:
            raise FixtureError("signer_verification")
    return response


def source_inventory(root, paths, *, allowed_symlinks=None):
    try:
        listed = subprocess.run(["git", "-C", str(root), "ls-files", "-z", "--", *paths],
                                check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout
    except (OSError, subprocess.CalledProcessError):
        raise FixtureError("source_inventory") from None
    names = sorted(set(p.decode("ascii") for p in listed.split(b"\0") if p))
    names = [name for name in names if not any(part in {"target", "__pycache__", ".git"}
             for part in Path(name).parts) and Path(name).name != "Cargo.lock"]
    allowed_symlinks = allowed_symlinks or {}
    if not set(allowed_symlinks).issubset(names):
        raise FixtureError("source_file")
    inventory = []
    for name in names:
        path = root / name
        if name in allowed_symlinks:
            # Only an explicitly pinned inherited link may opt in. Bind its
            # literal text separately from its regular target's inventory row.
            if not path.is_symlink() or any((root / parent).is_symlink() for parent in Path(name).parents):
                raise FixtureError("source_file")
            link = os.readlink(path)
            raw_target = Path(name).parent / link
            target = Path(os.path.normpath(str(raw_target)))
            if (link != allowed_symlinks[name] or target.is_absolute() or ".." in target.parts
                    or target.as_posix() not in names
                    or any((root / parent).is_symlink() for parent in [*reversed(raw_target.parents), raw_target])
                    or any((root / parent).is_symlink() for parent in [target, *target.parents])
                    or not (root / target).is_file() or not path.is_file()
                    or path.resolve() != (root / target).resolve()):
                raise FixtureError("source_file")
            inventory.append(dict(path=name, sha256=digest(link.encode("utf-8")), symlink_target=target.as_posix()))
            continue
        if any((root / parent).is_symlink() for parent in [Path(name), *Path(name).parents]) or not path.is_file():
            raise FixtureError("source_file")
        inventory.append(dict(path=name, sha256=digest(path.read_bytes())))
    for path in paths:
        if not any(row["path"] == path or row["path"].startswith(path.rstrip("/") + "/") for row in inventory):
            raise FixtureError("untracked_source")
    return inventory


def producer_identity(root, host, signer):
    host_inventory = source_inventory(root, ["Cargo.toml", "tests/slh-dsa-b128s/fixtures/host/",
        "tests/slh-dsa-b128s/fixtures/generate_transactions.py", "crates/pq-slh-dsa-b-exp/",
        "crates/pq-slh-dsa-b-verify/", "crates/pq-tx-context/", "crates/pq-test-support/", "crates/zakura-chain/"])
    signer_inventory = source_inventory(root, ["tests/slh-dsa-b128s/fixture-signer/", "crates/pq-slh-dsa-b-verify/"])
    producer = dict(zakura_revision=UPSTREAM, algorithm_revision=ALGORITHM, blake3_version="1.8.5",
        host_source_inventory_sha256=digest(canonical(host_inventory)),
        host_lock_sha256=digest((root / "Cargo.lock").read_bytes()), host_binary_sha256=digest(host.read_bytes()),
        signer_source_inventory_sha256=digest(canonical(signer_inventory)),
        signer_lock_sha256=digest((root / "tests/slh-dsa-b128s/fixture-signer/Cargo.lock").read_bytes()),
        signer_binary_sha256=digest(signer.read_bytes()))
    return producer, dict(host=host_inventory, signer=signer_inventory)


def source_state(root):
    paths = ["Cargo.toml", "Cargo.lock", "tests/slh-dsa-b128s/fixtures/host/",
             "tests/slh-dsa-b128s/fixtures/generate_transactions.py",
             "tests/slh-dsa-b128s/fixture-signer/", "crates/pq-slh-dsa-b-exp/",
             "crates/pq-slh-dsa-b-verify/", "crates/pq-tx-context/",
             "crates/pq-test-support/", "crates/zakura-chain/"]
    try:
        commit = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], check=True,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.decode("ascii").strip()
        status = subprocess.run(["git", "-C", str(root), "status", "--porcelain=v1",
                                 "--untracked-files=all", "--", *paths], check=True,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.decode("ascii").splitlines()
    except (OSError, UnicodeError, subprocess.CalledProcessError):
        raise FixtureError("source_state") from None
    hex_field(commit, 20)
    return dict(source_commit=commit, source_status=status)


def seed(index):
    return hashlib.sha512(b"Zakura/SLH-public-corpus/seed/v1\0" + index.to_bytes(4, "little")).digest()[:48].hex()


def randomizer(case, input_index, signer_index):
    return hashlib.sha256(b"Zakura/SLH-public-corpus/randomizer/v1\0" + case.encode("ascii") + b"\0"
                          + input_index.to_bytes(4, "little") + bytes([signer_index])).digest()[:16].hex()


def recipes(public_keys):
    if len(public_keys) != 15 or len(set(public_keys)) != 15:
        raise FixtureError("public_inventory")
    for key in public_keys:
        hex_field(key, 32)
    cases = [("1of1", [(1, 1)]), ("2of3", [(2, 3)]), ("3of5", [(3, 5)]),
             ("8of10", [(8, 10)]), ("10of10", [(10, 10)]), ("15of15", [(15, 15)]),
             ("1of15-index14", [(1, 15)]), ("16checks", [(15, 15), (1, 1)]),
             ("17checks", [(15, 15), (2, 3)])]
    for version in (5, 6):
        for name, policies in cases:
            case = f"v{version}-{name}"
            inputs = []
            for index, (threshold, participants) in enumerate(policies):
                txid = digest(b"Zakura/SLH-public-corpus/outpoint/v1\0" + case.encode("ascii") + b"\0"
                              + index.to_bytes(4, "little"))
                inputs.append(dict(outpoint=dict(txid_display_hex=txid, index=index + 1),
                    sequence=0xfffffffe, value_zat=100000, threshold=threshold,
                    public_keys_hex=public_keys[:participants],
                    signer_indices=[14] if name == "1of15-index14" else list(range(threshold))))
            yield dict(case_id=case, network="Regtest", transaction_version=version, lock_time=5,
                       expiry_height=140, inputs=inputs,
                       outputs=[dict(value_zat=value, input_policy_index=0) for value in (20000, 30000)])


def generate(root, host, signer, destination):
    producer, inventory = producer_identity(root, host, signer)
    state = source_state(root)
    if any(line.startswith("?? ") for line in state["source_status"]):
        raise FixtureError("untracked_source")
    if destination.exists():
        raise FixtureError("destination_exists")
    keys = {}
    public = []
    artifacts = []
    signature_count = 0
    try:
        for index in range(15):
            key = signer_call(signer, "keygen", seed=seed(index))
            if key["public_key"] in keys:
                raise FixtureError("duplicate_public_key")
            keys[key["public_key"]] = key["secret_key"]
            public.append(key["public_key"])
        for recipe in recipes(public):
            prepared = host_call(host, "prepare", recipe=recipe)
            if (prepared.get("case_id") != recipe["case_id"] or len(prepared.get("inputs", [])) != len(recipe["inputs"])):
                raise FixtureError("prepared_identity")
            records = []
            for input_index, item in enumerate(prepared["inputs"]):
                hex_field(item["message_hex"], 101)
                if item["context_hex"] != "" or [s["signer_index"] for s in item["signers"]] != recipe["inputs"][input_index]["signer_indices"]:
                    raise FixtureError("prepared_signers")
                entries = []
                for entry in item["signers"]:
                    public_key = hex_field(entry["public_key_hex"], 32)
                    if public_key not in keys:
                        raise FixtureError("prepared_key")
                    signed = signer_call(signer, "sign", secret_key=keys[public_key], message=item["message_hex"],
                        randomizer=randomizer(recipe["case_id"], input_index, entry["signer_index"]))
                    if signed["public_key"] != public_key:
                        raise FixtureError("signed_key")
                    entries.append(dict(signer_index=entry["signer_index"], public_key_hex=public_key,
                                        signature_hex=signed["signature"]))
                    signature_count += 1
                records.append(entries)
            artifact = host_call(host, "assemble", recipe=recipe, records=records, producer=producer)
            if artifact.get("case_id") != recipe["case_id"] or artifact.get("producer") != producer:
                raise FixtureError("artifact_identity")
            unhashed = {k: v for k, v in artifact.items() if k != "artifact_sha256"}
            if digest(canonical(unhashed)) != artifact.get("artifact_sha256"):
                raise FixtureError("artifact_hash")
            checked = host_call(host, "check", artifact=artifact)
            if checked.get("expectation_match") is not True or checked.get("observed", {}).get("native_authorization") != "accept":
                raise FixtureError("artifact_verification")
            encoded = canonical(artifact) + b"\n"
            if len(encoded) > MAX_HOST:
                raise FixtureError("artifact_size")
            artifacts.append((recipe["case_id"] + ".json", encoded))
        if len(artifacts) != 18 or signature_count != 146:
            raise FixtureError("corpus_count")
        # Verify the sources and executable bytes did not change during generation.
        if producer_identity(root, host, signer) != (producer, inventory) or source_state(root) != state:
            raise FixtureError("producer_changed")
        destination.mkdir(parents=True, exist_ok=False)
        for name, data in artifacts:
            (destination / name).write_bytes(data)
        receipt = dict(schema_version=1, contract=CONTRACT, public_fixture=True,
            kind="production-only-not-independent-acceptance", producer=producer, source_inventories=inventory, **state,
            artifact_count=18, signature_count=146,
            artifact_files=[dict(path=name, sha256=digest(data)) for name, data in artifacts])
        (destination / "production-receipt.json").write_bytes(canonical(receipt) + b"\n")
        return receipt
    finally:
        keys.clear()
        # Python does not promise erasure of immutable strings. Material is public.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, type=Path)
    parser.add_argument("--signer", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path, help="new directory; never overwrites existing fixtures")
    args = parser.parse_args()
    try:
        host, signer = args.host.resolve(strict=True), args.signer.resolve(strict=True)
        if not host.is_file() or not signer.is_file():
            raise FixtureError("binary_file")
        receipt = generate(ROOT, host, signer, args.output)
        print(json.dumps({"artifacts": receipt["artifact_count"], "signatures": receipt["signature_count"]}))
    except (FixtureError, OSError, KeyError, TypeError, ValueError):
        print("public fixture generation failed; no input or key material logged", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
