#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Produce two Testnet-domain fixtures with one public key and two signatures."""

import argparse
from pathlib import Path
import sys

import generate_transactions as corpus

UPSTREAM = "e33dc43089acca2fe2c6516927932f2b7618b8bc"
PIN_PATH = "docs/slh-dsa-b128s/imports.json"
SOURCE_PATHS = [PIN_PATH, "tests/slh-dsa-b128s/fixtures/generate_devnet_transactions.py",
                "tests/slh-dsa-b128s/fixtures/data/v5-1of1.json",
                "tests/slh-dsa-b128s/fixtures/data/v6-1of1.json"]


def identity(root, host, signer):
    pin = corpus.strict_json((root / PIN_PATH).read_bytes(), corpus.MAX_HOST)
    if not isinstance(pin, dict) or pin.get("upstream") != UPSTREAM:
        raise corpus.FixtureError("upstream_pin")
    producer, inventories = corpus.producer_identity(root, host, signer)
    # The original 18-case producer keeps its historical upstream pin. These
    # separate fixtures require the current node pin and inventory its source ledger.
    producer["zakura_revision"] = UPSTREAM
    inventories["devnet_generator"] = corpus.source_inventory(root, SOURCE_PATHS)
    return producer, inventories


def recipes(root, public_key):
    """Keep the public corpus's transaction effects; sign the actual Testnet message."""
    for version in (5, 6):
        source = root / f"tests/slh-dsa-b128s/fixtures/data/v{version}-1of1.json"
        artifact = corpus.strict_json(source.read_bytes(), corpus.MAX_HOST)
        item = artifact["inputs"][0]
        if (artifact["network"] != "Regtest" or len(artifact["inputs"]) != 1
                or item["records"][0]["public_key_hex"] != public_key):
            raise corpus.FixtureError("source_fixture")
        yield dict(case_id=f"v{version}-testnet-1of1", network="Testnet",
                   transaction_version=version, lock_time=5, expiry_height=140,
                   inputs=[dict(outpoint={name: item["outpoint"][name]
                                         for name in ("txid_display_hex", "index")},
                                sequence=item["sequence"], value_zat=item["spent_output"]["value_zat"],
                                threshold=1, public_keys_hex=[public_key], signer_indices=[0])],
                   outputs=[dict(value_zat=output["value_zat"], script_hex=output["script_hex"])
                            for output in artifact["outputs"]])


def generate(root, host, signer, destination):
    if destination.exists() or destination.is_symlink():
        raise corpus.FixtureError("destination_exists")
    producer, inventories = identity(root, host, signer)
    state = corpus.source_state(root)
    key = None
    artifacts = []
    try:
        key = corpus.signer_call(signer, "keygen", seed=corpus.seed(0))
        for recipe in recipes(root, key["public_key"]):
            prepared = corpus.host_call(host, "prepare", recipe=recipe)
            if (prepared.get("case_id") != recipe["case_id"] or prepared.get("network") != "Testnet"
                    or len(prepared.get("inputs", [])) != 1):
                raise corpus.FixtureError("prepared_identity")
            item = prepared["inputs"][0]
            message = bytes.fromhex(corpus.hex_field(item["message_hex"], 101))
            if (message[58:61] != bytes([0xf7, 1, recipe["transaction_version"]])
                    or item["context_hex"] != ""
                    or item["signers"] != [dict(signer_index=0, public_key_hex=key["public_key"])]):
                raise corpus.FixtureError("prepared_context")
            signed = corpus.signer_call(signer, "sign", secret_key=key["secret_key"],
                                        message=message.hex(),
                                        randomizer=corpus.randomizer(recipe["case_id"], 0, 0))
            if signed["public_key"] != key["public_key"]:
                raise corpus.FixtureError("signed_key")
            records = [[dict(signer_index=0, public_key_hex=key["public_key"],
                             signature_hex=signed["signature"])]]
            artifact = corpus.host_call(host, "assemble", recipe=recipe, records=records,
                                        producer=producer)
            if (artifact.get("case_id") != recipe["case_id"] or artifact.get("network") != "Testnet"
                    or artifact.get("producer") != producer
                    or corpus.digest(corpus.canonical({k: v for k, v in artifact.items()
                                                     if k != "artifact_sha256"})) != artifact.get("artifact_sha256")):
                raise corpus.FixtureError("artifact_identity")
            checked = corpus.host_call(host, "check", artifact=artifact)
            if (checked.get("expectation_match") is not True
                    or checked.get("observed", {}).get("native_authorization") != "accept"):
                raise corpus.FixtureError("artifact_verification")
            encoded = corpus.canonical(artifact) + b"\n"
            if len(encoded) > corpus.MAX_HOST:
                raise corpus.FixtureError("artifact_size")
            artifacts.append((recipe["case_id"] + ".json", encoded))
        if len(artifacts) != 2:
            raise corpus.FixtureError("devnet_fixture_count")
        if identity(root, host, signer) != (producer, inventories) or corpus.source_state(root) != state:
            raise corpus.FixtureError("producer_changed")
        destination.mkdir(parents=True, exist_ok=False)
        for name, encoded in artifacts:
            (destination / name).write_bytes(encoded)
        receipt = dict(schema_version=1, contract=corpus.CONTRACT, public_fixture=True,
                       kind="production-only-not-independent-acceptance", producer=producer,
                       source_inventories=inventories, **state, key_count=1,
                       artifact_count=2, signature_count=2,
                       artifact_files=[dict(path=name, sha256=corpus.digest(encoded))
                                       for name, encoded in artifacts])
        (destination / "production-receipt.json").write_bytes(corpus.canonical(receipt) + b"\n")
        return receipt
    finally:
        if key is not None:
            key.clear()
        # All key material is prescribed public test data; Python does not promise erasure.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, type=Path)
    parser.add_argument("--signer", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        receipt = generate(corpus.ROOT, args.host.resolve(strict=True),
                           args.signer.resolve(strict=True), args.output)
        print(f"{receipt['artifact_count']} public Testnet fixtures; {receipt['signature_count']} signatures")
    except (corpus.FixtureError, OSError, KeyError, TypeError, ValueError):
        print("public devnet fixture generation failed; no input or key material logged", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
