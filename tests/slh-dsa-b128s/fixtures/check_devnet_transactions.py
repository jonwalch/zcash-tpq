#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Check two Testnet fixtures and four derived negatives with the independent oracle."""

import argparse
import copy
from pathlib import Path
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "evidence"))
import artifacts  # noqa: E402
import mutations  # noqa: E402
import wire  # noqa: E402

oracle = artifacts.oracle


def controls(prepared):
    """Derive explicit failures; no host, signing or expected-value crypto calls."""
    result = []
    for name, raw in prepared:
        original = oracle.strict_json(raw)
        version = original["transaction_version"]
        if (original["network"] != "Testnet" or version not in (5, 6)
                or original["case_id"] != f"v{version}-testnet-1of1"
                or len(original["inputs"]) != 1
                or len(original["inputs"][0]["records"]) != 1):
            raise ValueError("devnet_fixture_shape")
        result.append((name, raw, "positive", oracle.sha256(raw)))
        for mutation in ("wrong-network", "corrupt-signature"):
            changed = copy.deepcopy(original)
            changed["case_id"] += "-" + mutation
            tx = wire.parse_transaction(bytes.fromhex(changed["transaction_hex"]))
            if mutation == "wrong-network":
                changed["network"] = "Regtest"
            else:
                descriptor, records = oracle.decode_authorization(tx["inputs"][0]["script"])
                signature = bytearray.fromhex(records[0]["signature_hex"])
                signature[100] ^= 1
                records[0]["signature_hex"] = signature.hex()
                tx["inputs"][0]["script"] = oracle.encode_authorization(descriptor, records)
            changed["expected"] = oracle.observation("signature", "signature", 0, 1)
            mutations.refresh(changed, tx)
            result.append((changed["case_id"] + ".json", oracle.canonical(changed),
                           mutation, oracle.sha256(raw)))
    if len(result) != 6:
        raise ValueError("devnet_fixture_count")
    return result


def run(fixtures, reference_inputs, output):
    output = Path(output)
    artifacts.require(not output.exists() and not output.is_symlink(), "fresh_receipt_required")
    artifacts.require(output.parent.is_dir(), "receipt_parent_required")
    checker_inputs = artifacts.checker_hashes()
    for path in [Path(__file__), HERE.parent / "transactions/mutations.py"]:
        checker_inputs[path.relative_to(artifacts.ROOT).as_posix()] = oracle.sha256(path.read_bytes())
    prepared = artifacts.preflight([fixtures / f"v{version}-testnet-1of1.json" for version in (5, 6)])
    cases = controls(prepared)
    with tempfile.TemporaryDirectory(prefix="slh-devnet-controls-") as directory:
        temporary = Path(directory)
        paths = []
        for name, raw, _, _ in cases:
            path = temporary / name
            path.write_bytes(raw)
            paths.append(path)
        receipt = artifacts.run(paths, reference_inputs, temporary / "independent.json")
    artifacts.require(all(oracle.sha256((artifacts.ROOT / name).read_bytes()) == digest
                          for name, digest in checker_inputs.items()), "checker_inputs_changed")
    receipt["checker_sha256"].update(checker_inputs)
    receipt["devnet_controls"] = [dict(file=name, kind=kind, source_file_sha256=source_hash)
                                  for name, _, kind, source_hash in cases]
    with output.open("x", encoding="ascii") as stream:
        stream.write(oracle.canonical(receipt).decode("ascii") + "\n")
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", required=True, type=Path)
    parser.add_argument("--reference-inputs", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    checked = run(arguments.fixtures, arguments.reference_inputs, arguments.output)
    print(f"{len(checked['artifacts'])} independent controls; "
          f"{checked['signature_callbacks']} signature callbacks; no node acceptance claim")
