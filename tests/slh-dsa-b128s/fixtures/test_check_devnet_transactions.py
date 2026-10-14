# SPDX-License-Identifier: MIT OR Apache-2.0
"""Mocked callback checks of devnet mutations; no primitive acceptance claim."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import check_devnet_transactions as checker


class DevnetControlTests(unittest.TestCase):
    def test_exact_positive_and_coherent_negative_shapes(self):
        prepared = []
        for version in (5, 6):
            raw = (checker.HERE / f"data/v{version}-1of1.json").read_bytes()
            # A synthetic stand-in for the future signed Testnet fixture. The
            # callback below recognizes bytes; it never claims SLH validity.
            artifact = checker.oracle.strict_json(raw)
            artifact["case_id"] = f"v{version}-testnet-1of1"
            artifact["network"] = "Testnet"
            tx = checker.wire.parse_transaction(bytes.fromhex(artifact["transaction_hex"]))
            checker.mutations.refresh(artifact, tx)
            prepared.append((artifact["case_id"] + ".json", checker.oracle.canonical(artifact)))
        valid = set()
        for _, raw in prepared:
            artifact = checker.oracle.strict_json(raw)
            record = artifact["inputs"][0]["records"][0]
            valid.add((record["public_key_hex"], record["signature_hex"], artifact["inputs"][0]["message_hex"]))
        calls = []
        def verify(key, signature, message, context):
            calls.append(1)
            return context == b"" and (key.hex(), signature.hex(), message.hex()) in valid
        controls = checker.controls(prepared)
        self.assertEqual([kind for _, _, kind, _ in controls],
                         ["positive", "wrong-network", "corrupt-signature"] * 2)
        for _, raw, _, _ in controls:
            artifact, observed = checker.oracle.evaluate(raw, verify)
            self.assertEqual(observed, artifact["expected"])
        self.assertEqual(len(calls), 6)
        with self.assertRaisesRegex(ValueError, "devnet_fixture_count"):
            checker.controls(prepared[:1])

    def test_expected_rejections_cannot_be_positive_controls(self):
        for invalid_versions in [(5,), (6,), (5, 6)]:
            with self.subTest(invalid_versions=invalid_versions), \
                    tempfile.TemporaryDirectory() as directory:
                fixtures = Path(directory)
                for version in (5, 6):
                    name = f"v{version}-testnet-1of1.json"
                    artifact = checker.oracle.strict_json((checker.HERE / "devnet" / name).read_bytes())
                    if version in invalid_versions:
                        tx = checker.wire.parse_transaction(bytes.fromhex(artifact["transaction_hex"]))
                        descriptor, records = checker.oracle.decode_authorization(tx["inputs"][0]["script"])
                        signature = bytearray.fromhex(records[0]["signature_hex"])
                        # Keep this distinct from the checker's byte-100 mutation.
                        signature[101] ^= 1
                        records[0]["signature_hex"] = signature.hex()
                        tx["inputs"][0]["script"] = checker.oracle.encode_authorization(descriptor, records)
                        artifact["expected"] = checker.oracle.observation("signature", "signature", 0, 1)
                        checker.mutations.refresh(artifact, tx)
                    (fixtures / name).write_bytes(checker.oracle.canonical(artifact))

                output = fixtures / "receipt.json"
                with patch.object(checker.artifacts, "run", side_effect=AssertionError(
                        "expected-negative originals must fail before reference verification")) as run:
                    with self.assertRaisesRegex(ValueError, "devnet_positive_expectation"):
                        checker.run(fixtures, Path("unused-reference"), output)
                    run.assert_not_called()
                self.assertFalse(output.exists())

    def test_positive_expectation_still_requires_verifier_acceptance(self):
        prepared = checker.artifacts.preflight([
            checker.HERE / f"devnet/v{version}-testnet-1of1.json" for version in (5, 6)])
        controls = checker.controls(prepared)
        verify = Mock(return_value=False)
        with self.assertRaisesRegex(ValueError, "independent_expected_mismatch"):
            checker.artifacts.evaluate([(name, raw) for name, raw, _, _ in controls], verify)
        verify.assert_called_once()


if __name__ == "__main__":
    unittest.main()
