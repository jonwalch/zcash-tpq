# SPDX-License-Identifier: MIT OR Apache-2.0
"""Mocked callback checks of devnet mutations; no primitive acceptance claim."""

import unittest

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


if __name__ == "__main__":
    unittest.main()
