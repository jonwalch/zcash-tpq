# SPDX-License-Identifier: MIT OR Apache-2.0
"""Mocked devnet fixture production; no key generation or signing is executed."""

import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import generate_devnet_transactions as devnet

corpus = devnet.corpus
PUBLIC_KEY = "1c9d2cab4b9657b55bdf96022ba262f652698f65686b8ddfc47ff0a70a8a3902"


class DevnetProducerTests(unittest.TestCase):
    def test_recipes_reuse_effects_and_explicit_testnet_context(self):
        recipes = list(devnet.recipes(corpus.ROOT, PUBLIC_KEY))
        self.assertEqual([recipe["case_id"] for recipe in recipes],
                         ["v5-testnet-1of1", "v6-testnet-1of1"])
        for recipe in recipes:
            version = recipe["transaction_version"]
            original = corpus.strict_json((corpus.HERE / f"data/v{version}-1of1.json").read_bytes(), corpus.MAX_HOST)
            self.assertEqual(recipe["network"], "Testnet")
            self.assertEqual(len(recipe["inputs"]), 1)
            self.assertEqual(recipe["inputs"][0]["threshold"], 1)
            self.assertEqual(recipe["inputs"][0]["outpoint"]["txid_display_hex"],
                             original["inputs"][0]["outpoint"]["txid_display_hex"])
            self.assertEqual(recipe["outputs"], [{key: output[key] for key in ("value_zat", "script_hex")}
                                                  for output in original["outputs"]])
        with self.assertRaisesRegex(corpus.FixtureError, "source_fixture"):
            list(devnet.recipes(corpus.ROOT, "00" * 32))

    def test_exact_bounded_production_and_no_secret_receipt_fields(self):
        calls = []

        def signer(_binary, operation, **fields):
            calls.append(operation)
            if operation == "keygen":
                self.assertEqual(fields["seed"], corpus.seed(0))
                return dict(public_key=PUBLIC_KEY, secret_key="ff" * 64)
            return dict(public_key=PUBLIC_KEY, signature="00" * 7856)

        def host(_binary, operation, **fields):
            if operation == "prepare":
                recipe = fields["recipe"]
                message = bytes(58) + bytes([0xf7, 1, recipe["transaction_version"]]) + bytes(40)
                return dict(case_id=recipe["case_id"], network="Testnet", inputs=[dict(
                    message_hex=message.hex(), context_hex="",
                    signers=[dict(signer_index=0, public_key_hex=PUBLIC_KEY)])])
            if operation == "assemble":
                artifact = dict(case_id=fields["recipe"]["case_id"], network="Testnet",
                                producer=fields["producer"], records=fields["records"])
                artifact["artifact_sha256"] = corpus.digest(corpus.canonical(artifact))
                return artifact
            return dict(expectation_match=True, observed=dict(native_authorization="accept"))

        with tempfile.TemporaryDirectory() as directory, \
                patch.object(corpus, "producer_identity", side_effect=lambda *_: (
                    {"zakura_revision": corpus.UPSTREAM}, {"host": [], "signer": []})), \
                patch.object(corpus, "source_state", return_value=dict(source_commit="0" * 40, source_status=[])), \
                patch.object(corpus, "signer_call", side_effect=signer), \
                patch.object(corpus, "host_call", side_effect=host):
            output = Path(directory) / "fixtures"
            receipt = devnet.generate(corpus.ROOT, Path("host"), Path("signer"), output)
            self.assertEqual(calls, ["keygen", "sign", "sign"])
            self.assertEqual((receipt["key_count"], receipt["artifact_count"], receipt["signature_count"]), (1, 2, 2))
            self.assertEqual(receipt["kind"], "production-only-not-independent-acceptance")
            self.assertEqual(receipt["producer"]["zakura_revision"],
                             "e33dc43089acca2fe2c6516927932f2b7618b8bc")
            for path in output.iterdir():
                artifact = corpus.strict_json(path.read_bytes(), corpus.MAX_HOST)
                self.assertEqual(artifact["producer"], receipt["producer"])
                for forbidden in ('"secret_key"', '"seed"', '"randomizer"'):
                    self.assertNotIn(forbidden, path.read_text())
            with self.assertRaisesRegex(corpus.FixtureError, "destination_exists"):
                devnet.generate(corpus.ROOT, Path("host"), Path("signer"), output)
            self.assertEqual(calls, ["keygen", "sign", "sign"])

    def test_current_upstream_pin_does_not_rewrite_original_generator(self):
        original = {"zakura_revision": corpus.UPSTREAM}
        with patch.object(corpus, "producer_identity", return_value=(copy.deepcopy(original), {})):
            producer, inventory = devnet.identity(corpus.ROOT, Path("host"), Path("signer"))
        self.assertEqual(producer["zakura_revision"], "e33dc43089acca2fe2c6516927932f2b7618b8bc")
        self.assertEqual(original["zakura_revision"], "9b175e9d3d46a6aa4cfb5552517c3d828852ecbc")
        self.assertIn(dict(path=devnet.PIN_PATH, sha256=corpus.digest((corpus.ROOT / devnet.PIN_PATH).read_bytes())),
                      inventory["devnet_generator"])

    def test_pin_drift_fails_before_any_production(self):
        for revision in ("9b175e9d3d46a6aa4cfb5552517c3d828852ecbc",
                         "24a17b3f0e7d88513688d607054f018ab6f15af2", "11" * 20, None):
            with self.subTest(revision=revision), tempfile.TemporaryDirectory() as directory, \
                    patch.object(corpus, "producer_identity") as producer, \
                    patch.object(corpus, "host_call") as host, \
                    patch.object(corpus, "signer_call") as signer:
                root = Path(directory)
                pin = root / devnet.PIN_PATH
                pin.parent.mkdir(parents=True)
                pin.write_bytes(corpus.canonical(dict(upstream=revision)))
                output = root / "fixtures"
                with self.assertRaisesRegex(corpus.FixtureError, "^upstream_pin$"):
                    devnet.generate(root, Path("host"), Path("signer"), output)
                producer.assert_not_called()
                host.assert_not_called()
                signer.assert_not_called()
                self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
