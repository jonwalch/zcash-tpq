"""Independent reference adapter controls; no signing workloads in these mocks."""

import hashlib
import json
from types import SimpleNamespace
from pathlib import Path
import tempfile
import unittest

import reference


class ReferenceTests(unittest.TestCase):
    def test_retained_bytes_match_receipt_and_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "vectors.json"
            reference.retain(destination, b'{"a": 1}\n', True)
            reference.retain(destination, b'{"a": 1}\n', False)
            with self.assertRaises(ValueError):
                reference.retain(destination, b'{"a":1}', False)
            with self.assertRaises(FileExistsError):
                reference.retain(destination, b'{"a": 2}\n', True)
            self.assertEqual(destination.read_bytes(), b'{"a": 1}\n')

    def test_rfc5869_case_one(self):
        prk, first, second = reference.expand(bytes.fromhex("0b" * 22), bytes(range(13)), bytes(range(0xf0, 0xfa)))
        self.assertEqual(prk.hex(), "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        self.assertEqual((first + second[:10]).hex(), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")

    def test_layout_and_bounds(self):
        answer = reference.derive(bytes(32), 1, 0xffffffff)
        self.assertEqual(bytes.fromhex(answer["info"]), reference.KEY_DOMAIN + bytes.fromhex("0102f70000000001ffffffff"))
        self.assertEqual(answer["seed"], answer["t1"] + answer["t2"][:32])
        for role, index in ((2, 0), (0, -1), (0, 0x100000000)):
            with self.assertRaises(ValueError):
                reference.derive(bytes(32), role, index)

    def test_retained_hkdf_answers(self):
        # Offline part of the retained corpus check; signatures need the
        # prepared portable-C reference and stay a human run.
        raw = (reference.HERE / "vectors.json").read_bytes()
        receipt = json.loads((reference.HERE / "receipt.json").read_bytes())
        self.assertEqual(hashlib.sha256(raw).hexdigest(), receipt["independent_expectations"]["vectors_sha256"])
        data = json.loads(raw)
        self.assertEqual(raw, (json.dumps(data, indent=2, sort_keys=True) + "\n").encode())
        self.assertEqual((data["schema_version"], data["material"], data["suite"]), (1, "public-test-only", 0xF7))
        self.assertEqual(data["salt"], b"ZcashTransparentPQ/wallet-root/v1\0".hex())
        root = bytes.fromhex(data["root"])
        self.assertEqual(root, bytes(range(32)))
        self.assertEqual([(case["role"], case["index"]) for case in data["cases"]], reference.COORDINATES)
        hkdf = ("info", "prk", "t1", "t2", "seed")
        domain = b"ZcashTransparentPQ/experimental/slh-dsa-b-128s/message/v1\0"
        signed = []
        for case in data["cases"]:
            role, index = case["role"], case["index"]
            with self.subTest(role=role, index=index):
                self.assertEqual({key: case[key] for key in hkdf}, reference.derive(root, role, index))
                self.assertEqual(len(bytes.fromhex(case["public_key"])), 32)
                if "signature" in case:
                    signed.append((role, index))
                    # Regtest, v5, NU7 branch ID, input index, then a public digest.
                    message = domain + bytes([0xF7, 2, 5]) + bytes.fromhex("d90a1977") + index.to_bytes(4, "little") + bytes(range(32))
                    self.assertEqual((len(domain), len(message)), (58, 101))
                    self.assertEqual(case["message"], message.hex())
                    self.assertEqual(case["randomness"], bytes(range(16 * role, 16 * role + 16)).hex())
                    self.assertEqual(len(bytes.fromhex(case["signature"])), 7856)
        self.assertEqual(signed, [(0, 0), (1, 0xFFFFFFFF)])
        separation = data["suite_separation"]
        self.assertEqual([row["suite"] for row in separation], [0, 0xF6, 0xF8])
        for row in separation:
            with self.subTest(suite=row["suite"]):
                self.assertEqual({key: row[key] for key in hkdf}, reference.derive(root, 0, 0, row["suite"]))
        seeds = [row["seed"] for row in separation] + [data["cases"][0]["seed"]]
        self.assertEqual(len(set(seeds)), 4)

    def fake_scheme(self):
        sentinel = object()
        return sentinel, SimpleNamespace(token_bytes=sentinel)

    def test_keygen_consumes_exact_components_and_restores_source(self):
        sentinel, scheme = self.fake_scheme()
        scheme.keygen = lambda _: ((scheme.token_bytes(16), scheme.token_bytes(16), scheme.token_bytes(16), b"r" * 16), (b"p" * 16, b"r" * 16))
        ref = SimpleNamespace(scheme=scheme, profile=None)
        seed = bytes(range(48))
        secret, public = reference.keygen(ref, seed)
        self.assertEqual(b"".join(secret[:3]), seed)
        self.assertEqual(public, b"p" * 16 + b"r" * 16)
        self.assertIs(scheme.token_bytes, sentinel)
        for requests, reason in (((16, 16), "independent keygen did not consume every seed component"),
                                 ((16, 16, 32), "unexpected keygen entropy request")):
            with self.subTest(requests=requests):
                sentinel, scheme = self.fake_scheme()
                scheme.keygen = lambda _, requests=requests: ([scheme.token_bytes(size) for size in requests], (b"p" * 16,))
                with self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                    reference.keygen(SimpleNamespace(scheme=scheme, profile=None), seed)
                self.assertIs(scheme.token_bytes, sentinel)

    def test_sign_adds_pure_once_and_requires_entropy(self):
        sentinel, scheme = self.fake_scheme()
        seen, frames = [], []

        def sign(message, secret, profile, randomize):
            seen.append((message, secret, profile, randomize, scheme.token_bytes(16)))
            return b"signature"

        def frame(message, context):
            frames.append((message, context))
            return b"\0\0" + message

        scheme.sign = sign
        ref = SimpleNamespace(scheme=scheme, profile="fixed", frame=frame)
        self.assertEqual(reference.sign(ref, "secret", b"m" * 101, bytes(16)), b"signature")
        self.assertEqual(frames, [(b"m" * 101, b"")])
        self.assertEqual(seen, [(b"\0\0" + b"m" * 101, "secret", "fixed", True, bytes(16))])
        self.assertIs(scheme.token_bytes, sentinel)
        for requests, reason in (((), "independent signing skipped prescribed randomness"),
                                 ((16, 16), "unexpected signing entropy request"),
                                 ((32,), "unexpected signing entropy request")):
            with self.subTest(requests=requests):
                scheme.sign = lambda *_, requests=requests, **__: [scheme.token_bytes(size) for size in requests]
                with self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                    reference.sign(ref, "secret", b"m" * 101, bytes(16))
                self.assertIs(scheme.token_bytes, sentinel)


if __name__ == "__main__":
    unittest.main()
