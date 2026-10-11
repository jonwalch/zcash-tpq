"""Independent reference adapter controls; no signing workloads in these mocks."""

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

    def test_keygen_consumes_exact_components_and_restores_source(self):
        sentinel = object()
        scheme = SimpleNamespace(token_bytes=sentinel)
        scheme.keygen = lambda _: ((scheme.token_bytes(16), scheme.token_bytes(16), scheme.token_bytes(16), b"r" * 16), (b"p" * 16, b"r" * 16))
        ref = SimpleNamespace(scheme=scheme, profile=None)
        seed = bytes(range(48))
        secret, public = reference.keygen(ref, seed)
        self.assertEqual(b"".join(secret[:3]), seed)
        self.assertEqual(public, b"p" * 16 + b"r" * 16)
        self.assertIs(scheme.token_bytes, sentinel)

    def test_sign_adds_pure_once_and_requires_entropy(self):
        sentinel = object()
        scheme = SimpleNamespace(token_bytes=sentinel)
        seen = []

        def sign(message, secret, profile, randomize):
            seen.append((message, secret, profile, randomize, scheme.token_bytes(16)))
            return b"signature"

        scheme.sign = sign
        ref = SimpleNamespace(scheme=scheme, profile="fixed", frame=lambda message, context: b"\0\0" + message)
        self.assertEqual(reference.sign(ref, "secret", b"m" * 101, bytes(16)), b"signature")
        self.assertEqual(seen, [(b"\0\0" + b"m" * 101, "secret", "fixed", True, bytes(16))])
        self.assertIs(scheme.token_bytes, sentinel)
        scheme.sign = lambda *args, **kwargs: b"no entropy"
        with self.assertRaises(ValueError):
            reference.sign(ref, "secret", b"m" * 101, bytes(16))
        self.assertIs(scheme.token_bytes, sentinel)


if __name__ == "__main__":
    unittest.main()
