"""Mocked producer and bounded subprocess transport checks; no keygen/signing."""

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("generate", Path(__file__).with_name("generate_transactions.py"))
gen = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gen)


class PublicCorpusTests(unittest.TestCase):
    def test_fixed_recipe_count_signatures_and_asymmetric_outpoints(self):
        keys = [bytes([i]).hex() * 32 for i in range(15)]
        cases = list(gen.recipes(keys))
        self.assertEqual(len(cases), 18)
        self.assertEqual(sum(i["threshold"] for c in cases for i in c["inputs"]), 146)
        self.assertEqual([c["case_id"] for c in cases][7:9], ["v5-16checks", "v5-17checks"])
        self.assertEqual(cases[6]["inputs"][0]["signer_indices"], [14])
        for case in cases:
            outpoints = [i["outpoint"]["txid_display_hex"] for i in case["inputs"]]
            self.assertEqual(len(set(outpoints)), len(outpoints))
            self.assertTrue(all(bytes.fromhex(s) != bytes.fromhex(s)[::-1] for s in outpoints))
        self.assertEqual(len(gen.seed(0)), 96)
        self.assertNotEqual(gen.seed(0), gen.seed(1))
        self.assertNotEqual(gen.randomizer("v5-1of1", 0, 0), gen.randomizer("v6-1of1", 0, 0))
        self.assertNotEqual(gen.randomizer("v5-16checks", 0, 0), gen.randomizer("v5-16checks", 1, 0))

    def test_strict_json_and_canonical_del(self):
        for data in [b'{"x":1,"x":2}', b'[-0]', b'[1.0]', b'[1e0]', b'[18446744073709551616]',
                     b'["\\u00e9"]', b'[NaN]', b'[' * 17 + b'0' + b']' * 17]:
            with self.assertRaises(gen.FixtureError):
                gen.strict_json(data, gen.MAX_HOST)
        with self.assertRaises(gen.FixtureError):
            gen.strict_json(b' ' * 101, 100)
        self.assertEqual(gen.canonical({"\x7f": "\x7f"}), b'{"\\u007f":"\\u007f"}')

    def test_signer_identity_and_no_secret_response_on_sign(self):
        response = dict(version=1, contract=gen.CONTRACT, public_fixture=True, material="public-test-only",
                        backend=dict(repository="https://github.com/PQC-Suite-B/signatures",
                                     revision=gen.ALGORITHM, blake3="1.8.5"),
                        public_key="11" * 32, signature="22" * 7856, locally_verified=True)
        with mock.patch.object(gen, "invoke", return_value=response):
            self.assertEqual(gen.signer_call(Path("signer"), "sign"), response)
        for key, value in [("secret_key", "secret-must-not-appear"), ("version", True),
                           ("locally_verified", False), ("signature", "AA" * 7856)]:
            changed = copy.deepcopy(response)
            changed[key] = value
            with mock.patch.object(gen, "invoke", return_value=changed):
                with self.assertRaises(gen.FixtureError) as error:
                    gen.signer_call(Path("signer"), "sign")
                self.assertNotIn("secret-must-not-appear", str(error.exception))

    def test_mock_generation_exact_count_and_public_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "data"
            producer = {"fixture": "identity"}
            source = {"host": [], "signer": []}
            calls = {"keygen": 0, "sign": 0}

            def signer_call(_binary, op, **fields):
                calls[op] += 1
                if op == "keygen":
                    key = f'{calls[op]:02x}' * 32
                    return {"public_key": key, "secret_key": key + "ff" * 32}
                return {"public_key": fields["secret_key"][:64], "signature": "00" * 7856}

            def host_call(_binary, op, **fields):
                if op == "prepare":
                    recipe = fields["recipe"]
                    return {"case_id": recipe["case_id"], "inputs": [
                        {"message_hex": "00" * 101, "context_hex": "", "signers": [
                            {"signer_index": i, "public_key_hex": item["public_keys_hex"][i]}
                            for i in item["signer_indices"]]} for item in recipe["inputs"]]}
                if op == "assemble":
                    artifact = {"case_id": fields["recipe"]["case_id"], "producer": fields["producer"],
                                "records": fields["records"]}
                    artifact["artifact_sha256"] = gen.digest(gen.canonical(artifact))
                    return artifact
                return {"expectation_match": True, "observed": {"native_authorization": "accept"}}

            with mock.patch.object(gen, "producer_identity", return_value=(producer, source)), \
                    mock.patch.object(gen, "source_state", return_value={"source_commit": "0" * 40, "source_status": []}), \
                    mock.patch.object(gen, "signer_call", side_effect=signer_call), \
                    mock.patch.object(gen, "host_call", side_effect=host_call):
                receipt = gen.generate(Path(directory), Path("host"), Path("signer"), output)
                with self.assertRaisesRegex(gen.FixtureError, "destination_exists"):
                    gen.generate(Path(directory), Path("host"), Path("signer"), output)
            self.assertEqual(calls, {"keygen": 15, "sign": 146})
            self.assertEqual(receipt["artifact_count"], 18)
            self.assertEqual(len(list(output.glob("v*.json"))), 18)
            for path in output.iterdir():
                for forbidden in ('"secret_key"', '"seed"', '"randomizer"'):
                    self.assertNotIn(forbidden, path.read_text())
            self.assertEqual(receipt["kind"], "production-only-not-independent-acceptance")

    def test_inventory_rejects_symlink_and_hashes_actual_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source.rs").write_bytes(b"source")
            (root / "link.rs").symlink_to("source.rs")
            with mock.patch.object(gen.subprocess, "run", return_value=types.SimpleNamespace(stdout=b"source.rs\0")):
                self.assertEqual(gen.source_inventory(root, ["source.rs"]),
                                 [{"path": "source.rs", "sha256": gen.digest(b"source")}])
            with mock.patch.object(gen.subprocess, "run", return_value=types.SimpleNamespace(stdout=b"link.rs\0")):
                with self.assertRaisesRegex(gen.FixtureError, "source_file"):
                    gen.source_inventory(root, ["link.rs"])


class Stream:
    def __init__(self, fd):
        self.fd, self.closed = fd, False

    def fileno(self):
        return self.fd

    def close(self):
        self.closed = True


class Selector:
    def __init__(self):
        self.entries = {}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass

    def register(self, stream, _events):
        self.entries[stream] = types.SimpleNamespace(fileobj=stream)

    def unregister(self, stream):
        del self.entries[stream]

    def get_map(self):
        return self.entries

    def select(self, _timeout):
        return [(key, None) for key in list(self.entries.values())]


class TransportTests(unittest.TestCase):
    def run_transport(self, chunks, bound, clock=None):
        process = mock.Mock(stdin=Stream(1), stdout=Stream(2), stderr=Stream(3))
        process.poll.return_value = None
        process.wait.return_value = 0
        streams = {2: iter(chunks), 3: iter([b""])}
        with mock.patch.object(gen.subprocess, "Popen", return_value=process), \
                mock.patch.object(gen.selectors, "DefaultSelector", Selector), \
                mock.patch.object(gen.os, "set_blocking"), \
                mock.patch.object(gen.os, "write", side_effect=lambda _fd, b: len(b)), \
                mock.patch.object(gen.os, "read", side_effect=lambda fd, _size: next(streams[fd], b"")), \
                mock.patch.object(gen.time, "monotonic", side_effect=clock or [0] * 20):
            try:
                return gen.invoke(Path("fake"), {}, bound, timeout=1)
            finally:
                process.kill.assert_called_once()
                self.assertTrue(all(s.closed for s in (process.stdin, process.stdout, process.stderr)))

    def test_bounded_stream_and_kill_on_overflow(self):
        self.assertEqual(self.run_transport([b'{"ok":true}', b''], 32), {"ok": True})
        with self.assertRaisesRegex(gen.FixtureError, "response_size"):
            self.run_transport([b'X' * 33], 32)
        with self.assertRaisesRegex(gen.FixtureError, "subprocess_timeout"):
            self.run_transport([b''], 32, [0, 2])


if __name__ == "__main__":
    unittest.main()
