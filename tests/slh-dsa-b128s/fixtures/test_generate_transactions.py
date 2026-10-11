"""Mocked producer and bounded subprocess transport checks; no keygen/signing."""

import copy
import importlib.util
import json
from pathlib import Path
import shlex
import sys
import tempfile
import time
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

    def test_recipes_match_committed_corpus_without_keys(self):
        # Key-independent recipe fields must reproduce the committed native corpus.
        keys = [bytes([i]).hex() * 32 for i in range(15)]
        recipes = {case["case_id"]: case for case in gen.recipes(keys)}
        paths = sorted((gen.HERE / "data").glob("v*.json"))
        self.assertEqual(sorted(path.stem for path in paths), sorted(recipes))
        for path in paths:
            artifact, recipe = json.loads(path.read_bytes()), recipes[path.stem]
            raw = bytes.fromhex(artifact["transaction_hex"])
            with self.subTest(case=path.stem):
                self.assertEqual((artifact["network"], artifact["transaction_version"]),
                                 (recipe["network"], recipe["transaction_version"]))
                # v5/v6 header: version, group, branch, then lock time and expiry.
                self.assertEqual((int.from_bytes(raw[12:16], "little"), int.from_bytes(raw[16:20], "little")),
                                 (recipe["lock_time"], recipe["expiry_height"]))
                self.assertEqual([o["value_zat"] for o in artifact["outputs"]],
                                 [o["value_zat"] for o in recipe["outputs"]])
                self.assertEqual({o["script_hex"] for o in artifact["outputs"]},
                                 {artifact["inputs"][0]["spent_output"]["script_hex"]})
                self.assertEqual(len(artifact["inputs"]), len(recipe["inputs"]))
                for item, expected in zip(artifact["inputs"], recipe["inputs"]):
                    descriptor = bytes.fromhex(item["descriptor_hex"])
                    self.assertEqual((item["outpoint"]["txid_display_hex"], item["outpoint"]["index"]),
                                     (expected["outpoint"]["txid_display_hex"], expected["outpoint"]["index"]))
                    self.assertEqual((item["sequence"], item["spent_output"]["value_zat"]),
                                     (expected["sequence"], expected["value_zat"]))
                    self.assertEqual((descriptor[2], descriptor[3]),
                                     (expected["threshold"], len(expected["public_keys_hex"])))
                    self.assertEqual([r["signer_index"] for r in item["records"]], expected["signer_indices"])

    def test_strict_json_and_canonical_del(self):
        for data, reason in [(b'{"x":1,"x":2}', "duplicate_key"), (b'[-0]', "numeric_token"),
                             (b'[1.0]', "numeric_token"), (b'[1e0]', "numeric_token"),
                             (b'[18446744073709551616]', "numeric_token"), (b'["\\u00e9"]', "non_ascii"),
                             (b'[NaN]', "numeric_token"), (b'[' * 17 + b'0' + b']' * 17, "nesting")]:
            with self.subTest(data=data), self.assertRaisesRegex(gen.FixtureError, f"^{reason}$"):
                gen.strict_json(data, gen.MAX_HOST)
        # Pad a valid document so only the size bound can reject it.
        with self.assertRaisesRegex(gen.FixtureError, "^response_size$"):
            gen.strict_json(b"[0]" + b" " * 98, 100)
        self.assertEqual(gen.strict_json(b"[0]" + b" " * 97, 100), [0])
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

    def test_inventory_explicit_link_binds_literal_text_and_regular_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "proto").mkdir()
            (root / "source.proto").write_bytes(b"first")
            (root / "proto/link.proto").symlink_to("../source.proto")
            listed = types.SimpleNamespace(stdout=b"proto/link.proto\0source.proto\0")
            links = {"proto/link.proto": "../source.proto"}
            with mock.patch.object(gen.subprocess, "run", return_value=listed):
                rows = gen.source_inventory(root, ["proto", "source.proto"], allowed_symlinks=links)
                self.assertEqual(rows, [
                    {"path": "proto/link.proto", "sha256": gen.digest(b"../source.proto"), "symlink_target": "source.proto"},
                    {"path": "source.proto", "sha256": gen.digest(b"first")},
                ])
                (root / "source.proto").write_bytes(b"second")
                changed = gen.source_inventory(root, ["proto", "source.proto"], allowed_symlinks=links)
                self.assertEqual(rows[0], changed[0])
                self.assertNotEqual(rows[1], changed[1])
                with self.assertRaisesRegex(gen.FixtureError, "source_file"):
                    gen.source_inventory(root, ["proto", "source.proto"])

    def test_inventory_link_opt_in_rejects_escapes_mutations_and_unbound_targets(self):
        for case in ("changed-link", "escape", "untracked", "excluded", "chained-file", "chained-directory", "hidden-chain", "missing-directory", "missing-link", "allowed-chain"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "source.proto").write_bytes(b"source")
                text = "source.proto"
                expected = text
                names = ["link.proto", "source.proto"]
                paths = ["."]
                extra_links = {}
                if case == "changed-link":
                    text = "./source.proto"
                elif case == "escape":
                    text = expected = "../outside.proto"
                elif case == "untracked":
                    names.remove("source.proto")
                elif case == "excluded":
                    (root / "target").mkdir()
                    (root / "target/source.proto").write_bytes(b"source")
                    text = expected = "target/source.proto"
                    names.append(text)
                elif case == "chained-file":
                    (root / "source.proto").unlink()
                    (root / "real.proto").write_bytes(b"source")
                    (root / "source.proto").symlink_to("real.proto")
                    names.append("real.proto")
                elif case == "chained-directory":
                    (root / "real").mkdir()
                    (root / "real/source.proto").write_bytes(b"source")
                    (root / "alias").symlink_to("real", target_is_directory=True)
                    text = expected = "alias/source.proto"
                    names.append(text)
                elif case == "hidden-chain":
                    (root / "real/child").mkdir(parents=True)
                    (root / "real/source.proto").write_bytes(b"different")
                    (root / "alias").symlink_to("real/child", target_is_directory=True)
                    text = expected = "alias/../source.proto"
                elif case == "missing-directory":
                    text = expected = "missing/../source.proto"
                elif case == "allowed-chain":
                    # Each link is allowed and valid alone; only the chain check rejects
                    # a link whose target is itself a link.
                    (root / "source.proto").unlink()
                    (root / "real.proto").write_bytes(b"source")
                    (root / "source.proto").symlink_to("real.proto")
                    names.append("real.proto")
                    paths = sorted(names)
                    extra_links = {"source.proto": "real.proto"}
                if case == "missing-link":
                    (root / "link.proto").write_bytes(b"source")
                else:
                    (root / "link.proto").symlink_to(text)
                listed = types.SimpleNamespace(stdout=("\0".join(names) + "\0").encode())
                with mock.patch.object(gen.subprocess, "run", return_value=listed):
                    with self.assertRaisesRegex(gen.FixtureError, "source_file"):
                        gen.source_inventory(root, paths, allowed_symlinks={"link.proto": expected, **extra_links})


class TransportTests(unittest.TestCase):
    """Real child processes through real pipes; offline, no builds or signing."""

    def child(self, code):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        script = Path(directory.name) / "child.py"
        script.write_text("import sys, time\n" + code + "\n")
        binary = Path(directory.name) / "child"
        binary.write_text(f"#!/bin/sh\nexec {shlex.quote(sys.executable)} {shlex.quote(str(script))}\n")
        binary.chmod(0o700)
        return binary

    def test_bounded_stream_and_kill_on_overflow(self):
        echo = self.child("sys.stdout.buffer.write(sys.stdin.buffer.read())")
        self.assertEqual(gen.invoke(echo, {"a": [1, "x"]}, 64), {"a": [1, "x"]})
        pad = {"pad": "x" * 150_000}  # Larger than a pipe buffer.
        self.assertEqual(gen.invoke(echo, pad, 200_000), pad)
        # Children that would outlive the test unless invoke kills them.
        stalled = "sys.stdin.buffer.read(); sys.stdout.flush(); time.sleep(60)"
        for name, code, request, bound, timeout, reason in (
            ("stdout", "sys.stdout.buffer.write(b'X' * 4096); sys.stdout.flush(); time.sleep(60)", {}, 32, 30, "response_size"),
            ("stderr", "sys.stderr.buffer.write(b'E' * (32768 + 1)); sys.stderr.flush(); time.sleep(60)", {}, 32, 30, "stderr_size"),
            ("timeout", stalled, {}, 32, 0.2, "subprocess_timeout"),
            ("status", "sys.stdout.write('{}'); sys.exit(1)", {}, 32, 30, "subprocess_failed"),
            ("broken-pipe", "sys.exit(0)", pad, 200_000, 30, "subprocess_failed"),
            ("request", "pass", pad, 32, 30, "request_size"),
        ):
            with self.subTest(name=name):
                started = time.monotonic()
                with self.assertRaisesRegex(gen.FixtureError, f"^{reason}$"):
                    gen.invoke(self.child(code), request, bound, timeout=timeout)
                self.assertLess(time.monotonic() - started, 20)


if __name__ == "__main__":
    unittest.main()
