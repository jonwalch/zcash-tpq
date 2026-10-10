# SPDX-License-Identifier: MIT OR Apache-2.0
"""Corpus replay provenance controls with mocked crypto/builds; no signing or compilation."""
from contextlib import ExitStack
import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

import check

sys.path[:0] = [str(check.REFERENCE), str(check.HERE.parent / "acceptance"),
               str(check.HERE.parent / "evidence")]
import artifacts
import build
import common
import reference


class ReplayTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.directory = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.host = self.directory / "host"
        self.host.write_bytes(b"mock comparison binary")
        self.build_path = self.directory / "build.json"
        self.source = {"source_commit": "a" * 40}
        command, _, features = build.command("host", self.directory / "target")
        self.record = {"schema_version": 1, "contract": common.CONTRACT, "kind": "host",
                       "complete": True, "source": self.source, "command": command,
                       "features": features, "binary_sha256": common.sha256(self.host),
                       "identity": None, "rustc": "mock compiler", "cargo": "mock Cargo",
                       "environment": {}}
        self.write_build()
        self.args = check.parser().parse_args([
            str(self.directory / "reference"), "--comparison-host", str(self.host),
            "--comparison-build", str(self.build_path), "--output", str(self.directory / "result.json")])
        self.original, self.hashes = check.replay_inputs(self.args.corpus)
        self.checked = {"cases": [{}] * 18, "mutations": [{}] * 60,
                        "corpus_files": self.hashes, "primitive_message_controls": {}}
        self.stack.enter_context(patch.object(common, "source_state", return_value=self.source))
        self.stack.enter_context(patch.object(check, "inventory", return_value=[{"path": "mock source"}]))
        self.factory = self.stack.enter_context(patch.object(reference, "Reference"))
        self.factory.return_value.hash_vectors.return_value = 105
        self.identity = self.stack.enter_context(patch.object(artifacts, "reference_identity",
                                                              return_value={"hash_build_sha256": "b" * 64}))
        self.real_compare = check.check_corpus
        self.compare = self.stack.enter_context(patch.object(check, "check_corpus", return_value=self.checked))

    def write_build(self):
        self.build_path.write_text(json.dumps(self.record))

    def test_current_comparison_identity_does_not_replace_original_producer(self):
        self.assertTrue(check.validate_mode(self.args))
        result = check.replay_corpus(self.args)
        self.assertTrue(result["artifact_producer_and_comparison_target_are_distinct"])
        self.assertEqual(result["artifact_producer_verification"], self.original)
        self.assertEqual(result["comparison_target"]["source_commit"], self.source["source_commit"])
        self.assertEqual(result["comparison_target"]["build"], self.record)
        self.assertEqual(result["comparison_target"]["build_receipt_sha256"], common.sha256(self.build_path))
        self.compare.assert_called_once()
        arguments = self.compare.call_args.args
        self.assertEqual(arguments[:3], (self.args.corpus.resolve(), self.factory.return_value, self.host.resolve()))
        self.assertEqual(arguments[3], self.original)
        self.assertNotEqual(self.original["claims"]["host_binary_sha256"], self.record["binary_sha256"])

    def test_incomplete_or_mixed_cli_modes_are_rejected(self):
        for field, value in (("comparison_host", None), ("comparison_build", None),
                             ("host", self.host), ("signer", self.host)):
            changed = copy.copy(self.args)
            setattr(changed, field, value)
            with self.subTest(field=field), self.assertRaises(ValueError):
                check.validate_mode(changed)
        original = check.parser().parse_args([str(self.directory), "--host", str(self.host),
                                             "--output", str(self.directory / "result.json")])
        with self.assertRaisesRegex(ValueError, "supply both binaries"):
            check.validate_mode(original)

    def test_existing_receipt_or_dangling_link_is_never_replaced(self):
        for link in (False, True):
            if link:
                self.args.output.symlink_to(self.directory / "absent")
            else:
                self.args.output.write_text("retained")
            with self.subTest(link=link), self.assertRaisesRegex(ValueError, "destination must be new"):
                check.validate_mode(self.args)
            self.args.output.unlink()

    def test_stale_source_binary_recipe_or_incomplete_build_fails_before_crypto(self):
        original = copy.deepcopy(self.record)
        for field, value in (("source", {"source_commit": "c" * 40}),
                             ("binary_sha256", "00" * 32), ("complete", False),
                             ("kind", "signer"), ("features", ["shielded-fixtures"]),
                             ("command", ["cargo", "check"])):
            self.record = {**original, field: value}
            self.write_build()
            with self.subTest(field=field), self.assertRaises(common.AcceptanceError):
                check.replay_corpus(self.args)
            self.factory.assert_not_called()
            self.compare.assert_not_called()

    def test_changed_retained_receipt_or_corpus_fails_before_crypto(self):
        modified = self.directory / "retained.json"
        modified.write_bytes(check.REPLAY_RECEIPT.read_bytes() + b"\n")
        with patch.object(check, "REPLAY_RECEIPT", modified), \
                self.assertRaisesRegex(ValueError, "retained producer receipt changed"):
            check.replay_corpus(self.args)
        corpus = self.directory / "corpus"
        shutil.copytree(self.args.corpus, corpus)
        self.args.corpus = corpus
        sample = corpus / "v5-1of1.json"
        sample.write_bytes(sample.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "retained corpus changed"):
            check.replay_corpus(self.args)
        self.factory.assert_not_called()
        self.compare.assert_not_called()

    def test_build_binary_reference_or_checker_drift_cannot_get_a_receipt(self):
        def altered(kind):
            def compare(*args):
                if kind == "binary":
                    self.host.write_bytes(b"replaced")
                elif kind == "build":
                    self.build_path.write_text(json.dumps(self.record) + "\n")
                return self.checked
            return compare
        for kind in ("binary", "build", "reference", "checker"):
            self.host.write_bytes(b"mock comparison binary")
            self.write_build()
            self.compare.side_effect = altered(kind)
            self.identity.side_effect = [{"hash": "first"}, {"hash": "changed" if kind == "reference" else "first"}]
            with patch.object(check, "replay_checker_files", side_effect=[{"hash": "first"},
                    {"hash": "changed" if kind == "checker" else "first"}]), self.subTest(kind=kind), \
                    self.assertRaises((ValueError, common.AcceptanceError)):
                check.replay_corpus(self.args)
            self.assertFalse(self.args.output.exists())

    def test_missing_hash_controls_or_incomplete_comparison_cannot_pass(self):
        for controls in (True, 104, 106):
            self.factory.return_value.hash_vectors.return_value = controls
            with self.subTest(controls=controls), self.assertRaisesRegex(ValueError, "official hash controls"):
                check.replay_corpus(self.args)
        self.factory.return_value.hash_vectors.return_value = 105
        self.compare.return_value = {**self.checked, "mutations": [{}] * 59}
        with self.assertRaisesRegex(ValueError, "bounded comparison coverage"):
            check.replay_corpus(self.args)

    def test_source_drift_during_comparison_is_rejected(self):
        with patch.object(common, "source_state", side_effect=[self.source, self.source,
                {"source_commit": "c" * 40}]), self.assertRaisesRegex(common.AcceptanceError, "stale_build_source"):
            check.replay_corpus(self.args)
        self.compare.assert_called_once()
        self.assertFalse(self.args.output.exists())

    def test_original_producer_mismatch_still_rejects_before_native_comparison(self):
        # Use the real fixed-corpus parser/digest/producer gate with a synthetic
        # accepting crypto callback. This is provenance coverage, not crypto evidence.
        with patch.object(check, "candidate") as native:
            with tempfile.TemporaryDirectory() as directory:
                corpus = Path(directory) / "corpus"
                shutil.copytree(check.HERE.parent / "fixtures/data", corpus)
                wrong = copy.deepcopy(self.original)
                wrong["claims"]["host_binary_sha256"] = "00" * 32
                with self.assertRaisesRegex(ValueError, "producer inputs/binary mismatch"):
                    self.real_compare(corpus, types.SimpleNamespace(verify=lambda *args: True),
                                      Path("unused"), wrong)
                native.assert_not_called()


if __name__ == "__main__":
    unittest.main()
