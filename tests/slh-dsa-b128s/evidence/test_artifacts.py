# SPDX-License-Identifier: MIT OR Apache-2.0
"""Offline wrapper controls with fake callbacks: these are not crypto evidence."""
import copy
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import Mock, patch

import artifacts

oracle = artifacts.oracle


class ArtifactEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        data = artifacts.HERE.parent / "fixtures/data"
        cls.small = oracle.strict_json((data / "v5-1of1.json").read_bytes())
        cls.large = oracle.strict_json((data / "v5-17checks.json").read_bytes())

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root / "receipt.json"
        self.library = self.root / "libslh_reference_blake3.so"
        self.library.write_bytes(b"mock reference library, never loaded")
        self.build = {"schema_version": 1, "library_name": self.library.name,
                      "library_sha256": oracle.sha256(self.library.read_bytes())}
        (self.root / "hash-build.json").write_bytes(oracle.canonical(self.build))
        self.reference = Mock()
        self.reference.hash_vectors.return_value = 105
        self.reference.verify.return_value = True
        self.factory = Mock(return_value=self.reference)

    def artifact(self, name="operator-case", source=None):
        value = copy.deepcopy(self.small if source is None else source)
        value["case_id"] = name
        return value

    def write(self, value=None, name="artifact.json"):
        value = self.artifact() if value is None else value
        value["artifact_sha256"] = oracle.artifact_hash(value)
        path = self.root / name
        path.write_bytes(oracle.canonical(value))
        return path

    def run_check(self, paths):
        return artifacts.run(paths, self.root, self.output, reference_factory=self.factory)

    def assert_preflight_failure(self, paths, reason=None):
        if reason is None:
            context = self.assertRaises((ValueError, oracle.InterfaceFailure))
        else:
            context = self.assertRaisesRegex((ValueError, oracle.InterfaceFailure), "^" + re.escape(reason) + "$")
        with context:
            self.run_check(paths)
        self.factory.assert_not_called()
        self.reference.verify.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_arbitrary_coherent_case_retains_bytes_and_limited_claims(self):
        path = self.write()
        raw = path.read_bytes()
        result = self.run_check([path])
        self.assertEqual(result["artifacts"][0]["file_sha256"], oracle.sha256(raw))
        self.assertEqual(result["artifacts"][0]["case_id"], "operator-case")
        self.assertEqual(result["signature_callbacks"], 1)
        self.assertEqual(result["claims"], {key: False for key in artifacts.CLAIMS})
        self.assertIn("caller-supplied", result["previous_outputs"])
        self.assertEqual(json.loads(self.output.read_text()), result)
        self.reference.verify.assert_called_once()

    def test_every_schema_is_checked_before_reference_or_crypto(self):
        good = self.write()
        for field, value in [("schema_version", True), ("transaction_version", True),
                             ("public_fixture", 1), ("inputs", None),
                             ("context_provenance", "authenticated-utxos"),
                             ("contract", "another-contract")]:
            with self.subTest(field=field):
                bad = self.artifact("bad-case")
                bad[field] = value
                self.assert_preflight_failure([good, self.write(bad, "bad.json")])
        for change in (lambda a: a.pop("expected"), lambda a: a.update(extra=1),
                       lambda a: a["inputs"][0]["records"][0].update(signature_hex="00"),
                       lambda a: a["inputs"][0]["records"][0].update(signer_index=True)):
            bad = self.artifact("bad-case")
            change(bad)
            self.assert_preflight_failure([good, self.write(bad, "bad.json")])

    def test_transport_duplicate_keys_and_operation_envelopes_rejected(self):
        value = self.artifact()
        value["artifact_sha256"] = oracle.artifact_hash(value)
        raw = oracle.canonical(value)
        # The duplicate repeats a valid artifact's final value, so only the
        # duplicate-key check can reject it.
        duplicate = raw.replace(b'"case_id":', b'"case_id":"x","case_id":', 1)
        decimal = raw.replace(b'"schema_version":1,', b'"schema_version":1.0,', 1)
        self.assertNotIn(raw, (duplicate, decimal))
        for payload, reason in ((duplicate, "schema/duplicate_key"), (b'{"op":"mixed"}', "schema/fields"),
                                (decimal, "schema/number"), (b'[]', "schema/fields"), (b'\xff', "schema/json")):
            with self.subTest(reason=reason):
                path = self.root / "bad.json"
                path.write_bytes(payload)
                self.assert_preflight_failure([path], reason)

    def test_empty_excess_count_and_per_file_bounds_precede_reference(self):
        self.assert_preflight_failure([], "artifact_count")
        paths = [self.write(self.artifact(f"case-{i}"), f"a{i}.json") for i in range(artifacts.MAX_ARTIFACTS + 1)]
        self.assertEqual(len(self.run_check(paths[:-1])["artifacts"]), artifacts.MAX_ARTIFACTS)
        self.output.unlink()
        self.factory.reset_mock()
        self.reference.verify.reset_mock()
        self.assert_preflight_failure(paths, "artifact_count")
        value = self.artifact()
        value["artifact_sha256"] = oracle.artifact_hash(value)
        raw = oracle.canonical(value)
        path = self.root / "large.json"
        # Trailing JSON whitespace keeps the artifact valid, so only the per-file
        # byte bound can reject one more byte.
        path.write_bytes(raw + b" " * (artifacts.MAX_FILE_BYTES - len(raw)))
        self.run_check([path])
        self.output.unlink()
        self.factory.reset_mock()
        self.reference.verify.reset_mock()
        path.write_bytes(raw + b" " * (artifacts.MAX_FILE_BYTES + 1 - len(raw)))
        self.assert_preflight_failure([path], "bounded regular input required")

    def test_aggregate_signature_bound_precedes_reference(self):
        paths = [self.write(self.artifact(f"case-{i}", self.large), f"a{i}.json") for i in range(9)]
        with self.assertRaisesRegex(ValueError, "aggregate_signature_bound"):
            self.run_check(paths)
        self.factory.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_aggregate_byte_bound_precedes_reference(self):
        paths = []
        for i in range(9):
            value = self.artifact(f"case-{i}")
            value["outputs"] = [{"output_index": j, "value_zat": 1, "script_hex": "00" * 10000} for j in range(50)]
            paths.append(self.write(value, f"a{i}.json"))
        with self.assertRaisesRegex(ValueError, "aggregate_artifact_bytes"):
            self.run_check(paths)
        self.factory.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_paths_regular_files_and_unique_identities(self):
        good = self.write()
        self.assert_preflight_failure([self.root], "bounded regular input required")
        self.assert_preflight_failure([self.root / "missing.json"], "bounded regular input required")
        symlink = self.root / "link.json"
        symlink.symlink_to(good)
        self.assert_preflight_failure([symlink], "bounded regular input required")
        hardlink = self.root / "hard.json"
        os.link(good, hardlink)
        self.assert_preflight_failure([good, hardlink], "duplicate_artifact_path")
        same = self.root / "same.json"
        same.write_bytes(good.read_bytes())
        self.assert_preflight_failure([good, same], "duplicate_artifact_bytes")
        nested = self.root / "nested"
        nested.mkdir()
        different = self.artifact("different")
        different["artifact_sha256"] = oracle.artifact_hash(different)
        (nested / good.name).write_bytes(oracle.canonical(different))
        self.assert_preflight_failure([good, nested / good.name], "duplicate_artifact_path")
        value = self.artifact()
        value["producer"]["host_binary_sha256"] = "11" * 32
        self.assert_preflight_failure([good, self.write(value, "case-collision.json")], "duplicate_case_identity")
        self.assert_preflight_failure([self.write(name="bad name.json")], "artifact_filename")

    def test_fresh_output_and_existing_parent_required_before_work(self):
        good = self.write()
        self.output.write_text("preserve")
        self.assert_preflight_failure_without_output_check([good])
        self.assertEqual(self.output.read_text(), "preserve")
        self.output.unlink()
        self.output.symlink_to(self.root / "absent")
        self.assert_preflight_failure_without_output_check([good])
        self.output.unlink()
        self.output = self.root / "missing-parent" / "receipt.json"
        self.assert_preflight_failure([good])

    def assert_preflight_failure_without_output_check(self, paths):
        with self.assertRaises(ValueError):
            self.run_check(paths)
        self.factory.assert_not_called()

    def test_receipt_hashes_bytes_retained_before_file_replacement(self):
        path = self.write()
        raw = path.read_bytes()
        def replace(_):
            path.write_bytes(b"later unrelated bytes")
            return self.reference
        self.factory.side_effect = replace
        result = self.run_check([path])
        self.assertEqual(result["artifacts"][0]["file_sha256"], oracle.sha256(raw))
        self.assertNotEqual(result["artifacts"][0]["file_sha256"], oracle.sha256(path.read_bytes()))

    def test_negative_exception_and_non_boolean_verdict_never_publish_success(self):
        good = self.write()
        for value in (False, 1, None, {"accept": True}):
            with self.subTest(value=value):
                self.reference.verify.return_value = value
                with self.assertRaises(ValueError):
                    self.run_check([good])
                self.assertFalse(self.output.exists())
        self.reference.verify.side_effect = TimeoutError("independent verifier failed")
        with self.assertRaises(TimeoutError):
            self.run_check([good])
        self.assertFalse(self.output.exists())

    def test_hash_controls_require_exact_105_and_reference_failures_propagate(self):
        good = self.write()
        for value in (104, True, 105.0):
            self.reference.hash_vectors.return_value = value
            with self.assertRaisesRegex(ValueError, "official_hash_controls"):
                self.run_check([good])
            self.reference.verify.assert_not_called()
        self.factory.side_effect = RuntimeError("checked loader failed")
        with self.assertRaises(RuntimeError):
            self.run_check([good])
        self.assertFalse(self.output.exists())

    def test_reference_input_changes_and_bad_library_paths_reject(self):
        good = self.write()
        def replace(*_):
            self.library.write_bytes(b"changed")
            return True
        self.reference.verify.side_effect = replace
        with self.assertRaisesRegex(ValueError, "reference_library_changed"):
            self.run_check([good])
        self.assertFalse(self.output.exists())
        self.build["library_name"] = "../external.so"
        (self.root / "hash-build.json").write_bytes(oracle.canonical(self.build))
        self.factory.reset_mock()
        with self.assertRaisesRegex(ValueError, "reference_library"):
            self.run_check([good])
        self.factory.assert_not_called()

    def test_checker_change_and_output_race_reject(self):
        good = self.write()
        with patch.object(artifacts, "checker_hashes", side_effect=[{"a": "before"}, {"a": "after"}]):
            with self.assertRaisesRegex(ValueError, "checker_inputs_changed"):
                self.run_check([good])
        self.assertFalse(self.output.exists())
        def race(*_):
            self.output.write_text("another writer")
            return True
        self.reference.verify.side_effect = race
        with self.assertRaises(FileExistsError):
            self.run_check([good])
        self.assertEqual(self.output.read_text(), "another writer")


if __name__ == "__main__":
    unittest.main()
