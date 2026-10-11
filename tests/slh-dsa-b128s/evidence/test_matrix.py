# SPDX-License-Identifier: MIT OR Apache-2.0
"""Offline evidence-index validation; no referenced tests or drivers execute."""
import copy
from pathlib import Path, PurePosixPath
import tempfile
import unittest

import matrix


class MatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.matrix = matrix.load()

    def invalid(self, change, reason):
        value = copy.deepcopy(self.matrix)
        change(value)
        with self.assertRaisesRegex(ValueError, reason):
            matrix.validate(value)

    def test_current_index_has_every_required_row_and_subcontrol(self):
        gaps = matrix.validate(self.matrix)
        self.assertEqual(len(self.matrix["rows"]), 12)
        self.assertEqual(sum(len(row["subcontrols"]) for row in self.matrix["rows"]), 63)
        self.assertTrue(any("daemon primitive-entry" in gap for gap in gaps))
        self.assertTrue(any("Valid-proof" in gap for gap in gaps))

    def test_missing_duplicate_and_unknown_rows_fail(self):
        self.invalid(lambda a: a["rows"].pop(), "twelve_rows_required")
        self.invalid(lambda a: a["rows"].__setitem__(1, copy.deepcopy(a["rows"][0])), "row_identity")
        self.invalid(lambda a: a["rows"][0].update(id="unknown"), "row_identity")

    def test_missing_duplicate_subcontrols_and_bad_references_fail(self):
        self.invalid(lambda a: a["rows"][0]["subcontrols"].pop(), "subcontrol_count")
        self.invalid(lambda a: a["rows"][0]["subcontrols"][1].update(id="answers"), "subcontrol_identity")
        self.invalid(lambda a: a["rows"][0]["subcontrols"][0].update(evidence=["absent"]), "evidence_references")
        self.invalid(lambda a: a["rows"][0]["subcontrols"][0].update(evidence=["pure", "pure"]), "evidence_references")

    def test_stale_hash_and_missing_anchor_fail(self):
        self.invalid(lambda a: a["references"]["pure"].update(sha256="00" * 32), "source_hash_changed")
        self.invalid(lambda a: a["references"]["pure"].update(anchor="absent_test_function_zzz"), "source_anchor_missing")

    def test_unsafe_paths_and_wrong_kinds_fail(self):
        for path in ("../outside", "/absolute", "crates/../outside", "crates//a", "crates\\a"):
            with self.subTest(path=path):
                self.invalid(lambda a: a["references"]["pure"].update(path=path), "relative_source_path")
        self.invalid(lambda a: a["references"]["pure"].update(kind="live_passed"), "reference_kind")

    def only_reference(self, **changes):
        value = copy.deepcopy(self.matrix)
        value["references"] = {"pure": dict(value["references"]["pure"], **changes)}
        return value

    def test_symlinked_sources_fail_inside_or_outside_root(self):
        value = self.only_reference()
        top = PurePosixPath(value["references"]["pure"]["path"]).parts[0]
        with tempfile.TemporaryDirectory() as directory:
            escaped, inside = Path(directory) / "escaped", Path(directory) / "inside"
            escaped.mkdir()
            (escaped / top).symlink_to(matrix.ROOT / top, target_is_directory=True)
            # A link that stays inside the root isolates the symlinked-component check.
            (inside / "store" / top).mkdir(parents=True)
            (inside / top).symlink_to(inside / "store" / top, target_is_directory=True)
            for root in (escaped, inside):
                with self.subTest(root=root.name), self.assertRaisesRegex(ValueError, "^regular_source_path$"):
                    matrix.validate(copy.deepcopy(value), root=root)

    def test_source_must_be_bounded_regular_file(self):
        with self.assertRaisesRegex(ValueError, "^bounded_source_file$"):
            matrix.validate(self.only_reference(path="crates"))
        with tempfile.TemporaryDirectory() as directory:
            with (Path(directory) / "large.rs").open("wb") as stream:
                stream.truncate(8 * 1024 * 1024 + 1)
            with self.assertRaisesRegex(ValueError, "^bounded_source_file$"):
                matrix.validate(self.only_reference(path="large.rs"), root=Path(directory))

    def test_scope_and_exact_types_cannot_upgrade_to_acceptance(self):
        self.invalid(lambda a: a.update(functional_acceptance_complete=True), "no_acceptance_claim")
        self.invalid(lambda a: a.update(functional_acceptance_complete=0), "no_acceptance_claim")
        self.invalid(lambda a: a.update(human_execution="passed"), "no_acceptance_claim")
        self.invalid(lambda a: a.update(schema_version=True), "schema_version")
        self.invalid(lambda a: a.update(overall_status="complete"), "exact_fields")
        self.invalid(lambda a: a["rows"][0].update(complete=True), "exact_fields")
        self.invalid(lambda a: a["rows"][0]["subcontrols"][0].update(passed=True), "exact_fields")

    def test_duplicate_json_keys_and_bounded_regular_matrix_required(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "index.json"
            path.write_text('{"schema_version":1,"schema_version":1}')
            with self.assertRaisesRegex(ValueError, "duplicate_key"):
                matrix.load(path)
            path.write_bytes(b" " * (256 * 1024 + 1))
            with self.assertRaisesRegex(ValueError, "bounded_matrix_file"):
                matrix.load(path)
            small = Path(directory) / "small.json"
            small.write_text("{}")
            self.assertEqual(matrix.load(small), {})
            link = Path(directory) / "link.json"
            link.symlink_to(small)
            with self.assertRaisesRegex(ValueError, "bounded_matrix_file"):
                matrix.load(link)


if __name__ == "__main__":
    unittest.main()
