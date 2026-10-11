"""Focused failure controls for the conformance harness, with no crypto builds."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import check
import prepare


class HarnessFailures(unittest.TestCase):
    def test_cached_source_tampering_fails_without_network_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.py"
            source.write_bytes(b"altered bytes")
            with patch("prepare.urllib.request.urlopen") as download:
                with self.assertRaisesRegex(ValueError, "source hash mismatch"):
                    prepare.fetch("https://example.invalid/source", source, prepare.digest(b"expected bytes"))
                download.assert_not_called()

    def test_adapter_schema_and_verdict_types_fail_closed(self):
        for response in (
            {"valid": "true", "error": None},
            {"valid": True},
            {"valid": True, "error": None, "unchecked": True},
            [True],
        ):
            with self.subTest(response=response):
                with patch("check.subprocess.run", return_value=subprocess.CompletedProcess([], 0, json.dumps(response))):
                    with self.assertRaises(ValueError):
                        check.native(Path("unused"), {})

    def test_adapter_failure_and_timeout_are_not_negative_verdicts(self):
        for error in (subprocess.CalledProcessError(1, "adapter"), subprocess.TimeoutExpired("adapter", 30)):
            with self.subTest(error=type(error)):
                with patch("check.subprocess.run", side_effect=error):
                    with self.assertRaises(type(error)):
                        check.native(Path("unused"), {})

    def test_independent_disagreement_stops_before_candidate_is_called(self):
        kats = json.loads(prepare.checked(check.ROOT / check.KAT_PATH, check.KAT_SHA256))["cases"]
        with patch("check.Reference") as reference, patch("check.native") as candidate:
            reference.return_value.hash_vectors.return_value = 105
            reference.return_value.verify.return_value = False
            with self.assertRaisesRegex(ValueError, "independent verdict: kat-0"):
                check.check(Path("unused"), Path("unused"), check.ROOT)
            candidate.assert_not_called()
        # Mutations are distinct inputs, not merely duplicate labels.
        cases = check.comparison_cases(kats)
        requests = {json.dumps(case["request"], sort_keys=True) for case in cases}
        self.assertEqual(len(requests), check.MAX_CASES)


if __name__ == "__main__":
    unittest.main()
