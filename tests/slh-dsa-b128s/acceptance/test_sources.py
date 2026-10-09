"""Offline provenance consistency; pinned research is not a test dependency."""
import hashlib
import json
from pathlib import Path
import unittest

from common import ROOT


class SourceMappingTests(unittest.TestCase):
    def test_each_adapter_and_attributed_target_matches_its_recorded_hash(self):
        record = json.loads((Path(__file__).parent / "sources.json").read_bytes())
        self.assertEqual(record["schema_version"], 1)
        self.assertEqual(record["contract"], "slh-dsa-b-128s-exp-v1")
        source_ids = {row["id"] for row in record["sources"]}
        self.assertEqual(len(source_ids), len(record["sources"]))
        for source in record["sources"]:
            self.assertRegex(source["commit"], r"^[0-9a-f]{40}$")
            self.assertRegex(source["sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(source["license"], "MIT OR Apache-2.0")
        targets = set()
        for row in record["targets"]:
            self.assertNotIn(row["path"], targets)
            targets.add(row["path"])
            self.assertTrue(row["adaptation"])
            self.assertTrue(set(row["sources"]).issubset(source_ids))
            self.assertEqual(hashlib.sha256((ROOT / row["path"]).read_bytes()).hexdigest(), row["sha256"], row["path"])
        adapters = {str(path.relative_to(ROOT)) for path in Path(__file__).parent.glob("*.py")}
        self.assertTrue(adapters.issubset(targets))
        for row in record["reused_product"]:
            self.assertEqual(hashlib.sha256((ROOT / row["path"]).read_bytes()).hexdigest(), row["sha256"], row["path"])


if __name__ == "__main__":
    unittest.main()
