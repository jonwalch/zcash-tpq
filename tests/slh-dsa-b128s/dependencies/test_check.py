from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import check


class DependencyGuardTests(unittest.TestCase):
    def test_cargo_tree_versions_features_and_repeated_nodes(self):
        tree = check.parse_tree(
            "zakura-pq-slh-dsa-b-verify v0.1.0 (/product/crates/verify)|\n"
            "blake3 v1.8.5|std\nblake3 v1.8.5|std (*)\n"
        )
        check.validate_tree(tree, required=(check.VERIFY, "blake3"))
        self.assertEqual(len(tree["blake3"]), 1)

    def test_missing_or_unexpected_tree_cannot_pass(self):
        for text in ("", "warning: unexpected output", "blake3"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                check.parse_tree(text)
        with self.assertRaises(ValueError):
            check.validate_tree({"blake3": {("1.8.5", ("std",))}}, required=(check.VERIFY,))

    def test_forbidden_dependencies_are_rejected(self):
        for name in (check.SIGN, check.WALLET, "ml-dsa", "pq-sqisign", "slh-fixture-host", "slh-dsa", "fips204", "fips205"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                check.validate_tree({name: {("0.1.0", ())}}, forbidden=(check.SIGN, check.WALLET))

    def test_hash_pin_and_parallel_feature_are_checked(self):
        for build in (("1.8.4", ("std",)), ("1.8.5", ("std", "rayon"))):
            with self.subTest(build=build), self.assertRaises(ValueError):
                check.validate_tree({"blake3": {build}})

    def test_signer_dependency_on_another_target_is_rejected(self):
        # Real Cargo graph resolution only: local empty libraries, no build or
        # registry dependencies. At least one dependency is inactive on the host.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["node", "sign", "wallet"]\nresolver = "2"\n'
            )
            for path, package in (("node", "zakura-consensus"),
                                  ("sign", check.SIGN), ("wallet", check.WALLET)):
                (root / path / "src").mkdir(parents=True)
                (root / path / "src/lib.rs").write_text("")
                (root / path / "Cargo.toml").write_text(
                    f'[package]\nname = "{package}"\nversion = "0.1.0"\nedition = "2021"\n'
                )
            with (root / "node/Cargo.toml").open("a") as manifest:
                manifest.write(
                    f"[target.'cfg(windows)'.dependencies]\n{check.SIGN} = {{ path = \"../sign\" }}\n"
                    f"[target.'cfg(not(windows))'.dependencies]\n{check.WALLET} = {{ path = \"../wallet\" }}\n"
                )
            subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=root,
                           check=True, capture_output=True, timeout=120)
            with patch.object(check, "ROOT", root):
                tree = check.graph("zakura-consensus", edges="normal,build,dev")
            self.assertIn(check.SIGN, tree)
            self.assertIn(check.WALLET, tree)
            for forbidden in (check.SIGN, check.WALLET):
                with self.subTest(forbidden=forbidden), self.assertRaisesRegex(
                    ValueError, "forbidden packages"
                ):
                    check.validate_tree(tree, forbidden=(forbidden,))


if __name__ == "__main__":
    unittest.main()
