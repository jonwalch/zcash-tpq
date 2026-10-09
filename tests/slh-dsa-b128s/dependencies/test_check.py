import unittest

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


if __name__ == "__main__":
    unittest.main()
