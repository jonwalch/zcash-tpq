"""Offline/mock tests only. Never starts a node, CLI terminal, signer or build."""
import copy
from decimal import Decimal
import hashlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import build
import common
import node_live
import nodes
import wallet_live


class BuildReceiptTests(unittest.TestCase):
    def record(self, kind="node-slh"):
        argv, _, features = build.command(kind, Path("/private/target"))
        return {"schema_version": 1, "contract": common.CONTRACT, "kind": kind, "complete": True,
                "source": {"pin": "exact"}, "command": argv, "features": features,
                "binary_sha256": "11" * 32, "identity": common.identity_expected(True, True),
                "rustc": "pinned compiler", "cargo": "pinned cargo", "environment": {}}

    def validate(self, record):
        with patch.object(common, "source_state", return_value={"pin": "exact"}), \
                patch.object(common, "sha256", return_value="11" * 32):
            return common.validate_build(record, Path("node"), "node-slh", runtime_required=True)

    def test_exact_build_recipe_and_identity(self):
        self.validate(self.record())
        for kind in ("node-default", "node-slh", "wallet-default", "wallet-slh", "host", "signer"):
            argv, binary, features = build.command(kind, Path("/new/target"))
            self.assertIn("--locked", argv)
            self.assertIn("--no-default-features", argv)
            self.assertNotIn("experimental-sqisign", features)
            self.assertNotIn("test-observer", features)
            self.assertIn(binary, argv)
        self.assertIn("--manifest-path", build.command("signer", Path("target"))[0])

    def test_receipts_refuse_missing_stale_extra_or_modified_inputs(self):
        controls = [dict(complete=False), dict(source={"pin": "old"}), dict(binary_sha256="22" * 32),
                    dict(features=[common.FEATURE]), dict(schema_version=True), dict(extra="not allowed")]
        for change in controls:
            with self.subTest(change=change):
                record = self.record()
                record.update(change)
                with self.assertRaises(common.AcceptanceError):
                    self.validate(record)
        record = self.record()
        del record["source"]
        with self.assertRaises(common.AcceptanceError):
            self.validate(record)

    def test_build_command_cannot_smuggle_features_or_other_packages(self):
        for extra in (["--features", "test-observer"], ["--manifest-path", "elsewhere/Cargo.toml"]):
            record = self.record()
            record["command"] += extra
            with self.assertRaises(common.AcceptanceError):
                self.validate(record)

    def test_runtime_readiness_and_boolean_identity_are_exact(self):
        for change in ({"runtime_supported": False}, {"verifier_compiled": 1}, {"schema_version": True},
                       {"backend": "other"}, {"test_observer": False}, {"algorithm_revision": "00" * 20}):
            with self.subTest(change=change):
                record = self.record()
                record["identity"].update(change)
                with self.assertRaises(common.AcceptanceError):
                    self.validate(record)
        common.validate_identity(common.identity_expected(False, False), False)
        with self.assertRaises(common.AcceptanceError):
            common.validate_identity(common.identity_expected(False, True), False)

    def test_write_json_is_exact_wallet_canonical_encoding(self):
        oracle = wallet_live.reference()
        corpus = common.read_json(common.ROOT / "tests/slh-dsa-b128s/wallet/formats/vectors.json")
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "profile.json"
            profile = wallet_live.profile("11" * 32)
            common.write_json(target, profile)
            self.assertEqual(target.read_bytes(), common.canonical(profile))
            self.assertEqual(oracle.canonical(target.read_bytes(), 4096), profile)
            with self.assertRaises(ValueError):
                oracle.canonical(target.read_bytes() + b"\n", 4096)
            with self.assertRaises(FileExistsError):
                common.write_json(target, profile)

    def test_symlink_artifacts_and_duplicate_keys_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            value = directory / "value"
            value.write_bytes(b'{"x":1,"x":2}')
            with self.assertRaises(Exception):
                common.read_json(value)
            link = directory / "link"
            link.symlink_to(value)
            with self.assertRaises(common.AcceptanceError):
                common.sha256(link)
            with self.assertRaises(common.AcceptanceError):
                common.read_json(link)

    def test_failed_attempt_is_retained_without_claiming_completion(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = SimpleNamespace(threshold=1, participants=1, inputs=1, version=5, classical="single",
                artifacts=Path(temporary) / "fresh", node_build=Path("missing"), node=Path("missing"))
            with patch.object(wallet_live, "read_json", side_effect=common.AcceptanceError("missing_receipt")):
                with self.assertRaises(common.AcceptanceError):
                    wallet_live.main(args)
            record = common.read_json(args.artifacts / "execution.json")
            self.assertIs(record["complete"], False)
            self.assertEqual(record["failure"], "missing_receipt")

    def test_toolchain_probes_and_build_share_the_repository_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = SimpleNamespace(kind="host", artifacts=Path(temporary) / "build")
            def cargo(argv, **kwargs):
                target = Path(argv[argv.index("--target-dir") + 1]) / "release"
                target.mkdir(parents=True)
                (target / "slh-dsa-b128s-fixture-host").write_bytes(b"mock executable")
            with patch.object(build, "source_state", return_value={"pin": "same"}), \
                    patch.object(build.subprocess, "check_output", return_value="mock toolchain") as probe, \
                    patch.object(build.subprocess, "run", side_effect=cargo) as compile_process, \
                    patch("sys.stdout", io.StringIO()):
                build.build(args)
            self.assertTrue(all(call.kwargs["cwd"] == common.ROOT for call in probe.call_args_list))
            self.assertEqual(compile_process.call_args.kwargs["cwd"], common.ROOT)


class FundingNode:
    def __init__(self):
        self.height, self.best = 110, "aa" * 32
        self.script = "a914" + "11" * 20 + "87"
        self.output = {"coinbase": True, "confirmations": 110,
                       "scriptPubKey": {"hex": self.script}, "value": Decimal("1.00000000")}
    def tip(self):
        return self.height, self.best
    def rpc(self, method, *args):
        if method == "getblockhash":
            return "bb" * 32
        if method == "getblock":
            return {"tx": ["cc" * 32]}
        if method == "getrawtransaction":
            return {"hex": "0102", "vin": [{"coinbase": "00"}],
                    "vout": [{"n": 0, "scriptPubKey": {"hex": self.script}}]}
        if method == "gettxout":
            return self.output
        raise AssertionError(method)


class FundingAndRpcTests(unittest.TestCase):
    def test_mature_actual_classical_coinbase_is_bound_to_both_nodes(self):
        first, second = FundingNode(), FundingNode()
        result = nodes.authenticate_coinbase([first, second], 1, first.script)
        self.assertEqual(result["txid"], "cc" * 32)
        self.assertEqual(result["parent_hex"], "0102")
        self.assertEqual(result["tip"], {"height": 110, "hash": "aa" * 32})

    def test_immature_spent_foreign_and_forked_outputs_reject(self):
        for mutation in (lambda node: setattr(node, "height", 99),
                         lambda node: setattr(node, "best", "bb" * 32),
                         lambda node: setattr(node, "output", None),
                         lambda node: node.output.update(confirmations=99),
                         lambda node: node.output.update(coinbase=False),
                         lambda node: node.output["scriptPubKey"].update(hex="5320" + "11" * 32 + "c0")):
            first, second = FundingNode(), FundingNode()
            mutation(second)
            with self.assertRaises(common.AcceptanceError):
                nodes.authenticate_coinbase([first, second], 1, first.script)

    def test_rpc_socket_addresses_match_cli_boundary(self):
        for valid in ("127.0.0.1:8232", "[::1]:8232"):
            self.assertEqual(common.endpoint(valid), valid)
        for invalid in ("http://127.0.0.1:8232", "localhost:8232", "127.0.0.1:0", "192.0.2.1:1",
                        "127.0.0.1:65536", "::1:8232", "127.0.0.1:-1"):
            with self.assertRaises(common.AcceptanceError):
                common.endpoint(invalid)

    def test_amounts_are_decimal_and_exact(self):
        self.assertEqual(common.zat(Decimal("0.00002403")), 2403)
        for invalid in (Decimal("0.000000001"), Decimal("NaN"), -1, Decimal("21000000.00000001")):
            with self.assertRaises(common.AcceptanceError):
                common.zat(invalid)

    def test_config_and_namespace_use_slh_only_explicit_limits(self):
        import tomllib
        config = tomllib.loads(nodes.configuration("127.0.0.1:1", 2, 3, Path("/private/state"), "public-address"))
        parameters = config["network"]["testnet_parameters"]
        self.assertEqual(parameters["experimental_slh_dsa_b128s_activation_height"], 110)
        self.assertEqual(parameters["experimental_slh_dsa_b128s_max_checks_per_transaction"], 16)
        self.assertEqual(parameters["experimental_slh_dsa_b128s_max_checks_per_block"], 64)
        self.assertEqual(config["network"]["initial_testnet_peers"], ["127.0.0.1:3"])
        self.assertFalse(config["state"]["ephemeral"])
        self.assertEqual(config["mining"]["miner_address"], "public-address")

    def test_rpc_rejection_requires_the_specific_diagnostic(self):
        node = common.Node("127.0.0.1:1")
        with patch.object(node, "response", return_value={"error": {"code": -26, "message": "limit of 16 SLH checks"}}):
            self.assertEqual(node.reject("sendrawtransaction", "limit of 16", "aa")["reason_contains"], "limit of 16")
            with self.assertRaises(common.AcceptanceError):
                node.reject("sendrawtransaction", "signature", "aa")


class WalletFlowTests(unittest.TestCase):
    def test_complete_mocked_enrollment_payment_recovery_and_following_payment(self):
        from fake_cli import FakeCli
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            node = SimpleNamespace(address="127.0.0.1:8232", tip=Mock(return_value=(110, "aa" * 32)))
            profile = common.write_json(directory / "profile.json", wallet_live.profile("00" * 32))
            demo = wallet_live.Demo(Path("mock-cli"), profile, directory, [node, node], b"mock-password")
            fake = FakeCli([node, node])
            demo.cli = fake
            # Actual driver methods run; every CLI/process boundary is replaced.
            group = demo.group(directory / "owners", 2, 3)
            self.assertTrue(all(signer.manifest["revision"] == 4 for signer in group))
            self.assertEqual(fake.calls.count("enroll"), 12)
            self.assertEqual(fake.calls.count("enroll-prepare"), 12)
            first_receiver = demo.cli("receive", group[0].store)
            self.assertNotEqual(demo.cli("receive", group[0].store), first_receiver)
            demo.cli("receive", group[0].store, success=False)
            demo.replenish_receive(group)
            self.assertNotEqual(demo.cli("receive", group[0].store), first_receiver)
            demo.cli("receive", group[0].store, success=False)
            recipient = demo.oracle.receiver(bytes.fromhex(group[0].manifest["entries"][1]["policy_hex"]))
            first = demo.payment(group, recipient, 5, 1, directory / "first")
            self.assertEqual(first["review"]["checks"], 2)
            restored, receipts = demo.recover(group, first, directory / "recovery")
            self.assertEqual(len(restored), 2)  # third independent root actually removed
            self.assertEqual(len(receipts), 2)
            self.assertTrue(all(not signer.backup.exists() for signer in group))
            node.tip.return_value = (110, "bb" * 32)
            refreshed = demo.refresh(restored, first, directory / "refresh")
            self.assertNotEqual(refreshed["old_id"], refreshed["new_id"])
            for signer in restored:
                fake.watches[signer.store]["balance"] = 500_000
            following = demo.payment(restored, recipient, 6, 1, directory / "following", all_value=500_000)
            self.assertEqual(following["review"]["change_value"], 0)
            self.assertEqual(following["review"]["checks"], 2)
            self.assertEqual(fake.calls.count("snapshot-restore"), 3)

    def test_budget_controls_refuse_unrelated_cli_failures(self):
        from fake_cli import FakeCli
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            node = SimpleNamespace(address="127.0.0.1:8232", tip=lambda: (110, "aa" * 32))
            demo = wallet_live.Demo(Path("mock-cli"), directory / "profile", directory, [node, node], b"mock")
            demo.cli = FakeCli([node, node])
            group = demo.group(directory / "owners", 2, 3)
            demo.cli = Mock(return_value=b"RPC unavailable")
            with self.assertRaisesRegex(common.AcceptanceError, "unexpected_budget_rejection"):
                demo.payment(group, "recipient", 5, 9, directory / "bad", reject=True)
            demo.cli.return_value = b"insufficient eligible funds within the payment limits"
            result = demo.payment(group, "recipient", 5, 9, directory / "good", reject=True)
            self.assertEqual(result["rejected_checks"], 18)

    def partial(self, directory, index=0, slot=14):
        public = "11" * 32
        owner = "22" * 16
        commitments = [b"\0" * 32] * 14 + [wallet_live.key_commitment(bytes.fromhex(public))]
        entry = {"policy_hex": (bytes([1, 247, 1, 15]) + b"".join(commitments)).hex(),
                 "origins": [{"wallet_id": "33" * 16}] * 14 + [{"wallet_id": owner}]}
        partial = {"input_index": index, "signer_index": slot, "format": wallet_live.PARTIAL_FORMAT,
                   "proposal_id": "44" * 32, "signature_hex": "55" * 7856, "public_key_hex": public}
        path = common.write_json(directory / "partial.json", partial)
        return path, {"inputs": [{"entry": entry}]}, partial, owner

    def test_index14_large_partial_preserves_owner_and_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, proposal, partial, owner = self.partial(Path(temporary))
            wallet_live.partials_match([path], proposal, partial["proposal_id"], owner)
            self.assertGreater(path.stat().st_size, 15_000)

    def test_foreign_duplicate_short_or_alternate_partial_refuses(self):
        for change in ({"signer_index": 15}, {"input_index": 1}, {"format": "other-suite"},
                       {"signature_hex": "00" * 7855}, {"public_key_hex": "00" * 32}):
            with tempfile.TemporaryDirectory() as temporary:
                path, proposal, partial, owner = self.partial(Path(temporary))
                partial.update(change)
                common.write_json(path, partial, fresh=False)
                with self.assertRaises(common.AcceptanceError):
                    wallet_live.partials_match([path], proposal, partial["proposal_id"], owner)
        with tempfile.TemporaryDirectory() as temporary:
            path, proposal, partial, owner = self.partial(Path(temporary))
            with self.assertRaises(common.AcceptanceError):
                wallet_live.partials_match([path, path], proposal, partial["proposal_id"], owner)

    def test_structural_capacity_uses_unchanged_independent_oracle(self):
        oracle = wallet_live.reference()
        self.assertEqual(oracle.transaction_bytes(5, [(15, 15)]), 119040)
        self.assertEqual(oracle.transaction_bytes(6, [(15, 15)]), 119041)
        self.assertEqual(oracle.check_payment_capacity(5, [(2, 3)] * 8)[1], 16)
        with self.assertRaises(ValueError):
            oracle.check_payment_capacity(5, [(2, 3)] * 9)
        with self.assertRaises(ValueError):
            oracle.check_payment_capacity(5, [(15, 15)] * 2)

    def test_human_drivers_require_explicit_run_and_real_artifact_paths(self):
        for parser in (wallet_live.parser, node_live.parser, build.parser):
            with patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit):
                parser().parse_args([])

    def test_public_output_parser_does_not_return_terminal_prefix(self):
        self.assertEqual(common.object_output(b'Backup password: \r\n{"suite":247}\r\n'), {"suite": 247})
        with self.assertRaises(common.AcceptanceError):
            common.object_output(b"no JSON here")


if __name__ == "__main__":
    unittest.main()
