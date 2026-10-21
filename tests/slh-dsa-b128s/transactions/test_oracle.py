# SPDX-License-Identifier: MIT OR Apache-2.0
"""Cheap tests of independent schemas/codecs/digests; no crypto acceptance claim."""

import copy
import unittest
from unittest.mock import patch

import check
import mutations
import oracle
import wire

CORPUS = check.HERE.parent / "fixtures/data"


def synthetic_artifacts():
    """Public zero signatures only: structural test data, never accepted corpus."""
    keys = [bytes([index]) * 32 for index in range(15)]
    result = {}
    for case in sorted(check.NAMES):
        version, shape = int(case[1]), case[3:]
        shapes = {"16checks": [(15, 15), (1, 1)], "17checks": [(15, 15), (2, 3)], "1of15-index14": [(1, 15)]}
        policies = shapes[shape] if shape in shapes else [tuple(int(value) for value in shape.split("of"))]
        inputs, items = [], []
        for index, (m, n) in enumerate(policies):
            selected = sorted((oracle.key_commitment(key), key) for key in keys[:n])
            descriptor = bytes([1, 0xf7, m, n]) + b"".join(commitment for commitment, _ in selected)
            indices = [14] if shape == "1of15-index14" else list(range(m))
            records = [{"signer_index": position, "public_key_hex": selected[position][1].hex(), "signature_hex": "00" * 7856} for position in indices]
            display = oracle.sha256(b"Zakura/SLH-public-corpus/outpoint/v1\0" + case.encode() + b"\0" + wire.le32(index))
            inputs.append({"outpoint": bytes.fromhex(display)[::-1] + wire.le32(index+1), "script": oracle.encode_authorization(descriptor, records), "sequence": 0xfffffffe})
            items.append({"input_index": index, "outpoint": {}, "sequence": 0xfffffffe,
                          "spent_output": {"value_zat": 100000, "script_hex": oracle.lock_script(descriptor).hex()},
                          "descriptor_hex": descriptor.hex(), "sighash_all_digest_hex": "", "message_hex": "", "context_hex": "", "records": records})
        producer = {name: "00" * 32 for name in oracle.PRODUCER.split()}
        producer.update(zakura_revision="9b175e9d3d46a6aa4cfb5552517c3d828852ecbc", algorithm_revision="b392fe82d2d9770142477a576a758a233888bc0a", blake3_version="1.8.5")
        a = {"schema_version": 1, "contract": oracle.CONTRACT, "public_fixture": True, "case_id": case,
             "context_provenance": "synthetic-public-fixture", "producer": producer, "network": "Regtest", "transaction_version": version,
             "consensus_branch_id": oracle.NU7, "transaction_hex": "", "transaction_sha256": "", "inputs": items,
             "outputs": [], "expected": oracle.observation(count=sum(m for m, _ in policies)), "artifact_sha256": ""}
        tx = {"header": wire.VERSIONS[version][0], "version": version, "branch": oracle.NU7, "lock_time": 5, "expiry": 140,
              "inputs": inputs, "outputs": [{"value": value, "script": bytes.fromhex(items[0]["spent_output"]["script_hex"])} for value in (20000, 30000)]}
        result[case] = mutations.refresh(a, tx)
    return result


def membership(artifacts):
    """Structural stand-in for crypto: accept only unchanged (key, signature, message) triples."""
    valid = {(record["public_key_hex"], record["signature_hex"], item["message_hex"])
             for artifact in artifacts.values() for item in artifact["inputs"] for record in item["records"]}
    calls = []

    def verify(public_key, signature, message, context):
        calls.append((public_key, signature, message, context))
        return context == b"" and (public_key.hex(), signature.hex(), message.hex()) in valid
    return verify, calls


def committed_corpus():
    return {path.stem: oracle.strict_json(path.read_bytes()) for path in sorted(CORPUS.glob("*.json"))}


class OracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifacts = synthetic_artifacts()

    def test_only_recorded_upstream_pins_are_accepted(self):
        artifact = copy.deepcopy(self.artifacts["v5-1of1"])
        for revision in ("9b175e9d3d46a6aa4cfb5552517c3d828852ecbc",
                         "24a17b3f0e7d88513688d607054f018ab6f15af2",
                         "e33dc43089acca2fe2c6516927932f2b7618b8bc",
                         "3f36c35031126a8f8cd52865ef0be9e5dc494b8d"):
            artifact["producer"]["zakura_revision"] = revision
            oracle.validate_schema(artifact)
        artifact["producer"]["zakura_revision"] = "00" * 20
        with self.assertRaisesRegex(oracle.InterfaceFailure, "schema/producer_pin"):
            oracle.validate_schema(artifact)

    def test_all_120_policy_shapes_roundtrip_and_exact_bounds(self):
        for n in range(1, 16):
            for m in range(1, n+1):
                keys = sorted((oracle.key_commitment(bytes([i])*32), bytes([i])*32) for i in range(n))
                descriptor = bytes([1, 0xf7, m, n]) + b"".join(item[0] for item in keys)
                records = [{"signer_index": i, "public_key_hex": keys[i][1].hex(), "signature_hex": "00"*7856} for i in range(m)]
                encoded = oracle.encode_authorization(descriptor, records)
                self.assertEqual(oracle.decode_authorization(encoded), (descriptor, records))
                self.assertEqual(len(encoded), m*7893 + len(oracle.push(descriptor)))
        self.assertEqual(len(encoded), 118882)
        self.assertEqual(wire.compact(len(encoded)), b"\xfe\x62\xd0\x01\x00")
        with self.assertRaisesRegex(oracle.NativeFailure, "authorization_size"):
            oracle.decode_authorization(bytes(131073))

    def test_recipe_coverage_and_structural_only_positive_pipeline(self):
        count = 0
        for artifact in self.artifacts.values():
            _, observed = oracle.evaluate(oracle.canonical(artifact), lambda *args: True)
            self.assertEqual(observed, artifact["expected"])
            check.corpus_contract(artifact)
            count += observed["signature_checks"]
        self.assertEqual(count, 146)
        self.assertEqual(len(bytes.fromhex(self.artifacts["v5-15of15"]["transaction_hex"])), 119040)
        self.assertEqual(len(bytes.fromhex(self.artifacts["v6-15of15"]["transaction_hex"])), 119041)

    def test_committed_corpus_digests_messages_and_codecs_match(self):
        # The host produced these digests, messages and authorizations natively.
        paths = sorted(CORPUS.glob("*.json"))
        self.assertEqual({path.stem for path in paths}, check.NAMES)
        count = 0
        for path in paths:
            with self.subTest(case=path.stem):
                # Crypto acceptance is the reference gate's claim, not this test's.
                artifact, observed = oracle.evaluate(path.read_bytes(), lambda *args: True)
                check.corpus_contract(artifact)
                self.assertEqual(observed, artifact["expected"])
                count += observed["signature_checks"]
        self.assertEqual(count, 146)

    def test_typed_mutations_precede_crypto_where_required(self):
        verify, _ = membership(self.artifacts)
        for artifact in self.artifacts.values():
            self.assertEqual(oracle.evaluate(oracle.canonical(artifact), verify)[1], artifact["expected"])
        cases = mutations.controls(self.artifacts)
        self.assertEqual(len(cases), 60)
        for case in cases:
            with self.subTest(case=case["name"]):
                # A mutation that leaves the signed triple unchanged is accepted here.
                verify, calls = membership(self.artifacts)
                if case["interface_stage"] is not None:
                    with self.assertRaises(oracle.InterfaceFailure) as caught:
                        oracle.evaluate(case["raw"], verify)
                    self.assertEqual(caught.exception.stage, case["interface_stage"])
                    self.assertEqual(calls, [])
                else:
                    _, observed = oracle.evaluate(case["raw"], verify)
                    self.assertEqual(observed, case["outcome"])
                    self.assertEqual(bool(calls), observed["native_rejection"]["stage"] == "signature")

    def test_committed_mutations_match_retained_review_receipt(self):
        # Pin request bytes and the oracle's exact stage/reason to the hash-pinned receipt.
        raw = check.REPLAY_RECEIPT.read_bytes()
        self.assertEqual(oracle.sha256(raw), check.REPLAY_RECEIPT_SHA256)
        retained = oracle.strict_json(raw)["mutations"]
        corpus = committed_corpus()
        cases = mutations.controls(corpus)
        self.assertEqual([case["name"] for case in cases], [row["name"] for row in retained])
        for case, row in zip(cases, retained):
            with self.subTest(case=case["name"]):
                self.assertEqual(oracle.sha256(case["raw"]), row["request_sha256"])
                verify, calls = membership(corpus)
                try:
                    independent = {"observed": oracle.evaluate(case["raw"], verify)[1]}
                except oracle.InterfaceFailure as failure:
                    independent = {"error": {"stage": failure.stage, "reason": failure.reason}}
                    self.assertEqual(calls, [])
                self.assertEqual(independent, row["independent"])

    def test_required_nullable_fields_and_outcome_consistency(self):
        outcomes = [oracle.observation(count=1), oracle.observation("context", "consensus_branch"),
                    oracle.observation("authorization", "encoding", 0), oracle.observation("signature", "signature", 0, 1)]
        for expected in outcomes:
            for owner_name, field in (("expected", "native_rejection"), ("expected", "signature_checks"), ("functional_profile", "stage")):
                a = copy.deepcopy(self.artifacts["v5-1of1"])
                a["expected"] = copy.deepcopy(expected)
                owner = a["expected"] if owner_name == "expected" else a["expected"][owner_name]
                del owner[field]
                with self.subTest(expected=expected, field=field), self.assertRaises(oracle.InterfaceFailure):
                    oracle.validate_schema(a)
        invalid = [oracle.observation(count=1)]
        invalid[0]["signature_checks"] = None
        value = oracle.observation("context", "consensus_branch")
        value["native_rejection"]["input_index"] = 0
        invalid.append(value)
        value = oracle.observation("authorization", "encoding", 1)
        invalid.append(value)
        value = oracle.observation("signature", "signature", 0, 1)
        value["signature_checks"] = None
        invalid.append(value)
        for bad_reason in ([], {}, 1, True):
            value = oracle.observation("context", "consensus_branch")
            value["native_rejection"]["reason"] = bad_reason
            invalid.append(value)
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(oracle.InterfaceFailure):
                oracle.expected_schema(value, 1)

    def test_canonical_ascii_escapes_duplicate_keys_numeric_and_depth(self):
        value = {"z": "\x7f/\b\t\n\f\r\"\\", "a": [True, None, 0, 2**64-1]}
        self.assertEqual(oracle.strict_json(oracle.canonical(value)), value)
        self.assertIn(b"\\u007f", oracle.canonical(value))
        for raw, reason in ((b'{"a":1,"a":2}', "duplicate_key"), (b'{"a":{"z":1,"z":2}}', "duplicate_key"),
                            (b'-0', "integer"), (b'0.0', "number"), (b'1e0', "number"), (b'NaN', "number"),
                            (b'18446744073709551616', "integer"), (b'"\\ud800"', "ascii"),
                            (b'['*17+b'0'+b']'*17, "nesting"), ('{"a":1}'.encode("utf-16"), "json"),
                            (b'\xef\xbb\xbf{"a":1}', "json")):
            with self.subTest(raw=raw), self.assertRaises(oracle.InterfaceFailure) as caught:
                oracle.strict_json(raw)
            self.assertEqual((caught.exception.stage, caught.exception.reason), ("schema", reason))
        # Pad a valid document so only the size bound can reject it.
        with self.assertRaises(oracle.InterfaceFailure) as caught:
            oracle.strict_json(b"[0]".ljust(oracle.MAX_JSON + 1))
        self.assertEqual((caught.exception.stage, caught.exception.reason), ("transport", "size"))
        with patch.object(oracle, "MAX_JSON", 100):
            self.assertEqual(oracle.strict_json(b"[0]".ljust(100)), [0])
            with self.assertRaises(oracle.InterfaceFailure) as caught:
                oracle.strict_json(b"[0]".ljust(101))
            self.assertEqual((caught.exception.stage, caught.exception.reason), ("transport", "size"))

    def test_digest_binds_order_context_and_outputs_but_excludes_scriptsig(self):
        a = self.artifacts["v6-16checks"]
        tx = wire.parse_transaction(bytes.fromhex(a["transaction_hex"]))
        previous = [{"value": item["spent_output"]["value_zat"], "script": bytes.fromhex(item["spent_output"]["script_hex"])} for item in a["inputs"]]
        first = wire.input_digest(tx, previous, 0)
        self.assertNotEqual(first, wire.input_digest(tx, previous, 1))
        changed = copy.deepcopy(tx)
        changed["inputs"][0]["script"] = b"garbage"
        self.assertEqual(first, wire.input_digest(changed, previous, 0))
        changed["outputs"][0]["value"] += 1
        self.assertNotEqual(first, wire.input_digest(changed, previous, 0))
        self.assertNotEqual(first, wire.input_digest(tx, list(reversed(previous)), 0))
        previous[1]["value"] += 1
        self.assertNotEqual(first, wire.input_digest(tx, previous, 0))

    def test_later_structural_failure_precedes_earlier_bad_signature(self):
        a = copy.deepcopy(self.artifacts["v6-16checks"])
        tx = wire.parse_transaction(bytes.fromhex(a["transaction_hex"]))
        tx["inputs"][1]["script"] += b"\0"
        a = mutations.refresh(a, tx)
        calls = []
        _, observed = oracle.evaluate(oracle.canonical(a), lambda *args: calls.append(args))
        self.assertEqual(observed, oracle.observation("authorization", "encoding", 1))
        self.assertEqual(calls, [])

    def test_claimed_expected_values_never_control_observed_result(self):
        a = copy.deepcopy(self.artifacts["v5-1of1"])
        a["expected"] = oracle.observation("signature", "signature", 0, 1)
        a["artifact_sha256"] = oracle.artifact_hash(a)
        _, observed = oracle.evaluate(oracle.canonical(a), lambda *args: True)
        self.assertEqual(observed, oracle.observation(count=1))

    def test_decodable_metadata_checked_despite_binding_failure(self):
        a = copy.deepcopy(self.artifacts["v5-1of1"])
        tx = wire.parse_transaction(bytes.fromhex(a["transaction_hex"]))
        script = bytearray.fromhex(a["inputs"][0]["spent_output"]["script_hex"])
        script[2] ^= 1
        a["inputs"][0]["spent_output"]["script_hex"] = script.hex()
        a = mutations.refresh(a, tx)
        _, observed = oracle.evaluate(oracle.canonical(a), lambda *args: self.fail("unexpected crypto"))
        self.assertEqual(observed, oracle.observation("authorization", "output_commitment", 0))
        a["inputs"][0]["descriptor_hex"] = "00"
        a["artifact_sha256"] = oracle.artifact_hash(a)
        with self.assertRaises(oracle.InterfaceFailure) as caught:
            oracle.evaluate(oracle.canonical(a), lambda *args: self.fail("unexpected crypto"))
        self.assertEqual(caught.exception.stage, "correspondence")

    def test_context_failure_still_checks_every_decodable_authorization(self):
        for version in (5, 6):
            a = copy.deepcopy(self.artifacts[f"v{version}-16checks"])
            tx = wire.parse_transaction(bytes.fromhex(a["transaction_hex"]))
            tx["branch"] = 0x37a5165b
            # Context rejection precedes an undecodable first authorization,
            # while the second input's raw fields remain available to compare.
            tx["inputs"][0]["script"] += b"\0"
            mutations.refresh(a, tx)
            for item in a["inputs"]:
                item["sighash_all_digest_hex"] = "00" * 32
                item["message_hex"] = "00" * 101
            a["artifact_sha256"] = oracle.artifact_hash(a)
            _, observed = oracle.evaluate(oracle.canonical(a), lambda *args: self.fail("unexpected crypto"))
            self.assertEqual(observed, oracle.observation("context", "consensus_branch"))
            for field, value in (("descriptor_hex", "00"), ("records", [])):
                changed = copy.deepcopy(a)
                changed["inputs"][1][field] = value
                changed["artifact_sha256"] = oracle.artifact_hash(changed)
                with self.subTest(version=version, field=field), self.assertRaises(oracle.InterfaceFailure) as caught:
                    oracle.evaluate(oracle.canonical(changed), lambda *args: self.fail("unexpected crypto"))
                self.assertEqual((caught.exception.stage, caught.exception.reason), ("correspondence", "authorization"))

    def test_wire_rejects_unknown_and_version_ineligible_branches(self):
        branches = {
            5: (0xc2d6d0b4, 0xc8e71055, 0x4dec4df0, 0x5437f330, 0x37a5165b, oracle.NU7),
            6: (0x37a5165b, oracle.NU7),
        }
        for version in (5, 6):
            artifact = self.artifacts[f"v{version}-1of1"]
            original = wire.parse_transaction(bytes.fromhex(artifact["transaction_hex"]))
            for branch in branches[version]:
                tx = copy.deepcopy(original)
                tx["branch"] = branch
                with self.subTest(version=version, valid_branch=branch):
                    self.assertEqual(wire.parse_transaction(wire.serialize(tx))["branch"], branch)
                    if branch != oracle.NU7:
                        a = mutations.refresh(copy.deepcopy(artifact), tx)
                        _, observed = oracle.evaluate(oracle.canonical(a), lambda *args: self.fail("unexpected crypto"))
                        self.assertEqual(observed, oracle.observation("context", "consensus_branch"))
            invalid = [0, 0xffffffff, 0xfffffffd, 0xe9ff75a6]
            if version == 6:
                invalid += [0xc2d6d0b4, 0xc8e71055, 0x4dec4df0, 0x5437f330]
            for branch in invalid:
                tx = copy.deepcopy(original)
                tx["branch"] = branch
                a = mutations.refresh(copy.deepcopy(artifact), tx)
                with self.subTest(version=version, invalid_branch=branch), self.assertRaises(oracle.InterfaceFailure) as caught:
                    oracle.evaluate(oracle.canonical(a), lambda *args: self.fail("unexpected crypto"))
                self.assertEqual((caught.exception.stage, caught.exception.reason), ("correspondence", "transaction_decode"))

    def test_wire_rejects_null_txid_with_every_index_class(self):
        for version in (5, 6):
            for index in (0, 1, 0xffffffff):
                a = copy.deepcopy(self.artifacts[f"v{version}-1of1"])
                tx = wire.parse_transaction(bytes.fromhex(a["transaction_hex"]))
                tx["inputs"][0]["outpoint"] = bytes(32) + wire.le32(index)
                mutations.refresh(a, tx)
                with self.subTest(version=version, index=index), self.assertRaises(oracle.InterfaceFailure) as caught:
                    oracle.evaluate(oracle.canonical(a), lambda *args: self.fail("unexpected crypto"))
                self.assertEqual((caught.exception.stage, caught.exception.reason), ("correspondence", "transaction_decode"))

    def test_metadata_indices_use_u32_schema_then_wire_correspondence(self):
        for version in (5, 6):
            for owner, field, first_invalid_position in (("inputs", "input_index", 32), ("outputs", "output_index", 64)):
                for value in (first_invalid_position, 0xffffffff, 0x100000000):
                    a = copy.deepcopy(self.artifacts[f"v{version}-1of1"])
                    a[owner][0][field] = value
                    a["artifact_sha256"] = oracle.artifact_hash(a)
                    with self.subTest(version=version, field=field, value=value), self.assertRaises(oracle.InterfaceFailure) as caught:
                        oracle.evaluate(oracle.canonical(a), lambda *args: self.fail("unexpected crypto"))
                    self.assertEqual(caught.exception.stage, "schema" if value > 0xffffffff else "correspondence")


if __name__ == "__main__":
    unittest.main()
