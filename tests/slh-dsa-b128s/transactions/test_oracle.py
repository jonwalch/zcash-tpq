# SPDX-License-Identifier: MIT OR Apache-2.0
"""Cheap tests of independent schemas/codecs/digests; no crypto acceptance claim."""

import copy
import unittest

import check
import mutations
import oracle
import wire


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


class OracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifacts = synthetic_artifacts()

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

    def test_typed_mutations_precede_crypto_where_required(self):
        for case in mutations.controls(self.artifacts):
            with self.subTest(case=case["name"]):
                calls = []
                def reject(*args):
                    calls.append(args)
                    return False
                if case["interface_stage"] is not None:
                    with self.assertRaises(oracle.InterfaceFailure) as caught:
                        oracle.evaluate(case["raw"], reject)
                    self.assertEqual(caught.exception.stage, case["interface_stage"])
                    self.assertEqual(calls, [])
                else:
                    _, observed = oracle.evaluate(case["raw"], reject)
                    self.assertEqual(observed, case["outcome"])
                    self.assertEqual(bool(calls), observed["native_rejection"]["stage"] == "signature")

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
        for raw in (b'{"a":1,"a":2}', b'{"a":{"z":1,"z":2}}', b'-0', b'0.0', b'1e0',
                    b'NaN', b'18446744073709551616', b'"\\ud800"', b'['*17+b'0'+b']'*17,
                    '{"a":1}'.encode("utf-16"), b'\xef\xbb\xbf{"a":1}'):
            with self.subTest(raw=raw), self.assertRaises(oracle.InterfaceFailure):
                oracle.strict_json(raw)
        with self.assertRaises(oracle.InterfaceFailure):
            oracle.strict_json(b" " * (oracle.MAX_JSON + 1))

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


if __name__ == "__main__":
    unittest.main()
