"""Bounded reference mutations, without product invocations or wallet secrets."""

import copy
import hashlib
import json
import unittest

import reference as R


class Interfaces(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = R.make_corpus()

    def test_retained_answers_are_independently_recomputed(self):
        self.assertEqual((json.dumps(self.corpus, indent=2, sort_keys=True) + "\n").encode(),
                         R.CORPUS.read_bytes())

    def test_enrollments_bind_exact_origins_and_are_order_independent(self):
        for case in self.corpus["enrollments"]:
            previous = json.loads(case["previous_json"])
            keys = [R.exchange(row["json"].encode()) for row in case["keys"]]
            result = R.enroll(previous, case["role"], case["threshold"], keys)
            self.assertEqual(R.F.j(result).decode(), case["inventory_json"])
            self.assertEqual(result, R.enroll(previous, case["role"], case["threshold"], keys[::-1]))
            for row, key in zip(case["keys"], keys):
                self.assertEqual(R.identity(R.KEY_FORMAT, key), row["fingerprint"])

    def test_enrollment_rejects_context_origin_and_pairing_shape_changes(self):
        case = self.corpus["enrollments"][0]
        original = [json.loads(row["json"]) for row in case["keys"]]
        previous = json.loads(case["previous_json"])
        for field, value in [("role", 1), ("suite", 1), ("format", "wrong"),
                             ("wallet_id", original[1]["wallet_id"]),
                             ("public_key_hex", original[1]["public_key_hex"])]:
            with self.subTest(field=field):
                keys = copy.deepcopy(original)
                keys[0][field] = value
                with self.assertRaises(ValueError):
                    R.enroll(previous, 0, 2, keys)
        wrong = copy.deepcopy(original)
        wrong[-1]["index"] = 1
        with self.assertRaises(ValueError):
            R.enroll(previous, 0, 2, wrong)
        with self.assertRaises(ValueError):
            R.enroll(previous, 0, 2, original[:-1])
        changed_profile = copy.deepcopy(original)
        changed_profile[0]["profile"]["max_block_pq_checks"] += 1
        with self.assertRaises(ValueError):
            R.enroll(previous, 0, 2, changed_profile)

    def test_exchange_parser_never_normalizes_untrusted_bytes(self):
        raw = self.corpus["enrollments"][0]["keys"][0]["json"].encode()
        for invalid in [raw + b"\n", b" " * 4097,
                        raw.replace(b'"suite":247', b'"suite":247,"suite":247'),
                        raw[:-1] + b',"zzz":0}', raw.replace(b'"role":0', b'"role":false')]:
            with self.assertRaises(ValueError):
                R.exchange(invalid)

    def test_receipt_mutations_and_hash_domain(self):
        snapshot = self.corpus["snapshot"]
        raw = snapshot["receipt_json"].encode()
        value = R.receipt(raw)
        self.assertEqual(R.identity(R.RECEIPT_FORMAT, value), snapshot["fingerprint"])
        for prefix in [b"", R.RECEIPT_FORMAT.encode(), R.KEY_FORMAT.encode() + b"\0"]:
            self.assertNotEqual(hashlib.sha256(prefix + raw).hexdigest(), snapshot["fingerprint"])
        for changed in snapshot["valid_identity_mutations"]:
            value = R.receipt(changed["json"].encode())
            self.assertEqual(R.identity(R.RECEIPT_FORMAT, value), changed["fingerprint"])
            self.assertNotEqual(changed["fingerprint"], snapshot["fingerprint"])
        for invalid in snapshot["invalid_receipts"]:
            with self.subTest(reason=invalid["reason"]), self.assertRaises(ValueError):
                R.receipt(invalid["json"].encode())

    def test_companions_bind_exact_bytes_and_have_no_authority_claim(self):
        snapshot = self.corpus["snapshot"]
        receipt = json.loads(snapshot["receipt_json"])
        state_raw = snapshot["state_json"].encode()
        state = json.loads(state_raw)
        self.assertFalse(state["scan"]["complete"])
        self.assertIsNone(state["scan"]["checkpoint"])
        self.assertEqual(state["payments"]["records"], [])
        self.assertIsNone(receipt["journal"]["generation"])
        self.assertEqual(receipt["state_sha256"], hashlib.sha256(state_raw).hexdigest())
        self.assertNotEqual(receipt["state_sha256"], hashlib.sha256(state_raw + b"\n").hexdigest())
        self.assertEqual(receipt["backup_sha256"], hashlib.sha256(bytes.fromhex(R.L1["backup"]["file_hex"])).hexdigest())
        self.assertEqual(receipt["journal"]["retained_bytes"], len(bytes.fromhex(snapshot["retained_object_hex"])))
        self.assertEqual(receipt["journal"]["reachable_objects"], 0)


if __name__ == "__main__":
    unittest.main()
