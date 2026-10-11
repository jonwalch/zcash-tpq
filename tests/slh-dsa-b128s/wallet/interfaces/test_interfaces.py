"""Bounded reference mutations, without product invocations or wallet secrets."""

import copy
import hashlib
import json
import re
import unittest
from unittest import mock

import reference as R

# Literal domains matching the Rust CLI and wallet, independent of R.identity.
KEY_DOMAIN = b"ZcashTransparentPQ/experimental/slh-dsa-b-128s/key-exchange/v1\0"
INVENTORY_DOMAIN = b"ZcashTransparentPQ/wallet-inventory/v1\0"
RECEIPT_DOMAIN = b"ZcashTransparentPQ/operational-snapshot-receipt/v1\0"
JOURNAL_ROOT_DOMAIN = b"ZcashTransparentPQ/wallet-journal-root-receipt/v1\0"
# Expected rejection for each retained invalid receipt.
INVALID_RECEIPTS = {"suite": "receipt format/suite", "receive_next": "integer",
                    "journal.generation": "journal identity pair", "journal.journal_id": "journal identity pair",
                    "profile.network": "network", "trailing newline": "ASCII/no escapes",
                    "duplicate field": "duplicate field", "unknown field": "fields", "byte limit": "size"}


def sha256(domain, raw):
    return hashlib.sha256(domain + raw).hexdigest()


def leaves(value, prefix=()):
    if isinstance(value, dict):
        return {path: leaf for key, child in value.items() for path, leaf in leaves(child, prefix + (key,)).items()}
    return {".".join(prefix): value}


class Interfaces(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Later tests check the retained answers that the Rust tests consume.
        cls.corpus = json.loads(R.CORPUS.read_bytes())

    def assert_rejects(self, check, raw, reason):
        with self.assertRaisesRegex(ValueError, "^" + re.escape(reason) + "$"):
            check(raw)

    def test_retained_answers_are_independently_recomputed(self):
        self.assertEqual((json.dumps(R.make_corpus(), indent=2, sort_keys=True) + "\n").encode(),
                         R.CORPUS.read_bytes())

    def test_enrollments_bind_exact_origins_and_are_order_independent(self):
        enrollments = self.corpus["enrollments"]
        self.assertEqual(len(enrollments), 3)
        for index, case in enumerate(enrollments):
            if index:
                self.assertEqual(case["previous_json"], enrollments[index - 1]["inventory_json"])
            previous = json.loads(case["previous_json"])
            keys = [R.exchange(row["json"].encode()) for row in case["keys"]]
            result = R.enroll(previous, case["role"], case["threshold"], keys)
            self.assertEqual(R.F.j(result).decode(), case["inventory_json"])
            self.assertEqual(result, R.enroll(previous, case["role"], case["threshold"], keys[::-1]))
            self.assertEqual(sha256(INVENTORY_DOMAIN, case["inventory_json"].encode()), case["inventory_fingerprint"])
            for row in case["keys"]:
                self.assertEqual(sha256(KEY_DOMAIN, row["json"].encode()), row["fingerprint"])

    def test_enrollment_rejects_context_origin_and_pairing_shape_changes(self):
        case = self.corpus["enrollments"][0]
        original = [json.loads(row["json"]) for row in case["keys"]]
        previous = json.loads(case["previous_json"])
        def enroll(keys):
            return R.enroll(previous, 0, 2, keys)
        enroll(original)
        for field, value, reason in [("role", 1, "cosigner context"), ("suite", 1, "exchange suite"),
                                     ("format", "wrong", "exchange format"),
                                     ("wallet_id", original[1]["wallet_id"], "duplicate participant"),
                                     ("public_key_hex", original[1]["public_key_hex"], "duplicate keys")]:
            with self.subTest(field=field):
                keys = copy.deepcopy(original)
                keys[0][field] = value
                self.assert_rejects(enroll, keys, reason)
        # The retained keys are in reverse participant order: the local key is last.
        wrong = copy.deepcopy(original)
        wrong[-1]["index"] = 1
        self.assert_rejects(enroll, wrong, "local origin")
        self.assert_rejects(enroll, original[:-1], "local origin")
        changed_profile = copy.deepcopy(original)
        changed_profile[0]["profile"]["max_block_pq_checks"] += 1
        self.assert_rejects(enroll, changed_profile, "cosigner context")

    def test_exchange_parser_never_normalizes_untrusted_bytes(self):
        raw = self.corpus["enrollments"][0]["keys"][0]["json"].encode()
        R.exchange(raw)
        for invalid, reason in [(raw + b"\n", "ASCII/no escapes"), (b" " * 4097, "size"),
                                (raw.replace(b'"suite":247', b'"suite":247,"suite":247'), "duplicate field"),
                                (raw[:-1] + b',"zzz":0}', "fields"),
                                (raw.replace(b'"role":0', b'"role":false'), "integer")]:
            with self.subTest(reason=reason):
                self.assert_rejects(R.exchange, invalid, reason)
        # Whitespace would also fail JSON decoding; the byte cap must come first.
        with mock.patch.object(R.F.json, "loads", side_effect=AssertionError("decode reached")):
            self.assert_rejects(R.exchange, b" " * 4097, "size")

    def test_receipt_mutations_and_hash_domain(self):
        snapshot = self.corpus["snapshot"]
        raw = snapshot["receipt_json"].encode()
        base = leaves(R.receipt(raw))
        self.assertEqual(sha256(RECEIPT_DOMAIN, raw), snapshot["fingerprint"])
        for prefix in [b"", R.RECEIPT_FORMAT.encode(), R.KEY_FORMAT.encode() + b"\0"]:
            self.assertNotEqual(hashlib.sha256(prefix + raw).hexdigest(), snapshot["fingerprint"])
        self.assertEqual(len(snapshot["valid_identity_mutations"]), 12)
        for changed in snapshot["valid_identity_mutations"]:
            with self.subTest(field=changed["field"]):
                value = leaves(R.receipt(changed["json"].encode()))
                self.assertEqual(sha256(RECEIPT_DOMAIN, changed["json"].encode()), changed["fingerprint"])
                self.assertNotEqual(changed["fingerprint"], snapshot["fingerprint"])
                # Each control changes exactly the named field (or the journal identity pair).
                fields = ({"journal.generation", "journal.journal_id"} if changed["field"].startswith("journal identity")
                          else {changed["field"]})
                self.assertEqual({path for path in base if base[path] != value[path]}, fields)
        self.assertEqual(sorted(row["reason"] for row in snapshot["invalid_receipts"]), sorted(INVALID_RECEIPTS))
        for invalid in snapshot["invalid_receipts"]:
            with self.subTest(reason=invalid["reason"]):
                self.assert_rejects(R.receipt, invalid["json"].encode(), INVALID_RECEIPTS[invalid["reason"]])
        with mock.patch.object(R.F.json, "loads", side_effect=AssertionError("decode reached")):
            self.assert_rejects(R.receipt, b" " * 4097, "size")

    def test_companions_bind_exact_bytes_and_have_no_authority_claim(self):
        snapshot = self.corpus["snapshot"]
        receipt = json.loads(snapshot["receipt_json"])
        state_raw = snapshot["state_json"].encode()
        state = json.loads(state_raw)
        self.assertFalse(state["scan"]["complete"])
        self.assertIsNone(state["scan"]["checkpoint"])
        self.assertEqual(state["payments"]["records"], [])
        self.assertIsNone(receipt["journal"]["generation"])
        self.assertEqual(state_raw, json.dumps(state, sort_keys=True, separators=(",", ":")).encode())
        self.assertEqual(receipt["state_sha256"], hashlib.sha256(state_raw).hexdigest())
        self.assertNotEqual(receipt["state_sha256"], hashlib.sha256(state_raw + b"\n").hexdigest())
        self.assertEqual(receipt["journal"]["root_fingerprint"], sha256(JOURNAL_ROOT_DOMAIN, state_raw))
        self.assertEqual(receipt["inventory_fingerprint"], R.L1["inventory_id"])
        self.assertEqual(receipt["backup_sha256"], hashlib.sha256(bytes.fromhex(R.L1["backup"]["file_hex"])).hexdigest())
        self.assertEqual(receipt["journal"]["retained_bytes"], len(bytes.fromhex(snapshot["retained_object_hex"])))
        self.assertEqual(receipt["journal"]["reachable_objects"], 0)


if __name__ == "__main__":
    unittest.main()
