"""Independent, bounded W0 format and mutation checks; no live wallet."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("slh_wallet_formats", Path(__file__).with_name("reference.py"))
r = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(r)

# Literal domain bytes, independent of the oracle's PREFIX/identifier helpers.
# The policy domain is in protocol.md; proposal and inventory match the Rust wallet.
POLICY_DOMAIN = b"ZcashTransparentPQ/experimental/slh-dsa-b-128s/policy/v1\0"


def domain_hash(domain, raw):
    return hashlib.sha256(b"ZcashTransparentPQ/" + domain + b"/v1\0" + raw).hexdigest()


class Formats(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads(r.CORPUS.read_bytes())
        cls.manifest = json.loads(cls.corpus["inventory_json"])
        cls.partial = json.loads(cls.corpus["partial_json"])
        cls.recovery = json.loads(cls.corpus["recovery_json"])
        cls.backup = bytes.fromhex(cls.corpus["backup"]["file_hex"])
        cls.key = bytes.fromhex(cls.corpus["backup"]["key_hex"])
        cls.password = bytes.fromhex(cls.corpus["backup"]["password_utf8_hex"])

    def reject_mutations(self, original, mutations, check):
        for label, mutation in mutations:
            with self.subTest(mutation=label):
                changed = copy.deepcopy(original)
                mutation(changed)
                with self.assertRaises(ValueError):
                    check(changed)

    def test_retained_corpus_exact_bytes_and_real_argon2_aead(self):
        self.assertEqual(r.CORPUS.read_bytes(), r.corpus_bytes(r.make_corpus()))
        # This independently recomputes the fixed Argon2id key and every AEAD
        # ciphertext/tag byte, without a Rust/production encryption dependency.

    def test_reference_never_overwrites_retained_vectors(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vectors.json"
            path.write_bytes(b"retained sentinel")
            with mock.patch.object(r, "CORPUS", path), mock.patch.object(r, "make_corpus", return_value={}):
                with mock.patch("sys.argv", ["reference.py", "--write"]), self.assertRaises(FileExistsError):
                    r.main()
                self.assertEqual(path.read_bytes(), b"retained sentinel")
                # Semantic JSON equality is insufficient: compare exact bytes.
                path.write_bytes(b"{}")
                with mock.patch("sys.argv", ["reference.py"]), self.assertRaises(ValueError):
                    r.main()

    def test_canonical_json_rejects_mutations(self):
        invalid = [b'{"x":0,"x":0}', b'{"x":1.0}', b'{"x":1e0}', b'{"x":-0}', b'{"x":-1}',
                   b'{"x":true}', b'{"x":false}', b'{"x":"\\u0061"}', b'{"x":"\\n"}',
                   b'{"x":0}\n', b'{ "x":0}', b'{"x":NaN}', b'{"x":Infinity}',
                   b'{"x":0} ', b'{"z":0,"a":1}', b'{"x":"\x7f"}', b'{"x":"\xc3\xa9"}',
                   b'{"x":01}', b'[] []', b'{"x":18446744073709551616}', b'[', b']']
        for raw in invalid:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                r.canonical(raw, 256)
        self.assertEqual(r.canonical(b'{"a":null,"b":[0,4294967296]}', 256), {"a": None, "b": [0, 2**32]})

    def test_json_depth_and_size_checked_before_decode(self):
        valid = b"[" * 16 + b"]" * 16
        self.assertEqual(r.j(r.canonical(valid, 32)), valid)
        with mock.patch.object(r.json, "loads", side_effect=AssertionError("decode reached")):
            for raw, cap in [(b"[" * 17 + b"]" * 17, 34), (b"{}", 1), (b'"\\x"', 5)]:
                with self.subTest(raw=raw), self.assertRaises(ValueError):
                    r.canonical(raw, cap)
        self.assertEqual(r.canonical(b'"' + b"x" * 254 + b'"', 256), "x" * 254)

    def test_all_120_policy_receivers_and_origins(self):
        self.assertEqual(len(self.corpus["policies"]), 120)
        seen = set()
        for row in self.corpus["policies"]:
            m, n = row["threshold"], row["participants"]
            with self.subTest(m=m, n=n):
                entry, enrolled = r.sample_entry(m, n)
                descriptor = r.check_entry(entry)
                r.check_origin_mapping(entry, enrolled)
                self.assertEqual(descriptor.hex(), row["policy_hex"])
                self.assertEqual(descriptor[:4], bytes([1, 0xF7, m, n]))
                self.assertEqual(len(descriptor), 4 + 32 * n)
                commitment = hashlib.sha256(POLICY_DOMAIN + descriptor).digest()
                self.assertEqual(r.commitment(descriptor), commitment)
                self.assertEqual(row["commitment_hex"], commitment.hex())
                self.assertEqual(r.decode(row["receiver"]), commitment)
                self.assertTrue(row["receiver"].startswith("tpqreg1"))
                self.assertEqual(len(row["receiver"]), 69)
                self.assertEqual(bytes.fromhex(row["script_hex"]), b"\x53\x20" + commitment + b"\xc0")
                seen.add((m, n))
        self.assertEqual(seen, {(m, n) for n in range(1, 16) for m in range(1, n + 1)})

    def test_bech32m_bip350_known_answers(self):
        # Valid BIP 350 Bech32m and BIP 173 Bech32 strings anchor polymod,
        # HRP expansion and the Bech32m constant outside this corpus.
        bech32m = ["a1lqfn3a", "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
                   "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
                   "split1checkupstagehandshakeupstreamerranterredcaperredlc445v", "?1v759aa"]
        bech32 = ["a12uel5l", "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
                  "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
                  "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w", "?1ezyfcl"]
        for value in bech32m + bech32:
            hrp, data = value.rsplit("1", 1)
            words = [r.ALPHABET.index(c) for c in data[:-6]]
            with self.subTest(value=value):
                if value in bech32m:
                    self.assertEqual(r.encode_words(words, hrp), value)
                else:
                    self.assertEqual(r.encode_words(words, hrp, constant=1), value)
                    self.assertNotEqual(r.encode_words(words, hrp), value)

    def test_receiver_mutations(self):
        receiver = self.corpus["policies"][0]["receiver"]
        payload = b"\x01\x02\xf7" + r.decode(receiver)
        words = [r.ALPHABET.index(c) for c in receiver[7:-6]]
        invalid = [receiver.upper(), "T" + receiver[1:], receiver + " ", receiver[:-1],
                   receiver + "q", receiver[:-1] + ("q" if receiver[-1] != "q" else "p"),
                   r.encode(payload, "tpqtes"), r.encode(payload, constant=1),
                   r.encode(b"\x02" + payload[1:]), r.encode(payload[:1] + b"\x01" + payload[2:]),
                   r.encode(payload[:-1]), r.encode(payload + b"\0"),
                   r.encode_words(words + [0]), r.encode_words(words + [1])]
        invalid += [r.encode(payload[:2] + bytes([suite]) + payload[3:]) for suite in (0, 1, 0xF3, 0xF6, 0xF8)]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                r.decode(value)

    def test_policy_mutations(self):
        entry, _ = r.sample_entry(2, 3)
        def descriptor_byte(position, value):
            def mutate(candidate):
                raw = bytearray.fromhex(candidate["policy_hex"])
                raw[position] = value
                candidate["policy_hex"] = raw.hex()
            return mutate
        def hashes(candidate, duplicate):
            raw = bytes.fromhex(candidate["policy_hex"])
            candidate["policy_hex"] = (raw[:4] + raw[36:68] + (raw[36:68] if duplicate else raw[4:36]) + raw[68:]).hex()
        changes = [(f"header {p}/{v}", descriptor_byte(p, v)) for p, v in [(0, 2), (1, 1), (1, 0xF3), (2, 0), (2, 4), (3, 16), (3, 2)]]
        changes += [("reordered hashes", lambda c: hashes(c, False)), ("duplicate hashes", lambda c: hashes(c, True)),
                    ("trailing descriptor", lambda c: c.update(policy_hex=c["policy_hex"] + "00")),
                    ("uppercase hex", lambda c: c.update(policy_hex=c["policy_hex"].upper())),
                    ("unknown entry field", lambda c: c.update(extra=0)), ("bad role", lambda c: c.update(role=2))]
        self.reject_mutations(entry, changes, r.check_entry)
        with self.assertRaises(ValueError):
            r.policy(1, [b"\0" * 32, b"\0" * 32])

    def test_origins_bounds_and_approved_mapping(self):
        entry, enrolled = r.sample_entry(2, 3)
        changes = [("origin index overflow", lambda c: c["origins"][0].update(index=2**32)),
                   ("origin index bool", lambda c: c["origins"][0].update(index=True)),
                   ("nonzero account", lambda c: c["origins"][0].update(account=1)),
                   ("unknown origin field", lambda c: c["origins"][0].update(extra=0)),
                   ("wallet ID length", lambda c: c["origins"][0].update(wallet_id="00")),
                   ("duplicate participant", lambda c: c["origins"][0].update(wallet_id=c["origins"][1]["wallet_id"]))]
        self.reject_mutations(entry, changes, r.check_entry)
        reordered = copy.deepcopy(entry)
        reordered["origins"].reverse()
        r.check_entry(reordered)  # Public descriptors alone cannot authenticate origins.
        with self.assertRaisesRegex(ValueError, "origin commitment"):
            r.check_origin_mapping(reordered, enrolled)
        with self.assertRaisesRegex(ValueError, "unapproved origin"):
            r.check_origin_mapping(entry, {})
        for origins in [None, {}, "", 0, [], entry["origins"] * 6]:
            candidate = dict(entry, origins=origins)
            with mock.patch.object(r, "hexadecimal", side_effect=AssertionError("hex reached")):
                with self.subTest(origins_type=type(origins)), self.assertRaises(ValueError):
                    r.check_entry(candidate)

    def test_partial_maximum_and_mutations(self):
        raw = self.corpus["partial_json"].encode()
        self.assertEqual(len(raw), 16001)
        self.assertEqual(r.MAX_PARTIAL, 16384)
        self.assertEqual(r.read_partial(raw), self.partial)
        for i in range(15):
            candidate = dict(self.partial, input_index=i, signer_index=i)
            r.read_partial(r.j(candidate))
        changes = [("old format", lambda c: c.update(format=r.PREFIX + "partial/v1")),
                   ("other suite", lambda c: c.update(format=r.PREFIX + "experimental/sqisign-iii-exp-v1/partial/v1")),
                   ("input overflow", lambda c: c.update(input_index=15)), ("signer overflow", lambda c: c.update(signer_index=15)),
                   ("input bool", lambda c: c.update(input_index=True)), ("signer negative", lambda c: c.update(signer_index=-1)),
                   ("short key", lambda c: c.update(public_key_hex="00" * 31)),
                   ("long key", lambda c: c.update(public_key_hex="00" * 33)),
                   ("short signature", lambda c: c.update(signature_hex="00" * 7855)),
                   ("long signature", lambda c: c.update(signature_hex="00" * 7857)),
                   ("uppercase ID", lambda c: c.update(proposal_id="AA" * 32)),
                   ("unknown field", lambda c: c.update(extra=0)), ("null signature", lambda c: c.update(signature_hex=None))]
        self.reject_mutations(self.partial, changes, r.check_partial)
        with mock.patch.object(r, "check_partial", side_effect=AssertionError("schema reached")):
            with self.assertRaises(ValueError):
                r.read_partial(b"x" * 16385)
        # A byte cap is an independent upper bound, not permission to pad JSON.
        with self.assertRaises(ValueError):
            r.read_partial(raw + b" " * (16384 - len(raw)))

    def test_compact_size_and_script_push_boundaries(self):
        answers = {0: "00", 252: "fc", 253: "fdfd00", 65535: "fdffff", 65536: "fe00000100",
                   2**32 - 1: "feffffffff", 2**32: "ff0000000001000000", 2**64 - 1: "ffffffffffffffffff"}
        for value, hex_value in answers.items():
            self.assertEqual(r.compact_size(value).hex(), hex_value)
        for invalid in (-1, True, 2**64):
            with self.assertRaises(ValueError):
                r.compact_size(invalid)
        self.assertEqual(r.push(bytes(75))[:1], b"\x4b")
        self.assertEqual(r.push(bytes(76))[:2], b"\x4c\x4c")
        self.assertEqual(r.push(bytes(255))[:2], b"\x4c\xff")
        self.assertEqual(r.push(bytes(256))[:3], b"\x4d\x00\x01")
        self.assertEqual(r.authorization_bytes(15, 15), 118882)
        self.assertEqual(len(r.compact_size(118882)), 5)
        # Outpoint, CompactSize, authorization and sequence of each full input.
        self.assertEqual(r.transaction_bytes(5, [(15, 15)] * 2) - r.transaction_bytes(5, [(15, 15)]),
                         36 + 5 + 118882 + 4)
        self.assertEqual(r.authorization_bytes(8, 10), 63471)
        self.assertEqual(r.authorization_bytes(9, 10), 71364)

    def test_transaction_bytes_and_budget_independence(self):
        answers = [(1, 1, 1, 8086), (1, 15, 15, 119040), (8, 2, 3, 127561),
                   (9, 2, 3, 143492), (2, 15, 15, 237967)]
        for inputs, m, n, v5 in answers:
            for version in (5, 6):
                with self.subTest(inputs=inputs, m=m, n=n, version=version):
                    self.assertEqual(r.transaction_bytes(version, [(m, n)] * inputs), v5 + version - 5)
                    self.assertLess(v5 + version - 5, r.MAX_TRANSACTION)
                    if inputs * m <= 16:
                        self.assertEqual(r.check_payment_capacity(version, [(m, n)] * inputs)[1], inputs * m)
                    else:
                        with self.assertRaisesRegex(ValueError, "check limit"):
                            r.check_payment_capacity(version, [(m, n)] * inputs)
                        r.check_payment_capacity(version, [(m, n)] * inputs, 30, 64)
        with self.assertRaisesRegex(ValueError, "transaction size"):
            r.check_payment_capacity(5, [(15, 15)] * 3, 64, 64)
        # Every shape has correct descriptor and CompactSize widths in both versions.
        for n in range(1, 16):
            for m in range(1, n + 1):
                for v in (5, 6):
                    r.check_payment_capacity(v, [(m, n)])

    def test_proposal_v1_envelopes_and_fingerprints(self):
        self.assertEqual(len(self.corpus["proposals"]), 2)
        for row in self.corpus["proposals"]:
            proposal = r.canonical(row["proposal_json"].encode(), r.MAX_PROPOSAL)
            r.check_proposal_envelope(proposal)
            self.assertEqual(domain_hash(b"wallet-proposal", row["proposal_json"].encode()), row["proposal_id"])
            tx = bytes.fromhex(proposal["transaction_hex"])
            self.assertEqual(len(tx), 154 + row["transaction_version"] - 5)
            self.assertEqual(tx[:4], struct.pack("<I", 0x80000000 | row["transaction_version"]))
            changes = [("version", lambda c: c.update(format=r.PREFIX + "proposal/v2")),
                       ("unknown field", lambda c: c.update(suite=247)),
                       ("no inputs", lambda c: c.update(inputs=[])),
                       ("sixteenth input", lambda c: c.update(inputs=c["inputs"] * 16)),
                       ("third output", lambda c: c["outputs"].append(c["outputs"][0])),
                       ("payment entry", lambda c: c["outputs"][0].update(entry=c["inputs"][0]["entry"])),
                       ("missing change entry", lambda c: c["outputs"][1].update(entry=None)),
                       ("policy transfer", lambda c: c["outputs"][1].update(kind="policy_transfer")),
                       ("spent policy", lambda c: c["inputs"][0].update(spent_output_hex="00" * 44)),
                       ("alternate suite", lambda c: c["inputs"][0]["entry"].update(
                           policy_hex="0101" + c["inputs"][0]["entry"]["policy_hex"][4:])),
                       ("tip hash", lambda c: c["tip"].update(hash="AA" * 32)),
                       ("transaction odd hex", lambda c: c.update(transaction_hex="0")),
                       ("transaction cap", lambda c: c.update(transaction_hex="00" * (r.MAX_TRANSACTION + 1)))]
            self.reject_mutations(proposal, changes, r.check_proposal_envelope)
            candidate = copy.deepcopy(proposal)
            candidate["tip"]["height"] += 1
            self.assertNotEqual(r.identifier("wallet-proposal", candidate), row["proposal_id"])

    def test_inventory_ids_and_h1_origin_binding(self):
        r.check_manifest(self.manifest)
        enrolled = {(r.PUBLIC_WALLET_ID, row["role"], 0, row["index"]): bytes.fromhex(row["public_key"])
                    for row in r.key_answers()["cases"]}
        for entry in self.manifest["entries"]:
            r.check_origin_mapping(entry, enrolled)
        inventory = self.corpus["inventory_json"].encode()
        profile = json.dumps(self.manifest["profile"], sort_keys=True, separators=(",", ":")).encode()
        self.assertIn(b'"profile":' + profile, inventory)
        self.assertEqual(domain_hash(b"wallet-inventory", inventory), self.corpus["inventory_id"])
        self.assertEqual(domain_hash(b"wallet-profile", profile), self.corpus["profile_id"])
        candidate = copy.deepcopy(self.manifest)
        candidate["allocator_id"] = "ee" * 16
        self.assertNotEqual(r.identifier("wallet-inventory", candidate), self.corpus["inventory_id"])

    def test_manifest_schema_and_context_mutations(self):
        changes = [("suite native", lambda c: c.update(suite=1)), ("suite alternate", lambda c: c.update(suite=0xF3)),
                   ("suite unknown", lambda c: c.update(suite=0xF8)), ("suite bool", lambda c: c.update(suite=True)),
                   ("version", lambda c: c.update(derivation_version=2)), ("format", lambda c: c.update(format=r.PREFIX + "inventory/v2")),
                   ("secret field", lambda c: c.update(root_hex="00" * 32)), ("entry order", lambda c: c["entries"].reverse()),
                   ("coverage", lambda c: c.update(receive_end=3)), ("retirement", lambda c: c.update(retired_change_end=3)),
                   ("end overflow", lambda c: c.update(receive_end=2**32 + 1)),
                   ("nonlocal entry", lambda c: c["entries"][0]["origins"][0].update(wallet_id="ff" * 16)),
                   ("network", lambda c: c["profile"].update(network=1)),
                   ("branch", lambda c: c["profile"].update(nu7_branch_id="c8e71055")),
                   ("activation", lambda c: c["profile"].update(pq_activation_height=105)),
                   ("zero checks", lambda c: c["profile"].update(max_tx_pq_checks=0)),
                   ("limit order", lambda c: c["profile"].update(max_block_pq_checks=15)),
                   ("check overflow", lambda c: c["profile"].update(max_block_pq_checks=2**32))]
        changes += [(f"entries type {type(x)}", lambda c, x=x: c.update(entries=x)) for x in (None, {}, "", 0)]
        self.reject_mutations(self.manifest, changes, r.check_manifest)
        # Old policy history is readable even if today's approved check limit
        # forbids new issuance/signing. Schema validation must not erase history.
        candidate = copy.deepcopy(self.manifest)
        candidate["profile"]["max_tx_pq_checks"] = 1
        large_entry = r.sample_entry(15, 15, index=0)[0]
        candidate.update(wallet_id=large_entry["origins"][0]["wallet_id"],
                         entries=[large_entry], receive_end=1, change_end=0)
        r.check_manifest(candidate)

    def test_manifest_monotonic_update_and_allocator_rotation(self):
        previous = copy.deepcopy(self.manifest)
        previous.update(receive_end=1, change_end=1, birthday_height=10)
        previous["entries"] = [self.manifest["entries"][0], self.manifest["entries"][2]]
        extended = copy.deepcopy(self.manifest)
        extended.update(revision=1, birthday_height=9)
        retired = copy.deepcopy(extended)
        retired.update(revision=2, retired_receive_end=2, retired_change_end=2)
        rotated = copy.deepcopy(retired)
        rotated.update(revision=3, allocator_id="ee" * 16)
        for before, after in [(previous, previous), (previous, extended), (extended, retired), (retired, rotated)]:
            retained = (r.j(before), r.j(after))
            r.check_manifest_update(before, after)
            self.assertEqual(retained, (r.j(before), r.j(after)))
        changes = [("revision rollback", lambda c: c.update(revision=0)),
                   ("conflicting revision", lambda c: c.update(revision=1, birthday_height=8)),
                   ("birthday advanced", lambda c: c.update(birthday_height=10)),
                   ("unretired rotation", lambda c: c.update(allocator_id="ee" * 16)),
                   ("profile changed", lambda c: c["profile"].update(genesis_hash="22" * 32))]
        candidate = copy.deepcopy(extended)
        candidate["revision"] = 2
        self.reject_mutations(candidate, changes, lambda c: r.check_manifest_update(extended, c))
        for role in ("receive", "change"):
            candidate = copy.deepcopy(rotated)
            candidate["retired_" + role + "_end"] = 1
            with self.assertRaisesRegex(ValueError, "retirement rollback"):
                r.check_manifest_update(retired, candidate)
        rewritten = copy.deepcopy(extended)
        rewritten["revision"] = 2
        rewritten["entries"][0]["policy_hex"] = r.policy(1, [b"X" * 32]).hex()
        r.check_manifest(rewritten)
        with self.assertRaisesRegex(ValueError, "entry history changed"):
            r.check_manifest_update(extended, rewritten)
        # Keep the birthday unchanged so that only shrinkage can reject.
        shrunken = copy.deepcopy(previous)
        shrunken.update(revision=2, birthday_height=extended["birthday_height"])
        r.check_manifest(shrunken)
        with self.assertRaisesRegex(ValueError, "^coverage rollback$"):
            r.check_manifest_update(extended, shrunken)
        exhausted = dict(rotated, revision=2**32 - 1)
        r.check_manifest_update(exhausted, copy.deepcopy(exhausted))
        with self.assertRaisesRegex(ValueError, "^revision rollback$"):
            r.check_manifest_update(exhausted, previous)

    def test_inventory_entry_and_byte_caps_are_independent(self):
        maximum_entry = json.loads(self.corpus["capacity"]["maximum_entry_json"])
        self.assertEqual(len(r.j(maximum_entry)), 2206)
        maximum_array = len(json.dumps([maximum_entry] * r.MAX_ENTRIES, sort_keys=True, separators=(",", ":")))
        self.assertEqual(maximum_array, 9039873)
        self.assertEqual(self.corpus["capacity"]["maximum_entry_array_bytes"], maximum_array)
        self.assertGreater(maximum_array, r.MAX_PLAINTEXT)
        def inventory(count, participants):
            result = copy.deepcopy(self.manifest)
            result.update(receive_end=count, change_end=0, entries=[])
            for index in range(count):
                keys = r.synthetic_keys(participants)
                keys[0] = hashlib.sha256(struct.pack("<I", index)).digest()
                rows = sorted((r.key_commitment(key), dict(account=0, index=index if slot == 0 else 2**32 - 1,
                                                          wallet_id=r.PUBLIC_WALLET_ID if slot == 0 else f"{slot:032x}"))
                              for slot, key in enumerate(keys))
                result["entries"].append(dict(role=0, policy_hex=r.policy(1, keys).hex(), origins=[row[1] for row in rows]))
            return result
        small = inventory(4096, 1)
        r.check_manifest(small)
        self.assertLess(len(r.j(small)), r.MAX_PLAINTEXT)
        too_many = dict(small, receive_end=4097, entries=small["entries"] + [small["entries"][0]])
        with mock.patch.object(r, "check_entry", side_effect=AssertionError("entry reached")):
            with self.assertRaisesRegex(ValueError, "coverage"):
                r.check_manifest(too_many)
        large = inventory(4096, 15)
        self.assertGreater(len(r.j(large)), r.MAX_PLAINTEXT)
        with self.assertRaisesRegex(ValueError, "policies/size"):
            r.check_manifest(large)

    def test_backup_header_parameters_and_lengths_before_kdf(self):
        def forbidden(*_):
            raise AssertionError("malformed header reached KDF")
        invalid = [self.backup[:55], self.backup[:-1], self.backup + b"\0"]
        for offset in (0, 8, 9, 10, 11, 12, 16, 20, 52):
            bad = bytearray(self.backup)
            bad[offset] ^= 1
            invalid.append(bytes(bad))
        for length in (0, 15, r.MAX_PLAINTEXT + 17, 2**32 - 1):
            invalid.append(self.backup[:52] + struct.pack("<I", length) + self.backup[56:])
        for bad in invalid:
            with self.subTest(length=len(bad)), self.assertRaises(ValueError):
                r.decrypt_backup(bad, self.password, forbidden)
        self.assertEqual(len(bytes.fromhex(self.corpus["backup"]["header_hex"])), 56)
        self.assertEqual(len(self.backup), 56 + len(self.corpus["recovery_json"].encode()) + 16)
        self.assertEqual(self.backup[:24].hex(), "5450514241434b0001010113000001000300000004000000")

    def test_backup_plaintext_boundary_and_preserved_outer_caps(self):
        class HeaderAccepted(Exception):
            pass
        def stop_after_header(*_):
            raise HeaderAccepted
        # Exact min/max ciphertext lengths reach KDF; max+1 cannot. No real KDF
        # or large plaintext encryption is required to exercise this boundary.
        caps = self.corpus["capacity"]
        for size in (16, r.MAX_PLAINTEXT + 16):
            blob = r.backup_header(bytes(16), bytes(12), size) + bytes(size)
            with self.assertRaises(HeaderAccepted):
                r.decrypt_backup(blob, b"public", stop_after_header)
        self.assertEqual(len(blob), caps["encrypted_backup_bytes_cap"])
        size = r.MAX_PLAINTEXT + 17
        blob = r.backup_header(bytes(16), bytes(12), size) + bytes(size)
        self.assertEqual(len(blob), caps["encrypted_backup_bytes_cap"] + 1)
        with self.assertRaisesRegex(ValueError, "length"):
            r.decrypt_backup(blob, b"public", stop_after_header)
        self.assertEqual(caps["encrypted_backup_bytes_cap"], 8388680)
        self.assertEqual(caps["journal_capability_bytes_cap"], 1048576)
        self.assertEqual(caps["watch_v2_bytes_cap"], 33554432)
        self.assertEqual(caps["watch_v3_metadata_bytes_cap"], 16384)
        self.assertEqual(caps["journal_commit_bytes_cap"], 67108864)
        # These outer caps are contract ledger values, not a journal parser or
        # proof that any count of maximally sized child objects will fit.

    def test_backup_authentication_and_password_controls(self):
        fixed_kdf = lambda *_: self.key
        self.assertEqual(r.decrypt_backup(self.backup, self.password, fixed_kdf), self.recovery)
        for offset in (24, 40, 56, len(self.backup) - 1):
            bad = bytearray(self.backup)
            bad[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaisesRegex(ValueError, "authentication"):
                r.decrypt_backup(bytes(bad), self.password, fixed_kdf)
        with self.assertRaisesRegex(ValueError, "authentication"):
            r.decrypt_backup(self.backup, b"wrong public password")
        for password in (b"", b"x" * 1025, b"\xff"):
            with self.subTest(password_length=len(password)), self.assertRaises((ValueError, UnicodeError)):
                r.decrypt_backup(self.backup, password, lambda *_: self.fail("invalid password reached KDF"))

    def test_authenticated_recovery_schema_mutations(self):
        mutations = [("alternate suite", lambda c: c["manifest"].update(suite=0xF3), "suite/version"),
                     ("unknown suite", lambda c: c["manifest"].update(suite=0xF8), "suite/version"),
                     ("wrong recovery version", lambda c: c.update(format=r.PREFIX + "recovery/v2"), "recovery format"),
                     ("short root", lambda c: c.update(root_hex="00" * 31), "hex"),
                     ("uppercase root", lambda c: c.update(root_hex="AA" * 32), "hex"),
                     ("journal in root envelope", lambda c: c.update(journal={}), "fields"),
                     ("entries not array", lambda c: c["manifest"].update(entries={}), "entries array"),
                     ("origins not array", lambda c: c["manifest"]["entries"][0].update(origins={}), "origins array")]
        # Authenticated invalid schemas use separate public test salt/key and
        # distinct nonces. Encrypt raw JSON directly to reach the reader checks.
        key, salt = b"K" * 32, b"S" * 16
        def blob(candidate, index):
            plaintext = r.j(candidate)
            nonce = index.to_bytes(12, "little")
            header = r.backup_header(salt, nonce, len(plaintext) + 16)
            return header + r.ChaCha20Poly1305(key).encrypt(nonce, plaintext, header)
        # The unmutated recovery authenticates and parses with this setup.
        self.assertEqual(r.decrypt_backup(blob(self.recovery, len(mutations)), b"public schema test",
                                          lambda *_: key), self.recovery)
        for index, (label, mutate, reason) in enumerate(mutations):
            candidate = copy.deepcopy(self.recovery)
            mutate(candidate)
            with self.subTest(mutation=label), self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                r.decrypt_backup(blob(candidate, index), b"public schema test", lambda *_: key)


if __name__ == "__main__":
    unittest.main()
