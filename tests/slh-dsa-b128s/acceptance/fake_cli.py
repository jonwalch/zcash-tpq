"""Strict offline test double for public command assembly, never cryptography.

Only test_acceptance imports this. No subprocess/network/terminal API is used.
Revision, canonical transport and local-origin checks model the existing public
CLI boundary so tests catch mistakes in complete driver flows. Like
terminal.run, each call must match the real argument count, password prompts
and exit status. Modeled refusals return the real diagnostic with a failure.
"""
import copy
import hashlib
from pathlib import Path

from common import canonical, endpoint, fingerprint, require, write_json
from wallet_live import FUNDING_VALUE, PARTIAL_FORMAT, key_commitment, reference

KEY_EXCHANGE = b"ZcashTransparentPQ/experimental/slh-dsa-b-128s/key-exchange/v1"
ROLES = {"receive": 0, "change": 1}
# Real `expected` argument counts in crates/pq-cli/src minus the command and
# profile arguments that Demo.cli adds. test_acceptance parses those tables.
ARITY = {"create-slh-exp": (2,), "inspect": (1,), "export": (2,), "key-export": (4,), "enroll": (4,),
         "watch-create": (4,), "propose": (5,), "review": (5,), "sign": (7,), "assemble": (6,),
         "payment-history-export": (3,), "snapshot-save": (3,), "restore": (3,),
         "sync": (3,), "receive": (1,), "status": (1,), "watch-import": (3,),
         "refresh-propose": (5,), "refresh-review": (5,), "refresh-approve": (6,), "submit": (4,),
         "payments": (2,),
         # enrollment::validate_arguments: one key file and fingerprint per participant.
         "enroll-prepare": tuple(range(6, 35, 2)),
         # recovery::trust: unknown, or known <receipt> --retired-old-allocators.
         "snapshot-restore": (3, 5)}
# Prompts read before other work (main.rs, discovery.rs, enrollment.rs,
# payments.rs, recovery.rs). Every other modeled command never prompts.
NEW_PASSWORD = {"create-slh-exp"}
BACKUP_PASSWORD = {"inspect", "export", "enroll", "key-export", "propose", "review", "sign", "assemble",
                   "refresh-propose", "refresh-review", "refresh-approve", "submit",
                   "restore", "snapshot-save", "snapshot-restore"}
MISMATCH = b"proposal, approved intent or partial authorization does not match"
FINGERPRINT = b"inventory fingerprint does not match the independently approved fingerprint"
INSUFFICIENT = b"insufficient eligible funds within the payment limits"
MONITOR = b"this watcher does not own the receiver allocator"


class FakeCli:
    def __init__(self, nodes):
        self.oracle = reference()
        self.nodes = nodes
        self.wallets, self.watches, self.snapshots = {}, {}, {}
        self.calls, self.endpoints = [], []
        self.counter = 0

    def result(self, value):
        return True, canonical(value)

    def canonical_file(self, path):
        raw = Path(path).read_bytes()
        return self.oracle.canonical(raw, 262144)

    def identifier(self, proposal):
        return hashlib.sha256(canonical(proposal)).hexdigest()

    def wallet(self, path):
        # State is in memory: a deleted backup must not keep answering.
        path = Path(path)
        require(path.is_file() and path in self.wallets, "fake_missing_backup")
        return self.wallets[path]

    def watch(self, path):
        path = Path(path)
        require(path.is_dir() and path in self.watches, "fake_missing_store")
        return self.watches[path]

    def tip(self, command, address):
        rows = [node for node in self.nodes if node.address == endpoint(address)]
        require(len(rows) == 1, "fake_unknown_endpoint")
        self.endpoints.append((command, rows[0].address))
        height, block_hash = rows[0].tip()
        return {"height": height, "hash": block_hash}

    def write_backup(self, path, manifest):
        path = Path(path)
        path.write_bytes(b"fake encrypted backup, no key material")
        path.chmod(0o600)
        self.wallets[path] = copy.deepcopy(manifest)

    def new_watch(self, manifest, mode):
        return {"manifest": manifest, "mode": mode, "partials": [], "raw": None, "proposal": None,
                "intent": None, "review": None, "receive_next": manifest["retired_receive_end"],
                "coins": [FUNDING_VALUE], "checkpoint": None}

    def restored(self, manifest):
        self.counter += 1
        return dict(manifest, allocator_id=f"{self.counter:032x}", revision=manifest["revision"] + 1,
                    retired_receive_end=manifest["receive_end"], retired_change_end=manifest["change_end"])

    def __call__(self, command, *args, secret=False, success=True, prompts=None):
        if command not in ARITY:
            raise AssertionError(command)
        require(len(args) in ARITY[command], "fake_cli_arity_" + command)
        # Demo.cli answers one backup prompt for `secret`; terminal.run then
        # requires each given prompt to appear, and no command prompts twice.
        if prompts is None:
            prompts = [(b"Backup password: ", None)] if secret else []
        expected = ([b"New backup password: ", b"Repeat new password: "] if command in NEW_PASSWORD
                    else [b"Backup password: "] if command in BACKUP_PASSWORD else [])
        require([prompt for prompt, _ in prompts] == expected, "fake_cli_prompts_" + command)
        self.calls.append(command)
        ok, output = self.dispatch(command, args)
        require(ok == success, "cli_exit_status")
        return output

    def prepare(self, args):
        manifest, role, threshold = self.canonical_file(args[0]), ROLES[args[1]], args[2]
        if not 1 <= threshold <= len(args[4::2]) <= 15:
            return False, b"expected 1 <= threshold <= participants <= 15"
        public = []
        for path, digest in zip(args[4::2], args[5::2]):
            raw = Path(path).read_bytes()
            if hashlib.sha256(KEY_EXCHANGE + b"\0" + raw).hexdigest() != digest:
                return False, b"public key pairing fingerprint mismatch"
            public.append(self.oracle.canonical(raw, 262144))
        if (len({item["wallet_id"] for item in public}) != len(public)
                or any(item["role"] != role or item["suite"] != 247 or item["profile"] != manifest["profile"]
                       for item in public)):
            return False, b"cosigner profile, role, suite or participant mismatch"
        index = manifest["receive_end" if role == 0 else "change_end"]
        if any(item["wallet_id"] == manifest["wallet_id"] and item["index"] != index for item in public):
            return False, b"local key must use the next cumulative inventory index"
        public.sort(key=lambda item: key_commitment(bytes.fromhex(item["public_key_hex"])))
        entry = {"role": role, "policy_hex": self.oracle.policy(threshold,
            [bytes.fromhex(item["public_key_hex"]) for item in public]).hex(),
            "origins": [{"account": 0, "index": item["index"], "wallet_id": item["wallet_id"]} for item in public]}
        manifest["entries"].append(entry)
        manifest["entries"].sort(key=lambda item: (item["role"], next(origin["index"]
            for origin in item["origins"] if origin["wallet_id"] == manifest["wallet_id"])))
        manifest["receive_end" if role == 0 else "change_end"] += 1
        manifest["revision"] += 1
        self.oracle.check_manifest(manifest)
        write_json(args[3], manifest)
        return self.result({"inventory": manifest, "fingerprint": fingerprint(manifest), "threshold": threshold})

    def dispatch(self, command, args):
        if command == "create-slh-exp":
            self.counter += 1
            manifest = dict(self.oracle.sample_manifest(), wallet_id=f"{self.counter:032x}",
                            allocator_id=f"{1000 + self.counter:032x}", entries=[], receive_end=0, change_end=0)
            self.write_backup(args[0], manifest)
            return True, b"created"
        if command == "inspect":
            return self.result(self.wallet(args[0]))
        if command == "export":
            write_json(args[1], self.wallet(args[0]))
            return True, b"exported"
        if command == "key-export":
            manifest = self.wallet(args[0])
            role = ROLES[args[1]]
            key = hashlib.sha256(canonical([manifest["wallet_id"], role, args[2]])).hexdigest()
            exchange = {"format": KEY_EXCHANGE.decode(), "index": args[2], "role": role,
                        "profile": manifest["profile"], "suite": 247, "wallet_id": manifest["wallet_id"],
                        "public_key_hex": key}
            write_json(args[3], exchange)
            digest = hashlib.sha256(KEY_EXCHANGE + b"\0" + canonical(exchange)).hexdigest()
            return self.result({"exchange": exchange, "fingerprint": digest})
        if command == "enroll-prepare":
            return self.prepare(args)
        if command == "enroll":
            original = self.wallet(args[0])
            candidate = self.canonical_file(args[1])
            if args[2] != fingerprint(candidate):
                return False, FINGERPRINT
            require(candidate["revision"] == original["revision"] + 1, "fake_enrollment_revision")
            self.oracle.check_manifest_update(original, candidate)
            self.write_backup(args[3], candidate)
            return True, b"enrolled"
        if command == "watch-create":
            inventory = self.canonical_file(args[0])
            if args[1] != fingerprint(inventory):
                return False, FINGERPRINT
            require(args[3] in ("monitor", "allocator"), "fake_watch_mode")
            path = Path(args[2]); path.mkdir(mode=0o700)
            self.watches[path] = self.new_watch(inventory, args[3])
            return self.result({"mode": args[3]})
        if command == "watch-import":
            watch = self.watch(args[0])
            candidate = self.canonical_file(args[1])
            if args[2] != fingerprint(candidate):
                return False, FINGERPRINT
            self.oracle.check_manifest_update(watch["manifest"], candidate)
            watch["manifest"] = candidate
            return True, b"imported"
        if command == "submit":
            self.wallet(args[0])
            watch = self.watch(args[1])
            self.tip(command, args[2])
            # Only the monitor refusal is modeled; allocator submission is live-only.
            require(watch["mode"] == "monitor", "fake_allocator_submission")
            return False, MONITOR
        if command == "payments":
            watch = self.watch(args[0])
            self.tip(command, args[1])
            rows = []
            if watch["proposal"] is not None:
                state = "signed" if watch["raw"] else "partially_signed" if watch["partials"] else "prepared"
                rows.append({"proposal_id": self.identifier(watch["proposal"]), "state": state,
                             "amount": watch["intent"]["amount"], "receiver": watch["intent"]["receiver"]})
            return True, canonical(rows)
        if command in ("propose", "review"):
            manifest, watch = self.wallet(args[0]), self.watch(args[1])
            tip = self.tip(command, args[2])
            intent = self.canonical_file(args[3])
            entry = manifest["entries"][0]
            policy = bytes.fromhex(entry["policy_hex"])
            shape = (policy[2], policy[3])
            auth = self.oracle.authorization_bytes(*shape)
            size = 36 + len(self.oracle.compact_size(auth)) + auth + 4
            # Fewest funded equal-policy outputs paying amount and fee, within
            # the independent oracle's per-transaction check limit.
            for count in range(1, len(watch["coins"]) + 1):
                fee = max(2, (size * count + 149) // 150) * 400
                value = sum(watch["coins"][:count])
                if value >= intent["amount"] + fee:
                    break
            else:
                return False, INSUFFICIENT
            try:
                self.oracle.check_payment_capacity(intent["version"], [shape] * count)
            except ValueError:
                return False, INSUFFICIENT
            change = value - intent["amount"] - fee
            change_entry = next(row for row in manifest["entries"] if row["role"] == 1)
            proposal = {"inputs": [{"entry": entry} for _ in range(count)], "outputs": [{"entry": None}],
                        "transaction_hex": "00", "tip": tip}
            if change:
                proposal["outputs"].append({"entry": change_entry})
            if command == "propose":
                write_json(args[4], proposal)
            elif self.canonical_file(args[4]) != proposal:
                return False, MISMATCH
            if watch["proposal"] != proposal:
                watch.update(proposal=proposal, intent=intent, partials=[], raw=None)
            local = next(origin["index"] for origin in change_entry["origins"] if origin["wallet_id"] == manifest["wallet_id"])
            review = {"checks": policy[2] * count, "fee": fee, "conventional_fee": fee,
                "final_bytes": self.oracle.transaction_bytes(intent["version"], [shape] * count, 2 if change else 1),
                "proposal_id": self.identifier(proposal), "local_change": {"local_index": local, "advancement": None} if change else None,
                "change_value": change, "version": intent["version"], "tip": tip, "expiry_height": 130}
            watch["review"] = review
            return self.result(review)
        if command in ("refresh-propose", "refresh-review", "refresh-approve"):
            self.wallet(args[0])
            watch = self.watch(args[1])
            tip = self.tip(command, args[2])
            if watch["proposal"] is None or args[3] != self.identifier(watch["proposal"]):
                return False, b"unknown proposal"
            proposal = dict(copy.deepcopy(watch["proposal"]), tip=tip)
            identifier = self.identifier(proposal)
            review = dict(watch["review"], proposal_id=identifier, tip=tip)
            if command == "refresh-propose":
                write_json(args[4], proposal)
            elif self.canonical_file(args[4]) != proposal:
                return False, MISMATCH
            if command == "refresh-approve":
                if args[5] != identifier:
                    return False, MISMATCH
                watch["partials"] = [dict(partial, proposal_id=identifier) for partial in watch["partials"]]
                watch.update(proposal=proposal, review=review)
            return self.result(review)
        if command == "sign":
            manifest, watch = self.wallet(args[0]), self.watch(args[1])
            self.tip(command, args[2])
            proposal = self.canonical_file(args[4])
            identifier = self.identifier(proposal)
            if args[5] != identifier or watch["proposal"] != proposal:
                return False, MISMATCH
            directory = Path(args[6]); directory.mkdir(mode=0o700)
            for index, item in enumerate(proposal["inputs"]):
                slot = next(slot for slot, origin in enumerate(item["entry"]["origins"])
                            if origin["wallet_id"] == manifest["wallet_id"])
                origin = item["entry"]["origins"][slot]
                key = hashlib.sha256(canonical([manifest["wallet_id"], 0, origin["index"]])).hexdigest()
                partial = {"input_index": index, "signer_index": slot, "format": PARTIAL_FORMAT,
                           "proposal_id": identifier, "public_key_hex": key, "signature_hex": "55" * 7856}
                write_json(directory / f"input-{index:04}-signer-{slot:02}.json", partial)
                if partial not in watch["partials"]:
                    watch["partials"].append(partial)
            return True, b"signed"
        if command == "assemble":
            self.wallet(args[0])
            watch = self.watch(args[1])
            self.tip(command, args[2])
            intent = self.canonical_file(args[3])
            proposal = self.canonical_file(args[4])
            identifier = self.identifier(proposal)
            if watch["proposal"] != proposal:
                return False, MISMATCH
            partials = [self.canonical_file(path) for path in Path(args[5]).iterdir()]
            shapes = []
            for index, item in enumerate(proposal["inputs"]):
                policy = bytes.fromhex(item["entry"]["policy_hex"])
                slots = {partial["signer_index"] for partial in partials
                         if partial["input_index"] == index and partial["proposal_id"] == identifier}
                if len(slots) < policy[2]:
                    return False, b"not enough distinct partials for every input threshold"
                shapes.append((policy[2], policy[3]))
            watch["raw"] = "00" * self.oracle.transaction_bytes(intent["version"], shapes, len(proposal["outputs"]))
            return True, b"assembled"
        if command == "payment-history-export":
            watch = self.watch(args[0])
            if watch["proposal"] is None or args[1] != self.identifier(watch["proposal"]):
                return False, b"unknown proposal"
            directory = Path(args[2]); directory.mkdir(mode=0o700)
            write_json(directory / "proposal.json", watch["proposal"])
            write_json(directory / "payment.json", {"mode": watch["mode"]})
            for partial in watch["partials"]:
                write_json(directory / f'input-{partial["input_index"]:04}-signer-{partial["signer_index"]:02}.json', partial)
            if watch["raw"]:
                (directory / "signed-transaction.hex").write_text(watch["raw"])
            write_json(directory / "complete.json", {"format": "ZcashTransparentPQ/payment-export/v1"})
            return True, b"exported"
        if command == "snapshot-save":
            self.wallet(args[0])
            watch = self.watch(args[1])
            directory = Path(args[2]); directory.mkdir(mode=0o700)
            self.counter += 1
            receipt = f"{self.counter:064x}"
            self.snapshots[directory] = (copy.deepcopy(watch), receipt)
            return self.result({"receipt_fingerprint": receipt, "receipt": {"journal": {"generation": 1}}})
        if command in ("restore", "snapshot-restore"):
            if command == "restore":
                manifest = self.wallet(args[0])
                if args[1] != fingerprint(manifest):
                    return False, FINGERPRINT
                watch = self.new_watch(manifest, "monitor")
                directory, mode, authority = Path(args[2]), "monitor", "unknown"
            else:
                require(Path(args[0]).is_dir() and Path(args[0]) in self.snapshots, "fake_missing_snapshot")
                saved, receipt = self.snapshots[Path(args[0])]
                directory, authority = Path(args[1]), args[2]
                if (authority, len(args)) not in (("unknown", 3), ("known", 5)) or (
                        authority == "known" and args[4] != "--retired-old-allocators"):
                    return False, b"use unknown, or known <independently-trusted-receipt> --retired-old-allocators"
                if authority == "known" and args[3] != receipt:
                    return False, FINGERPRINT
                watch, manifest = copy.deepcopy(saved), saved["manifest"]
                mode = "allocator" if authority == "known" else "monitor"
            if directory.exists():
                return False, b"wallet storage operation failed"
            directory.mkdir(mode=0o700)
            manifest = self.restored(manifest)
            self.write_backup(directory / "backup-restored.tpq", manifest)
            (directory / "watch").mkdir(mode=0o700)
            watch.update(manifest=manifest, mode=mode, receive_next=manifest["retired_receive_end"])
            self.watches[directory / "watch"] = watch
            return self.result({"mode": mode, "authority": authority})
        if command == "sync":
            watch = self.watch(args[0])
            watch["checkpoint"] = self.tip(command, args[1])
            return self.status(watch)
        if command == "status":
            return self.status(self.watch(args[0]))
        if command == "receive":
            watch = self.watch(args[0])
            manifest = watch["manifest"]
            if watch["mode"] == "monitor":
                return False, MONITOR
            if watch["receive_next"] == manifest["receive_end"]:
                return False, b"wallet revision or derivation range exhausted"
            entry = manifest["entries"][watch["receive_next"]]
            watch["receive_next"] += 1
            return True, self.oracle.receiver(bytes.fromhex(entry["policy_hex"])).encode("ascii")
        raise AssertionError(command)

    def status(self, watch):
        return self.result({"mode": watch["mode"], "scan": {"complete_at_checkpoint": watch["checkpoint"] is not None,
            "checkpoint": watch["checkpoint"], "confirmed_zatoshis": sum(watch["coins"])}})
