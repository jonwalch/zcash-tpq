#!/usr/bin/env python3
"""HUMAN ONLY: adapted pinned research terminal/backup regression suite.

Actual terminal, password/KDF and wallet operations; agents must not execute it.
No build, node, signing, benchmark or private transcript retention is performed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import unicodedata
from common import (AcceptanceError, CONTRACT, fingerprint, object_output, read_json,
                    require, sha256, source_state, validate_build, write_json)
from terminal import new_password, run as terminal_run
from wallet_live import reference

PASSWORD = b"public-cli-test-password"
NEW_PASSWORD = b"another-public-cli-test-password"


def exercise(binary):
    def run(arguments, prompts, success=True):
        return terminal_run(binary, arguments, prompts, success)
    with tempfile.TemporaryDirectory(prefix="pq-wallet-cli-") as temporary:
        directory = Path(temporary)
        profile = directory / "profile.json"
        profile.write_text(json.dumps(reference().sample_manifest()["profile"], sort_keys=True, separators=(",", ":")))
        first, second = directory / "first.tpq", directory / "second.tpq"
        run(["create-slh-exp", profile, first, "0"], new_password(PASSWORD))
        original = first.read_bytes()
        assert first.stat().st_mode & 0o777 == 0o600
        public = run(["inspect", profile, first], [(b"Backup password: ", PASSWORD)])
        assert b'"entries":[]' in public and b'"revision":0' in public
        empty_fingerprint = fingerprint(object_output(public))
        assert b"root_hex" not in public
        run(["inspect", profile, first], [(b"Backup password: ", b"incorrect")], success=False)
        run(["rekey", profile, first, second], [(b"Backup password: ", PASSWORD)] + new_password(NEW_PASSWORD))
        assert first.read_bytes() == original
        # Real command flow: extend a backup before exporting its finite public
        # ranges, authenticate pairing, then reserve receivers across processes.
        extended = directory / "extended.tpq"
        run(["extend", profile, first, extended, "3", "2"], [(b"Backup password: ", PASSWORD)])
        inventory = directory / "inventory.json"
        exported = run(["export", profile, extended, inventory], [(b"Backup password: ", PASSWORD)])
        manifest = json.loads(inventory.read_bytes())
        assert manifest["receive_end"] == 3 and manifest["change_end"] == 2
        assert b"root_hex" not in inventory.read_bytes()
        inventory_fingerprint = hashlib.sha256(b"ZcashTransparentPQ/wallet-inventory/v1\0" + inventory.read_bytes()).hexdigest()
        assert inventory_fingerprint.encode() in exported
        watcher = directory / "watcher"
        run(["watch-create", profile, inventory, "00" * 32, watcher, "allocator"], [], success=False)
        assert not watcher.exists()
        run(["watch-create", profile, inventory, inventory_fingerprint, watcher, "allocator"], [])
        receivers = set()
        for index in range(3):
            run(["watch-import", profile, watcher, inventory, inventory_fingerprint], [])
            receiver = run(["receive", profile, watcher], []).strip()
            assert receiver.startswith(b"tpqreg1") and len(receiver) == 69
            receivers.add(receiver)
            status = json.loads(run(["status", profile, watcher], []))
            assert status["receive_next"] == index + 1
            assert not status["scan"]["complete_at_checkpoint"]
            assert status["scan"]["confirmed_zatoshis"] is None
        assert len(receivers) == 3
        run(["receive", profile, watcher], [], success=False)
        monitor = directory / "monitor"
        run(["watch-create", profile, inventory, inventory_fingerprint, monitor, "monitor"], [])
        run(["receive", profile, monitor], [], success=False)
        run(["sync", profile, monitor, "127.0.0.1:1", "100"], [], success=False)
        assert not json.loads(run(["status", profile, monitor], []))["scan"]["complete_at_checkpoint"]
        reenrolled = directory / "enrolled.tpq"
        run(["enroll", profile, first, inventory, inventory_fingerprint, reenrolled], [(b"Backup password: ", PASSWORD)])
        inspected = run(["inspect", profile, reenrolled], [(b"Backup password: ", PASSWORD)])
        assert json.loads(next(line for line in inspected.splitlines() if line.startswith(b"{"))) == manifest
        assert first.read_bytes() == original
        assert second.read_bytes()[24:52] != original[24:52]
        run(["inspect", profile, second], [(b"Backup password: ", NEW_PASSWORD)])
        run(["inspect", profile, second], [(b"Backup password: ", PASSWORD)], success=False)
        # Previously invalid bytes were silently replaced with U+FFFD before
        # confirmation/KDF. Reject them before publishing any backup generation.
        rejected = directory / "rejected.tpq"
        malformed = b"public-prefix-\xff-public-suffix"
        replacement = "public-prefix-\ufffd-public-suffix".encode()
        run(["create-slh-exp", profile, rejected, "0"], [(b"New backup password: ", malformed)], success=False)
        assert not rejected.exists()
        run(["create-slh-exp", profile, rejected, "0"], [
            (b"New backup password: ", replacement),
            (b"Repeat new password: ", malformed),
        ], success=False)
        assert not rejected.exists()
        for invalid in [b"", b"a" * 1025, b"\x03", b"\x04", b"\x1a"]:
            run(["create-slh-exp", profile, rejected, "0"], [(b"New backup password: ", invalid)], success=False)
            assert not rejected.exists()
        # Exact valid Unicode (including U+FFFD) and whitespace remain distinct
        # from trimmed/normalized passwords. Exercise the entire 1024-byte bound
        # through the real terminal, beyond some canonical terminal line limits.
        exact_password = (" \t" + "e\u0301" * 336 + "\ufffd\U0001f511  \t").encode()
        assert len(exact_password) == 1020
        exact_password += b" end"
        unicode_backup = directory / "unicode.tpq"
        run(["create-slh-exp", profile, unicode_backup, "0"], new_password(exact_password))
        run(["inspect", profile, unicode_backup], [(b"Backup password: ", exact_password)])
        run(["inspect", profile, unicode_backup], [(b"Backup password: ", exact_password.strip())], success=False)
        normalized = unicodedata.normalize("NFC", exact_password.decode()).encode()
        run(["inspect", profile, unicode_backup], [(b"Backup password: ", normalized)], success=False)
        run(["inspect", profile, unicode_backup], [(b"Backup password: ", malformed)], success=False)
        restored = directory / "restored"
        run(["restore", profile, second, empty_fingerprint, restored], [(b"Backup password: ", NEW_PASSWORD)])
        public = run(["inspect", profile, restored / "backup-restored.tpq"], [(b"Backup password: ", NEW_PASSWORD)])
        assert b'"revision":1' in public and b"root_hex" not in public
        assert restored.stat().st_mode & 0o777 == 0o700
        assert first.read_bytes() == original
    print("Rust CLI backup, enrollment, inventory export/pairing, durable receive allocation and unavailable-node controls passed; strict UTF-8, 1024-byte input, cancellation and terminal restoration passed; no passwords echoed or retained artifacts.")


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--human-run", action="store_true", required=True)
    result.add_argument("--cli", type=Path, required=True)
    result.add_argument("--cli-build", type=Path, required=True)
    result.add_argument("--artifacts", type=Path, required=True)
    return result


def main(args):
    require(__debug__, "terminal_controls_require_assertions")
    destination = args.artifacts.resolve()
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    record = {"schema_version": 1, "contract": CONTRACT, "complete": False}
    write_json(destination / "execution.json", record)
    try:
        record["build"] = validate_build(read_json(args.cli_build), args.cli, "wallet-slh")
        before = source_state()
        exercise(args.cli)
        require(source_state() == before, "source_changed_during_terminal_suite")
        require(sha256(args.cli) == record["build"]["binary_sha256"], "binary_changed_during_terminal_suite")
        record.update(complete=True, private_material_deleted=True)
    except BaseException as error:
        # Legacy assertion text may contain parser/terminal details. Keep only
        # a fixed public category; never save passwords, backups or transcripts.
        record["failure"] = str(error) if isinstance(error, AcceptanceError) else type(error).__name__
        raise
    finally:
        write_json(destination / "execution.json", record, fresh=False)


if __name__ == "__main__":
    main(parser().parse_args())
