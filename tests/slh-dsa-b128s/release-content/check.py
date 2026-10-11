#!/usr/bin/env python3
"""Offline source/publication audit. Never builds, signs, runs nodes or publishes.

Reuse: pinned research pq_node_provenance's exact source/input association and
the product fixture module's bounded strict JSON and canonical hashing. See NOTICE.
"""
import argparse
import fnmatch
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tests/slh-dsa-b128s/fixtures"))
from generate_transactions import canonical, strict_json  # noqa: E402

FOUNDATION = "9b175e9d3d46a6aa4cfb5552517c3d828852ecbc"
FOUNDATION_TREE = "ac1ad49b6262001d4c07b7458f9638859cc75c36"
UPSTREAM = "a29a968575e37223cbeb8ac7a5d57aba135fb93a"
UPSTREAM_TREE = "dbf61abd2440d12929350572894860a58a16a29e"
LEDGER = "docs/slh-dsa-b128s/imports.json"
KINDS = {"adapted", "new", "upstream-modification", "public-fixture", "attribution"}
PRODUCT_PACKAGES = {"zakura-pq-cli", "zakura-pq-wallet", "zakura-pq-slh-dsa-b-sign",
    "zakura-pq-slh-dsa-b-verify", "zakura-pq-slh-dsa-b-exp", "zakura-pq-tx-context",
    "zakura-pq-test-support", "slh-dsa-b128s-fixture-host", "slh-dsa-b128s-public-fixture"}
ALTERNATE = re.compile(r"(?:ml[-_]?dsa|sqisign|falcon|fips20[45])", re.I)
FORBIDDEN_PARTS = {".context", "experiments", "node_modules", "__pycache__", "target"}
PUBLICATION_GATE = "vars.SLH_RELEASE_PUBLICATION == 'enabled'"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git(root, *args):
    # A partial checkout must fail explicitly rather than acquire unrecorded input.
    environment = dict(os.environ, GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0")
    return subprocess.check_output(["git", "-C", str(root), *args], env=environment, timeout=120)


def path_name(value):
    require(type(value) is str and value and "\\" not in value and "\0" not in value,
            "invalid repository path")
    path = PurePosixPath(value)
    require(not path.is_absolute() and all(part not in ("", ".", "..") for part in value.split("/")),
            "path escapes repository: " + value)
    return path


def product_path(value):
    path = path_name(value)
    require(not FORBIDDEN_PARTS.intersection(path.parts), "private/generated path: " + value)
    require(not value.startswith(("docs/remaining/", "docs/archive/", "node/zakura/")),
            "research overlay/planning path: " + value)
    require(not ALTERNATE.search(value), "alternate scheme path: " + value)


def tree(root, revision):
    rows = {}
    for item in git(root, "ls-tree", "-r", "-z", revision).split(b"\0"):
        if not item:
            continue
        header, name = item.split(b"\t", 1)
        mode, kind, oid = header.decode("ascii").split()
        name = name.decode("utf8")
        path_name(name)
        rows[name] = (mode, kind, oid)
    return rows


def blob(root, oid):
    return git(root, "cat-file", "blob", oid)


def changed_paths(base, current):
    return {path for path in base.keys() | current.keys() if base.get(path) != current.get(path)}


def validate_ledger(record, base, current, root):
    require(set(record) == {"schema_version", "foundation", "foundation_tree", "upstream", "upstream_tree",
                            "files", "history_only", "note"},
            "import ledger fields")
    require(type(record["schema_version"]) is int and record["schema_version"] == 2
            and record["foundation"] == FOUNDATION and record["foundation_tree"] == FOUNDATION_TREE
            and record["upstream"] == UPSTREAM and record["upstream_tree"] == UPSTREAM_TREE, "ledger pin")
    require(type(record["files"]) is list and type(record["history_only"]) is list, "ledger arrays")
    mapped = set()
    for row in record["files"]:
        require(set(row) == {"path", "sha256", "disposition", "reason", "provenance"}, "ledger entry fields")
        path = row["path"]
        product_path(path)
        require(path not in mapped and path in current, "duplicate/missing ledger path: " + path)
        mapped.add(path)
        require(row["disposition"] in KINDS and type(row["reason"]) is str and bool(row["reason"].strip()),
                "missing import disposition: " + path)
        require(type(row["provenance"]) is list and bool(row["provenance"]), "missing provenance: " + path)
        for reference in row["provenance"]:
            path_name(reference)
            require(reference in current, "missing provenance file: " + reference)
        require(re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is not None
                and sha(blob(root, current[path][2])) == row["sha256"], "stale import hash: " + path)
    # The ledger cannot contain its own hash. Git's selected tree binds it.
    expected = changed_paths(base, current) - {LEDGER}
    require(mapped == expected, "unmapped/unexpected changed files: " + repr(sorted(mapped ^ expected)))
    for row in record["history_only"]:
        require(set(row) == {"path", "reason"} and row["reason"], "historical disposition")
        product_path(row["path"])
        require(row["path"] not in mapped, "history path still present")
    return mapped | {row["path"] for row in record["history_only"]} | {LEDGER}


def resolve_path(origin, value):
    require(type(value) is str and value and not Path(value).is_absolute() and "\\" not in value
            and re.match(r"^[A-Za-z]:", value) is None,
            "absolute or invalid dependency path")
    parts = list(PurePosixPath(origin).parent.parts)
    for part in value.split("/"):
        if part == "..":
            require(bool(parts), "dependency escapes checkout")
            parts.pop()
        elif part not in ("", "."):
            parts.append(part)
    return "/".join(parts)


def manifest_paths(path, data, names, *, added, require_tracked_paths=True):
    manifest = tomllib.loads(data.decode("utf8"))
    package = manifest.get("package", {})
    if added and package:
        require(package.get("name") in PRODUCT_PACKAGES, "unapproved product crate: " + str(package.get("name")))
        require(package.get("publish") is False, "experimental crate can publish: " + path)
    build = package.get("build", False)
    require(build is False or isinstance(build, str), "invalid package build path")
    if isinstance(build, str):
        target = resolve_path(path, build)
        if require_tracked_paths:
            require(target in names, "package build script outside tracked source")
    workspace = manifest.get("workspace", {})
    for field in ("members", "default-members", "exclude"):
        values = workspace.get(field, [])
        require(type(values) is list, "workspace path list")
        for value in values:
            target = resolve_path(path, value)
            # Cargo permits glob patterns and excludes with no current match.
            # Every form must stay inside the checkout, even when unmatched.
            if field != "exclude" and require_tracked_paths:
                pattern = target + "/Cargo.toml" if target else "Cargo.toml"
                require(any(fnmatch.fnmatchcase(name, pattern) for name in names), "workspace member not tracked")

    def walk(value):
        if not isinstance(value, dict):
            return
        for key, item in value.items():
            if key in ("dependencies", "dev-dependencies", "build-dependencies") and isinstance(item, dict):
                for name, specification in item.items():
                    require(not ALTERNATE.search(name), "alternate dependency: " + name)
                    if isinstance(specification, dict):
                        require(not ALTERNATE.search(specification.get("package", name)), "renamed alternate dependency")
                        if "git" in specification:
                            require("zcash-transparent-pq" not in specification["git"], "research Git dependency")
                        if "path" in specification:
                            target = resolve_path(path, specification["path"]) + "/Cargo.toml"
                            if require_tracked_paths:
                                require(target in names, "untracked/outside dependency: " + target)
            walk(item)
    walk(manifest)
    # Includes patches/replacements, package build scripts and workspace membership.
    def paths(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "path" and isinstance(item, str):
                    target = resolve_path(path, item)
                    if require_tracked_paths:
                        require(target in names or target + "/Cargo.toml" in names, "manifest path missing: " + target)
                if key == "git" and isinstance(item, str):
                    require("zcash-transparent-pq" not in item, "research Git source")
                paths(item)
        elif isinstance(value, list):
            for item in value:
                paths(item)
    paths(manifest)
    return package.get("name")


def verify_paths(root, base, current, changed, *, require_tracked_paths=True):
    packages = []
    for path, (mode, kind, oid) in current.items():
        require(kind == "blob", "submodule in source tree: " + path)
        if mode == "120000":
            target = resolve_path(path, blob(root, oid).decode("utf8"))
            require(target in current or any(name.startswith(target + "/") for name in current),
                    "symlink target outside tracked tree: " + path)
        if path in changed:
            product_path(path)
            require(mode in ("100644", "100755"), "product symlink/submodule: " + path)
        if path.endswith("Cargo.toml"):
            name = manifest_paths(path, blob(root, oid), current, added=path not in base,
                                  require_tracked_paths=require_tracked_paths)
            if path in changed and name:
                packages.append((path, name))
    return packages


def ancestor(root, earlier, later):
    return subprocess.run(["git", "-C", str(root), "merge-base", "--is-ancestor", earlier, later],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                          env=dict(os.environ, GIT_NO_LAZY_FETCH="1"), timeout=120).returncode == 0


def history(root, base, allowed):
    # The current baseline defines the final delta, but old product commits
    # descend from the original foundation, not later upstream releases.
    revisions = git(root, "rev-list", "HEAD", "^" + UPSTREAM).decode().splitlines()
    paths = set()
    upstream_entries = 0
    for revision in revisions:
        require(ancestor(root, FOUNDATION, revision),
                "foreign ancestry in selected history")
        parents = git(root, "rev-list", "--parents", "-n", "1", revision).decode().split()[1:]
        require(bool(parents), "foreign root commit")
        previous = tree(root, parents[0])
        state = tree(root, revision)
        touched = changed_paths(previous, state)
        # Only exact entries from a merged, pinned upstream ancestor are
        # inherited. A merge resolution with different bytes is product work.
        inherited = [tree(root, parent) for parent in parents[1:] if ancestor(root, parent, UPSTREAM)]
        for path in touched:
            if any(state.get(path) == upstream.get(path) for upstream in inherited):
                upstream_entries += 1
                continue
            require(path in allowed, "unreviewed historical path: " + path)
            product_path(path)
            if path in state:
                require(state[path][0] in ("100644", "100755"), "historical product symlink: " + path)
                if path.endswith("Cargo.toml"):
                    # A registration-only commit can precede its target source
                    # merge. Historical paths must remain bounded; final-tree
                    # path existence is enforced by verify_paths above.
                    manifest_paths(path, blob(root, state[path][2]), state, added=path not in base,
                                   require_tracked_paths=False)
            paths.add(path)
    return {"commits": len(revisions), "changed_paths": len(paths),
            "commits_sha256": sha(canonical(sorted(revisions))), "foundation": FOUNDATION,
            "upstream": UPSTREAM, "inherited_merge_entries": upstream_entries}


def refs(root):
    rows = []
    for line in git(root, "for-each-ref", "--format=%(refname) %(objectname)").decode().splitlines():
        name, oid = line.split()
        contained = subprocess.run(["git", "-C", str(root), "merge-base", "--is-ancestor", oid, "HEAD"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
        rows.append({"ref": name, "object": oid, "included_in_selected_ancestry": contained})
    return rows


def other_ref_history(root):
    """Inspect unpublished worker refs too, exempting known upstream refs.

    The upstream remote URL must be canonical; its refs are inventoried, not
    shipped. A clean single-branch clone has no such exemptions or worker refs.
    """
    upstream_refs = git(root, "for-each-ref", "--format=%(refname)", "refs/remotes/upstream/").decode().splitlines()
    if upstream_refs:
        require(git(root, "remote", "get-url", "upstream").decode().strip()
                == "https://github.com/zakura-core/zakura.git", "unrecognized upstream ref source")
    extra = git(root, "rev-list", "--all", "--not", "HEAD", *upstream_refs).decode().splitlines()
    for revision in extra:
        require(ancestor(root, FOUNDATION, revision),
                "foreign ancestry on unselected ref")
        state = tree(root, revision)
        # Workers may predate the refresh. Compare each against its own
        # authenticated upstream ancestor, never an unrelated remote tip.
        baseline = git(root, "merge-base", UPSTREAM, revision).decode().strip()
        base = tree(root, baseline)
        verify_paths(root, base, state, changed_paths(base, state), require_tracked_paths=False)
    return {"extra_product_commits": len(extra), "extra_commits_sha256": sha(canonical(sorted(extra))),
            "upstream_refs_excluded_from_publication": upstream_refs}


def archive(root, current):
    observed = set()
    with tempfile.TemporaryFile() as stream:
        subprocess.run(["git", "-C", str(root), "archive", "--format=tar", "HEAD"], stdout=stream,
                       check=True, timeout=120, env=dict(os.environ, GIT_NO_LAZY_FETCH="1"))
        stream.seek(0)
        with tarfile.open(fileobj=stream, mode="r|") as packed:
            for member in packed:
                if member.isdir():
                    continue
                path_name(member.name)
                require(member.name in current and member.name not in observed, "archive path inventory")
                observed.add(member.name)
                mode, _, oid = current[member.name]
                if member.issym():
                    require(mode == "120000" and member.linkname.encode() == blob(root, oid), "archive symlink")
                else:
                    require(member.isfile() and mode in ("100644", "100755"), "archive member type")
                    source = packed.extractfile(member)
                    require(source is not None, "missing archive bytes")
                    require(hashlib.file_digest(source, "sha256").hexdigest() == sha(blob(root, oid)), "archive bytes differ")
    require(observed == set(current), "archive omits tracked files")
    return {"files": len(observed), "paths_sha256": sha(canonical(sorted(observed)))}


def package_lists(root, packages, current):
    results = []
    for manifest, name in packages:
        command = ["cargo", "package", "--list", "--locked", "--offline", "--manifest-path", manifest]
        output = subprocess.check_output(command, cwd=root, timeout=120, stderr=subprocess.PIPE).decode().splitlines()
        specification = tomllib.loads(blob(root, current[manifest][2]).decode())["package"]
        copied = {}
        # Cargo copies explicitly named repository README/license files to the
        # package root. These remain tracked source, not untracked payloads.
        for field in ("readme", "license-file"):
            value = specification.get(field)
            if isinstance(value, str):
                target = resolve_path(manifest, value)
                require(target in current, "package companion outside tracked source")
                copied[PurePosixPath(value).name] = target
        validate_package_list(manifest, output, current, copied)
        results.append({"package": name, "manifest": manifest, "files": output, "command": command,
                        "copied_manifest_files": copied})
    return results


def validate_package_list(manifest, output, current, copied=None):
    require(bool(output) and len(output) == len(set(output)), "empty/duplicate package listing")
    parent = PurePosixPath(manifest).parent
    for relative in output:
        path_name(relative)
        if relative in (".cargo_vcs_info.json", "Cargo.lock", "Cargo.toml", "Cargo.toml.orig"):
            continue
        if relative in (copied or {}):
            require(copied[relative] in current, "untracked package companion")
            continue
        target = str(parent / relative)
        require(target in current, "untracked package payload: " + target)


def publication_guard(root, current):
    path = ".github/workflows/release-binaries.yml"
    text = blob(root, current[path][2]).decode()
    for step in ("Ensure release exists", "Upload assets to release"):
        condition = text.split("- name: " + step + "\n", 1)[1].splitlines()[0].strip()
        require(condition == "if: ${{ !inputs.stage_release_assets && (github.repository == 'zakura-core/zakura' || "
                + PUBLICATION_GATE + ") }}", "fork GitHub publication condition changed: " + step)
    return {"workflow": path, "fork_gate": PUBLICATION_GATE, "default": "disabled"}


def validate_baselines(root):
    require(git(root, "rev-parse", FOUNDATION + "^{tree}").decode().strip() == FOUNDATION_TREE,
            "foundation tree mismatch")
    require(git(root, "rev-parse", UPSTREAM + "^{tree}").decode().strip() == UPSTREAM_TREE, "upstream tree mismatch")
    require(ancestor(root, FOUNDATION, UPSTREAM), "upstream does not descend from foundation")
    require(ancestor(root, UPSTREAM, "HEAD"), "current upstream is not integrated")


def check(root, *, packages=False):
    root = root.resolve()
    require(not git(root, "status", "--porcelain", "--untracked-files=all"), "commit product inputs before auditing")
    validate_baselines(root)
    base, current = tree(root, UPSTREAM), tree(root, "HEAD")
    require(LEDGER in current, "import ledger missing")
    record = strict_json(blob(root, current[LEDGER][2]), 4 * 1024 * 1024)
    allowed = validate_ledger(record, base, current, root)
    changed = changed_paths(base, current)
    candidates = verify_paths(root, base, current, changed)
    result = {"schema_version": 2, "source_commit": git(root, "rev-parse", "HEAD").decode().strip(),
        "source_tree": git(root, "rev-parse", "HEAD^{tree}").decode().strip(), "upstream": UPSTREAM,
        "upstream_tree": UPSTREAM_TREE, "foundation": FOUNDATION, "foundation_tree": FOUNDATION_TREE,
        "ledger_sha256": sha(blob(root, current[LEDGER][2])), "tracked_files": len(current),
        "changed_files": len(changed), "history": history(root, tree(root, FOUNDATION), allowed), "refs": refs(root),
        "unselected_ref_audit": other_ref_history(root),
        "archive": archive(root, current), "publication": publication_guard(root, current),
        "package_lists": package_lists(root, candidates, current) if packages else None}
    require(not git(root, "status", "--porcelain", "--untracked-files=all"), "audit modified source")
    return result


def refresh(root):
    """Refresh existing reviewed rows only. New paths require explicit disposition."""
    path = root / LEDGER
    record = strict_json(path.read_bytes(), 4 * 1024 * 1024)
    require(not git(root, "ls-files", "--others", "--exclude-standard"), "stage new files before refreshing")
    changed = set(git(root, "diff", "--name-only", UPSTREAM).decode().splitlines()) - {LEDGER}
    mapped = {row["path"] for row in record["files"]}
    require(changed == mapped, "add explicit dispositions before refreshing: " + repr(sorted(changed ^ mapped)))
    for row in record["files"]:
        require(not (root / row["path"]).is_symlink(), "refuse symlink while refreshing")
        row["sha256"] = sha((root / row["path"]).read_bytes())
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packages", action="store_true", help="also inspect Cargo file lists; never compile")
    parser.add_argument("--refresh-hashes", action="store_true", help="update existing dispositions, refusing unmapped paths")
    args = parser.parse_args()
    if args.refresh_hashes:
        refresh(ROOT)
    else:
        print(json.dumps(check(ROOT, packages=args.packages), indent=2, sort_keys=True))
