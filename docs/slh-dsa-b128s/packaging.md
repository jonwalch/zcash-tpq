# Source, builds, and packaging

The distribution unit is the full checkout or source archive.
The seven added product crates and two fixture packages have `publish = false`.
They are not standalone crates.io releases.
Some tests use files elsewhere in the checkout.
Upstream packages retain their release process.

The [import ledger](imports.json) records each changed file, its purpose, hash, and attribution.
Component source maps record revisions and adaptations.
[Node reuse](node-reuse.json) covers node changes.
The product does not depend on the internal research checkout.

## Check release content

Run these commands from a clean, committed checkout with its selected Git history:

```sh
python3 -m unittest discover -s tests/slh-dsa-b128s/release-content -p 'test_*.py' -v
python3 tests/slh-dsa-b128s/release-content/check.py
python3 tests/slh-dsa-b128s/release-content/check.py --packages
```

The guard checks these properties:

- Each change from pinned upstream has a ledger entry.
- Product history and local product refs exclude forbidden imports, including files deleted in later commits.
- Cargo paths stay inside the checkout.
- Added product crates cannot become publishable or acquire alternate PQ dependencies.
- Symlinks resolve to tracked source.
- `git archive HEAD` preserves tracked paths and bytes.
- With `--packages`, Cargo lists only permitted tracked content, including copied README and license files.

`--packages` runs `cargo package --list --locked --offline`.
It does not compile, publish, or run a node or signer.
Dependencies and registry metadata must already be available.
The separate [dependency guard](../../tests/slh-dsa-b128s/dependencies/README.md) checks resolved feature graphs.

Missing Git objects cause failure. The guard disables lazy fetches.
It identifies canonical upstream refs separately and excludes them from the product release.
Hashes permit comparison but cannot replace manual review for secrets and licenses.

Publish only the selected branch.
Do not publish all refs, all tags, or a mirror of a developer clone.

## Update the ledger

Add a purpose, disposition, and provenance row for each new file.
Stage the intended edits.
Run the hash update:

```sh
python3 tests/slh-dsa-b128s/release-content/check.py --refresh-hashes
```

The helper updates existing rows only.
The ledger does not hash itself. Git records its bytes.
Historical receipts apply to their original source and must retain their identities.

Review the ledger diff.
Commit the edits and ledger together.
After integration, check the merged result.

## Check an isolated clone

Create an independent clone with `git clone --no-local --single-branch --no-tags`.
Select the committed product branch.
Check for Git object alternates, external source links, and Cargo paths outside the clone.
Start with empty Cargo home and target directories.
Run the guard tests and archive audit.

Offline package listing also needs these inputs:

- Registry index metadata, including when Cargo does not compile.
- The declared Git source `PQC-Suite-B/signatures@b392fe82d2d9770142477a576a758a233888bc0a` for the isolated fixture signer.

If you copy registry metadata, record its URL and file hashes.
Do not copy crate archives, extracted registry sources, binaries, or build caches for this check.
Record missing inputs and each retrieval.
Keep the empty-cache audit separate from checks after input retrieval.

These checks do not establish a clean-machine build or reproducible binaries.
`rust-toolchain.toml` selects the changing `stable` channel.
The minimum Rust version is 1.97. No exact compiler release is pinned.
Build receipts record compiler versions, dependencies, features, flags, binaries, and configurations.

## Publication controls

The product has no selected remote, visibility, installer, registry namespace, or release owner.
Inherited package names do not select publication destinations.

The inherited `release-binaries.yml` can build `v*` tags in forks.
Its two GitHub publication steps require `SLH_RELEASE_PUBLICATION == 'enabled'` in the repository variables.
Upstream retains its original behavior.
The variable is disabled by default in a new product repository.
It neither selects a destination nor establishes acceptance.

Before publication, review the destination, release metadata, and test evidence.
Do not dispatch inherited upstream release or deployment workflows for this fork.
Do not install upstream credentials.

Build triggers, staged artifacts, checksums, and existing Docker/Cargo guards remain.
The added `SLH source content` workflow checks source and archives.
It performs no heavy build, live test, or upload.
