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

- Each change from the current pinned upstream has a ledger entry.
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

The ledger records two exact upstream commits and trees.
`foundation` is the original Zakura base for product history.
`upstream` is the current Zakura base for the final file comparison.
The current upstream must descend from the foundation and must be merged into the product.
The guard checks all product commits outside the pinned upstream history.
At an upstream merge, it exempts only entries with the same mode and bytes as a merged upstream parent.
It still checks product merge resolutions and both sides of product merges.
Deleted private files and unrelated repository history remain forbidden.
Use `history_only` for former product changes that now match upstream.

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
Record the commit and tree, then remove the clone's source remote.
Disable Git lazy fetching and check the complete local object graph with `git fsck`.
Run later commands with the research checkout and old caches inaccessible.
On macOS, a process sandbox can deny those paths to the command and its children.
Record the sandbox rules and test that forbidden reads fail.

Use an explicit command environment.
Set fresh Cargo, target, temporary and compiler cache directories outside the research checkout.
Disable global and system Git configuration, credential helpers, Python user packages and compiler cache wrappers.
Keep the existing home directory value; do not use its files as build inputs.
Record the preinstalled compiler, SDK and command tools, including their versions and hashes.
These tools are declared prerequisites.

Offline package listing also needs these inputs:

- Registry index metadata, including when Cargo does not compile.
- The declared Git source `PQC-Suite-B/signatures@b392fe82d2d9770142477a576a758a233888bc0a` for the isolated fixture signer.

If you copy registry metadata, record its URL and file hashes.
Do not copy crate archives, extracted registry sources, binaries, or build caches for this check.
Record missing inputs and each retrieval.
Keep the empty-cache audit separate from checks after input retrieval.

For a cold build, do not copy registry metadata either.
Download the locked public inputs into the empty Cargo home with `cargo fetch --locked`.
Fetch the root workspace and the independent fixture signer workspace if the selected checks need both.
Then disable network access and use `--locked --offline` for builds and checks.
Keep the source guard, package lists and dependency guard in that offline stage.
Record each command, its result, dependency inputs, source identity and output hashes.
The first compilation must start with an empty target directory.
Later checks can reuse files created during that run; identify this reuse in the receipt.

These checks do not establish a clean-machine build or reproducible binaries.
`rust-toolchain.toml` selects the changing `stable` channel.
The minimum Rust version is 1.97. No exact compiler release is pinned.
Build receipts record compiler versions, dependencies, features, flags, binaries, and configurations.

## Publication controls

The source repository, [jonwalch/zcash-tpq](https://github.com/jonwalch/zcash-tpq), is private.
GitHub Actions is disabled in this repository, including inherited scheduled jobs.
Binary and package releases are not configured.
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
