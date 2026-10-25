# Source, builds, and packaging

The distribution unit is the full checkout or source archive.
The eight added product crates and two fixture packages have `publish = false`.
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

## Experimental node images

The default Docker feature set does not enable SLH. An explicitly selected
experimental node image uses the repository runtime target and these features:

```sh
docker build --target runtime \
  --build-arg FEATURES=default-release-binaries,experimental-slh-dsa-b128s \
  -f docker/Dockerfile .
```

This is a dedicated container build and requires explicit approval before an
agent runs it. The command is not a live qualification receipt.

The release stage mounts every Cargo workspace member, including the wallet
and fixture manifests. Cargo needs those manifests even when it only builds
the node package. The narrow fixture exception in `.dockerignore` provides
that member's source; it does not enable its optional proof-generation feature.
Only node executables are copied into the runtime image. The node dependency
guard remains responsible for excluding wallet signing and fixture dependencies
from the node runtime graph.

The release-content unit suite reconstructs this mounted workspace and runs
offline Cargo metadata without compiling. This catches missing source mounts,
but does not qualify Docker execution, image provenance or running-node support.

Missing Git objects cause failure. The guard disables lazy fetches.
It identifies canonical upstream refs separately and excludes them from the product release.
Hashes permit comparison but cannot replace manual review for secrets and licenses.

The ledger records two exact upstream commits and trees.
`foundation` is the original Zakura base for product history.
`upstream` is the current Zakura base for the final file comparison.
The current upstream must descend from the foundation. Integration requires
upstream ancestry or the exact authenticated squash record below.
The guard checks all product commits outside the pinned upstream history.
At an upstream merge, it exempts only entries with the same mode and bytes as a merged upstream parent.
It still checks product merge resolutions and both sides of product merges.
At a product merge, it can reuse an exact entry from a non-first product parent.
It still audits every commit on that parent's history, including the entry's
original introduction. It reports reused product entries separately from
authenticated upstream entries.
Deleted private files and unrelated repository history remain forbidden.
Use `history_only` for former product changes that now match upstream.

PR #12 imported the previous upstream through a GitHub squash merge. Its commit
has no upstream parent. The guard records this exact historical association:

| Item | Pinned value |
| --- | --- |
| Product squash commit | `de7880372c50bbb285a622bcc4e577df7b35ca7d` |
| Product squash tree | `bc284612ef8b367a9c364019b89f8bd366d2318f` |
| Sole product parent | `91d2e2132fe9e9cacdde20362489c8462cf94baf` |
| Imported upstream commit | `e33dc43089acca2fe2c6516927932f2b7618b8bc` |
| Imported upstream tree | `88637ce09b0bbd5669b664e47b20b37b35523323` |

The record applies only when that exact product commit is in the selected
history. The guard checks its tree, sole parent, and upstream pins. At that
commit only, it exempts entries with the same mode, object kind, and bytes as
the pinned upstream tree. Other entries still need a product disposition.
An unrecorded commit cannot use this exception, even if its tree is identical.
The record also establishes integration of that recorded upstream when later
feature PRs are squashed onto this imported base. It cannot establish integration
of a newer upstream. The current update restores the recorded upstream ancestry
with a tree-preserving merge, then merges the new upstream normally.
Without that authenticated record, the upstream must be a real ancestor.
Both paths require the exact upstream commit and tree as local audit inputs.
Local Git tests cover changed entries, invalid records, unselected and later
commits, later feature and fix squashes, and deleted private files on merged
side branches.

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
Squash merges can leave the pinned upstream object outside product ancestry.
Before the offline audit, retrieve the current upstream and its history. This
also supplies the previous upstream object needed to authenticate PR #12:

```sh
git fetch --no-tags https://github.com/zakura-core/zakura.git b1dd280d1b5a4d70bd3d7b682a3f7fd37cd25f73
```

The content CI uses the same explicit input step. This adds no upstream branch
or tags to the product. The audit checks the commit, tree, and foundation
relationship; it never fetches missing objects itself.

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

The source repository, [jonwalch/zcash-tpq](https://github.com/jonwalch/zcash-tpq), is public.
Its workflow definitions are active. A branch push or pull request can start
automatic CI; this does not authorize manual heavy workflow dispatch or reruns.
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
