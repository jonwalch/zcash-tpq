# Source and packaging audit

The delivery unit is a curated upstream-Zakura source repository. The upstream
commit/tree, optional SLH code, standalone public test signer and public corpus
are pinned. The [import ledger](imports.json) gives each changed file a current
hash, disposition, reason and a local provenance reference. Existing module
source maps retain detailed algorithm/source hashes and licenses;
[node reuse](node-reuse.json) records the selective node mechanisms. No internal
planning or agent review material is needed to build or inspect this product.

## Reusable checks

Run from a clean, committed checkout with full selected ancestry:

```sh
python3 -m unittest discover -s tests/slh-dsa-b128s/release-content -p 'test_*.py' -v
python3 tests/slh-dsa-b128s/release-content/check.py
python3 tests/slh-dsa-b128s/release-content/check.py --packages
```

The last command asks Cargo only for `package --list --locked --offline` for
the added/changed package manifests, including the isolated signer. It does
not compile, create a release, upload a crate, run a daemon, or execute a test
signer. Package verification builds are not part of this check. The distribution
unit is the complete checkout/source archive: unpublished crates' tests may
intentionally consume repository-relative public fixtures outside their individual
Cargo file lists. Cargo also copies explicitly named repository README/license
files into a package; those companions are checked against tracked source.
This audit makes no standalone-crate compilation claim. Inherited
unchanged packages, including the generated upstream `zakura-assets` payload,
retain their existing release process and are not relabeled as SLH packages.

The guard checks the selected tree against the exact upstream tree, requires a
complete changed-file ledger, and inspects every post-upstream commit so that
deleting an accidentally committed experiment does not hide it. It verifies
normal/dev/build/target/patch Cargo paths, rejects alternate backend dependencies
and newly publishable product crates, and requires symlinks to resolve within
tracked source. The existing dependency guard separately checks resolved feature
graphs. A streamed `git archive HEAD` must contain the tracked bytes and paths;
actual Cargo listings must not introduce untracked package payloads.

Every ref is inventoried. Unselected product commits are checked for foreign
ancestry and forbidden/path-dependent contents too. Existing upstream remote
refs are recognized only with the canonical upstream remote URL; their contents
are inherited, excluded from the selected release, and not turned into SLH
cleanup gates. Publish only a deliberately selected branch, never a mirror or
`--all`/`--tags` push of a developer repository. An isolated `--single-branch
--no-tags` clone has no worker or unrelated upstream branch refs. Git lazy
fetching is disabled during the audit: missing objects are an explicit failure.

For a change to an already reviewed file, stage the intended changes and run
`python3 tests/slh-dsa-b128s/release-content/check.py --refresh-hashes`, then
review the ledger diff and commit both. The helper refuses new/unmapped paths.
Add an explicit disposition/reason/provenance row for each new file first;
history-only rows are for reviewed removed product paths, never private notes
or experiments. The ledger excludes its own hash; the selected Git tree binds
that file. Integration must refresh and re-audit sibling additions, so a worker
receipt is not automatically a receipt for the merged release tree.

Hashes and allowlists establish traceability and catch regressions; they cannot
prove arbitrary source text contains no secret or that an attribution is legally
complete. Review newly added files and imported licenses. Public deterministic
fixture keys are test material, never operational wallet secrets. Historical
test receipts keep their original source/binary/config identity; a content pass
does not change their covered inputs or establish target execution.

## Isolated clone validation

Create a temporary ordinary clone of the selected committed branch using
`git clone --no-local --single-branch --no-tags`. Confirm there is no Git object
alternate, symlink to another checkout, worktree dependency or Cargo path outside
the clone. Start with an empty Cargo home/target; no node build is needed. The
bounded guard tests and archive audit must succeed without a research checkout
or source download. Cargo's offline `package --list` also requires registry index
metadata even though it does not compile or need crate source payloads. Record
an empty-cache failure as a missing metadata prerequisite. For offline listings,
an existing registry index can be copied into the isolated Cargo home: record
its original registry URL and every copied file hash, and exclude crate archives,
extracted sources, binaries and target caches. Keep the package-list receipt
separate from the empty-cache source audit; do not claim empty-cache package
success. If source bytes are also required, report that exact prerequisite
instead of silently downloading them. Keep all source/command/output hashes in
the release validation record.

The audit is allowed to fail on missing source objects, missing toolchains or a
package-list prerequisite. Report that specific limit; do not compensate by
running live suites, changing upstream packages, fetching unrecorded inputs or
claiming a warmed developer checkout is an isolated result.

## Publication boundary

All seven new product crates and both fixture packages have `publish = false`.
Existing upstream package names and repository metadata are preserved. They are
not new product registry destinations. The product remote, visibility, installer,
registry namespace and release ownership have not been selected by this audit.

The inherited `release-binaries.yml` can build on `v*` tags in forks. Its GitHub
release create/upload/delete-asset steps previously ran in those forks too,
even though upstream Cargo/Docker publication already had repository guards.
This extension gates exactly those two GitHub publication steps with repository
variable `SLH_RELEASE_PUBLICATION == 'enabled'`; upstream's own repository keeps
its prior behavior. The default in a new product repository is disabled. Build
triggers, checksum/manifest creation, staged workflow artifacts, provenance and
existing Docker/Cargo checks are retained. This variable does not select a
destination or establish acceptance; configure it only after a separate release
review of the chosen repository, release metadata and validation evidence.

Inherited manual `create-release`, release-drafter, registry and deployment
workflows are upstream operator tooling. They are not approved product release
or deployment entry points. Do not provision their upstream credentials or
dispatch them for this experimental fork. The new `SLH source content` workflow
only runs bounded Python/source/archive checks with read-only permissions; it
adds no heavy build or live workload and uploads nothing.
