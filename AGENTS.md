# SLH extension rules

These rules take precedence over the inherited upstream command examples below.
This repository adds experimental SLH-DSA-B-128s and a 20 MB devnet block limit
to pinned upstream Zakura.
Use plain English guided by ASD-STE100 for SLH docs and the root README, aiming
for 80% rather than strict conformity. Follow `docs/slh-dsa-b128s/writing.md`.
Preserve inherited documentation, historical evidence, and license text.

Read `docs/slh-dsa-b128s/protocol.md`. Preserve canonical encoding, trusted UTXO
resolution, existing classical/shielded behavior, source pins and attribution.
Reuse existing code and tests with the smallest necessary adaptations. Record
the reason and regression coverage for new behavior or rewritten modules.
Use the coordinator's pinned research source as the first reference for modules,
APIs, command flows and tests. Preserve coherent working mechanisms where they
fit; record source mappings and justify necessary SLH adaptations. Attribution
does not authorize importing research notes, history or alternate backends, or a
runtime dependency on a research checkout.

Focus implementation and review fixes on failures and regressions introduced by
this SLH extension. Check suspected inherited issues against pinned upstream
Zakura. Do not undertake general upstream cleanup or make unrelated existing bugs
completion gates; record them separately. Make a minimal upstream change only
when this integration exposes a failure or it directly blocks the requested SLH
implementation.

Keep experimental SLH support off by default and Regtest-only. The 20 MB block
limit applies to all network configurations in this devnet fork. This exception
does not enable SLH on public networks. Node dependencies
must not include key generation, signing, alternate PQ backends, fixture tools
or a dependency on an external research checkout. Never add research notes,
experiments, raw results, real secrets or research Git history to this repository.

Workers commit locally for coordinator integration; only the coordinator may
deliver integrated changes to a designated product remote. Do not push upstream
Zakura or infer that an unrelated repository's origin is the product destination.
Preserve assigned branches. The coordinator owns shared manifests, lockfiles,
feature wiring and cross-lane integration; obtain ownership before editing a
shared file. Use a separate working tree per worker.

Heavy validation requires explicit user approval before agent execution. When a
task needs heavy validation, prepare the exact commands and scope, explain why
the run is needed, and ask the user for approval. Wait for the answer before
running it; do not silently skip the check. Approval already given in the
conversation remains valid for the approved scope. Record runs that await
approval or that the user declines as pending, with the reason.
This applies to dedicated node/container builds, live node/Regtest drivers,
wallet live payment/recovery/discovery or terminal backup suites, Docker
restart/reorg suites, real shielded-proof fixture generation, profiling,
large-context workloads and full performance matrices. It includes wrappers,
background/delegated runs and manual CI dispatch/reruns.
Existing automatic CI is exempt; do not change CI triggers to bypass this rule.
Review inherited release/deployment automation before publishing to a new remote.

Agents may run proportional focused Rust/library/crypto/corpus tests, mocked
Python unit tests, dependency/provenance guards and bounded comparisons. For
changed packages run formatting, locked focused tests and clippy with warnings
denied, selecting packages explicitly; do not use the full-workspace or live
commands below as blanket authorization. Serialize substantial compilations on
the shared host. Preserve independent crypto/digest references and mutation
controls. Identify checks not run and their reasons precisely.

Unchanged proof-covered approval source retains only its recorded existing proof
scope. A change to covered source requires a checker consuming these actual
target files; never edit generated proofs or add admissions. Never claim crypto
or target execution proved by an unrelated source-checkout run.

# Zakura — Agent Guidelines

> This file is read by AI coding agents (Claude Code, GitHub Copilot, Cursor, Devin, etc.).
> It provides project context and contribution policies.

# Working in This Repository

- Keep changes focused and avoid unrelated refactors.
- Run formatting and the checks relevant to the code you changed.
- For fixes, explain the root cause, how the solution addresses it, and how the tests exercise the affected behavior.

## Project Structure & Module Organization

Zakura is a Rust workspace; the member crates live under `crates/`. Main crates include:

`crates/zakura-assets/` is a publish-only packaging crate and is deliberately excluded from the workspace because its payload is generated and not committed.

- `crates/zakurad/` (node CLI/orchestration),
- core libraries like `crates/zakura-chain/`, `crates/zakura-consensus/`, `crates/zakura-network/`, `crates/zakura-state/`, `crates/zakura-rpc/`, `crates/zakura-script/`,
- support crates like `crates/zakura-node-services/`, `crates/zakura-test/`, `crates/zakura-utils/`, `crates/zakura-jsonl-trace/`, `crates/tower-batch-control/`, `crates/tower-fallback/`, and `crates/xtask/`.

Code is primarily in each crate's `src/`; integration tests are in `crates/*/tests/`; many unit/property tests are colocated in `src/**/tests/` (for example `prop.rs`, `vectors.rs`, `preallocate.rs`). Documentation is in `docs/` and crate READMEs. CI and policy automation live in `.github/workflows/`.

## Build, Test, and Development Commands

Choose checks that are proportional to the change. Workspace-wide commands are useful for broad or cross-crate changes:

```bash
# Optional full build check
cargo build --workspace --locked

# Formatting, linting, and workspace tests
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# Run a single crate's tests
cargo test -p zakura-chain
cargo test -p zakura-state

# Run a single test by name
cargo test -p zakura-chain -- test_name

# CI-like nextest profile for broad coverage
cargo nextest run --profile all-tests --locked --release --features default-release-binaries --run-ignored=all

# Run with nextest (integration profiles)
cargo nextest run --profile zakura-integration
```

## Commit & Pull Request Guidelines

- PR titles must follow [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/#specification) (PRs are squash-merged — the PR title becomes the commit message)
- Use `.github/pull_request_template.md`. For fixes, connect the root cause to both the solution and the test coverage.
- Every PR that changes a Rust source file or any `Cargo.toml` adds one
  `docs/changelog/unreleased/<PR-number>.md` fragment, including an explicit
  no-changelog fragment for internal-only work. Do not edit the shared
  changelog in ordinary PRs. See `docs/changelog/guidelines.md`.

## Project Overview

Zakura is a Zcash full node implementation in Rust. It is a validator node — it excludes features not strictly needed for block validation and chain sync.

- **Rust edition**: 2021
- **MSRV**: 1.97 (unified across the internal crates and the zakurad binary)
- **Database format version**: defined in `crates/zakura-state/src/constants.rs`

## Crate Architecture

```text
zakurad (CLI orchestration)
  ├── zakura-consensus (block/transaction verification)
  │     └── zakura-script (script validation in Rust)
  ├── zakura-state (finalized + non-finalized storage)
  ├── zakura-network (P2P, peer management)
  └── zakura-rpc (JSON-RPC + gRPC)
        └── zakura-node-services (service trait aliases)
              └── zakura-chain (core data types, no async)
```

**Dependency rules**:

- Dependencies flow **downward only** — lower crates must not depend on higher ones
- `zakura-chain` is **sync-only**: no async, no tokio, no Tower services
- `zakura-node-services` defines service trait aliases used across crates
- `zakurad` orchestrates all components but contains minimal logic
- Utility crates: `tower-batch-control`, `tower-fallback`, `zakura-test`

### Per-Crate Concerns

| Crate | Key Concerns |
| --- | --- |
| `zakura-chain` | Serialization correctness, no async, consensus-critical data structures |
| `zakura-network` | Protocol correctness, peer handling, rate limiting, DoS resistance |
| `zakura-consensus` | Verification completeness, error handling, checkpoint vs semantic paths |
| `zakura-state` | Read/write separation (`ReadRequest` vs `Request`), database migrations |
| `zakura-rpc` | zcashd compatibility, error responses, timeout handling |
| `zakura-script` | Script execution, signature callbacks, consensus sigop accounting |

## Coding Style & Naming Conventions

- Rust 2021 conventions and `rustfmt` defaults apply across the workspace (4-space indentation).
- Naming: `snake_case` for functions/modules/files, `CamelCase` for types/traits, `SCREAMING_SNAKE_CASE` for constants.
- Respect the workspace lint policy (`[workspace.lints]` in the root `Cargo.toml`) and the crate-level lint attributes at the top of each crate's `lib.rs`.
- Keep dependencies flowing downward across crates; maintain `zakura-chain` as sync-only.

## Code Patterns

### Tower Services

All services must include these bounds:

```rust
S: Service<Req, Response = Resp, Error = BoxError> + Send + Clone + 'static,
S::Future: Send + 'static,
```

- `poll_ready` must check all inner services
- Clone services before moving into async blocks

### Error Handling

- Use `thiserror` with `#[from]` / `#[source]` for error chaining
- `expect()` messages must explain **why** the invariant holds, not what happens if it fails:

  ```rust
  .expect("block hash exists because we just inserted it")  // good
  .expect("failed to get block")                            // bad
  ```

- Don't turn invariant violations into misleading `None`/default values

### Numeric Safety

- External/untrusted values: use `saturating_*` / `checked_*` arithmetic
- All `as` casts must have a comment explaining why the cast is safe

### Async & Concurrency

- CPU-heavy work (crypto, proofs): use `tokio::task::spawn_blocking`
- All external waits need timeouts (network, state, channels)
- Prefer `tokio::sync::watch` over `Mutex` for shared async state
- Prefer freshness tracking ("time since last change") to detect stalls

### Security

- Use `TrustedPreallocate` for deserializing collections from untrusted sources
- Bound all loops/allocations over attacker-controlled data
- Validate at system boundaries (network, RPC, disk)

### Performance

- Prefer existing indexed structures (maps/sets) over scanning/iterating
- Avoid unnecessary clones — structs may grow in size over time
- Use `impl Into<T>` to reduce verbose `.into()` at call sites
- Don't add unnecessary comments, docstrings, or type annotations to code you didn't change

## Testing Guidelines

- Unit/property tests: `src/*/tests/` within each crate (`prop.rs`, `vectors.rs`, `preallocate.rs`)
- Integration tests: `crate/tests/` (standard Rust layout)
- Async tests: `#[tokio::test]` with timeouts for long-running tests
- Test configs must match real network parameters (don't rely on defaults)

```bash
# Unit tests
cargo test --workspace

# Integration tests with nextest
cargo nextest run --profile zakura-integration
```

## Metrics & Observability

- Metrics use dot-separated hierarchical names with existing prefixes: `checkpoint.*`, `state.*`, `sync.*`, `rpc.*`, `peer.*`, `zcash.chain.*`
- Use `#[instrument(skip(large_arg))]` for tracing spans on important operations
- Errors must be logged with context

## Changelog

- After opening a draft PR that changes a Rust source file or any `Cargo.toml`,
  add exactly one `docs/changelog/unreleased/<PR-number>.md` file for that PR.
- Put user-visible `zakurad` entries under the appropriate Keep a Changelog
  category heading.
- For internal-only work, use `<!-- changelog: none -->` and explain why.
- Do not directly edit `[Unreleased]` in ordinary PRs; the release flow
  assembles fragments into the root changelog.
- Apply the appropriate PR label (`C-feature`, `C-bug`, `C-security`, etc.)
- Run `./scripts/changelog.py check` and see
  `docs/changelog/unreleased/README.md` and
  `docs/changelog/guidelines.md` for the exact format.

## Configuration

```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Documentation for field
    pub field: Type,
}
```

- Use `#[serde(deny_unknown_fields)]` for strict validation
- Use `#[serde(default)]` for backward compatibility
- All fields must have documentation
- Defaults must be sensible for production
