# Bitcoin Suite — Project Constitution

## §1 Documentation

### Documentation Decision Matrix

If you modified a file in this context, update the corresponding documentation files:

| Modified Code In | Update These Docs |
|---|---|
| `bitcoinsuite-core/src/**` | `docs/contexts/core/CONTEXT.md`, `docs/CONTEXT_MAP.md` (shared kernel) |
| `bitcoinsuite-bitcoind/src/**` | `docs/contexts/bitcoind/CONTEXT.md` |
| `bitcoinsuite-bitcoind-nng/src/**` | `docs/contexts/bitcoind-nng/CONTEXT.md`, `docs/SCHEMA.md` (flatbuffer schema) |
| `bitcoinsuite-bitcoind-stratum/src/**` | `docs/contexts/bitcoind-stratum/CONTEXT.md` |
| `bitcoinsuite-chronik-client/src/**` | `docs/contexts/chronik-client/CONTEXT.md`, `docs/SCHEMA.md` (proto schema) |
| `chronik-client/**` | `docs/contexts/chronik-client/CONTEXT.md` |
| `bitcoinsuite-error/src/**` | `docs/contexts/error/CONTEXT.md` |
| `bitcoinsuite-error-derive/src/**` | `docs/contexts/error/CONTEXT.md` |
| `bitcoinsuite-error-warp/src/**` | `docs/contexts/error/CONTEXT.md` |
| `bitcoinsuite-ecc-secp256k1/src/**` | `docs/contexts/ecc/CONTEXT.md` |
| `bitcoinsuite-slp/src/**` | `docs/contexts/slp/CONTEXT.md`, `docs/SCHEMA.md` |
| `bitcoinsuite-slpv2/src/**` | `docs/contexts/slp/CONTEXT.md` |
| `bitcoinsuite-test-utils/src/**` | `docs/contexts/test-utils/CONTEXT.md` |
| `bitcoinsuite-test-utils-blockchain/src/**` | `docs/contexts/test-utils/CONTEXT.md` |
| `Cargo.toml` (workspace root) | `docs/CONTEXT_MAP.md` (add/remove context), `docs/README.md` |
| `Cargo.lock` generated | No doc update needed |
| `Makefile.toml` | `CLAUDE.md` if build process changes |
| New ADR-eligible decision | Create new `docs/adrs/<nnn>-*.md` |

### ADR Criteria

Create an Architecture Decision Record (ADR) only when a decision meets **all three** criteria:

1. **Hard to reverse** — Changing your mind later would be expensive or risky.
2. **Surprising without context** — A newcomer wouldn't guess why this way was chosen.
3. **Real trade-off** — The choice involved giving up something of value.

ADR template: `docs/adrs/000-template.md` (title, context, decision, considered options, consequences).

### Fallback Rule

If no explicit documentation entry exists for a module, update `docs/CONTEXT_MAP.md` with any new dependency relationships and verify that the module's imports are reflected in `docs/contexts/<name>/CONTEXT.md` boundaries.

---

## §2 Testing & Quality

### Testing Patterns (observed in codebase)

| Pattern | Where Found | Rule |
|---|---|---|
| Unit tests in `#[cfg(test)] mod tests` | `bitcoinsuite-core`, `bitcoinsuite-slp`, `bitcoinsuite-ecc-secp256k1`, `bitcoinsuite-bitcoind-nng/src/*.rs` | Preferred location — co-located with implementation |
| Integration tests in `tests/` dir | `bitcoinsuite-core/tests/test_blocks.rs`, `tests/test_txs.rs`, `bitcoinsuite-chronik-client/tests/test_chronik_client.rs`, `bitcoinsuite-test-utils-blockchain/tests/test_setup_chain.rs`, `bitcoinsuite-error-derive/tests/test_derive.rs` | For tests that need external binaries, blockchain state, or protobuf compilation |
| TypeScript tests with mocha+chai | `chronik-client/test/test.ts` | JS SDK testing |
| Std `#[test]` attribute | All Rust crates | Standard approach |
| `#[tokio::test]` for async | `bitcoinsuite-bitcoind` RPC client tests, integration tests | Only when testing async code paths |
| `DummyEcc` mock | `bitcoinsuite-core/src/ecc/mod.rs` | Mock at trait boundary (Ecc trait), not in business logic |
| `bitcoinsuite-test-utils` helpers | Shared test infrastructure | For bin folder discovery, port picking, HTTP serving |
| `bitcoinsuite-test-utils-blockchain` | Integration chain setup | Spins up real bitcoind instances for integration tests |

### Mocking Rules

- Mock only at **trait boundaries** (e.g., `Ecc` trait → `DummyEcc`).
- Do not mock internal functions or private methods.
- Integration tests use real bitcoind binaries; unit tests use minimal mocks.

### Nondeterminism Ban

- Tests must not rely on timing luck. No `sleep()` calls for synchronization.
- For async: use channels, `tokio::sync`, or await real events.
- Port picking uses `bitcoinsuite-test-utils::pick_ports` to avoid conflicts.

### Test-First vs Test-After

- **Test-first** for bug fixes: write a failing test that reproduces the bug, then fix.
- **Test-after** for new features on existing patterns: add tests covering the new behavior after implementation.
- **Always** for all changes: test suite must pass before completion.

### Pre-Commit Verification

1. `cargo check` — all crates compile without warnings.
2. `cargo test -p <changed-crate>` — unit tests for affected crate(s).
3. `cargo test` — full workspace (note: requires `BITCOINSUITE_BIN_DIR` for integration tests).
4. `cargo clippy` — no new lint warnings (target the affected crate).

---

## §3 Implementation Workflow

Every implementation task **must** follow this workflow. No exceptions.

### Phase 1: EXPLORE

- Read the relevant source files, tests, and existing documentation.
- Understand the existing patterns before proposing changes.
- Identify which bounded contexts are affected.

### Phase 2: DEFINE

- State the final goal explicitly: WHAT, WHY, success criteria.
- If unclear, ask one clarifying question before proceeding.

### Phase 3: PLAN (includes Documentation Updates)

The PLAN phase **must** include a **Documentation Updates** subsection:

```markdown
### Documentation Updates
- [ ] `docs/contexts/<name>/CONTEXT.md` — update [specific section]
- [ ] `docs/CONTEXT_MAP.md` — update dependency flow [if applicable]
- [ ] `docs/adrs/<nnn>-*.md` — new ADR needed? [yes/no]
- [ ] `docs/SCHEMA.md` — schema change? [if applicable]
```

Share the plan with the user and wait for confirmation before creating todos.

### Phase 4: TODO

Create atomic, verifiable todos. Each todo must encode: WHERE, WHY, HOW, EXPECTED RESULT.

### Phase 5: EXECUTE

One `in_progress` todo at a time. Mark completed immediately after finishing each item.

### Phase 6: VERIFY

Run the review gates checklist (§6) before marking the task done.

---

## §4 Skill Activation Guide

When an agent with access to the [AgentiveStack/skills](https://github.com/AgentiveStack/skills) system is active, use these skills:

| Situation | Skill | Why |
|---|---|---|
| New feature from scratch | `spec` | Interview-driven PRD grounded in domain model |
| Breaking down a feature into tasks | `slice` | Produce vertical tracer bullets through all layers |
| Implementing a slice | `tdd` | Test-driven implementation, one test at a time |
| Tangled or hard-to-test code | `architect` | Explore alternative interface designs via parallel sub-agents |
| Terminology confusion or domain mismatch | `domain` | Stress-test domain model against code, update CONTEXT.md |
| Bug hunting or QA session | `qa` | File durable GitHub issues using project domain language |
| Lost in details or unfamiliar area | `holistic` | Trace cross-cutting concerns and surface hidden dependencies |

### Without skills system

If no skills system is available, use these fallback approaches:

| Need | Approach |
|---|---|
| Spec writing | Write a PRD with: problem statement, scope, user stories, success criteria, open questions |
| Slicing | Decompose the spec into end-to-end "tracer bullet" tasks, each touching all layers |
| TDD | One failing test → implement → pass → refactor → repeat |
| Architecture review | Draw module dependency graph, identify cyclic deps, assess interface depth |
| Domain modeling | Extract glossary of terms from code, verify each has a single consistent meaning |
| QA | Systematic exploration: happy path → edge cases → error paths → concurrent access |

---

## §5 Code Standards

### Module Architecture

```
bitcoinsuite-error               (foundation: ErrorMeta trait, error-reporting pipeline)
  ├── bitcoinsuite-error-derive  (proc-macro for ErrorMeta derive)
  └── bitcoinsuite-error-warp    (warp framework integration)

bitcoinsuite-core                (foundation: Bitcoin primitives, BitcoinCode trait, Ecc trait, types)
  ├── bitcoinsuite-ecc-secp256k1 (Ecc trait impl using secp256k1_abc)
  ├── bitcoinsuite-slp           (SLP token parsing + validation)
  │   └── bitcoinsuite-slpv2     (SLPv2 OP_RETURN building)
  ├── bitcoinsuite-bitcoind      (node management + JSON-RPC client)
  │   ├── bitcoinsuite-bitcoind-nng    (NNG flatbuffer RPC + PubSub)
  │   │   └── bitcoinsuite-bitcoind-stratum (Stratum V1 mining protocol)
  │   └── bitcoinsuite-chronik-client   (Rust Chronik indexer client)
  ├── bitcoinsuite-test-utils    (test infrastructure)
  │   └── bitcoinsuite-test-utils-blockchain (blockchain test setup)
  └── chronik-client             (TypeScript Chronik client — outside workspace)

Dependency direction: error ← core ← everything else. No circular deps.
```

### Error Handling

- Errors use `thiserror::Error` + `#[derive(ErrorMeta)]` with severity annotations.
- Severity levels: `#[critical()]`, `#[bug()]`, `#[warning()]`, `#[invalid_client_input()]`, `#[invalid_user_input()]`, `#[not_found()]`.
- Error results use `bitcoinsuite_error::Result<T>` (re-export of `eyre::Result`).
- Each error enum variant gets a `#[error("...")]` display message.
- Use `WrapErr` from `bitcoinsuite_error` for context chaining.
- The `report_to_details()` function converts errors to structured `ErrorDetails` with severity, error code, tags, and full debug report.
- Call `bitcoinsuite_error::install()` once at startup to set up `stable_eyre`.

### Config Loading

- **Bitcoind instances**: Configured via `BitcoindConf` struct with path, args, ports. Uses `tempdir` for data directories.
- **Bitcoind RPC client**: Configured via `BitcoindRpcClientConf` (url, rpc_user, rpc_pass).
- **NNG interface**: Configured via URL strings passed to `open()` methods.
- **Environment**: `BITCOINSUITE_BIN_DIR` env var for binary discovery in tests (`Makefile.toml` sets `downloads/`).

### Naming Conventions

- **Cargo crates**: `bitcoinsuite-<name>` (lowercase, hyphenated).
- **Rust types**: PascalCase (`BitcoindInstance`, `SlpValidTxData`, `ChronikClient`).
- **Functions**: snake_case (`lotus_merkle_leaf`, `compress_amount`, `validate_slp_tx`).
- **Modules**: snake_case directory/file names.
- **Error enums**: PascalCase (`BitcoindError`, `SlpError`, `ChronikClientError`).
- **Traits**: PascalCase (`BitcoinCode`, `Ecc`, `ErrorMeta`, `Hashed`).
- **NNG structs**: same names as flatbuffer schema types.
- **Test functions**: snake_case, prefixed with `test_`.

### Database Patterns

No traditional database is used. Data persistence is via:
- **FlatBuffers** (`*.fbs`): binary serialization for NNG RPC/PubSub messages (`nng_interface.fbs`).
- **Protobuf** (`*.proto`): wire format for Chronik HTTP/WebSocket API (`chronik.proto`).
- **Bitcoind's own data files**: accessed via JSON-RPC or NNG interface.

### State Management Patterns

- **Mutable state**: `std::sync::Mutex` for RPC interface (serializes NNG requests).
- **Atomic state**: `std::sync::atomic::AtomicUsize` for request IDs in RPC client.
- **Immutable by default**: All core Bitcoin types (`Tx`, `Block`, `Script`) use owned data with builder patterns.
- **Async**: `tokio` runtime for async operations (NNG pubsub listeners, HTTP clients).
- **Lazy init**: `lazy_static` or `once_cell` for global state (error handle lock, NNG aio callbacks).
- **Reference counting**: `Arc` for shared config (e.g., last_id counter in `BitcoindRpcClient`).

---

## §6 Review Gates

Before marking any task complete, verify **all** of the following:

- [ ] **All tests pass** — `cargo test -p <affected-crates>` (unit + integration).
- [ ] **Documentation updated** — per decision matrix in §1. Every modified file's docs were checked.
- [ ] **No regressions** — pre-existing test behavior is preserved. Known pre-existing failures are noted, not silently fixed.
- [ ] **No silent error suppression** — `unwrap()`, `expect()`, `ok()`, or `_` patterns are justified, not used to bypass type errors.
- [ ] **Build succeeds** — `cargo check` on the entire workspace (or at minimum the affected crates).
- [ ] **Clippy clean** — `cargo clippy` on affected crates (no new warnings).
- [ ] **Minimal changes** — Only lines necessary to satisfy the requirement were touched.
- [ ] **BDD tests pass** — For TypeScript: `cd chronik-client && npm test` (if changed).
