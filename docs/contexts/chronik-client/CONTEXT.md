# Context: bitcoinsuite-chronik-client (+ chronik-client TS)

## Boundary

**Inside**: HTTP + WebSocket client for the Chronik blockchain indexer API. Rust crate and TypeScript npm package.

**Outside**: Core blockchain types, error infrastructure, the Chronik server itself.

## Dependencies

### bitcoinsuite-chronik-client (Rust)

| Dependency | Type | Purpose |
|---|---|---|
| `bitcoinsuite-core` | Runtime | Bytes, Sha256d |
| `bitcoinsuite-error` | Runtime | ErrorMeta, Result, WrapErr |
| `reqwest` | Runtime | HTTP client |
| `prost` | Build (via build.rs) | Protobuf code generation |
| `thiserror` | Runtime | Error derive |
| `tokio` | Dev | Async test support |
| `serde` | Dev | JSON test support |

### chronik-client (TypeScript)

| Dependency | Type | Purpose |
|---|---|---|
| `axios` | Runtime | HTTP requests |
| `ws` / `isomorphic-ws` | Runtime | WebSocket client |
| `protobufjs` | Runtime | Protobuf decoding |

## Module Structure

```
bitcoinsuite-chronik-client/
├── build.rs          Compile chronik.proto via prost
├── proto/chronik.proto  Protobuf schema for Chronik API
├── src/lib.rs        ChronikClient (Rust), ScriptEndpoint, PluginEndpoint, error types
└── tests/test_chronik_client.rs  Integration tests (need running Chronik)

chronik-client/ (TypeScript)
├── index.ts          ChronikClient (JS), types, WS subscription manager
├── chronik.ts        Protobuf-generated TypeScript types
├── hex.ts            Hex encoding utilities
├── test/test.ts      Mocha tests
├── package.json      npm config, scripts, dependencies
├── tsconfig.json     TypeScript config
├── typedoc.json      Documentation config
└── .eslintrc.js      Lint rules
```

## Key Invariants

1. **Two separate clients** — The Rust client (`bitcoinsuite-chronik-client`) and TypeScript client (`chronik-client`) are independent implementations with the same API surface. Changes must be synchronized.
2. **URL must not end with '/'** — Both clients enforce this at construction time. Trailing slash = error.
3. **HTTP + WebSocket** — Chronik provides REST endpoints for querying (blocks, txs, scripts) and WebSocket for real-time subscription (address tx notifications).
4. **Protobuf wire format** — Both Rust (via prost) and TypeScript (via protobuf.js) compile the same `chronik.proto` file.
5. **Script endpoint patterns** — REST endpoints follow pattern: `/v1/chronik/script/:script_type/:script_payload`.
6. **Plugin support** — Chronik supports plugins with custom endpoints: `/v1/chronik/plugin/:plugin_name/:payload`.

## Key Contracts

### Rust

| Contract | Type | Description |
|---|---|---|
| `ChronikClient` | struct: `new(url)`, `script()`, `plugin()`, `broadcast_tx()`, `subscribe()` | Main client class |
| `ScriptEndpoint` | builder: `utxos()`, `history()`, `slp()` etc. | Script query builder |
| `PluginEndpoint` | builder: `get()`, `post()` | Plugin query builder |
| `ScriptType` | enum: `Other`, `P2pk`, `P2pkh`, `P2sh`, `P2trCommitment`, `P2trState` | Script type for endpoints |
| `ChronikClientError` | enum with `#[critical()]` severity | Error types |

### TypeScript

| Contract | Type | Description |
|---|---|---|
| `ChronikClient` | class: `constructor(url)`, `script(type, payload)`, `plugin(name, payload)`, `broadcastTx(rawTx)`, WsSubscription | Main client class |
| `ScriptType` | type union: `"other" \| "p2pk" \| "p2pkh" \| "p2sh"` | Script type literal |
| `Tx` / `Block` / `ScriptUtxo` | TS interfaces matching protobuf messages | API response types |
