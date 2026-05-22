# Context: bitcoinsuite-error (+ error-derive, error-warp)

## Boundary

**Inside**: Error severity classification, error metadata extraction, structured error reporting, proc-macro for derive, warp HTTP integration.

**Outside**: Specific error types (BitcoindError, SlpError, etc.). Business logic that produces errors.

## Dependencies

### bitcoinsuite-error

| Dependency | Type | Purpose |
|---|---|---|
| `lazy_static` | Runtime | Global error handle lock |
| `eyre` / `stable-eyre` | Runtime | Error chaining, panic formatting |
| `bitcoinsuite-error-derive` | Runtime | Proc-macro for `ErrorMeta` derive |

### bitcoinsuite-error-derive

| Dependency | Type | Purpose |
|---|---|---|
| `convert_case` | Proc | Variant name → kebab-case error code |
| `proc-macro2` | Proc | Token stream generation |
| `quote` | Proc | Rust code generation |
| `syn` | Proc | Parsing Rust enums |

### bitcoinsuite-error-warp

| Dependency | Type | Purpose |
|---|---|---|
| `bitcoinsuite-error` | Runtime | ErrorDetails type |
| `warp` | Runtime | HTTP framework integration |

## Module Structure

```
bitcoinsuite-error/
└── src/lib.rs         ErrorMeta trait, ErrorSeverity, ErrorDetails, report_to_details(), install()

bitcoinsuite-error-derive/
└── src/lib.rs         Proc-macro: #[derive(ErrorMeta)]
                        Reads #[critical()], #[bug()], #[warning()],
                        #[invalid_client_input()], #[invalid_user_input()],
                        #[not_found()] variant attributes

bitcoinsuite-error-warp/
└── src/lib.rs         ErrorDetails → warp::reply conversion
```

## Key Invariants

1. **`install()` must be called once** — Sets up `stable_eyre` for the global error handler. Uses a mutex + atomic flag to ensure single initialization. Calling it multiple times is safe (second call is a no-op).
2. **`ErrorMeta` is not object-safe for dynamic dispatch** — `report_to_details()` uses a `Fn(&Report) -> Option<&dyn ErrorMeta>` closure to extract metadata from a reporter, not dynamic dispatch on the error itself.
3. **Severity annotations are proc-macro only** — Cannot be set programmatically; must be compile-time annotations on enum variants.
4. **Error codes auto-derived from variant names** — `TestInstance` → `"test-instance"`, `JsonRpcCode` → `"json-rpc-code"`. Can be overridden via attribute.

## Key Contracts

| Contract | Type | Description |
|---|---|---|
| `ErrorMeta` trait | `severity() -> ErrorSeverity`, `error_code() -> Cow<'static, str>`, `tags() -> Cow<'static, [(Cow<'static, str>, Cow<'static, str>)]>` | Structured error metadata |
| `ErrorSeverity` enum | `Unknown`, `NotFound`, `InvalidUserInput`, `InvalidClientInput`, `Warning`, `Bug`, `Critical` | Severity classification |
| `ErrorDetails` struct | Full error: severity, error_code, tags, short_msg, msg, full_debug_report | Structured error for API responses |
| `report_to_details()` fn | `(&Report, impl Fn(&Report) -> Option<&dyn ErrorMeta>) -> ErrorDetails` | Convert any error to structured details |
| `install()` fn | Sets up `stable_eyre`, safe to call multiple times | Global error handler initialization |
| `Result<T>` | Re-export of `eyre::Result<T>` | Standard result type |
| `ErrorFmt` trait | `fmt_err() -> String` | Error display formatting |
