# ADR 003: Structured Error Handling with `ErrorMeta` Trait

**Date**: 2026-05-22 (inferred from codebase)

## Context

Bitcoin Suite has multiple crates that need to produce errors visible to end users (API responses, CLI output). A plain `thiserror` enum gives a message but no structured metadata. Downstream consumers need to know:
- How severe is this error? (critical? bug? user input?)
- What error code should the API return?
- What tags/labels can help categorize or route errors?
- What's the full debug context?

## Decision

Create a three-component error system:

1. **`bitcoinsuite-error`**: Defines `ErrorMeta` trait with `severity()`, `error_code()`, and `tags()` methods. Defines `ErrorSeverity` enum (Unknown, NotFound, InvalidUserInput, InvalidClientInput, Warning, Bug, Critical). Provides `report_to_details()` to convert any `eyre::Report` to structured `ErrorDetails`. Re-exports `eyre::{Result, Report, WrapErr, bail}`.
2. **`bitcoinsuite-error-derive`**: Proc-macro `#[derive(ErrorMeta)]` that reads severity annotations on enum variants (`#[critical()]`, `#[bug()]`, etc.), derives error codes from variant names (kebab-case), and collects tags from custom attributes.
3. **`bitcoinsuite-error-warp`**: Converts `ErrorDetails` to warp HTTP responses with appropriate status codes and JSON bodies.

Errors use `thiserror::Error` for Display + Error impl and `eyre` for error chaining and context wrapping.

## Considered Options

1. **Plain `thiserror` + manual helper methods** — Works but verbose, no standard way to extract metadata from a `&dyn Error`.
2. **`snafu`** — Different philosophy, more verbose, harder to integrate with existing error patterns.
3. **Custom error enum per context** — Already exists (BitcoindError, SlpError, etc.) plus a unifying trait.
4. **`ErrorMeta` trait + derive (chosen)** — Standardizes metadata extraction across all contexts while keeping per-context enums.

## Consequences

**Positive**:
- All errors in the project carry severity, error code, and tags
- `report_to_details()` converts any error to structured output suitable for API responses
- Proc-macro derive reduces boilerplate to zero
- `eyre` integration enables context wrapping via `WrapErr`
- `install()` sets up `stable_eyre` once at startup for consistent panic/error formatting

**Negative**:
- Three crates to maintain instead of one (`error`, `error-derive`, `error-warp`)
- Proc-macro has limited visibility into enum structure (can only use annotation attributes, not function logic)
- `eyre` API is not `no_std` compatible
- The `lazy_static!` + `atomic` guarded `install()` pattern is a singleton that could cause issues in test isolation
