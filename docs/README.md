# Bitcoin Suite Documentation

## File Tree

```
docs/
├── README.md                  # This file — table of contents for all docs
├── CONSTITUTION.md            # Project constitution: governance, testing, workflow, standards, review gates
├── CONTEXT_MAP.md             # Bounded context map with dependency flow and shared kernel
├── SCHEMA.md                  # Data schema reference (SLP tokens, protobuf messages)
├── adrs/                      # Architecture Decision Records
│   ├── 001-ecc-trait-abstraction.md
│   ├── 002-bitcoin-code-serialization.md
│   ├── 003-error-meta-system.md
│   ├── 004-flatbuffers-nng-interface.md
│   ├── 005-lotus-merkle-variant.md
│   └── 006-stratum-v1-lotus-extensions.md
└── contexts/                  # Per-context bounded context documentation
    ├── core/CONTEXT.md
    ├── error/CONTEXT.md
    ├── bitcoind/CONTEXT.md
    ├── bitcoind-nng/CONTEXT.md
    ├── bitcoind-stratum/CONTEXT.md
    ├── slp/CONTEXT.md
    ├── chronik-client/CONTEXT.md
    ├── ecc/CONTEXT.md
    └── test-utils/CONTEXT.md
```

## Documentation Reference

| File | Description | Updated When |
|------|-------------|--------------|
| `CLAUDE.md` | Project root agent guide — redirects to CONSTITUTION.md | New crate added or build system changed |
| `docs/CONSTITUTION.md` | Full governance: docs, testing, workflow, skills, code standards, review gates | Any policy, pattern, or standard changes |
| `docs/CONTEXT_MAP.md` | Bounded context map, dependency flow, shared kernel, cross-cutting concerns | New context added or dependency direction changes |
| `docs/SCHEMA.md` | SLP token types, protobuf & flatbuffer schema summaries, data formats | New token type, new message, or schema field changed |
| `docs/adrs/<nnn>-*.md` | Architecture Decision Records (one per decision meeting criteria) | New architectural decision made |
| `docs/contexts/<name>/CONTEXT.md` | Per-context boundary, invariants, contracts, module structure | Context API surface changes or invariants evolve |

## Usage

- **Reading**: Start with `CONTEXT_MAP.md` for the big picture, then drill into relevant `contexts/<name>/CONTEXT.md`.
- **Planning changes**: Read `CONSTITUTION.md` §3 (Implementation Workflow) for the required process.
- **Making decisions**: Read `CONSTITUTION.md` §1 for ADR criteria before committing to a design.
- **Before committing**: Run `CONSTITUTION.md` §6 (Review Gates) checklist.
