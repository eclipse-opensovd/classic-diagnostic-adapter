---
name: cda
description: CDA development agent with project context, code style rules, and ASPICE documentation guidance
mode: primary
---

# Classic Diagnostic Adapter (CDA)

An Eclipse OpenSOVD component that bridges legacy vehicle diagnostics (UDS over DoIP)
to the modern SOVD REST API. Written in Rust (edition 2024, MSRV 1.88.0).

## Build, Lint, Test

```bash
# Build
cargo build --locked

# Format (requires nightly toolchain)
cargo +nightly format

# Lint
cargo lint                        # alias for: cargo clippy -- -D warnings

# Unit tests
cargo test --locked --lib

# Integration tests (requires Docker — spins up ECU simulator + CDA)
cargo test --locked -p integration-tests --features integration-tests

# Pre-commit hooks (install once, then auto-runs)
uv run --group tools prek run

# License/source/ban checks
cargo deny check
```

Always run `cargo +nightly format` and `cargo lint` before committing. CI will reject
unformatted or clippy-failing code.

## Project Structure

```text
cda-interfaces/       Shared types, traits, error definitions (dependency root)
cda-database/         MDD/FlatBuffers/Protobuf database loading
cda-comm-doip/        DoIP communication layer
cda-comm-uds/         UDS communication layer
cda-core/             Diagnostic kernel — ECU manager, diag services
cda-sovd/             SOVD REST API (axum web server, routes, OpenAPI)
cda-sovd-interfaces/  SOVD interface traits (error mapping, IntoSovdError)
cda-main/             Binary entry point, CLI parsing, configuration
cda-tracing/          Logging/tracing setup (DLT, OpenTelemetry, file, console)
cda-plugin-security/  Security plugin interface
cda-health/           Health check endpoint
cda-extra/            Optional extras (e.g., systemd-notify)
cda-storage/          Storage abstraction layer
cda-build/            Shared build script utilities
opensovd-axum-extra/  Extra axum utilities
comm-mbedtls/         mbedTLS bindings (mbedtls-sys + mbedtls-rs)
integration-tests/    End-to-end integration tests (Docker-based)
testcontainer/        Docker Compose environment + ECU simulator (Kotlin)
docs/                 Sphinx documentation, ADRs, OpenAPI specs
concepts/             Design documents (error_handling.md)
```

**Dependency flow**: `cda-interfaces` -> communication layers -> `cda-core` -> `cda-sovd` -> `cda-main`.
Lower layers never depend on higher layers. Dependency inversion via traits in `cda-interfaces`.

## Architecture Conventions

- **Async everywhere**: Tokio multi-threaded runtime, async traits, futures-based concurrency.
- **Dynamic routing**: The web server starts immediately; routes are added dynamically after
  database loading completes.
- **Feature flags**: `health`, `openssl`/`mbedtls`, `dlt-tracing`, `tokio-tracing`,
  `systemd-notify`, `config-optional`, `integration-tests`.
- **Global allocator**: mimalloc.
- **Configuration**: figment (TOML + env + CLI via clap). Reference config in `opensovd-cda.toml`.

## Code Style

Refer to `CODESTYLE.md` for full details. Key rules:

- **Max line width**: 100 characters.
- **Formatting**: Nightly `rustfmt` required. Run `cargo +nightly format`.
- **Import order**: Three groups separated by blank lines — (1) std, (2) external crates,
  (3) internal modules. Granularity at `Crate` level.
- **Explicit types**: Prefer explicit over implicit; annotate types when not obvious.
- **Constants**: Use `const` or `static` — never magic values.
- **Shared state**: `Arc`/`Mutex`/`RwLock`.

### Clippy

Clippy runs at pedantic level with warnings denied. Key enforced lints:

- `unwrap_used` — denied in production code (`allow-unwrap-in-tests = true`).
- `indexing_slicing` — denied; use `.get()` or iterators.
- `arithmetic_side_effects` — denied; handle overflow explicitly.
- `clone_on_ref_ptr` — denied; use `Arc::clone(&x)` not `x.clone()`.
- `disallowed_methods` — `std::thread::sleep` and `tokio::time::sleep` are banned;
  use `tokio_ext::sleep_for` instead.
- Any `#[allow(...)]` must include a justification comment.

### Comments and Documentation

- All public items documented with `///` doc comments.
- Inline comments use `//` only (never `/* */`), and explain **why**, not **what**.

## Error Handling

Detailed in `concepts/error_handling.md`. Summary:

- Each crate defines its own error enum using `thiserror`.
- `cda-sovd` is the single point where domain errors map to HTTP/SOVD responses via
  `From<LayerError> for ApiError`.
- Error enums derive `Serialize` alongside `thiserror`; `#[serde(flatten)]` +
  `extract_parameters()` auto-surfaces fields into SOVD JSON `parameters`.
- Plugin errors use `IntoSovdError` trait from `cda-sovd-interfaces` and propagate
  through layers as opaque `PluginError(Box<dyn IntoSovdError>)`.
- Non-SOVD crates never depend on `cda-sovd-interfaces` (unless carrying `PluginError`).
- Error messages must start with a capital letter.

## Tracing and Logging

- Use `tracing::info!`, `tracing::debug!`, etc. — never `println!` or `eprintln!`.
- Annotate important functions with `#[tracing::instrument]`.
- Functions include a `dlt_context` field for AUTOSAR DLT compatibility.

## Commit Conventions

- **Conventional Commits** enforced via pre-commit hook.
- Format: `type(scope): description` (e.g., `feat(sovd): add fault filtering endpoint`).

## Licensing

- Every source file must have an SPDX header: `Apache-2.0`. Enforced by REUSE annotations.
- Allowed dependency licenses: `Apache-2.0`, `BSD-3-Clause`, `ISC`, `MIT`, `Unicode-3.0`, `Zlib`.
- Run `cargo deny check` to validate.

## Traceability

The project uses Sphinx with `sphinx-needs` and `sphinx-codelinks` for requirements
traceability. Full conventions are in `docs/01_about/04_traceability.rst`.

### Need Types

| Prefix   | Type    | Purpose                            |
|----------|---------|------------------------------------|
| `req~`   | `req`   | Software Requirement               |
| `arch~`  | `arch`  | Software Architecture              |
| `dsgn~`  | `dsgn`  | Detailed Design (standalone)       |
| `impl~`  | `impl`  | Implementation (standalone)        |
| `dimpl~` | `dimpl` | Detailed Design & Implementation   |
| `test~`  | `test`  | Unit Test                          |
| `itest~` | `itest` | Integration Test                   |

IDs follow the pattern `type~short-description`. The short description must only contain
letters, numbers, and hyphens (no dots or underscores).

### When to Use `dimpl~` vs `dsgn~` + `impl~`

- **`dimpl~`** combines detailed design and implementation into one marker. Use it when the
  design is straightforward and easier to show in code comments than in separate documents.
  This is the most common case and the default type for code markers.
- **`dsgn~`** and **`impl~`** are separate markers for detailed design and implementation
  respectively. Use them when the design is complex enough to warrant its own documentation
  separate from the implementation.

Every requirement should ideally be traced through: `req` -> `arch` -> `dsgn`/`impl` (or
`dimpl`) -> `test`/`itest`. In trivial cases, skipping `arch` and/or `dsgn` is acceptable.

### Code Markers

Source code traceability uses inline `[[ ... ]]` comment markers in Rust files. The format is:

```text
[[ <ID>, <Title>, <Type>, <Links> ]]
```

- **ID** (required): The need ID, e.g. `dimpl~sovd-api-http-server`.
- **Title** (required): A human-readable description of what this code implements.
- **Type** (optional): Defaults to `dimpl` if omitted.
- **Links** (optional): Semicolon-separated list of related need IDs.

Markers can appear in doc comments (`///`) or inline comments (`//`):

```rust
/// [[ dimpl~sovd-api-http-server, Starts HTTP Server ]]
/// Launches the SOVD HTTP(S) web server with deferred initialization.
pub async fn launch_webserver(...) { ... }

// [[ dimpl~sovd-api-ecu-variant-detection, PUT endpoint for ECU variant detection ]]
async fn put_ecu_variant(...) { ... }
```

Multi-line definitions are not supported by the `src-trace` directive.

### RST Documentation Markers

In Sphinx RST files, needs are defined as directives with `:links:` to create the
traceability chain:

```rst
.. req:: HTTP-Server
    :id: req~sovd-api-http-server
    :links: arch~sovd-api-http-server
    :status: draft
    :type: functional

    The CDA must provide an HTTP- or HTTPS-server.

.. arch:: SOVD-API over HTTP
    :id: arch~sovd-api-http-server
    :links: dimpl~sovd-api-http-server
    :status: draft
```

Status values: `draft`, `valid`, `approved`, `rejected`, `obsolete`.
Requirement types (`:type:`): `functional`, `non-functional`, `interface`, `constraint`.

## Key Domain Concepts

- **SOVD**: Service-Oriented Vehicle Diagnostics — the modern REST API standard.
- **UDS**: Unified Diagnostic Services — the legacy diagnostic protocol.
- **DoIP**: Diagnostics over Internet Protocol — transport for UDS messages.
- **MDD**: Diagnostic description database files (converted from ODX via `odx-converter`).
- **ECU**: Electronic Control Unit — the vehicle component being diagnosed.
- **DTC**: Diagnostic Trouble Code — fault codes stored by ECUs.
