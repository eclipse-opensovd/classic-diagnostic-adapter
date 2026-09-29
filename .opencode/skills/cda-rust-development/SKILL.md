---
name: cda-rust-development
description: Rust coding rules, build/test/lint commands and pre-finish checklist for the Classic Diagnostic Adapter (CDA) Cargo workspace. Use whenever writing, modifying, reviewing, building or testing Rust code in this repository.
---

<!--
SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation

See the NOTICE file(s) distributed with this work for additional
information regarding copyright ownership.

This program and the accompanying materials are made available under the
terms of the Apache License Version 2.0 which is available at
https://www.apache.org/licenses/LICENSE-2.0

SPDX-License-Identifier: Apache-2.0
-->

# CDA Rust Development

Rust Cargo workspace (edition 2024, MSRV 1.88).

## Commands

Use the `Makefile` targets; they pin the toolchains (`STABLE`, `NIGHTLY` in the `Makefile`).
Do not call `cargo +nightly` or the `cargo lint` alias directly, they may use a different
toolchain. Extra cargo arguments go through `ARGS="..."`.

```sh
make build                    # or `make release`
make test                     # workspace tests
make integration-test         # needs Docker (CAN: make integration-test-can)
make lint                     # clippy, deny warnings (all features: make lint-all-features)
make fmt                      # nightly rustfmt (check only: make fmt-check)
make deny                     # cargo deny check
make precommit                # all pre-commit hooks
make help                     # list all targets; `make doctor` checks the toolchain setup
```

Run a single test: `make test ARGS="-p <crate> <test_name>"`.
Logging level: `RUST_LOG=debug` (default `info`).

## Rules

- Follow `CODESTYLE.md`. Clippy `pedantic` is denied workspace-wide; also denied: `unwrap_used`,
  `indexing_slicing`, `arithmetic_side_effects`, `string_slice`, `clone_on_ref_ptr`.
  Use `checked_*`/`saturating_*`, `.get()`, and `?` instead.
- `#[allow(...)]` needs a `reason`; prefer `#[expect(..., reason = "...")]` where applicable.
- No `std::thread::sleep` / `tokio::time::sleep`; use `tokio_ext::sleep_for`.
- NEVER import `std::future::Future`; it is already in the prelude.
- Errors: `thiserror` only, no `anyhow` (ADR-005). Error messages start with a capital letter.
- Logging: `tracing` macros; `#[tracing::instrument]` for significant spans.
- Modules: `foo.rs` + `foo/`, never `foo/mod.rs`.
- Comments: `//` only, explain why, no banner comments, no non-ASCII characters (except `µ`, `§`).
  Document public items with `///`.
- New dependencies must go through `[workspace.dependencies]` and pass `cargo deny`
  (allowed: Apache-2.0, BSD-3-Clause, ISC, MIT, Unicode-3.0, Zlib).

## Before finishing a change

1. `make fmt`
2. `make lint-all-features`
3. `make test` (and `make integration-test` if behavior across layers changed)
4. `make precommit`
