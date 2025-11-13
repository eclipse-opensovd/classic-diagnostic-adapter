# Code Style Guide

## Linting & Clippy

- **Clippy**: Always run with `clippy::pedantic` enabled for stricter linting.
  - Example: `cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic`
- **Allow/Forbid**: Use `#[allow(...)]` only when necessary, and always document the reason.
  - Example: `#[allow(clippy::ref_option)] // Not compatible with serde derive`
- **Warnings**: Treat all warnings as errors.

## Formatting

This repository follows most of the defaults in rustfmt, with some opinionated usage of nightly-only rules such as `group_imports=StdExternalCrate`.

- **rustfmt**: Use nightly `rustfmt` with the following settings:
  - Maximum line width: 100
  - Group imports by `StdExternalCrate`.
  - Import granularity at `crate` level.
  - Error on line overflow and error if rustfmt is unable to format a section. This prevents rustfmt from silently skipping the rest of the file.
  - Enable formatting of strings.

As we do not want to require nightly rust for the entire repository, these settings are not yet included in `rustfmt.toml` (but will be once stabilized).
Instead, run this command to apply the correct formatting:
```sh
cargo +nightly fmt -- --check --config error_on_unformatted=true,error_on_line_overflow=true,format_strings=true,group_imports=StdExternalCrate,imports_granularity=Crate
```

It is recommended to configure your IDE to use nightly rustfmt with these settings as well.
Example for VS Code:
```json
"rust-analyzer.rustfmt.overrideCommand": [
    "rustfmt",
    "+nightly",
    "--edition",
    "2024",
    "--config",
    "error_on_unformatted=true,error_on_line_overflow=true,format_strings=true,group_imports=StdExternalCrate,imports_granularity=Crate",
    "--"
]
```

## Imports
As noted in the formatting section, imports must be grouped and separated with a new line as follows:
  1. Standard library
  2. External crates
  3. Internal modules

Additionally the import granularity is set to `crate` to group all imports from the same crate into a single block.

## General Style

- Prefer explicit over implicit: always annotate types when not obvious.
- Use `const` and `static` for constants.
- Use `Arc`, `Mutex`, and `RwLock` for shared state, as seen in the codebase.
- Use tracing macros, like `tracing::info!`, as appropriate to record relevant information.
- Annotate functions with `tracing::instrument` when they are important for creating new tracing spans.
- Error messages should start with a capital letter.
- Literal suffixes (i.e. `u8` vs `_u8`) are preferably written without seperator.
  Separting the suffix is allowed, to improve readability, for example for long base 2 literals (i.e. `0b_0000_0111_u8`).
  This rule is not enforced by clippy to allow edge cases like the one mentioned above.

## Licensing & Dependencies

- Only allow SPDX-approved licenses:
  `Apache-2.0`, `BSD-3-Clause`, `ISC`, `MIT`, `Unicode-3.0`, `Zlib`
- Use `cargo-deny` to enforce dependency and license policies.

## Documentation

- Document all public items with `///` doc comments.
- Use clear, concise language and provide context for complex logic.

---
