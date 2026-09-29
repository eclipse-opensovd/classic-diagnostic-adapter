<!--
SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation

See the NOTICE file(s) distributed with this work for additional
information regarding copyright ownership.

This program and the accompanying materials are made available under the
terms of the Apache License Version 2.0 which is available at
https://www.apache.org/licenses/LICENSE-2.0

SPDX-License-Identifier: Apache-2.0
-->

# AGENTS.md

Guidance for AI coding agents working in the Eclipse OpenSOVD Classic Diagnostic Adapter (CDA).
The CDA translates SOVD (REST) requests into UDS diagnostic requests sent to ECUs over DoIP or
CAN/ISO-TP, using ECU descriptions from MDD database files (converted from ODX).

## Repository layout

Rust Cargo workspace (see the `cda-rust-development` skill).

| Path | Purpose |
| --- | --- |
| `cda-main` | Binary (`opensovd-cda`), CLI, config loading (`src/config/`) |
| `cda-sovd`, `cda-sovd-interfaces` | SOVD HTTP server (axum) and its API types |
| `cda-core` | Diagnostic core: maps SOVD operations to UDS services via the database |
| `cda-database` | MDD database loading (protobuf / flatbuffers) |
| `cda-comm-uds` | UDS layer (sessions, security access, tester present, ...) |
| `cda-transport-router` | Routes UDS traffic to the right transport |
| `cda-comm-doip`, `cda-comm-can` | DoIP and CAN/ISO-TP transports |
| `cda-interfaces` | Shared traits and types between crates |
| `cda-tracing` | Logging, DLT, OpenTelemetry setup |
| `cda-plugin-*` | Plugins (security, lock priority, runtime update, communication management) |
| `cda-health`, `cda-storage`, `cda-extra`, `cda-build` | Health checks, storage, extras, build helpers |
| `opensovd-axum-extra` | Shared axum extensions (extractors, OpenAPI helpers) |
| `override-macros` | Proc macros for vendor-overridable implementations |
| `comm-mbedtls/` | mbedtls FFI bindings (`mbedtls-sys`) and async wrapper (`mbedtls-rs`) |
| `integration-tests/` | End-to-end tests against Docker containers |
| `testcontainer/` | Docker compose env, Kotlin ECU simulator (`ecu-sim/`), ODX, test config |
| `docs/` | Sphinx docs: requirements, architecture, ADRs (`docs/04_adr/`) |

## Rust development

For any Rust work (build, test, lint, format, coding rules, dependencies, pre-finish checklist)
load the `cda-rust-development` skill and follow it.

Config: `opensovd-cda.toml`, overridable with `CDA_`-prefixed env vars; file selectable via
`--config-file`. All pre-commit hooks: `uv run --group tools prek run --all-files`.

## Rules

- Every new file needs the SPDX/REUSE license header (see any existing file).
- Commits use Conventional Commits with a crate scope, e.g. `fix(transport-router): ...`.
- Commits must carry a DCO sign-off (`git commit -s`, adds `Signed-off-by: Name <email>`).
  Do not add `Co-authored-by:` trailers (or any other AI attribution) to commit messages.
- Do not commit, push or open PRs unless asked.

## Agents

- `.opencode/agents/cda-issue-analyst.md` - root-cause analysis of issues, logs and failing tests.
- `.opencode/agents/cda-mdd-inspector.md` - inspect and diff MDD databases.
- `.opencode/agents/cda-spec-expert.md` - UDS, DoIP and CAN/ISO-TP specification questions and
  CDA docs. Requests markdown spec text or excerpts from the user when needed.

Recommended model classes (the repository stays provider-neutral; no `model` is set in the
agent files):

| Agent | Model class | Examples | Temperature | Reason |
| --- | --- | --- | --- | --- |
| `cda-mdd-inspector` | lightweight / fast | Claude Haiku, GPT mini, Gemini Flash | 0.1 | Mostly MCP tool calls and factual reporting |
| `cda-spec-expert` | strong reasoning | Claude Opus/Sonnet, GPT-5, Gemini Pro | 0.1 | Interprets normative text, must not hallucinate |
| `cda-issue-analyst` | strong reasoning | Claude Opus/Sonnet, GPT-5, Gemini Pro | 0.2 | Root-cause analysis across crates and layers |

Without a configured model, a subagent uses the model of the agent that invoked it. Set a
concrete model per user in `~/.config/opencode/opencode.json` (`opencode models` lists the
available IDs), e.g.:

```json
{ "agent": { "cda-mdd-inspector": { "model": "github-copilot/claude-haiku-4.5" } } }
```

## Skills

- `.opencode/skills/cda-rust-development` - Rust coding rules, build/test/lint commands and
  pre-finish checklist.
- `.opencode/skills/cda-diagnostic-protocol-spec` - UDS, DoIP and CAN/ISO-TP knowledge, doc sources
  and how to request specification text from the user.
- `.opencode/skills/cda-issue-analysis` - structured analysis of bug reports and issues.
- `.opencode/skills/cda-mdd-mcp-setup` - install and register the mdd-mcp server (`mdd-mcp_*` tools).
- `.opencode/skills/cda-pdf-reader-setup` - install and register the PDF MCP server (`pdf-reader_*` tools).
- `.opencode/skills/cda-github-mcp-setup` - install and register the GitHub MCP server (`github_*` tools).
