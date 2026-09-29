---
name: cda-issue-analysis
description: Analyze bug reports, GitHub issues, failing tests, logs or unexpected ECU/SOVD behavior in the Classic Diagnostic Adapter (CDA). Use when asked to investigate, triage, reproduce, root-cause or explain an issue, error, NRC, timeout or log output.
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

# CDA Issue Analysis

Goal: go from an issue description to a verified root cause and a concrete fix proposal.
Do not change code until the root cause is identified, unless the user asks for it.

## 1. Collect the facts

- Issue source (repo `eclipse-opensovd/classic-diagnostic-adapter`):   use the `github_*`
  MCP tools or, equally fine, the `gh` CLI (`gh issue view <nr> --comments`, `gh pr view`,
  `gh run view --log-failed`). Only if neither is available/authenticated, load the
  `cda-github-mcp-setup` skill.
  Alternatively a Jira ticket via the Atlassian tools, or the text supplied by the user.
- Extract and write down:
  - Expected vs. actual behavior, exact error text / HTTP status / NRC.
  - SOVD request (method, path, body) and ECU name, variant, service.
  - Transport (DoIP or CAN), CDA version / commit (`git log`), config used, relevant MDD file.
  - Logs and their level. If missing, list exactly what to ask the reporter for
    (`RUST_LOG=debug` log, config file, MDD file, request sequence).
- Whenever logs would help confirm or rule out a hypothesis and they are not yet
  available, ask the user for them, stating which time window / request they should cover:
  - Application logs: DLT traces (`.dlt`, CDA logs via `cda-tracing` DLT output) or text
    log files, ideally at `RUST_LOG=debug` (or `trace` for the affected crate).
  - Communication logs: Wireshark captures (`.pcap` / `.pcapng`) of the DoIP (TCP/UDP 13400)
    or CAN traffic between CDA and ECU. Use them to verify what was actually sent and
    received on the wire (UDS requests/responses, NRCs, timing, routing activation).
  - Correlate application and communication logs by timestamp.
- Check for duplicates and recent related changes:
  `gh issue list --search "<keywords>"`, `git log --oneline -30 -- <crate>`, `git log -S '<error text>'`.

## 2. Locate the layer

Request flow: `cda-sovd` (HTTP, routing, JSON) -> `cda-core` (SOVD to UDS mapping via
`cda-database`) -> `cda-comm-uds` (sessions, security, tester present, NRC handling) ->
`cda-transport-router` -> `cda-comm-doip` / `cda-comm-can` -> ECU.

Typical symptom to layer mapping:

| Symptom | Start at |
| --- | --- |
| 404 / wrong path / JSON schema mismatch | `cda-sovd`, `cda-sovd-interfaces` |
| Wrong/missing parameter, bad encoding/decoding of values | `cda-core`, `cda-database`, the MDD content |
| NRC 0x78 handling, session/security problems, lock issues | `cda-comm-uds` |
| Timeouts, no response, reconnects, routing activation | `cda-transport-router`, `cda-comm-doip`, `cda-comm-can`, com params in config |
| Startup failure, wrong defaults | `cda-main/src/config*`, `opensovd-cda.toml` |
| Missing/odd logs | `cda-tracing` |

Grep for the exact error message first; error enums are `thiserror` types, so the message
text usually leads directly to the variant and its construction sites.
Delegate broad searches to an `explore` subagent.

## 3. Inspect the diagnostic database (if data related)

If an MDD file is involved and the `mdd-mcp_*` tools are available:
`load_mdd` -> `search_nodes` (service / DID / parameter name) -> `get_node_details`.
Use `diff_mdd` / `export_diff` to compare a working and a failing database.
Verify request/response layout, coded constants, and com params before blaming the code.

If the `mdd-mcp_*` tools are not available, load the `cda-mdd-mcp-setup` skill, which explains
how to install and register the mdd-mcp server. If that is not possible, ask the user
for the relevant MDD content. Only if the problem occurs with the testcontainer databases
can the ODX sources in `testcontainer/` be used as a fallback.

## 4. Reproduce

Prefer the smallest reproduction that proves the hypothesis:

1. A unit test in the affected crate (`#[tokio::test]`, `mockall` mocks) - `cargo test -p <crate> <name>`.
2. An integration test in `integration-tests/tests/sovd/` using the ECU simulator
   (`testcontainer/ecu-sim`): `cargo test --locked -p integration-tests --features integration-tests <name> -- --show-output`.
3. Manual run: `RUST_LOG=debug cargo run -- --config-file <cfg>` against the docker compose
   environment in `testcontainer/` (see `testcontainer/first_steps.md`).

A reproducing test that fails before and passes after the fix is the preferred deliverable.

## 5. Determine the root cause

- Trace the actual code path; cite locations as `path:line`.
- Distinguish: code bug vs. configuration vs. database content vs. ECU (simulator) behavior
  vs. spec ambiguity. Check requirements in `docs/02_requirements` and decisions in `docs/04_adr`.
- Verify protocol behavior (NRCs, timing, sessions, security access, DoIP, ISO-TP) against
  the specification via the `cda-spec-expert` subagent instead of relying on memory.
- For concurrency issues look at locks (`parking_lot`, tokio), actor mailboxes (`kameo`),
  cancellation and timeouts; consider `tokio-console` (`--features tokio-tracing`).
- State confidence explicitly; list hypotheses that were ruled out and why.

## 6. Report

Answer with this structure (concise):

```text
Summary:        one sentence
Classification: bug | config | database | ECU/sim | feature request | not reproducible | duplicate of #N
Affected:       crates / files (path:line)
Reproduction:   steps or test name
Root cause:     explanation with evidence (code, logs, MDD data)
Fix proposal:   concrete change, risks, tests to add
Open questions: info still needed from the reporter
```

Only post comments to GitHub/Jira or apply fixes when the user asks. Any fix must follow
the `cda-rust-development` skill (`make fmt`, `make lint`, `make test`, SPDX headers).
