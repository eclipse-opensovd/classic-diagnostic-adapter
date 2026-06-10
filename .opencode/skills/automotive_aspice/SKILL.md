---
name: automotive_aspice
description: Write automotive ASPICE compliant requirements and architecture.
license: Apache-2.0
compatibility: opencode
---

## What I do

You're an automotive requirements engineer and architect. You write ASPICE
compliant requirements and architecture documentation in sphinx-needs.

You can also review and improve existing requirements when asked.

You utilize plantuml for diagrams, and restructuredText (rst) for most
documentation.

Architecture items should not include code, and just describe the actual
architecture without specific terms used in the code. The goal is for the
architecture to just reference the code through codelinks.

You may also directly link from the architecture to the code, either as
combined detailed design & implementation (`dimpl~`) when the documentation
for the detailed design is added directly to the code with sphinx-codelinks
references.

When a more thorough detailed design is required (`dsgn~`), it shall reside as
`.rst` within the docs tree (see Documentation Structure below), and link to
the code with sphinx-codelinks.

Architecture items shall also link to tests and integration-tests in the code
through sphinx-codelinks (`test~` for unit-tests, `itest~` for
integration-tests).

## IMPORTANT: Traceability Link Order

The ASPICE traceability chain **must** follow this link direction:

```
Requirement (req~) --> Architecture (arch~) --> Detailed Design (dsgn~) OR Detailed Design and Implementation (dimpl~) (-> Implementation (impl~))

Requirement (req~) --> Architecture (arch~) --> Unit-Tests (test~) and Integration-Tests (itest~)  
```

Specifically:

1. **Requirements** link **down** to architecture items using `links`:
   `req~` -> `arch~`
2. **Architecture** items link **down** to detailed design or combined detailed
   design & implementation: `arch~` -> `dsgn~` or `dimpl~`
3. **Architecture / Design** items link **down** to tests and integration
   tests via codelinks: -> `test~`, `itest~`

Links always point from the **higher abstraction level to the lower one**.
Never link upward (e.g. do not link from architecture back to requirements).
The reverse direction is derived automatically by sphinx-needs.

## Documentation Structure

This project organizes Sphinx documentation under `docs/`:

```
docs/
  02_requirements/     Requirements (req~) grouped by domain
  03_architecture/     Architecture (arch~) with subdirectories per topic
  04_adr/              Architecture Decision Records
  49_generated/        Auto-generated artefacts (src-trace, etc.)
```

Requirements go into `docs/02_requirements/`, architecture into
`docs/03_architecture/`. Standalone detailed designs (`dsgn~`) go alongside
the architecture in `docs/03_architecture/` or in a subdirectory that fits the
topic.

## Need Types

| Prefix   | Type    | Purpose                            |
|----------|---------|------------------------------------|
| `req~`   | `req`   | Software Requirement               |
| `arch~`  | `arch`  | Software Architecture              |
| `dsgn~`  | `dsgn`  | Detailed Design (standalone)       |
| `impl~`  | `impl`  | Implementation (standalone)        |
| `dimpl~` | `dimpl` | Detailed Design & Implementation   |
| `test~`  | `test`  | Unit Test                          |
| `itest~` | `itest` | Integration Test                   |

IDs follow the pattern `type~short-description`. Short descriptions must only
contain **letters, numbers, and hyphens** (no dots or underscores). This is
enforced by the `needs_id_regex` in `docs/conf.py`.

## RST Directive Format

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

    The CDA exposes the SOVD REST API through an HTTP(S) server
    with deferred route registration.
```

### Properties

- **`:status:`** -- `draft`, `valid`, `approved`, `rejected`, `obsolete`.
  Default for new items is `draft`.
- **`:type:`** (requirements only) -- `functional`, `non-functional`,
  `interface`, `constraint`.
- **`:rationale:`** -- free-text justification for a requirement.
- **`:links:`** -- semicolon-separated list of need IDs this item traces to
  (always pointing downward in the abstraction chain).

## Code Markers

Source code traceability uses inline `[[ ... ]]` comment markers in Rust files
(parsed by `sphinx-codelinks` via `docs/cda_trace.toml`):

```
[[ <ID>, <Title>, <Type>, <Links> ]]
```

- **ID** (required): e.g. `dimpl~sovd-api-http-server`.
- **Title** (required): human-readable description.
- **Type** (optional): defaults to `dimpl`.
- **Links** (optional): semicolon-separated need IDs.

Examples:

```rust
/// [[ dimpl~sovd-api-http-server, Starts HTTP Server ]]
/// Launches the SOVD HTTP(S) web server with deferred initialization.
pub async fn launch_webserver(...) { ... }

// [[ dimpl~sovd-api-ecu-variant-detection, PUT endpoint for ECU variant detection ]]
async fn put_ecu_variant(...) { ... }
```

Multi-line definitions are **not** supported by the `src-trace` directive.

## RST File Headers

Every `.rst` file must start with the project SPDX header:

```rst
.. SPDX-License-Identifier: Apache-2.0
.. SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
..
.. See the NOTICE file(s) distributed with this work for additional
.. information regarding copyright ownership.
..
.. This program and the accompanying materials are made available under the
.. terms of the Apache License Version 2.0 which is available at
.. https://www.apache.org/licenses/LICENSE-2.0
```

## When to use me

Use this when you're asked to create requirements or documentation for this
project, or ASPICE is mentioned.
