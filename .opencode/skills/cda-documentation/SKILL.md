---
name: cda-documentation
description: Write or edit Classic Diagnostic Adapter (CDA) documentation under docs/ (Sphinx, sphinx-needs, sphinx-codelinks, plantuml) - requirements, architecture, design, test sets and traceability links. Use whenever adding or changing req~/arch~/dsgn~/dimpl~/impl~/testset~/test~/itest~ items or `[[ ... ]]` code trace comments.
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

# CDA Documentation

## Structure

```text
docs/
  01_about/          - project info, traceability conventions (04_traceability.rst)
  02_requirements/   - req~ items
  03_architecture/   - arch~ items (and dsgn~ where not in code)
  04_adr/            - architecture decision records
  05_verification/   - testset~ items grouping test~/itest~ items
  49_generated/      - generated content
  conf.py            - need types, ID regex, link direction check
  cda_trace.toml     - sphinx-codelinks config for `[[ ... ]]` code comments
```

## Need types and IDs

| Type | Meaning | Where |
| --- | --- | --- |
| `req~` | Software requirement | `docs/02_requirements/` |
| `arch~` | Software architecture | `docs/03_architecture/` |
| `dsgn~` | Detailed design | docs or code |
| `impl~` / `dimpl~` | Implementation / design & implementation | code comments |
| `testset~` | Test set (group of tests) | `docs/05_verification/` |
| `test~` / `itest~` | Unit / integration test | code comments |

IDs match `^(req|arch|dsgn|impl|dimpl|testset|test|itest)~[a-zA-Z0-9\-]+$` - no dots, no
underscores. Every item gets `:status:` (`draft`, `valid`, `approved`, `rejected`, `obsolete`).

Code trace comment: `/// [[ <id>, <title>, <type>, <links> ]]` (type defaults to `dimpl`).

## IMPORTANT: Traceability link direction

`:links:` always points from the higher abstraction level **down** to the lower-level item(s)
realizing or verifying it. sphinx-needs derives the reverse direction (`links_back`)
automatically - never add the reverse link.

```text
req -> arch -> dsgn -> impl/dimpl
       arch/dsgn -> testset -> test/itest
```

1. `req~` links down to the `arch~` item(s) satisfying it.
2. `arch~` links down to `dsgn~` / `dimpl~` / `impl~` items and to the `testset~` item(s)
   verifying it. An `arch~` item must **not** link back to its `req~`.
3. Tests are **not** linked individually from req/arch/dsgn/impl. Add the test to a
   `testset~` in `docs/05_verification/` and link that test set from the `arch~` or `dsgn~`
   item instead. `req~` -> `testset~` links are also allowed (not enforced at this time).
4. `impl~` / `dimpl~` items (incl. `[[ ... ]]` code comments) must **not** link to a
   `testset~` - link it from the `arch~`/`dsgn~` item for readability.
5. `[[ test~... ]]` / `[[ itest~... ]]` code comments carry **no** links.
6. Same-level links (e.g. `arch~` -> `arch~`) are allowed but must not form cycles.
7. Separate links with `, ` (not `;`).

Enforced by `check_link_direction` in `docs/conf.py`: upward links, `impl`/`dimpl` -> `testset`
links and same-level cycles are
emitted as warnings and fail the `sphinx-build -W` build (locally and in CI). The gap reports in
`docs/01_about/04_traceability.rst` list items missing a trace (informational).

## Adding a test

1. Annotate the test: `/// [[ test~<area>-<what>, <title>, test ]]` (or `itest~` in
   `integration-tests/`).
2. Add its ID to the `:links:` of a matching `.. testset::` in `docs/05_verification/`, or
   create a new test set:

   ```rst
   .. testset:: Lock Acquisition Policy
       :id: testset~sovd-api-lock-acquisition-policy
       :links: test~sovd-api-lock-acquisition-policy-config, itest~sovd-api-lock-acquisition-policy
       :status: draft

       Verifies configuration and enforcement of the lock acquisition policy.
   ```

3. For a new test set, link it from the `arch~` or `dsgn~` item it verifies (optionally also
   from the `req~`; never from `impl~`/`dimpl~`).

## Build

```sh
cd docs && uv run sphinx-build -W -b html . _build/html   # needs plantuml
make docs                                                  # Docker based
```

The build must pass with `-W`. New `.rst` files need the SPDX header (see existing files) and
must be added to a `toctree`.
