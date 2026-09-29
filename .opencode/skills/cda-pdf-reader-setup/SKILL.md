---
name: cda-pdf-reader-setup
description: Install and register the pdf-reader MCP server (I-CAN-hack/pdf-mcp) that provides the `pdf-reader_*` tools for searching and reading PDF files, e.g. specification PDFs in `OPENSOVD_SPEC_DIR`. Use when those tools are missing and a PDF needs to be read.
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

# pdf-reader Setup

The PDF MCP server is [pdf-mcp](https://github.com/I-CAN-hack/pdf-mcp) (MIT, Python,
PyMuPDF). It runs over stdio and provides `get_pdf_info`, `get_table_of_contents`,
`get_page_text`, `get_page_image` and `search_text`. All calls are stateless and take
the PDF path as a parameter.

Ask the user before installing anything or changing their configuration.

## 1. Check whether it is already installed

- Tools named `pdf-reader_*` are available: nothing to do.
- Otherwise check that `uv` is installed (`command -v uvx`). If missing, tell the user to
  install it (https://docs.astral.sh/uv/) instead of installing it yourself.

## 2. Register the server in the coding environment

Name the server `pdf-reader` so the tools appear as `pdf-reader_*`, matching what other
skills expect. `uvx` fetches and runs the server automatically; no clone is needed.

OpenCode (`~/.config/opencode/opencode.json` for all projects, or `opencode.json` in the
project root):

```json
{
  "mcp": {
    "pdf-reader": {
      "type": "local",
      "command": ["uvx", "--from", "git+https://github.com/I-CAN-hack/pdf-mcp.git@c430ba664d82b06140f24358310dbf7016b532a1", "pdf-mcp"]
    }
  }
}
```

The server is pinned to a known-good commit. Never drop the `@<sha>` or replace it with a
branch name; updating the pin requires reviewing the upstream changes first (supply chain).

Alternative with a local clone (same pinned revision, works offline):

```sh
git clone https://github.com/I-CAN-hack/pdf-mcp ~/tools/pdf-mcp
git -C ~/tools/pdf-mcp checkout c430ba664d82b06140f24358310dbf7016b532a1
uv --directory ~/tools/pdf-mcp sync
```

and use `["uv", "--directory", "/absolute/path/to/pdf-mcp", "run", "pdf-mcp"]` as command.

Other MCP clients (Claude Code, VS Code, Cursor, ...) use the same stdio command; add it
with the client's MCP configuration mechanism (e.g. `.mcp.json` with `mcpServers`).

Prefer the user-level config; do not commit a machine-specific path to this repository.

## 3. Activate

The coding environment must be restarted to pick up the new MCP server. Tell the user to
restart, then check that the `pdf-reader_*` tools are available and call
`pdf-reader_get_pdf_info` on an absolute PDF path to verify.
