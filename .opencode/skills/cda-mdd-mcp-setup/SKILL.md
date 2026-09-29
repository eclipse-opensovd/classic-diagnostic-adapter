---
name: cda-mdd-mcp-setup
description: Install and register the mdd-mcp server (from eclipse-opensovd/mdd-ui) that provides the `mdd-mcp_*` tools for inspecting MDD diagnostic databases. Use when those tools are missing and an MDD file needs to be analyzed.
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

# mdd-mcp Setup

The MDD MCP server is part of [mdd-ui](https://github.com/eclipse-opensovd/mdd-ui). It runs
over stdio (`mdd-ui mcp`) and provides `load_mdd`, `browse_tree`, `get_node_details`,
`search_nodes`, `diff_mdd` and `export_diff`.

Ask the user before cloning, building or changing their configuration.

## 1. Check whether it is already installed

- Tools named `mdd-mcp_*` are available: nothing to do.
- An `mdd-ui` binary exists (`command -v mdd-ui`, or a previous clone) and `mdd-ui mcp`
  starts without an unknown-subcommand error: skip to step 3.

## 2. Clone and build with the `mcp` feature

Prerequisites: Rust 1.88+ (edition 2024). Pick a location outside the CDA repository,
e.g. `~/code/mdd-ui`.

```sh
git clone https://github.com/eclipse-opensovd/mdd-ui
cd mdd-ui
git checkout 63ae70d11b8de6efe858064bb944a676a92a3856   # pinned, known-good revision
cargo build --release --features mcp
```

Always build the pinned revision; do not use another branch or commit unless the user
explicitly asks. Updating the pin requires reviewing the upstream changes first (supply
chain).

The binary is `target/release/mdd-ui`. Verify with `target/release/mdd-ui mcp --help`.

On Linux the Tauri dependencies may require system packages (webkit2gtk, gtk3, etc.);
if the build fails, report the missing packages to the user instead of installing them
yourself. See the mdd-ui `README.md` for details.

## 3. Register the server in the coding environment

Use the absolute path to the built binary. Name the server `mdd-mcp` so the tools appear
as `mdd-mcp_*`, matching what other skills expect.

OpenCode (`~/.config/opencode/opencode.json` for all projects, or `opencode.json` in the
project root):

```json
{
  "mcp": {
    "mdd-mcp": {
      "type": "local",
      "command": ["/absolute/path/to/mdd-ui/target/release/mdd-ui", "mcp"]
    }
  }
}
```

Other MCP clients (Claude Code, VS Code, Cursor, ...) use the same stdio command
`<path>/mdd-ui mcp`; add it with the client's MCP configuration mechanism.

Prefer the user-level config; do not commit a machine-specific path to this repository.

## 4. Activate

The coding environment must be restarted to pick up the new MCP server. Tell the user to
restart, then check that the `mdd-mcp_*` tools are available and call `load_mdd` on an
absolute MDD path to verify.
