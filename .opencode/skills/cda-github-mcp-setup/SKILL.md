---
name: cda-github-mcp-setup
description: Install and register the official GitHub MCP server (github/github-mcp-server) that provides the `github_*` tools for reading issues, pull requests, comments, commits and Actions logs. Use when GitHub issues or PRs need to be analyzed and those tools are missing.
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

# GitHub MCP Setup

The [GitHub MCP server](https://github.com/github/github-mcp-server) gives agents structured
access to issues, PRs, comments, commits and GitHub Actions logs. Upstream OpenCode guide:
`docs/installation-guides/install-opencode.md` in that repository.

Ask the user before changing their configuration. Never write a token into any file.

## 1. Check whether it is needed at all

- The `gh` CLI is an equally valid alternative. If `gh auth status` succeeds, installing
  the MCP server is optional; ask the user whether they want it before proceeding.
- Tools named `github_*` (e.g. `github_issue_read`, `github_get_me`) are available: nothing to do.
- `opencode mcp list` shows a `github` server as failed: run `opencode mcp debug github`
  and report the output (usually an expired / missing token).

## 2. Provide a token

The server needs a GitHub Personal Access Token in `GITHUB_PERSONAL_ACCESS_TOKEN`
in the environment opencode is started from. Use a dedicated, read-only fine-grained PAT;
do not use a classic PAT or a broadly scoped token.

Create it at https://github.com/settings/personal-access-tokens/new:

- Token name: e.g. `opencode-cda-readonly`.
- Expiration: short (e.g. 30-90 days).
- Resource owner: the user's own account (public repositories of other owners such as
  `eclipse-opensovd` are readable with it).
- Repository access: "Public repositories" (read-only access to all public repositories).
  If private repositories are needed, use "Only select repositories" instead and pick them.
- Repository permissions (only with "Only select repositories"), all **Read-only**:

  | Permission | Needed for |
  | --- | --- |
  | Metadata | Mandatory, selected automatically |
  | Contents | Files, commits, branches |
  | Issues | Issues and issue comments |
  | Pull requests | PRs, review comments, diffs |
  | Actions | Workflow runs and job logs |

- Account permissions: none.

Then export it in the shell profile, e.g. `export GITHUB_PERSONAL_ACCESS_TOKEN=...`
(or load it from a secret manager).

The user has to set this up themselves; do not read, print or store the token.

## 3. Register the server

Name the server `github` so the tools appear as `github_*`. Prefer the user-level config
(`~/.config/opencode/opencode.json`); do not commit it to this repository.

Remote server (recommended, no Docker needed). Restrict to read-only and the toolsets
needed for issue analysis to keep the context small:

```json
{
  "mcp": {
    "github": {
      "type": "remote",
      "url": "https://api.githubcopilot.com/mcp/",
      "enabled": true,
      "oauth": false,
      "headers": {
        "Authorization": "Bearer {env:GITHUB_PERSONAL_ACCESS_TOKEN}",
        "X-MCP-Toolsets": "context,repos,issues,pull_requests,actions",
        "X-MCP-Readonly": "true"
      }
    }
  }
}
```

Local alternative (requires a running Docker):

```json
{
  "mcp": {
    "github": {
      "type": "local",
      "command": [
        "docker", "run", "-i", "--rm",
        "-e", "GITHUB_PERSONAL_ACCESS_TOKEN",
        "-e", "GITHUB_TOOLSETS=context,repos,issues,pull_requests,actions",
        "-e", "GITHUB_READ_ONLY=1",
        "ghcr.io/github/github-mcp-server"
      ],
      "enabled": true,
      "environment": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "{env:GITHUB_PERSONAL_ACCESS_TOKEN}"
      }
    }
  }
}
```

Notes: opencode uses `environment` (not `env`), `command` is a single array, and
`{env:VAR}` (not `${VAR}`) for interpolation.

Optionally, to keep the many GitHub tools out of other agents' context, disable them
globally and re-enable per agent:

```json
{
  "tools": { "github_*": false },
  "agent": { "cda-issue-analyst": { "tools": { "github_*": true } } }
}
```

## 4. Activate

opencode must be restarted to pick up the new server. Tell the user to restart, then
verify with `opencode mcp list` and a `github_get_me` call. Until then, fall back to the
`gh` CLI (`gh issue view <nr> --comments`).
