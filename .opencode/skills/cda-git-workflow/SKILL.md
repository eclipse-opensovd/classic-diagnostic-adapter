---
name: cda-git-workflow
description: Commit and pull request rules for the Classic Diagnostic Adapter (CDA) repository. Use whenever creating a commit, writing a commit message, pushing a branch or opening/updating a pull request.
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

# CDA Git Workflow

Do not commit, push or open PRs unless the user asks for it.

## GitHub access

GitHub operations (reading the PR template, creating/updating PRs) can use either:

- the `gh` CLI (if `gh auth status` succeeds), or
- the GitHub MCP server tools (`github_*`, see the `cda-github-mcp-setup` skill).

Use whichever is available; prefer `gh` if both are. If neither is available, ask the user
to authenticate `gh` or set up the MCP server via `cda-github-mcp-setup`.

Note: the setup in `cda-github-mcp-setup` is read-only (`X-MCP-Readonly` / `GITHUB_READ_ONLY`
and a read-only PAT). Creating or updating PRs via MCP requires the user to have configured
the server without read-only mode and with a token that has **Pull requests: Read and write**
permission. If a write tool (e.g. `github_create_pull_request`) is missing or fails with a
permission error, fall back to `gh` or give the user the title and body to create the PR
manually. Pushing branches always uses `git`, the MCP server cannot push local commits.

## Commits

- Use Conventional Commits with a crate scope, e.g. `fix(transport-router): ...`,
  `feat(doip): ...`, `chore(deps): ...`. Check `git log --oneline -10` for the style.
- Every commit must carry a DCO sign-off: `git commit -s`
  (adds `Signed-off-by: Name <email>` from the git config).
- Do not add `Co-authored-by:` trailers or any other AI attribution to commit messages.
- Before committing, inspect `git status` and `git diff`, stage only the intended files and
  never commit secrets. Run the pre-commit hooks
  (`uv run --group tools prek run --all-files`) and fix findings.
- If a hook rejects the commit, fix the issue and create a new commit; do not amend a failed
  commit or skip hooks.

## Pull requests

### Description

Use the Eclipse OpenSOVD PR template. The repository has no local template; it is the
organization default from `eclipse-opensovd/.github`:

```sh
gh api repos/eclipse-opensovd/.github/contents/PULL_REQUEST_TEMPLATE.md --jq .content | base64 -d
```

With the GitHub MCP server, read the same file with `github_get_file_contents`
(owner `eclipse-opensovd`, repo `.github`, path `PULL_REQUEST_TEMPLATE.md`).

Fill in every section of the template (drop the HTML comments and the SPDX header):

- **Summary**: what, why and how.
- **Checklist**: tick only items that are actually done; remove irrelevant lines.
- **Related**: linked issues/PRs (`Fixes #12`, `Closes #34`), or remove if none.
- **Notes for Reviewers**: open questions, decisions, known limitations (optional).

### PR description trailer

Some contributors must add a trailer to the PR description (e.g. a ticket reference or a
statement required by their organization). It is configured per user in the gitignored file
`.opencode/pr-trailer` (relative to the repository root).

1. Check whether `.opencode/pr-trailer` exists.
2. If it exists, append its content verbatim at the end of the PR description, after the
   template sections, separated by an empty line.
3. If the file does not exist, no trailer is needed. Do not create the file or invent a
   trailer.

The trailer applies only to the PR description, never to commit messages.

### Creating the PR

1. Inspect `git status`, the remote tracking branch, and all commits of the PR against the
   base branch (`git log origin/main..HEAD`, `git diff origin/main...HEAD`), not just the
   latest commit.
2. Verify every commit follows the commit rules above.
3. Push the branch (`git push -u origin <branch>`; never force-push unless asked).
4. Create the PR with the title in conventional commit style and the description (filled
   template plus the PR trailer, if configured):
   - `gh`: write the description to a temporary file and run
     `gh pr create --title "<title>" --body-file <file>`.
   - GitHub MCP: call `github_create_pull_request` with `owner`, `repo`, `title`, `body`,
     `head` (pushed branch, `<fork-owner>:<branch>` for forks) and `base` (e.g. `main`).
     Use `github_update_pull_request` to update an existing PR.
   Return the PR URL.
