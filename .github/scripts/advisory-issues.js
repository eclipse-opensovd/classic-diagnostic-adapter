// SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Syncs the advisories reported by `cargo deny --format json check advisories`
// with GitHub issues: one issue per advisory ID, labelled `advisory`.
// New advisories open an issue, still reported ones get a reminder comment
// (closed issues are reopened), advisories no longer reported close their issue.
// Called from .github/workflows/advisories.yml via actions/github-script.

const fs = require('node:fs');

const LABEL = 'advisory';
const LABEL_COLOR = 'f75c39';
const EXTRA_LABELS = ['dependencies'];
const MAX_PATHS = 10;
const MAX_BODY_LENGTH = 60000;

function parseRecipients(value) {
  return [...new Set((value || '')
    .split(/[\s,]+/)
    .map(handle => handle.replace(/^@/, '').trim())
    .filter(Boolean))];
}

function dependencyPaths(node, suffix = [], paths = []) {
  if (paths.length >= MAX_PATHS) {
    return paths;
  }
  const krate = node.Krate;
  const kind = krate.kind ? ` (${krate.kind})` : '';
  const chain = [...suffix, `${krate.name} ${krate.version}${kind}`];
  if (!node.parents || node.parents.length === 0 || node.repeat) {
    paths.push(chain.join(' <- '));
    return paths;
  }
  for (const parent of node.parents) {
    dependencyPaths(parent, chain, paths);
  }
  return paths;
}

function parseReport(text) {
  const advisories = new Map();
  const otherDiagnostics = [];
  let summary = null;

  for (const line of text.split('\n')) {
    if (!line.startsWith('{')) {
      continue;
    }
    let entry;
    try {
      entry = JSON.parse(line);
    } catch {
      continue;
    }
    if (entry.type === 'summary') {
      summary = entry.fields;
      continue;
    }
    if (entry.type !== 'diagnostic') {
      continue;
    }
    const fields = entry.fields || {};
    const advisory = fields.advisory;
    if (!advisory) {
      otherDiagnostics.push(fields);
      continue;
    }

    let item = advisories.get(advisory.id);
    if (!item) {
      const solution = (fields.notes || []).find(note => note.startsWith('Solution: '));
      item = {
        id: advisory.id,
        kind: fields.code,
        severity: fields.severity,
        advisory,
        solution: solution ? solution.slice('Solution: '.length) : null,
        versions: new Set(),
        paths: [],
      };
      advisories.set(advisory.id, item);
    }
    for (const graph of fields.graphs || []) {
      item.versions.add(graph.Krate.version);
      for (const path of dependencyPaths(graph)) {
        if (item.paths.length < MAX_PATHS && !item.paths.includes(path)) {
          item.paths.push(path);
        }
      }
    }
  }

  return { advisories, otherDiagnostics, summary };
}

function issueTitle(item) {
  return `${item.id} (${item.advisory.package}): ${item.advisory.title}`;
}

function issueId(issue) {
  return issue.title.split(' ')[0];
}

function mentions(recipients) {
  return recipients.length > 0 ? `\n\ncc ${recipients.map(r => `@${r}`).join(' ')}` : '';
}

function issueBody(item, runUrl, recipients) {
  const a = item.advisory;
  const rows = [
    ['Advisory', `[${a.id}](https://rustsec.org/advisories/${a.id})`],
    ['Kind', item.kind],
    ['Crate', `\`${a.package}\``],
    ['Versions in Cargo.lock', [...item.versions].map(v => `\`${v}\``).join(', ')],
    ['Date', a.date],
  ];
  if (a.cvss) {
    rows.push(['CVSS', `\`${a.cvss}\``]);
  }
  if (a.aliases && a.aliases.length > 0) {
    rows.push(['Aliases', a.aliases.join(', ')]);
  }
  if (a.url) {
    rows.push(['Details', a.url]);
  }
  if (item.solution) {
    rows.push(['Solution', item.solution]);
  }

  const body = [
    `\`cargo deny check advisories\` reports **${a.id}**: ${a.title}`,
    '',
    '| | |',
    '| --- | --- |',
    ...rows.map(([key, value]) => `| ${key} | ${String(value).replace(/\|/g, '\\|')} |`),
    '',
    '### Dependency paths',
    '',
    '```text',
    ...item.paths,
    '```',
    '',
    '<details><summary>Advisory description</summary>',
    '',
    a.description || '_No description._',
    '',
    '</details>',
    '',
    '### How to resolve',
    '',
    '- Update or replace the affected dependency so that `make deny ARGS=advisories` passes, or',
    '- if the advisory does not affect the CDA, add the ID with a reason to `[advisories].ignore` in `deny.toml`.',
    '',
    'The weekly advisory check comments here while the advisory is still reported, reopens the issue if it',
    'was closed without resolving it and closes it once the advisory is no longer reported.',
    '',
    `_Reported by ${runUrl}_${mentions(recipients)}`,
  ].join('\n');

  return body.length > MAX_BODY_LENGTH ? `${body.slice(0, MAX_BODY_LENGTH)}\n\n_(truncated)_` : body;
}

async function ensureLabel(github, owner, repo) {
  try {
    await github.rest.issues.getLabel({ owner, repo, name: LABEL });
  } catch (e) {
    if (e.status !== 404) {
      throw e;
    }
    await github.rest.issues.createLabel({
      owner,
      repo,
      name: LABEL,
      color: LABEL_COLOR,
      description: 'Security advisory reported by cargo-deny',
    });
  }
}

async function existingIssues(github, owner, repo) {
  const issues = await github.paginate(github.rest.issues.listForRepo, {
    owner,
    repo,
    labels: LABEL,
    state: 'all',
    per_page: 100,
  });
  const byId = new Map();
  for (const issue of issues) {
    if (issue.pull_request) {
      continue;
    }
    const id = issueId(issue);
    const known = byId.get(id);
    // prefer an open issue, otherwise the most recent one
    if (!known
      || (issue.state === 'open' && known.state !== 'open')
      || (issue.state === known.state && issue.number > known.number)) {
      byId.set(id, issue);
    }
  }
  return byId;
}

module.exports = async ({ github, context, core }) => {
  const { owner, repo } = context.repo;
  const runUrl = `${context.serverUrl}/${owner}/${repo}/actions/runs/${context.runId}`;
  const recipients = parseRecipients(process.env.ADVISORY_RECIPIENTS);
  const report = fs.readFileSync(process.env.DENY_REPORT, 'utf8');
  const { advisories, otherDiagnostics, summary } = parseReport(report);

  if (!summary) {
    core.setFailed(
      `cargo-deny exited with ${process.env.DENY_EXIT_CODE} without a summary, see the "Check advisories" step log`,
    );
    return;
  }
  if (recipients.length === 0) {
    core.warning('ADVISORY_RECIPIENTS is empty, only repository watchers are notified');
  }

  await ensureLabel(github, owner, repo);
  const issues = await existingIssues(github, owner, repo);
  const results = [];

  for (const item of advisories.values()) {
    const issue = issues.get(item.id);
    if (!issue) {
      const { data: created } = await github.rest.issues.create({
        owner,
        repo,
        title: issueTitle(item),
        body: issueBody(item, runUrl, recipients),
        labels: [LABEL, ...EXTRA_LABELS],
        assignees: recipients,
      });
      core.info(`${item.id}: opened #${created.number}`);
      results.push([item, created, 'opened']);
      continue;
    }

    const reopen = issue.state === 'closed';
    await github.rest.issues.update({
      owner,
      repo,
      issue_number: issue.number,
      title: issueTitle(item),
      body: issueBody(item, runUrl, recipients),
      ...(reopen ? { state: 'open', state_reason: 'reopened' } : {}),
    });
    if (recipients.length > 0) {
      await github.rest.issues.addAssignees({
        owner, repo, issue_number: issue.number, assignees: recipients,
      });
    }
    const message = reopen
      ? 'Reopened: the advisory is still reported. To accept it, add the ID with a reason to'
        + ' `[advisories].ignore` in `deny.toml`.'
      : 'Reminder: the advisory is still reported.';
    await github.rest.issues.createComment({
      owner,
      repo,
      issue_number: issue.number,
      body: `${message}\n\n_Checked by ${runUrl}_${mentions(recipients)}`,
    });
    core.info(`${item.id}: ${reopen ? 'reopened' : 'reminded on'} #${issue.number}`);
    results.push([item, issue, reopen ? 'reopened' : 'reminded']);
  }

  for (const [id, issue] of issues) {
    if (issue.state !== 'open' || advisories.has(id)) {
      continue;
    }
    await github.rest.issues.createComment({
      owner,
      repo,
      issue_number: issue.number,
      body: `The advisory is no longer reported (dependency updated or ignored in \`deny.toml\`), closing.\n\n`
        + `_Checked by ${runUrl}_`,
    });
    await github.rest.issues.update({
      owner, repo, issue_number: issue.number, state: 'closed', state_reason: 'completed',
    });
    core.info(`${id}: closed #${issue.number}`);
    results.push([{ id, kind: '-', advisory: { package: '-' } }, issue, 'closed']);
  }

  await core.summary
    .addHeading('Advisories')
    .addTable([
      [
        { data: 'Advisory', header: true },
        { data: 'Kind', header: true },
        { data: 'Crate', header: true },
        { data: 'Issue', header: true },
        { data: 'Action', header: true },
      ],
      ...results.map(([item, issue, action]) => [
        item.id, item.kind, item.advisory.package, `#${issue.number}`, action,
      ]),
    ])
    .write();

  const errors = otherDiagnostics.filter(d => d.severity === 'error');
  for (const d of otherDiagnostics) {
    const log = d.severity === 'error' ? core.error : core.warning;
    log(`${d.code}: ${d.message}`);
  }
  if (errors.length > 0) {
    core.setFailed(`cargo-deny reported ${errors.length} error(s) that are not advisories`);
  }
};
