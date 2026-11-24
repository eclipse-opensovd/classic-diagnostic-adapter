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
// New advisories open an issue, still reported ones get a reminder comment once
// their issue had no activity for REMINDER_INTERVAL_DAYS (closed issues are
// reopened), advisories no longer reported close their issue.
// Called from .github/workflows/advisories.yml via actions/github-script.

const fs = require('node:fs');

const LABEL = 'advisory';
const LABEL_COLOR = 'f75c39';
const EXTRA_LABELS = ['dependencies'];
const MAX_PATHS = 10;
const MAX_BODY_LENGTH = 60000;
const DAY_MS = 24 * 60 * 60 * 1000;

function parseRecipients(value) {
  return [...new Set((value || '')
    .split(/[\s,]+/)
    .map(handle => handle.replace(/^@/, '').trim())
    .filter(Boolean))];
}

function parseInterval(value) {
  const days = Number(value);
  return Number.isFinite(days) && days >= 0 && String(value).trim() !== '' ? days : null;
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

function normalize(text) {
  return (text || '').replace(/\r\n/g, '\n').trim();
}

function issueBody(item, workflowUrl, recipients, intervalDays) {
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
    `The [advisory check](${workflowUrl}) runs daily. While the advisory is still reported, it posts a`,
    `reminder after ${intervalDays} day(s) without activity on this issue and reopens the issue if it was closed`,
    'without resolving it. Once the advisory is no longer reported, the issue is closed.',
    '',
    `_Reported by \`cargo deny check advisories\`_${mentions(recipients)}`,
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
  const workflowUrl = `${context.serverUrl}/${owner}/${repo}/actions/workflows/advisories.yml`;
  const recipients = parseRecipients(process.env.ADVISORY_RECIPIENTS);
  const intervalDays = parseInterval(process.env.REMINDER_INTERVAL_DAYS);
  const report = fs.readFileSync(process.env.DENY_REPORT, 'utf8');
  const { advisories, otherDiagnostics, summary } = parseReport(report);

  if (intervalDays === null) {
    core.setFailed(
      `REMINDER_INTERVAL_DAYS must be a non-negative number, got "${process.env.REMINDER_INTERVAL_DAYS}"`,
    );
    return;
  }
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
  const now = Date.now();

  for (const item of advisories.values()) {
    const issue = issues.get(item.id);
    const title = issueTitle(item);
    const body = issueBody(item, workflowUrl, recipients, intervalDays);
    if (!issue) {
      const { data: created } = await github.rest.issues.create({
        owner,
        repo,
        title,
        body,
        labels: [LABEL, ...EXTRA_LABELS],
        assignees: recipients,
      });
      core.info(`${item.id}: opened #${created.number}`);
      results.push([item, created, 'opened']);
      continue;
    }

    // Any write bumps `updated_at`, which is the activity the reminder interval is based on,
    // so the issue is only touched when something actually changed or a reminder is due.
    const reopen = issue.state === 'closed';
    const changed = issue.title !== title || normalize(issue.body) !== normalize(body);
    const idleDays = (now - Date.parse(issue.updated_at)) / DAY_MS;
    const remind = !reopen && idleDays >= intervalDays;

    if (changed || reopen) {
      await github.rest.issues.update({
        owner,
        repo,
        issue_number: issue.number,
        title,
        body,
        ...(reopen ? { state: 'open', state_reason: 'reopened' } : {}),
      });
    }
    const assigned = new Set((issue.assignees || []).map(a => a.login));
    const missing = recipients.filter(r => !assigned.has(r));
    if (missing.length > 0 && (changed || reopen || remind)) {
      await github.rest.issues.addAssignees({
        owner, repo, issue_number: issue.number, assignees: missing,
      });
    }
    if (!reopen && !remind) {
      core.info(`${item.id}: #${issue.number} ${changed ? 'updated' : 'unchanged'}, idle ${idleDays.toFixed(1)} day(s)`);
      results.push([item, issue, changed ? 'updated' : 'unchanged']);
      continue;
    }

    const message = reopen
      ? 'Reopened: the advisory is still reported. To accept it, add the ID with a reason to'
        + ' `[advisories].ignore` in `deny.toml`.'
      : `Reminder: the advisory is still reported and this issue had no activity for ${Math.floor(idleDays)} day(s).`;
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
