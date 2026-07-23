#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import json
import os


def normalize(p):
    return p.lstrip("./")


def analyze(report_path, changed_files):
    if not os.path.exists(report_path):
        return []

    with open(report_path) as f:
        report = json.load(f)

    duplicates = report.get("duplicates", [])
    changed_set = {normalize(f) for f in changed_files}
    findings = []

    for dup in duplicates:
        first = dup.get("firstFile")
        second = dup.get("secondFile")
        if not first or not second:
            continue

        first_name = normalize(first.get("name", ""))
        second_name = normalize(second.get("name", ""))
        if first_name not in changed_set and second_name not in changed_set:
            continue

        findings.append(
            {
                "firstFile": first_name,
                "firstStart": first.get("start"),
                "firstEnd": first.get("end"),
                "secondFile": second_name,
                "secondStart": second.get("start"),
                "secondEnd": second.get("end"),
                "lines": dup.get("lines"),
                "tokens": dup.get("tokens"),
                "format": dup.get("format", ""),
                "fragment": dup.get("fragment", ""),
            }
        )

    return findings


def format_comment_body(findings):
    marker = "<!-- duplicate-code-check -->"
    if not findings:
        return f"{marker}\nDuplicate-code check passed - no duplication found in changed files."

    lines = [
        marker,
        "**Duplicate code detected (informational)** - these clusters touch files "
        "changed in this PR:",
    ]
    for i, f in enumerate(findings):
        a, b = f["firstFile"], f["secondFile"]
        lines.append("")
        lines.append(
            f"### {i + 1}. `{a}:{f['firstStart']}-{f['firstEnd']}` "
            f"matches `{b}:{f['secondStart']}-{f['secondEnd']}` "
            f"({f['lines']} lines, {f['tokens']} tokens)"
        )
        if f.get("fragment"):
            lines.append("")
            lines.append(f"```{f['format']}")
            lines.append(f["fragment"])
            lines.append("```")
    return "\n".join(lines)


def check_summary(findings):
    if not findings:
        return "No duplication touching this PR's changed files."
    return "\n".join(
        f"{f['firstFile']}:{f['firstStart']}-{f['firstEnd']} "
        f"matches {f['secondFile']}:{f['secondStart']}-{f['secondEnd']}"
        for f in findings
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("report", help="Path to jscpd JSON report")
    parser.add_argument("changed_files", help="Path to newline-separated changed files list")
    parser.add_argument("--outdir", default="/tmp", help="Output directory for generated files")
    args = parser.parse_args()

    with open(args.changed_files) as f:
        changed_files = [line.strip() for line in f if line.strip()]

    findings = analyze(args.report, changed_files)

    os.makedirs(args.outdir, exist_ok=True)

    body = format_comment_body(findings)
    with open(os.path.join(args.outdir, "body.md"), "w") as f:
        f.write(body)

    ok = len(findings) == 0
    with open(os.path.join(args.outdir, "check-title.txt"), "w") as f:
        f.write("No duplicate code found" if ok else "Duplicate code found (informational)")

    with open(os.path.join(args.outdir, "check-summary.txt"), "w") as f:
        f.write(check_summary(findings))

    msg = (
        "No duplicate code found touching PR changed files."
        if ok
        else (
            f"Found {len(findings)} duplicate code cluster(s) touching "
            "PR changed files (informational)."
        )
    )
    print(msg)


if __name__ == "__main__":
    main()
