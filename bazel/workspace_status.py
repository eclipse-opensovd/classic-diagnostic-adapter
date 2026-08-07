#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation
#
# SPDX-License-Identifier: Apache-2.0

import datetime
import os
import subprocess


def git_output(*args: str) -> str:
    return subprocess.run(
        ["git", *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


source_date_epoch = os.environ.get("SOURCE_DATE_EPOCH")
if source_date_epoch is None:
    git_date = datetime.datetime.fromisoformat(git_output("log", "-1", "--format=%aI"))
    build_date = git_date.strftime("%Y-%m-%dT%H:%M:%SZ")
else:
    build_date = datetime.datetime.fromtimestamp(
        int(source_date_epoch),
        datetime.UTC,
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

commit_hash = os.environ.get("SOURCE_GIT_SHA") or git_output("rev-parse", "--short", "HEAD")

print(f"STABLE_BUILD_DATE {build_date}")
print(f"STABLE_GIT_COMMIT_HASH {commit_hash}")
