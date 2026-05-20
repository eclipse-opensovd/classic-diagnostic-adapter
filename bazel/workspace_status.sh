#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0

# Workspace status script for Bazel.
# Provides git metadata used by the cda-main build.rs (via SOURCE_DATE_EPOCH / SOURCE_GIT_SHA).
#
# Bazel calls this script before each build (--workspace_status_command).
# The output is available via ctx.info_file / ctx.version_file in Starlark.

set -euo pipefail

# Stable keys (changes cause a rebuild of targets that depend on them)
echo "STABLE_GIT_COMMIT $(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"

# Volatile keys (changes do NOT cause a rebuild)
echo "GIT_COMMIT_FULL $(git rev-parse HEAD 2>/dev/null || echo 'unknown')"
echo "BUILD_TIMESTAMP $(date +%s)"
echo "GIT_DATE $(git log -1 --format=%aI 2>/dev/null || echo '1970-01-01T00:00:00+00:00')"
