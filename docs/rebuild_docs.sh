#!/bin/sh

# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

rm -rf "${SCRIPT_DIR}/_build"

# Build with uv (local, requires plantuml on PATH or PLANTUML env var set):
#   cd docs && uv run sphinx-build -W -b html . _build/html
#
# Build with Docker (self-contained):
SCRIPT_UID=$(id -u)
SCRIPT_GID=$(id -g)

docker build -f Dockerfile . -t sovdsphinx:latest
docker run --rm --user "${SCRIPT_UID}:${SCRIPT_GID}" \
		-e _JAVA_OPTIONS="-Djava.io.tmpdir=/tmp -Duser.home=/tmp" \
		-v "${SCRIPT_DIR}/..:/workspace" \
		-w /workspace/docs \
		sovdsphinx:latest sphinx-build -W -b html . _build/html
