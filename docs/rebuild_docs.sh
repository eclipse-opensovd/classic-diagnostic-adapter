#!/bin/sh
# Copyright (c) 2025-2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

rm -rf "${SCRIPT_DIR}/_build"

UID=$(id -u)
GID=$(id -g)

docker build -f Dockerfile . -t sovdsphinx:latest
docker run --rm --user "${UID}:${GID}" \
		-e _JAVA_OPTIONS="-Djava.io.tmpdir=/tmp -Duser.home=/tmp" \
		-v "${SCRIPT_DIR}:/docs" \
		-v "${SCRIPT_DIR}/..:/project" \
		-it sovdsphinx:latest sphinx-build -W -b html /docs /docs/_build/html
