# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0

#/bin/sh -e
SCRIPT_DIR=$(dirname "$(realpath "$0")")
docker build -f "$SCRIPT_DIR/docker/Dockerfile" "$SCRIPT_DIR" -t cda-odx-gen
docker run -v "$SCRIPT_DIR:/data" -u $(id -u):$(id -g) -t cda-odx-gen
