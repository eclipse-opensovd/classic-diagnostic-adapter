#!/bin/sh -e

# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0

SCRIPT_DIR=$(dirname "$(realpath "$0")")
TARGET_DIR=$(realpath "$SCRIPT_DIR/..")

echo "Building ecu-sim"
"$TARGET_DIR/gradlew" -p "$TARGET_DIR" build shadowJar

echo "Building docker container for ecu-sim"
docker build -f "$TARGET_DIR/docker/Dockerfile" "$TARGET_DIR" -t ecu-sim
