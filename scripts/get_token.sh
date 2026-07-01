#!/bin/bash

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

# Simple script to get a JWT token from CDA
# Usage: ./get_token.sh [host] [port]

CDA_HOST="${1:-localhost}"
CDA_PORT="${2:-20002}"
BASE_URL="http://${CDA_HOST}:${CDA_PORT}/vehicle/v15"

# Get token. Credentials match the test_client/test_secret defaults used by
# get_data.sh, test_can_e2e.sh and test_all_data_services.py.
TOKEN=$(curl -s -X POST "${BASE_URL}/authorize" \
  -H "Content-Type: application/json" \
  -d '{"client_id":"test_client","client_secret":"test_secret"}' | jq -r '.access_token')

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
    echo "Error: Failed to get token" >&2
    exit 1
fi

# Output just the token
echo "$TOKEN"
