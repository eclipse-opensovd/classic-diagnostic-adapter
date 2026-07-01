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

# Generic CDA data retrieval script: authenticates with CDA and reads one
# data item from one component.
#
# Usage: ./get_data.sh <component> <data-item>
# Example: ./get_data.sh flxc1000 vindataidentifier
#
# Credentials default to the test_client/test_secret pair shared with
# test_can_e2e.sh and test_all_data_services.py.

set -e

# Configuration
CDA_HOST="${CDA_HOST:-localhost}"
CDA_PORT="${CDA_PORT:-20002}"
BASE_URL="http://${CDA_HOST}:${CDA_PORT}/vehicle/v15"
CLIENT_ID="${CLIENT_ID:-test_client}"
CLIENT_SECRET="${CLIENT_SECRET:-test_secret}"

if [ $# -lt 2 ]; then
    echo "Usage: $0 <component> <data-item>" >&2
    echo "Example: $0 flxc1000 vindataidentifier" >&2
    exit 1
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check for jq
if ! command -v jq &> /dev/null; then
    echo -e "${YELLOW}Warning: jq is not installed. Output will not be formatted.${NC}"
    echo "Install with: sudo apt-get install jq"
    USE_JQ=false
else
    USE_JQ=true
fi

echo "========================================="
echo "CDA Data Retrieval"
echo "========================================="
echo "Server: ${BASE_URL}"
echo "Client ID: ${CLIENT_ID}"
echo ""

# Step 1: Get JWT token
echo -e "${YELLOW}[1/2] Authenticating...${NC}"
AUTH_RESPONSE=$(curl -s -X POST "${BASE_URL}/authorize" \
  -H "Content-Type: application/json" \
  -d "{
    \"client_id\": \"${CLIENT_ID}\",
    \"client_secret\": \"${CLIENT_SECRET}\"
  }")

if [ "$USE_JQ" = true ]; then
    TOKEN=$(echo "$AUTH_RESPONSE" | jq -r '.access_token')
else
    TOKEN=$(echo "$AUTH_RESPONSE" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
fi

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
    echo -e "${RED}Failed to get authentication token!${NC}"
    echo "Response: $AUTH_RESPONSE"
    exit 1
fi

echo -e "${GREEN}[OK] Authentication successful${NC}"
echo "Token: ${TOKEN:0:30}..."
echo ""

echo -e "${YELLOW}[2/2] Retrieving '${BASE_URL}/components/$1/data/$2' ...${NC}"
RESPONSE=$(curl -s -X GET "${BASE_URL}/components/$1/data/$2" \
  -H "Authorization: Bearer $TOKEN")

echo "Response from $1:"
if [ "$USE_JQ" = true ]; then
    echo "$RESPONSE" | jq '.'
else
    echo "$RESPONSE"
fi
echo ""
