#!/bin/bash
#
# Google OAuth Desktop Flow Test Script (Bash)
#
# This script demonstrates the complete Google OAuth authentication flow
# for the Classic Diagnostic Adapter running on localhost:20002.
#
# Prerequisites:
# 1. Set environment variables:
#    export GOOGLE_CLIENT_ID="your-client-id.apps.googleusercontent.com"
#    export GOOGLE_CLIENT_SECRET="your-client-secret"
#
# 2. Start the CDA server with Google OAuth plugin enabled:
#    cargo run
#
# 3. Run this script:
#    ./oauth_flow_test.sh
#
# Requirements:
# - curl (for HTTP requests)
# - jq (for JSON parsing)
#

set -e  # Exit on error

# Configuration
BASE_URL="http://localhost:20002"
AUTHORIZE_ENDPOINT="${BASE_URL}/vehicle/v15/authorize"
CALLBACK_ENDPOINT="${BASE_URL}/vehicle/v15/oauth/callback"
PROTECTED_ENDPOINT="${BASE_URL}/vehicle/v15/components"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check dependencies
command -v curl >/dev/null 2>&1 || { echo -e "${RED}❌ ERROR: curl is required but not installed.${NC}" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo -e "${RED}❌ ERROR: jq is required but not installed. Install with: brew install jq${NC}" >&2; exit 1; }

echo "======================================================================"
echo "Google OAuth Desktop Flow Test"
echo "CDA Server: ${BASE_URL}"
echo "======================================================================"

# Check if server is reachable
echo -e "\n${BLUE}Checking if server is reachable...${NC}"
if curl -s -f -o /dev/null -m 2 "${BASE_URL}/vehicle/v15/components" 2>/dev/null || [ $? -eq 22 ]; then
    echo -e "${GREEN}✅ Server is reachable at ${BASE_URL}${NC}"
else
    echo -e "${RED}❌ ERROR: Cannot reach server at ${BASE_URL}${NC}"
    echo "   Make sure the CDA server is running with:"
    echo "   cargo run --bin cda-main"
    exit 1
fi

# Generate random state
STATE="test-state-$(openssl rand -hex 8)"

# STEP 1: Initiate Authorization
echo ""
echo "======================================================================"
echo "STEP 1: Initiating OAuth Authorization"
echo "======================================================================"

REQUEST_JSON=$(cat <<EOF
{
  "state": "${STATE}",
  "scopes": ["openid", "email", "profile"]
}
EOF
)

echo -e "\nSending POST request to: ${AUTHORIZE_ENDPOINT}"
echo "Request body:"
echo "${REQUEST_JSON}" | jq .

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "${AUTHORIZE_ENDPOINT}" \
    -H "Content-Type: application/json" \
    -d "${REQUEST_JSON}")

HTTP_CODE=$(echo "${RESPONSE}" | tail -n1)
RESPONSE_BODY=$(echo "${RESPONSE}" | sed '$d')

echo -e "\nResponse Status: ${HTTP_CODE}"

if [ "${HTTP_CODE}" != "200" ]; then
    echo -e "${RED}❌ Failed to initiate auth: ${HTTP_CODE}${NC}"
    echo "Response: ${RESPONSE_BODY}"
    exit 1
fi

AUTH_URL=$(echo "${RESPONSE_BODY}" | jq -r '.authorization_url')
RETURNED_STATE=$(echo "${RESPONSE_BODY}" | jq -r '.state')

if [ "${RETURNED_STATE}" != "${STATE}" ]; then
    echo -e "${YELLOW}⚠️  WARNING: State mismatch! Sent: ${STATE}, Received: ${RETURNED_STATE}${NC}"
fi

echo -e "\n${GREEN}✅ Authorization URL received:${NC}"
echo "   ${AUTH_URL}"

# STEP 2: User Authentication
echo ""
echo "======================================================================"
echo "STEP 2: User Authentication in Browser"
echo "======================================================================"

echo -e "\n${BLUE}Opening authorization URL in your default browser...${NC}"
echo "If the browser doesn't open automatically, copy this URL:"
echo ""
echo "   ${AUTH_URL}"
echo ""

# Try to open browser (macOS)
if command -v open >/dev/null 2>&1; then
    open "${AUTH_URL}" 2>/dev/null || true
fi

echo "In your browser:"
echo "1. Log into your Google account (if not already logged in)"
echo "2. Review and grant the requested permissions"
echo "3. Google will display an authorization code"
echo "4. Copy the authorization code from the browser"
echo ""
echo "----------------------------------------------------------------------"
read -p "Paste the authorization code here: " AUTH_CODE
echo "----------------------------------------------------------------------"

if [ -z "${AUTH_CODE}" ]; then
    echo -e "${RED}❌ ERROR: No authorization code provided${NC}"
    exit 1
fi

echo -e "\n${GREEN}✅ Authorization code received (length: ${#AUTH_CODE})${NC}"

# STEP 3: Exchange Code for Token
echo ""
echo "======================================================================"
echo "STEP 3: Exchanging Code for Access Token"
echo "======================================================================"

CALLBACK_JSON=$(cat <<EOF
{
  "code": "${AUTH_CODE}",
  "state": "${STATE}"
}
EOF
)

echo -e "\nSending POST request to: ${CALLBACK_ENDPOINT}"
echo "Request body:"
echo "${CALLBACK_JSON}" | jq .

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "${CALLBACK_ENDPOINT}" \
    -H "Content-Type: application/json" \
    -d "${CALLBACK_JSON}")

HTTP_CODE=$(echo "${RESPONSE}" | tail -n1)
RESPONSE_BODY=$(echo "${RESPONSE}" | sed '$d')

echo -e "\nResponse Status: ${HTTP_CODE}"

if [ "${HTTP_CODE}" != "200" ]; then
    echo -e "${RED}❌ Failed to exchange code: ${HTTP_CODE}${NC}"
    echo "Response: ${RESPONSE_BODY}"
    exit 1
fi

ACCESS_TOKEN=$(echo "${RESPONSE_BODY}" | jq -r '.access_token')
TOKEN_TYPE=$(echo "${RESPONSE_BODY}" | jq -r '.token_type')
EXPIRES_IN=$(echo "${RESPONSE_BODY}" | jq -r '.expires_in')

echo -e "\n${GREEN}✅ Access Token received:${NC}"
echo "   Token Type: ${TOKEN_TYPE}"
echo "   Expires In: ${EXPIRES_IN} seconds"
echo "   Token (first 50 chars): ${ACCESS_TOKEN:0:50}..."
echo "   Token Length: ${#ACCESS_TOKEN} characters"

# STEP 4: Test Protected Resource
echo ""
echo "======================================================================"
echo "STEP 4: Accessing Protected Resource"
echo "======================================================================"

echo -e "\nSending GET request to: ${PROTECTED_ENDPOINT}"
echo "Authorization Header: Bearer ${ACCESS_TOKEN:0:30}..."

RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "${PROTECTED_ENDPOINT}" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    -H "Accept: application/json")

HTTP_CODE=$(echo "${RESPONSE}" | tail -n1)
RESPONSE_BODY=$(echo "${RESPONSE}" | sed '$d')

echo -e "\nResponse Status: ${HTTP_CODE}"

if [ "${HTTP_CODE}" = "200" ]; then
    echo -e "\n${GREEN}✅ SUCCESS! Protected resource accessed successfully${NC}"
    echo -e "\nResponse Body:"
    echo "${RESPONSE_BODY}" | jq . 2>/dev/null || echo "${RESPONSE_BODY}"
elif [ "${HTTP_CODE}" = "401" ]; then
    echo -e "\n${RED}❌ UNAUTHORIZED: Token is invalid or expired${NC}"
    echo "Response: ${RESPONSE_BODY}"
else
    echo -e "\n${YELLOW}⚠️  Unexpected status code: ${HTTP_CODE}${NC}"
    echo "Response: ${RESPONSE_BODY}"
fi

# Summary
echo ""
echo "======================================================================"
echo "OAuth Flow Complete!"
echo "======================================================================"
echo -e "\nYour access token is valid for ${EXPIRES_IN} seconds."
echo "You can now use it to access protected resources:"
echo ""
echo "curl -H 'Authorization: Bearer ${ACCESS_TOKEN:0:30}...' \\"
echo "     ${PROTECTED_ENDPOINT}"
echo ""

# Save token to file for convenience
TOKEN_FILE="./access_token.txt"
echo "${ACCESS_TOKEN}" > "${TOKEN_FILE}"
echo -e "${GREEN}💾 Access token saved to: ${TOKEN_FILE}${NC}"
echo ""
