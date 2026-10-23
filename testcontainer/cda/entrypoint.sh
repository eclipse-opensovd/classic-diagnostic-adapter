#!/bin/sh -e

# SPDX-FileCopyrightText: 2025 Copyright (c) Contributors to the Eclipse Foundation
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

# Environment:
#   CDA_CONFIG_FILE        Configuration file to use. If it exists, a copy with
#                          `[doip] tester_address` set to the container IP is
#                          created and used instead (the original may be a
#                          read-only mount).
#   CDA_ENTRYPOINT_HOOK_DIR Directory with additional scripts executed before
#                          the CDA starts (default: /app/entrypoint.d). Every
#                          regular file in it is run in lexical order with sh.
#                          A missing or empty directory is ignored.

DOIP_TESTER_IP=$(ip -4 a show scope global | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n 1)
HOOK_DIR="${CDA_ENTRYPOINT_HOOK_DIR:-/app/entrypoint.d}"

echo "Using arguments: $*"
echo "Using DoIpTesterIp: $DOIP_TESTER_IP"

# Writes a copy of config file $1 to $2 with `tester_address` in the [doip]
# section set to $3. Replaces an existing (or commented out) entry, otherwise
# appends it to the section. Adds the section if it does not exist.
update_tester_address() {
    awk -v ip="$3" '
        function emit() { print "tester_address = \"" ip "\""; done = 1 }
        /^[[:space:]]*\[/ {
            if (in_doip && !done) emit()
            in_doip = ($0 ~ /^[[:space:]]*\[doip\][[:space:]]*(#.*)?$/)
            seen = seen || in_doip
            print; next
        }
        in_doip && !done && /^[[:space:]]*#?[[:space:]]*tester_address[[:space:]]*=/ { emit(); next }
        { print }
        END {
            if (in_doip && !done) emit()
            if (!seen) { print ""; print "[doip]"; emit() }
        }
    ' "$1" > "$2"
}

if [ -n "$CDA_CONFIG_FILE" ] && [ -f "$CDA_CONFIG_FILE" ] && [ -n "$DOIP_TESTER_IP" ]; then
    PATCHED_CONFIG="/tmp/$(basename "$CDA_CONFIG_FILE")"
    update_tester_address "$CDA_CONFIG_FILE" "$PATCHED_CONFIG" "$DOIP_TESTER_IP"
    echo "Set [doip] tester_address = $DOIP_TESTER_IP in $PATCHED_CONFIG (from $CDA_CONFIG_FILE)"
    CDA_CONFIG_FILE="$PATCHED_CONFIG"
    export CDA_CONFIG_FILE
fi

if [ -d "$HOOK_DIR" ]; then
    for hook in "$HOOK_DIR"/*; do
        [ -f "$hook" ] || continue
        echo "Running entrypoint hook: $hook"
        sh "$hook"
    done
fi

find "." -maxdepth 1 -type f -print0 | xargs -0 sha1sum

# Exec is needed for the coverage results, to detach the CDA from PID 1 of the container.
# Otherwise the container will be stopped after the CDA has finished but the coverage won't be fully written to disk yet.
exec /app/opensovd-cda --tester-address "$DOIP_TESTER_IP" "$@"
