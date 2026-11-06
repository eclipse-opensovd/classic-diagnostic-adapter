#!/usr/bin/env bash
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

# Records DoIP captures of CDA <-> ECU sim traffic for the capture analysis demo.
# Usage: run-demo.sh <scenario>... | all | list

set -euo pipefail
# shellcheck disable=SC1091 # sourced relative to the script
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

VIN_PATH="components/${ECU,,}/data/VINDataIdentifier"
VIN_REQ="22F190"

declare -A DESCRIPTIONS=(
    [healthy]="lock, extended session, read VIN, idle for tester present, unlock"
    [late-response]="ECU answers after 1500 ms without sending 0x78"
    [pending-ok]="ECU sends 4x 0x78 every 800 ms, then the real response"
    [pending-gap]="ECU sends 0x78, then stays silent for 1500 ms before the next one"
    [busy-retry]="ECU answers 3x NRC 0x21 (busy), then the real response"
    [no-response]="ECU never answers the request"
)
ORDER=(healthy late-response pending-ok pending-gap busy-retry no-response)

scenario_healthy() {
    sovd POST "components/${ECU,,}/locks" '{"lock_expiration": 60}'
    local lock_id
    lock_id=$(jq -r '.id // empty' <<<"${LAST_BODY}")
    sovd PUT "components/${ECU,,}/modes/session" '{"value": "extended"}'
    sovd GET "${VIN_PATH}"
    log "idling 8 s so tester present traffic is visible"
    sleep 8
    sovd GET "${VIN_PATH}"
    [[ -n "${lock_id}" ]] && sovd DELETE "components/${ECU,,}/locks/${lock_id}"
}

# The interceptor forwards to the regular ECU handler ("response": null) after the delay,
# so the final response is the genuine VIN.
with_interceptor() {
    local body=$1
    set_interceptor demo "${body}"
    sovd GET "${VIN_PATH}"
    clear_interceptor demo
}

scenario_late-response() {
    with_interceptor "{\"request\":\"${VIN_REQ}\",\"response\":null,\"delayMs\":1500,\"removeAfterNRequest\":1}"
}

scenario_pending-ok() {
    with_interceptor "{\"request\":\"${VIN_REQ}\",\"response\":null,\"pendingResponses\":4,\"pendingIntervalMs\":800,\"removeAfterNRequest\":1}"
}

scenario_pending-gap() {
    with_interceptor "{\"request\":\"${VIN_REQ}\",\"response\":null,\"pendingResponses\":2,\"pendingIntervalMs\":1500,\"removeAfterNRequest\":1}"
}

scenario_busy-retry() {
    with_interceptor "{\"request\":\"${VIN_REQ}\",\"response\":\"7F2221\",\"removeAfterNRequest\":3}"
}

scenario_no-response() {
    with_interceptor "{\"request\":\"${VIN_REQ}\",\"response\":\"\"}"
}

run_scenario() {
    local name=$1
    declare -F "scenario_${name}" >/dev/null || die "unknown scenario '${name}' (try: list)"
    log "=== scenario ${name}: ${DESCRIPTIONS[$name]} (ECU ${ECU})"
    sim POST reset
    clear_interceptor demo
    # shellcheck disable=SC2034 # used by sovd() in common.sh
    TOKEN=$(token)
    # warm up (not captured): variant detection and DoIP connection outside of the capture.
    # Reads Identification (22 F100), the DID also used for variant detection.
    log "warm-up (not captured)"
    sovd GET "components/${ECU,,}/data/Identification"
    start_capture "${name}.pcap"
    local since
    since=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
    "scenario_${name}"
    stop_capture
    save_cda_logs "${OUT_DIR}/${name}.log" "${since}"
    log "=== done: ${OUT_DIR}/${name}.pcap, CDA logs: ${OUT_DIR}/${name}.log"
}

main() {
    [[ $# -gt 0 ]] || set -- list
    if [[ $1 == list ]]; then
        for s in "${ORDER[@]}"; do printf '  %-14s %s\n' "$s" "${DESCRIPTIONS[$s]}"; done
        exit 0
    fi
    [[ $1 == all ]] && set -- "${ORDER[@]}"
    require_tools
    mkdir -p "${OUT_DIR}"
    wait_ready
    for s in "$@"; do run_scenario "$s"; done
}

main "$@"
