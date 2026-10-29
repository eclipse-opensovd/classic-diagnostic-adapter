# shellcheck shell=bash
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

# Shared helpers for the capture analysis demo. Sourced by run-demo.sh.

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTCONTAINER_DIR="$(cd "${DEMO_DIR}/../.." && pwd)"

# Same port configuration as docker compose (the integration tests generate random ports)
if [[ -f "${TESTCONTAINER_DIR}/.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "${TESTCONTAINER_DIR}/.env"
    set +a
fi

CDA_URL="${CDA_URL:-http://localhost:${CDA_PORT:-20002}}"
SIM_URL="${SIM_URL:-http://localhost:${SIM_CONTROL_PORT:-8181}}"
SOVD="${CDA_URL}/vehicle/v15"
ECU="${ECU:-FLXC1000}"
OUT_DIR="${OUT_DIR:-${DEMO_DIR}/out}"
CAPTURE_IMAGE="${CAPTURE_IMAGE:-nicolaka/netshoot}"
CAPTURE_CONTAINER="cda-demo-capture"

log() { printf '[%s] %s\n' "$(date +%H:%M:%S.%3N)" "$*" | tee -a "${NOTES_FILE:-/dev/null}"; }
die() { echo "error: $*" >&2; exit 1; }

require_tools() {
    for t in docker curl jq; do
        command -v "$t" >/dev/null || die "'$t' is required"
    done
}

wait_ready() {
    log "waiting for CDA at ${CDA_URL}"
    for _ in $(seq 1 60); do
        [[ "$(curl -s -o /dev/null -w '%{http_code}' "${CDA_URL}/health/ready")" == "204" ]] && return 0
        sleep 1
    done
    die "CDA not ready; start it with: (cd ${TESTCONTAINER_DIR} && docker compose up -d --build)"
}

token() {
    curl -sf -X POST "${SOVD}/authorize" -H 'Content-Type: application/json' \
        --data '{"client_id":"test","client_secret":"test"}' | jq -r .access_token
}

# sovd <METHOD> <path> [json-body]  -> logs HTTP status, duration and body
sovd() {
    local method=$1 path=$2 body=${3:-}
    local args=(-s -X "$method" -H "Authorization: Bearer ${TOKEN}" -w '\n%{http_code} %{time_total}')
    [[ -n "$body" ]] && args+=(-H 'Content-Type: application/json' --data "$body")
    log "SOVD ${method} ${path} ${body}"
    local res status
    res=$(curl "${args[@]}" "${SOVD}/${path}")
    status=$(tail -n1 <<<"$res")
    log "  -> HTTP ${status% *} after ${status#* }s: $(head -n -1 <<<"$res" | tr -d '\n' | cut -c1-300)"
    # shellcheck disable=SC2034 # read by run-demo.sh
    LAST_BODY=$(head -n -1 <<<"$res")
}

sim() {
    local method=$1 path=$2 body=${3:-}
    local args=(-s -o /dev/null -w '%{http_code}' -X "$method")
    [[ -n "$body" ]] && args+=(-H 'Content-Type: application/json' --data "$body")
    local code
    code=$(curl "${args[@]}" "${SIM_URL}/${path}")
    log "SIM ${method} /${path} ${body} -> ${code}"
}

set_interceptor() { sim PUT "interceptor/${ECU}/inbound/$1" "$2"; }
clear_interceptor() { sim DELETE "interceptor/${ECU}/inbound/$1"; }

sim_container() {
    docker compose -f "${TESTCONTAINER_DIR}/docker-compose.yml" ps -q ecu-sim
}

# Capture DoIP traffic inside the network namespace of the ecu-sim container.
# No host privileges or tshark on the host are needed for capturing.
start_capture() {
    local file=$1 cid
    cid=$(sim_container)
    [[ -n "$cid" ]] || die "ecu-sim container not running"
    docker rm -f "${CAPTURE_CONTAINER}" >/dev/null 2>&1 || true
    docker run -d --rm --name "${CAPTURE_CONTAINER}" --net "container:${cid}" \
        -v "${OUT_DIR}:/cap" "${CAPTURE_IMAGE}" \
        tcpdump -i any -U -w "/cap/${file}" 'tcp port 13400 or udp port 13400' >/dev/null
    sleep 2 # let tcpdump attach
    log "capture started: ${OUT_DIR}/${file}"
}

# save_cda_logs <file> <since-rfc3339>: CDA container logs since the given time, ANSI colors removed
save_cda_logs() {
    local file=$1 since=$2
    docker compose -f "${TESTCONTAINER_DIR}/docker-compose.yml" logs cda \
        --no-color --no-log-prefix --timestamps --since "${since}" 2>&1 \
        | sed -E 's/\x1b\[[0-9;]*m//g' >"${file}"
    log "CDA logs saved: ${file}"
}

stop_capture() {
    sleep 1
    docker stop "${CAPTURE_CONTAINER}" >/dev/null 2>&1 || true
    # tcpdump runs as root in the container, hand the files back to the user
    docker run --rm -v "${OUT_DIR}:/cap" "${CAPTURE_IMAGE}" chown -R "$(id -u):$(id -g)" /cap >/dev/null
    log "capture stopped"
}
