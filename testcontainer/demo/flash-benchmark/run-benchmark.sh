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

# Flash performance benchmark: flashes a random file through the CDA into the ECU simulator
# (DoIP) once per maxNumberOfBlockLength and records a capture, the CDA logs and a CSV summary.
#
# For every capture analyze_gaps.py (needs tshark) measures the time from the ECU's 0x76
# response until the CDA starts sending the next 0x36.
#
# Usage: run-benchmark.sh [maxNumberOfBlockLength...]   (default: 4096 8192 16384 32768 65535)
# Env:   FILE_SIZE  size of the random flash file in bytes (default 104857600 = 100 MiB)
#        SNAPLEN    tcpdump snap length, 0 = full packets (default 0)
#        ECU        ECU to flash (default FLXC1000)
#        OUT_DIR    output directory (default ./out next to this script)
#        CDA_RUST_LOG  RUST_LOG of the CDA during the benchmark (default info, the
#                   testcontainer default debug distorts the timings); the CDA container is
#                   recreated with it and restored to the compose default on exit
#
# Portable to macOS (BSD date/stat, bash 3.2); python3 is used for millisecond timestamps.

set -euo pipefail

BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${OUT_DIR:-${BENCH_DIR}/out}"
# shellcheck disable=SC1091 # sourced relative to the script
source "${BENCH_DIR}/../capture-analysis/common.sh"
CAPTURE_CONTAINER="cda-flash-benchmark-capture"

FILE_SIZE="${FILE_SIZE:-104857600}"
SNAPLEN="${SNAPLEN:-0}"
FLASH_FILE_NAME="benchmark_random_${FILE_SIZE}.bin"
FLASH_FILE="${TESTCONTAINER_DIR}/flash_files/${FLASH_FILE_NAME}"
DEFAULT_BLOCK_LENGTHS=(4096 8192 16384 32768 65535)
ECU_PATH="components/$(tr '[:upper:]' '[:lower:]' <<<"${ECU}")"
DL_PATH="${ECU_PATH}/x-sovd2uds-download"
POLL_INTERVAL=0.2

# FLASH_TIMEOUT: max seconds to wait for one transfer
FLASH_TIMEOUT="${FLASH_TIMEOUT:-3600}"
CDA_RUST_LOG="${CDA_RUST_LOG:-info}"

# recreate_cda [rust_log]: recreates the CDA container, without argument with the compose default
recreate_cda() {
    local env_arg=(-u CDA_RUST_LOG)
    [[ $# -eq 0 ]] || env_arg=("CDA_RUST_LOG=$1")
    env "${env_arg[@]}" docker compose -f "${TESTCONTAINER_DIR}/docker-compose.yml" \
        up -d --no-deps --no-build cda >/dev/null 2>&1
}

# Runs the CDA with RUST_LOG=${CDA_RUST_LOG} and restores the compose default on exit, so later
# integration test runs against the same stack get the usual log output
set_cda_log_level() {
    log "CDA log level: ${CDA_RUST_LOG}"
    trap restore_cda_log_level EXIT
    recreate_cda "${CDA_RUST_LOG}" || die "could not restart the CDA"
}

restore_cda_log_level() {
    log "restoring the CDA log level to the compose default"
    recreate_cda || log "could not restore the CDA log level"
}

# date +%s%3N is GNU only
now_ms() {
    if command -v python3 >/dev/null; then
        python3 -c 'import time; print(int(time.time() * 1000))'
    else
        echo $(($(date +%s) * 1000))
    fi
}

file_size() { wc -c <"$1" | tr -d ' '; }

# sha1sum (GNU) or shasum (macOS)
sha1() {
    if command -v sha1sum >/dev/null; then sha1sum "$1"; else shasum -a 1 "$1"; fi | cut -d' ' -f1
}

# Like tcpdump in common.sh, but with snap length and only DoIP TCP (no UDP discovery)
start_bench_capture() {
    local file=$1 cid
    cid=$(sim_container)
    [[ -n "$cid" ]] || die "ecu-sim container not running"
    docker rm -f "${CAPTURE_CONTAINER}" >/dev/null 2>&1 || true
    docker run -d --rm --name "${CAPTURE_CONTAINER}" --net "container:${cid}" \
        -v "${OUT_DIR}:/cap" "${CAPTURE_IMAGE}" \
        tcpdump -i any -U -s "${SNAPLEN}" -B 65536 -w "/cap/${file}" 'tcp port 13400' >/dev/null
    sleep 2 # let tcpdump attach
    log "capture started: ${OUT_DIR}/${file} (snaplen ${SNAPLEN})"
}

create_flash_file() {
    if [[ -f "${FLASH_FILE}" && "$(file_size "${FLASH_FILE}")" == "${FILE_SIZE}" ]]; then
        log "reusing ${FLASH_FILE}"
    else
        log "creating ${FLASH_FILE} with ${FILE_SIZE} random bytes"
        head -c "${FILE_SIZE}" /dev/urandom >"${FLASH_FILE}.tmp"
        mv "${FLASH_FILE}.tmp" "${FLASH_FILE}"
    fi
    FLASH_SHA1=$(sha1 "${FLASH_FILE}")
    log "sha1 ${FLASH_SHA1}"
}

flash_file_id() {
    sovd GET "apps/sovd2uds/bulk-data/flashfiles"
    FILE_ID=$(jq -r --arg n "${FLASH_FILE_NAME}" \
        '.items[] | select(."x-sovd2uds-OrigPath" | tostring | endswith($n)) | .id' <<<"${LAST_BODY}" | head -n1)
    [[ -n "${FILE_ID}" ]] || die "flash file ${FLASH_FILE_NAME} not listed by the CDA (is flash_files mounted?)"
}

# Seed "0x00 0x01 ..." -> key: every byte + 13 (ECU sim algorithm)
security_key() {
    local out=() b
    for b in $1; do out+=("$(printf '0x%02x' $(((b + 13) & 0xFF)))"); done
    echo "${out[*]}"
}

hex4() { printf '0x%02x 0x%02x 0x%02x 0x%02x' $((($1 >> 24) & 255)) $((($1 >> 16) & 255)) $((($1 >> 8) & 255)) $(($1 & 255)); }

prepare_ecu() {
    local max_block_length=$1
    sim POST reset
    sim PUT "${ECU}/state" "{\"variant\":\"BOOT\",\"maxNumberOfBlockLength\":${max_block_length}}"
    sovd POST "${ECU_PATH}/locks" "{\"lock_expiration\": $((FLASH_TIMEOUT + 300))}"
    LOCK_ID=$(jq -r '.id // empty' <<<"${LAST_BODY}")
    [[ -n "${LOCK_ID}" ]] || die "could not lock ${ECU}"
    sovd PUT "${ECU_PATH}" # variant detection -> BOOT
    sovd PUT "${ECU_PATH}/modes/session" '{"value": "programming"}'
    sovd PUT "${ECU_PATH}/modes/security" '{"value": "Level_7_RequestSeed"}'
    local seed
    seed=$(jq -r '.seed.Request_Seed // empty' <<<"${LAST_BODY}")
    [[ -n "${seed}" ]] || die "no seed received"
    sovd PUT "${ECU_PATH}/modes/security" \
        "{\"value\": \"Level_7\", \"Key\": {\"Send_Key\": \"$(security_key "${seed}")\"}}"
    [[ "$(jq -r '.value // empty' <<<"${LAST_BODY}")" == "Level_7" ]] || die "security access failed"
}

# poll_transfer <id>: waits until the transfer is finished
poll_transfer() {
    local id=$1 deadline status body
    deadline=$(($(date +%s) + FLASH_TIMEOUT))
    while :; do
        body=$(curl -s -H "Authorization: Bearer ${TOKEN}" "${SOVD}/${DL_PATH}/flashtransfer/${id}")
        status=$(jq -r '.status // "unknown"' <<<"${body}")
        case "${status}" in
            finished) return 0 ;;
            aborted) log "transfer aborted: ${body}"; return 1 ;;
        esac
        (($(date +%s) < deadline)) || { log "transfer timed out: ${body}"; return 1; }
        sleep "${POLL_INTERVAL}"
    done
}

run_one() {
    local max_block_length=$1
    local name="flash_${FILE_SIZE}B_maxblock${max_block_length}"
    log "=== ${name}"
    TOKEN=$(token)
    prepare_ecu "${max_block_length}"
    flash_file_id

    start_bench_capture "${name}.pcap"
    local since t_start t_transfer t_end result=ok
    # second resolution (portable), docker logs --since includes the whole second
    since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    t_start=$(now_ms)

    sovd PUT "${DL_PATH}/requestdownload" "$(jq -n --arg size "$(hex4 "${FILE_SIZE}")" '{
        requestdownload: {
            DataFormatIdentifier: 0,
            AddressAndLengthFormatIdentifier: 68,
            MemoryAddress: "0x00 0x00 0x00 0x00",
            MemorySize: $size
        }}')"
    local ecu_max block_size
    ecu_max=$(jq -r '.requestdownload.MaxNumberOfBlockLength // empty' <<<"${LAST_BODY}")
    [[ -n "${ecu_max}" ]] || die "RequestDownload failed"
    # maxNumberOfBlockLength includes SID and block sequence counter (ISO 14229-1)
    block_size=$((ecu_max - 2))

    t_transfer=$(now_ms)
    sovd POST "${DL_PATH}/flashtransfer" "$(jq -n --arg id "${FILE_ID}" --argjson bs "${block_size}" \
        --argjson len "${FILE_SIZE}" \
        '{blocksequencecounter: 1, blocksize: $bs, offset: 0, length: $len, id: $id}')"
    local transfer_id
    transfer_id=$(jq -r '.id // empty' <<<"${LAST_BODY}")
    [[ -n "${transfer_id}" ]] || die "flash transfer not started"
    poll_transfer "${transfer_id}" || result=aborted
    local t_transfer_end
    t_transfer_end=$(now_ms)

    sovd DELETE "${DL_PATH}/flashtransfer/${transfer_id}"
    sovd PUT "${DL_PATH}/transferexit"
    t_end=$(now_ms)
    stop_capture
    save_cda_logs "${OUT_DIR}/${name}.log" "${since}"

    # verify what the simulated flash received
    local sim_state sim_sha1 sim_bytes sim_blocks sim_repeated sim_ms
    sim_state=$(curl -s "${SIM_URL}/${ECU}/datatransfers/downloads" | jq '.transfers[-1]')
    echo "${sim_state}" >"${OUT_DIR}/${name}.sim.json"
    sim_sha1=$(jq -r '.checksum // "" | gsub(" "; "") | ascii_downcase' <<<"${sim_state}")
    sim_bytes=$(jq -r '.bytesReceived' <<<"${sim_state}")
    sim_blocks=$(jq -r '.dataTransferCount' <<<"${sim_state}")
    sim_repeated=$(jq -r '.repeatedBlocks' <<<"${sim_state}")
    sim_ms=$(jq -r '.durationMs // ""' <<<"${sim_state}")
    [[ "${sim_sha1}" == "${FLASH_SHA1}" ]] || { [[ ${result} == ok ]] && result=checksum_mismatch; }

    [[ -n "${LOCK_ID}" ]] && sovd DELETE "${ECU_PATH}/locks/${LOCK_ID}"

    local transfer_ms=$((t_transfer_end - t_transfer))
    local throughput
    throughput=$(awk -v b="${FILE_SIZE}" -v ms="${transfer_ms}" 'BEGIN { printf "%.1f", (ms > 0) ? b / 1024 / (ms / 1000) : 0 }')
    local gap_stats="0,,,,,"
    if command -v tshark >/dev/null; then
        gap_stats=$("${BENCH_DIR}/analyze_gaps.py" "${OUT_DIR}/${name}.pcap" || true)
    fi
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' "${max_block_length}" "${block_size}" "${FILE_SIZE}" \
        "${sim_blocks}" "${sim_repeated}" "${sim_bytes}" "${transfer_ms}" "${sim_ms}" \
        "$((t_end - t_start))" "${throughput}" "${gap_stats}" "${result}" "${name}.pcap" >>"${CSV}"
    log "=== ${name}: ${result}, transfer ${transfer_ms} ms (${throughput} KiB/s), ${sim_blocks} blocks, ECU ack -> next 0x36 (count,mean,median,p95,max,min ms): ${gap_stats}"
}

main() {
    require_tools
    command -v sha1sum >/dev/null || command -v shasum >/dev/null || die "'sha1sum' or 'shasum' is required"
    mkdir -p "${OUT_DIR}"
    NOTES_FILE="${OUT_DIR}/benchmark.log"
    set_cda_log_level
    wait_ready
    create_flash_file
    CSV="${OUT_DIR}/results_$(date +%Y%m%d_%H%M%S).csv"
    echo "# cda_rust_log=${CDA_RUST_LOG}" >"${CSV}"
    echo "max_block_length,data_per_block,file_size,blocks,repeated_blocks,bytes_received,transfer_ms,ecu_transfer_ms,total_ms,throughput_kib_s,gap_count,gap_mean_ms,gap_median_ms,gap_p95_ms,gap_max_ms,gap_min_ms,result,capture" >>"${CSV}"
    local lengths=("$@")
    [[ ${#lengths[@]} -gt 0 ]] || lengths=("${DEFAULT_BLOCK_LENGTHS[@]}")
    for l in "${lengths[@]}"; do
        [[ "$l" =~ ^[0-9]+$ && "$l" -gt 2 ]] || die "invalid maxNumberOfBlockLength '$l'"
        run_one "$l"
    done
    log "results: ${CSV}"
    grep -v '^#' "${CSV}" | column -s, -t | tee -a "${NOTES_FILE}"
}

main "$@"
