#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)

# End-to-end test of the CAN bus transport: for each MDD, start the
# cda-simulator on a (virtual) CAN interface, start CDA with the `can`
# feature against the same interface, and verify over the SOVD REST API
# that the ECU is discovered, variant detection completes, and data can
# be read through the full HTTP -> ISO-TP/CAN -> simulator round trip.
#
# Usage:
#   ./scripts/test_can_e2e.sh [options] [mdd-file ...]
#
# Options:
#   -i, --interface IF   CAN interface to use (default: vcan0)
#   -p, --port PORT      CDA SOVD port (default: 20102)
#   -t, --transport MODE Transport backend (default: kernel):
#                          kernel  - kernel ISO-TP sockets (modules vcan +
#                                    can_isotp)
#                          rawcan  - userspace ISO-TP over raw CAN; only the
#                                    vcan module is needed, NOT can_isotp
#                          tcp     - CAN frames over TCP; no (v)can or ISO-TP
#                                    kernel support needed at all
#   --tcp-port PORT      TCP port for -t tcp (default: 19800)
#   -v, --variant NAME   Variant the simulator should present (default: the
#                        MDD's base variant). Useful for single-MDD runs,
#                        e.g. a boot variant exposes no data services.
#   --setup              Create the CAN interface via sudo if it is missing
#                        (modprobe vcan [can_isotp]; ip link add ... type vcan)
#   --release            Use release builds
#   --skip-build         Do not (re)build the binaries
#
# Without MDD arguments, all example MDDs from testcontainer/odx/ are
# tested (functional_groups.mdd is skipped - it describes functional
# groups, not an ECU).
#
# The example MDDs contain a CAN protocol layer but no CAN addressing
# com-params, so the script assigns explicit request/response CAN IDs
# (0x7E0/0x7E8) in that case. MDDs that do carry CAN IDs (e.g. via
# CP_UniqueRespIdTable) are used as-is, and the summary reports which
# source was used.
#
# Requirements: Linux with SocketCAN + ISO-TP (kernel modules vcan and
# can_isotp for virtual testing), python3, curl.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$REPO_ROOT" || exit 1

INTERFACE="vcan0"
CDA_PORT="20102"
TRANSPORT="kernel"
TCP_PORT="19800"
PROFILE="debug"
CARGO_PROFILE_ARG=""
DO_SETUP=0
SKIP_BUILD=0
SIM_VARIANT=""
MDDS=()

while [ $# -gt 0 ]; do
    case "$1" in
        -i|--interface) INTERFACE="$2"; shift 2 ;;
        -p|--port)      CDA_PORT="$2"; shift 2 ;;
        -t|--transport) TRANSPORT="$2"; shift 2 ;;
        --tcp-port)     TCP_PORT="$2"; shift 2 ;;
        -v|--variant)   SIM_VARIANT="$2"; shift 2 ;;
        --setup)        DO_SETUP=1; shift ;;
        --release)      PROFILE="release"; CARGO_PROFILE_ARG="--release"; shift ;;
        --skip-build)   SKIP_BUILD=1; shift ;;
        -h|--help)      grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -45; exit 0 ;;
        *)              MDDS+=("$1"); shift ;;
    esac
done

# Per-transport interface strings (the tokio-socketcan-isotp fork selects
# its backend from the address scheme) and cargo feature set.
case "$TRANSPORT" in
    kernel)
        SIM_IF="$INTERFACE"
        CDA_IF="$INTERFACE"
        CARGO_FEATURES="opensovd-cda/can"
        ;;
    rawcan)
        SIM_IF="rawcan:$INTERFACE"
        CDA_IF="rawcan:$INTERFACE"
        CARGO_FEATURES="opensovd-cda/can-isotp-userspace"
        ;;
    tcp)
        SIM_IF="tcplisten:127.0.0.1:$TCP_PORT"
        CDA_IF="tcp:127.0.0.1:$TCP_PORT"
        CARGO_FEATURES="opensovd-cda/can-tcp"
        ;;
    *)
        echo "[e2e][FAIL] unknown transport '$TRANSPORT' (kernel|rawcan|tcp)" >&2
        exit 1
        ;;
esac

if [ ${#MDDS[@]} -eq 0 ]; then
    for f in "$REPO_ROOT"/testcontainer/odx/*.mdd; do
        case "$(basename "$f")" in
            functional_groups.mdd) ;;
            *) MDDS+=("$f") ;;
        esac
    done
fi

# Fallback CAN IDs for MDDs without CAN addressing com-params
FALLBACK_REQUEST_ID="0x7E0"
FALLBACK_RESPONSE_ID="0x7E8"

# Static VIN marker the simulator seeds via the per-MDD
# <name>.defaults.toml. Exactly 17 ASCII characters (ISO 3779 length),
# deliberately prefixed "CDA-SIM-" so it cannot be mistaken for a real VIN.
EXPECTED_VIN="CDA-SIM-MARKER000"

SIM_BIN="$REPO_ROOT/target/$PROFILE/cda-simulator"
CDA_BIN="$REPO_ROOT/target/$PROFILE/opensovd-cda"
BASE_URL="http://127.0.0.1:${CDA_PORT}/vehicle/v15"

SIM_PID=""
CDA_PID=""
WORK_DIR=""

log()  { echo "[e2e] $*"; }
fail() { echo "[e2e][FAIL] $*" >&2; }

cleanup_procs() {
    if [ -n "$CDA_PID" ] && kill -0 "$CDA_PID" 2>/dev/null; then
        kill "$CDA_PID" 2>/dev/null
        wait "$CDA_PID" 2>/dev/null
    fi
    if [ -n "$SIM_PID" ] && kill -0 "$SIM_PID" 2>/dev/null; then
        kill "$SIM_PID" 2>/dev/null
        wait "$SIM_PID" 2>/dev/null
    fi
    SIM_PID=""
    CDA_PID=""
}

# shellcheck disable=SC2329  # invoked via the EXIT trap
cleanup_all() {
    cleanup_procs
    [ -n "$WORK_DIR" ] && rm -rf "$WORK_DIR"
}
trap cleanup_all EXIT

# Interface (tcp mode needs no CAN interface at all)
if [ "$TRANSPORT" != "tcp" ] && ! ip link show "$INTERFACE" >/dev/null 2>&1; then
    if [ "$DO_SETUP" -eq 1 ]; then
        log "Creating CAN interface $INTERFACE (requires sudo)"
        sudo modprobe vcan || { fail "modprobe vcan failed"; exit 1; }
        if [ "$TRANSPORT" = "kernel" ]; then
            sudo modprobe can_isotp || { fail "modprobe can_isotp failed"; exit 1; }
        fi
        sudo ip link add dev "$INTERFACE" type vcan || { fail "ip link add failed"; exit 1; }
        sudo ip link set up "$INTERFACE" || { fail "ip link set up failed"; exit 1; }
    else
        fail "CAN interface $INTERFACE does not exist. Re-run with --setup, or create it:"
        if [ "$TRANSPORT" = "kernel" ]; then
            fail "  sudo modprobe vcan can_isotp"
        else
            fail "  sudo modprobe vcan"
        fi
        fail "  sudo ip link add dev $INTERFACE type vcan && sudo ip link set up $INTERFACE"
        exit 1
    fi
fi

# Build
if [ "$SKIP_BUILD" -eq 0 ]; then
    log "Building cda-simulator and opensovd-cda (--features $CARGO_FEATURES) [$PROFILE]"
    # shellcheck disable=SC2086
    cargo build $CARGO_PROFILE_ARG -p cda-simulator -p opensovd-cda --features "$CARGO_FEATURES" \
        || { fail "build failed"; exit 1; }
fi
[ -x "$SIM_BIN" ] || { fail "missing $SIM_BIN"; exit 1; }
[ -x "$CDA_BIN" ] || { fail "missing $CDA_BIN"; exit 1; }

WORK_DIR="$(mktemp -d /tmp/cda-can-e2e.XXXXXX)"

# Helpers
json_get() {
    # json_get <python-expression-on-d> ; JSON on stdin
    python3 -c "import json,sys; d=json.load(sys.stdin); print($1)" 2>/dev/null
}

wait_for_log() {
    # wait_for_log <file> <pattern> <timeout-s>
    local file="$1" pattern="$2" timeout="$3" i=0
    while [ "$i" -lt $((timeout * 10)) ]; do
        grep -q "$pattern" "$file" 2>/dev/null && return 0
        sleep 0.1
        i=$((i + 1))
    done
    return 1
}

# Per-MDD test
RESULTS=()
OVERALL_RC=0

run_one() {
    local mdd="$1"
    local name sim_log cda_log mdd_dir cfg req_id resp_id id_source ecu ecu_lc
    name="$(basename "$mdd" .mdd)"
    sim_log="$WORK_DIR/$name-sim.log"
    cda_log="$WORK_DIR/$name-cda.log"

    log "=== $name ==="

    local sim_args=(-m "$mdd" -i "$SIM_IF" --no-api)
    if [ -n "$SIM_VARIANT" ]; then
        sim_args+=(--variant "$SIM_VARIANT")
    fi

    # 1. Start the simulator without explicit IDs to find out whether the
    #    MDD provides CAN addressing on its own.
    id_source="MDD"
    "$SIM_BIN" "${sim_args[@]}" > "$sim_log" 2>&1 &
    SIM_PID=$!
    if ! wait_for_log "$sim_log" "Starting CAN listener" 10; then
        if grep -q "CanIdNotAvailable" "$sim_log"; then
            # 2. MDD has no CAN IDs - retry with the explicit fallback pair.
            wait "$SIM_PID" 2>/dev/null; SIM_PID=""
            id_source="fallback"
            "$SIM_BIN" "${sim_args[@]}" \
                --request-id "$FALLBACK_REQUEST_ID" --response-id "$FALLBACK_RESPONSE_ID" \
                > "$sim_log" 2>&1 &
            SIM_PID=$!
            if ! wait_for_log "$sim_log" "Starting CAN listener" 10; then
                fail "$name: simulator did not start (see $sim_log)"
                tail -5 "$sim_log" >&2
                RESULTS+=("$name|FAIL|simulator did not start|$id_source")
                cleanup_procs
                return 1
            fi
        else
            fail "$name: simulator did not start (see $sim_log)"
            tail -5 "$sim_log" >&2
            RESULTS+=("$name|FAIL|simulator did not start|$id_source")
            cleanup_procs
            return 1
        fi
    fi

    # The IDs the simulator actually uses (CLI override or MDD-provided).
    # The log contains ANSI color codes; strip them before parsing.
    local sim_log_plain
    sim_log_plain="$(sed 's/\x1b\[[0-9;]*m//g' "$sim_log")"
    req_id="$(echo "$sim_log_plain" \
        | sed -n 's/.*CAN IDs configured.*request_id="\(0x[0-9A-Fa-f]*\)".*/\1/p' | head -1)"
    resp_id="$(echo "$sim_log_plain" \
        | sed -n 's/.*CAN IDs configured.*response_id="\(0x[0-9A-Fa-f]*\)".*/\1/p' | head -1)"
    ecu="$(echo "$sim_log_plain" \
        | sed -n 's/.*Loaded ECU data.*ecu_name=\([A-Za-z0-9_-]*\).*/\1/p' | head -1)"
    ecu="${ecu:-$name}"
    if [ -z "$req_id" ] || [ -z "$resp_id" ]; then
        fail "$name: could not parse CAN IDs from simulator log ($sim_log)"
        RESULTS+=("$name|FAIL|cannot parse CAN IDs|$id_source")
        cleanup_procs
        return 1
    fi
    ecu_lc="$(echo "$ecu" | tr '[:upper:]' '[:lower:]')"
    log "$name: ECU=$ecu request_id=$req_id response_id=$resp_id (IDs from $id_source)"

    # Give the simulator a moment to open its first ISO-TP socket: the
    # "Starting CAN listener" log line precedes the actual bind, and CDA's
    # discovery probe at startup is one-shot. In tcp mode this also covers
    # the hub bind; if CDA still connects too early, the 3-attempt restart
    # loop below re-probes.
    sleep 1

    # 3. CDA config: temp database dir containing only this MDD.
    # Protocol selection is adaptive: most MDDs work with the per-ECU
    # `protocol = "UDS_CAN"` alias chain, but some example MDDs (e.g.
    # TMCC3000) contain no protocol definitions at all and need
    # `ignore_protocol = true` instead (same as testcontainer/cda-test-config.toml).
    mdd_dir="$WORK_DIR/$name-mdds"
    mkdir -p "$mdd_dir"
    cp "$mdd" "$mdd_dir/"
    cfg="$WORK_DIR/$name-cda.toml"

    write_config() {
        # write_config <protocol-mode: uds_can | ignore_protocol>
        local ecu_block
        if [ "$1" = "uds_can" ]; then
            ecu_block="[ecu.$ecu]
protocol = \"UDS_CAN\""
        else
            ecu_block="[ecu.$ecu]
ignore_protocol = true"
        fi
        cat > "$cfg" <<EOF
flash_files_path = "$WORK_DIR"

[server]
address = "127.0.0.1"
port = $CDA_PORT

[database]
path = "$mdd_dir"

[doip]
enabled = false

[can]
interface = "$CDA_IF"
response_timeout_ms = 2000
probe_timeout_ms = 500

[[can.ecu_mappings]]
ecu_name = "$ecu"
request_id = $((req_id))
response_id = $((resp_id))

$ecu_block

[logging.otel]
enabled = false
EOF
    }

    start_cda() {
        CDA_CONFIG_FILE="$cfg" RUST_LOG="${RUST_LOG:-info}" "$CDA_BIN" > "$cda_log" 2>&1 &
        CDA_PID=$!
    }

    stop_cda() {
        if [ -n "$CDA_PID" ] && kill -0 "$CDA_PID" 2>/dev/null; then
            kill "$CDA_PID" 2>/dev/null
            wait "$CDA_PID" 2>/dev/null
        fi
        CDA_PID=""
    }

    # component_listed: 0 if the ECU shows up in /components
    component_listed() {
        curl -sf "$BASE_URL/components" 2>/dev/null \
            | json_get "','.join(i['id'] for i in d['items'])" | grep -q "$ecu_lc"
    }

    local protocol_mode="uds_can"
    write_config "$protocol_mode"
    start_cda

    # 4. Assert: the MDD loads and the ECU is listed as component. If the
    #    protocol lookup failed, retry once with ignore_protocol = true.
    local i=0 found=0
    while [ "$i" -lt 30 ]; do
        if ! kill -0 "$CDA_PID" 2>/dev/null; then
            fail "$name: CDA exited early (see $cda_log)"
            tail -5 "$cda_log" >&2
            RESULTS+=("$name|FAIL|CDA exited early|$id_source")
            cleanup_procs
            return 1
        fi
        if component_listed; then
            found=1
            break
        fi
        if grep -q "Failed to create DiagServiceManager" "$cda_log" \
            && [ "$protocol_mode" = "uds_can" ]; then
            log "$name: MDD rejected protocol UDS_CAN, retrying with ignore_protocol = true"
            protocol_mode="ignore_protocol"
            stop_cda
            write_config "$protocol_mode"
            start_cda
            i=0
            continue
        fi
        sleep 0.5
        i=$((i + 1))
    done
    if [ "$found" -ne 1 ]; then
        fail "$name: ECU $ecu not in component list (see $cda_log)"
        tail -5 "$cda_log" >&2
        RESULTS+=("$name|FAIL|ECU not discovered|$id_source")
        cleanup_procs
        return 1
    fi

    # 5. Assert: variant detection completed -> state Online. CDA's CAN
    #    discovery probe is one-shot at startup; if it raced the simulator,
    #    restart CDA up to twice (3 attempts total) before giving up.
    local state variant attempt
    state=""
    for attempt in 1 2 3; do
        i=0
        while [ "$i" -lt 30 ]; do
            state="$(curl -sf "$BASE_URL/components/$ecu_lc" | json_get "d['variant']['state']")"
            [ "$state" = "Online" ] && break
            sleep 0.5
            i=$((i + 1))
        done
        [ "$state" = "Online" ] && break
        if [ "$attempt" -lt 3 ]; then
            log "$name: state=$state after attempt $attempt, restarting CDA for a re-probe"
            stop_cda
            start_cda
        fi
    done
    variant="$(curl -sf "$BASE_URL/components/$ecu_lc" | json_get "d['variant']['name']")"
    if [ "$state" != "Online" ]; then
        fail "$name: ECU state is '$state', expected Online (variant=$variant)"
        RESULTS+=("$name|FAIL|state=$state|$id_source")
        cleanup_procs
        return 1
    fi
    log "$name: online, variant=$variant (protocol mode: $protocol_mode)"

    # 7. Assert: an authorized data read over CAN succeeds, and the
    #    returned VIN matches the static default-value marker exactly.
    local token items item ok rc vin
    token="$(curl -sf -X POST "$BASE_URL/authorize" -H "Content-Type: application/json" \
        -d '{"client_id":"test_client","client_secret":"test_secret"}' \
        | json_get "d['access_token']")"
    if [ -z "$token" ]; then
        fail "$name: could not get auth token"
        RESULTS+=("$name|FAIL|auth failed|$id_source")
        cleanup_procs
        return 1
    fi
    items="$(curl -sf -H "Authorization: Bearer $token" "$BASE_URL/components/$ecu_lc/data" \
        | json_get "'\n'.join(i['id'] for i in d['items'])")"
    if [ -z "$items" ]; then
        fail "$name: data item list is empty"
        RESULTS+=("$name|FAIL|no data items|$id_source")
        cleanup_procs
        return 1
    fi
    ok=0
    vin=""
    while IFS= read -r item; do
        rc="$(curl -s -o "$WORK_DIR/$name-data.json" -w '%{http_code}' \
            -H "Authorization: Bearer $token" "$BASE_URL/components/$ecu_lc/data/$item")"
        if [ "$rc" = "200" ]; then
            ok=1
            log "$name: read data item '$item' -> $(head -c 120 "$WORK_DIR/$name-data.json")"
            # Read VIN data item directly so we can assert the exact value.
            # The data-item id returned by CDA is the MDD short name
            # (e.g. "VINDataIdentifier"); compare case-insensitively.
            if [ "${item,,}" = "vindataidentifier" ]; then
                vin="$(python3 -c \
                    "import json;d=json.load(open('$WORK_DIR/$name-data.json'));print(d.get('data',{}).get('VIN',''))" 2>/dev/null)"
            fi
            # If the first 5 data items don't include VINDataIdentifier
            # (the example MDDs always put it first, so this is the cold
            # path), fall back to a single explicit fetch. The simulator
            # only opens a fresh ISO-TP socket per request, so a second
            # immediate fetch can race the first one; a brief sleep keeps
            # it reliable.
            if [ -z "$vin" ] && [ "${item,,}" != "vindataidentifier" ]; then
                sleep 0.2
                rc2="$(curl -s -o "$WORK_DIR/$name-vin.json" -w '%{http_code}' \
                    -H "Authorization: Bearer $token" \
                    "$BASE_URL/components/$ecu_lc/data/vindataidentifier")"
                if [ "$rc2" = "200" ]; then
                    vin="$(python3 -c \
                        "import json;d=json.load(open('$WORK_DIR/$name-vin.json'));print(d.get('data',{}).get('VIN',''))" 2>/dev/null)"
                fi
            fi
            break
        fi
    done <<< "$(echo "$items" | head -5)"
    if [ "$ok" -ne 1 ]; then
        fail "$name: none of the first 5 data items returned HTTP 200"
        RESULTS+=("$name|FAIL|data read failed|$id_source")
        cleanup_procs
        return 1
    fi

    # 8. Assert: the static VIN marker is present and exactly 17 chars long.
    if [ "$vin" != "$EXPECTED_VIN" ]; then
        fail "$name: VIN mismatch (expected='$EXPECTED_VIN' len=${#EXPECTED_VIN}, got='$vin' len=${#vin})"
        RESULTS+=("$name|FAIL|vin='$vin'|$id_source")
        cleanup_procs
        return 1
    fi
    if [ "${#vin}" -ne 17 ]; then
        fail "$name: VIN length is ${#vin}, expected 17 (ISO 3779)"
        RESULTS+=("$name|FAIL|vin_len=${#vin}|$id_source")
        cleanup_procs
        return 1
    fi
    log "$name: VIN '$vin' matches the static default marker"

    RESULTS+=("$name|PASS|variant=$variant vin=$vin ($protocol_mode)|$id_source")
    cleanup_procs
    return 0
}

for mdd in "${MDDS[@]}"; do
    if [ ! -f "$mdd" ]; then
        fail "MDD not found: $mdd"
        RESULTS+=("$(basename "$mdd" .mdd)|FAIL|file not found|-")
        OVERALL_RC=1
        continue
    fi
    run_one "$mdd" || OVERALL_RC=1
done

echo ""
echo "==================== CAN e2e summary ===================="
printf '%-14s %-6s %-32s %s\n' "ECU" "RESULT" "DETAIL" "CAN-IDs"
for r in "${RESULTS[@]}"; do
    IFS='|' read -r n s detail src <<< "$r"
    printf '%-14s %-6s %-32s %s\n' "$n" "$s" "$detail" "$src"
done
echo "=========================================================="
exit "$OVERALL_RC"
