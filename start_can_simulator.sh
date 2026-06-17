#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)

# Start or stop the cda-simulator (Linux CAN/ISO-TP ECU simulator).
#
# Usage:
#   ./start_can_simulator.sh                                  # needs SIM_MDD env or -m
#   ./start_can_simulator.sh -m path/to/foo.mdd start        # explicit MDD, then start
#   ./start_can_simulator.sh start vxcan0                    # default MDD on vxcan0
#   ./start_can_simulator.sh -m foo.mdd start -v Foo_App_0101 # with variant
#   ./start_can_simulator.sh stop                            # stop a running instance
#   ./start_can_simulator.sh status                          # report whether running
#   ./start_can_simulator.sh restart                         # stop then start
#
# On start:
#   - runs `cargo run -p cda-simulator` in the background
#   - writes the PID to ./simulator.pid
#   - redirects stdout+stderr to ./simulator.log
#   - any args after the lifecycle verb are forwarded to cda-simulator
#     (e.g. interface name like vxcan0, variant flag -v ..., request-id,
#     response-id, --defaults <path>, etc.)
#
# The MDD path is resolved from, in order: explicit -m/--mdd, the SIM_MDD
# environment variable. If neither is set, start() fails with an actionable
# error.
#
# On stop:
#   - sends SIGTERM to the cargo wrapper, then to the cda-simulator child
#   - removes ./simulator.pid

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PID_FILE="$SCRIPT_DIR/simulator.pid"
LOG_FILE="$SCRIPT_DIR/simulator.log"

is_running() {
    [ -f "$PID_FILE" ] || return 1
    local pid
    pid=$(cat "$PID_FILE")
    [ -n "$pid" ] || return 1
    kill -0 "$pid" 2>/dev/null
}

start() {
    if is_running; then
        echo "Simulator is already running (pid $(cat "$PID_FILE")). Use '$0 stop' first."
        return 1
    fi

    # Resolve MDD: -m flag passed to cda-simulator (forwarded in $@), then
    # SIM_MDD env. Extract -m/--mdd from the forwarded arg list without
    # using getopt (keeps the script portable to plain bash).
    local mdd=""
    local args=("$@")
    local i=0
    while [ "$i" -lt "${#args[@]}" ]; do
        case "${args[$i]}" in
            -m|--mdd)
                if [ $((i+1)) -lt "${#args[@]}" ]; then
                    mdd="${args[$((i+1))]}"
                fi
                i=$((i+2))
                ;;
            -m=*|--mdd=*)
                mdd="${args[$i]#*=}"
                i=$((i+1))
                ;;
            *)
                i=$((i+1))
                ;;
        esac
    done
    if [ -z "$mdd" ]; then
        mdd="${SIM_MDD:-}"
    fi
    if [ -z "$mdd" ]; then
        echo "ERROR: no MDD path provided. Use -m <path>, set SIM_MDD, or pass --mdd <path>."
        echo "Example: $0 -m testcontainer/odx/FLXC1000.mdd start"
        return 1
    fi
    if [ ! -f "$mdd" ]; then
        echo "ERROR: MDD file not found: $mdd"
        return 1
    fi

    : > "$LOG_FILE"
    echo "Starting cda-simulator in background..."
    echo "  MDD file: $mdd"
    echo "  args:     $*"
    echo "Output is being redirected to: $LOG_FILE"

    nohup cargo run -p cda-simulator -- \
        -m "$mdd" \
        "$@" > "$LOG_FILE" 2>&1 &
    echo $! > "$PID_FILE"

    # Wait a moment to catch immediate-startup failures.
    sleep 2
    if is_running; then
        echo "[OK] Simulator started (pid $(cat "$PID_FILE")). Tail with: tail -f $LOG_FILE"
    else
        echo "[FAIL] Simulator exited immediately. Last log lines:"
        tail -20 "$LOG_FILE"
        rm -f "$PID_FILE"
        return 1
    fi
}

stop() {
    if ! is_running; then
        echo "Simulator is not running (no pid file or process gone)."
        rm -f "$PID_FILE"
        return 0
    fi

    local pid
    pid=$(cat "$PID_FILE")
    echo "Stopping simulator (pid $pid)..."

    # The pid is the cargo wrapper; cargo's child is cda-simulator.
    # Kill the child first (graceful), then the wrapper if needed.
    pkill -TERM -P "$pid" 2>/dev/null || true
    kill -TERM "$pid" 2>/dev/null || true

    # Wait up to 10s for graceful exit
    for _ in $(seq 1 20); do
        if ! kill -0 "$pid" 2>/dev/null; then
            rm -f "$PID_FILE"
            echo "[OK] Simulator stopped."
            return 0
        fi
        sleep 0.5
    done

    echo "Process did not stop gracefully, sending SIGKILL..."
    pkill -KILL -P "$pid" 2>/dev/null || true
    kill -KILL "$pid" 2>/dev/null || true
    rm -f "$PID_FILE"
    echo "[OK] Simulator killed."
}

status() {
    if is_running; then
        echo "Simulator is running (pid $(cat "$PID_FILE"))."
        echo "Log: $LOG_FILE"
    else
        echo "Simulator is not running."
        [ -f "$PID_FILE" ] && echo "(stale pid file present)" || true
    fi
}

case "${1:-start}" in
    start)   shift; start "$@" ;;
    stop)    stop ;;
    restart) shift; stop || true; start "$@" ;;
    status)  status ;;
    *)
        # Backward compatibility: any other verb (e.g. "-v", "vxcan0")
        # is treated as a simulator argument and we start in the default mode.
        start "$@"
        ;;
esac
