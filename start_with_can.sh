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

# Start or stop the CDA process running over CAN.
#
# Usage:
#   ./start_with_can.sh           # start in background with RUST_LOG=debug
#   ./start_with_can.sh start     # same as above
#   ./start_with_can.sh stop      # stop a previously started instance
#   ./start_with_can.sh status    # report whether CDA is running
#   ./start_with_can.sh restart   # stop then start
#
# On start:
#   - sets RUST_LOG=debug and uses opensovd-cda-can.toml
#   - launches `cargo run` in the background
#   - writes the PID to ./cda.pid
#   - redirects stdout+stderr to ./cda.log
#
# On stop:
#   - sends SIGTERM to the cargo wrapper, then to the opensovd-cda child
#   - removes ./cda.pid

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

export CDA_CONFIG_FILE="opensovd-cda-can.toml"
export RUST_LOG="${RUST_LOG:-debug}"

PID_FILE="$SCRIPT_DIR/cda.pid"
LOG_FILE="$SCRIPT_DIR/cda.log"

is_running() {
    [ -f "$PID_FILE" ] || return 1
    local pid
    pid=$(cat "$PID_FILE")
    [ -n "$pid" ] || return 1
    kill -0 "$pid" 2>/dev/null
}

start() {
    if is_running; then
        echo "CDA is already running (pid $(cat "$PID_FILE")). Use '$0 stop' first."
        return 1
    fi

    : > "$LOG_FILE"
    echo "Starting CDA in background (RUST_LOG=$RUST_LOG, config=$CDA_CONFIG_FILE)..."
    echo "Output is being redirected to: $LOG_FILE"

    # CAN support is behind the `can` cargo feature (disabled by default);
    # without it the binary rejects the [can] section in the config file.
    nohup cargo run -p opensovd-cda --features can > "$LOG_FILE" 2>&1 &
    echo $! > "$PID_FILE"

    sleep 1
    if is_running; then
        echo "[OK] CDA started (pid $(cat "$PID_FILE")). Tail with: tail -f $LOG_FILE"
    else
        echo "[FAIL] CDA exited immediately. Last log lines:"
        tail -20 "$LOG_FILE"
        rm -f "$PID_FILE"
        return 1
    fi
}

stop() {
    if ! is_running; then
        echo "CDA is not running (no pid file or process gone)."
        rm -f "$PID_FILE"
        return 0
    fi

    local pid
    pid=$(cat "$PID_FILE")
    echo "Stopping CDA (pid $pid)..."

    # The pid is the cargo wrapper; cargo's child is opensovd-cda.
    # Kill the child first (graceful), then the wrapper if needed.
    pkill -TERM -P "$pid" 2>/dev/null || true
    kill -TERM "$pid" 2>/dev/null || true

    # Wait up to 10s for graceful exit
    for _ in $(seq 1 20); do
        if ! kill -0 "$pid" 2>/dev/null; then
            rm -f "$PID_FILE"
            echo "[OK] CDA stopped."
            return 0
        fi
        sleep 0.5
    done

    echo "Process did not stop gracefully, sending SIGKILL..."
    pkill -KILL -P "$pid" 2>/dev/null || true
    kill -KILL "$pid" 2>/dev/null || true
    rm -f "$PID_FILE"
    echo "[OK] CDA killed."
}

status() {
    if is_running; then
        echo "CDA is running (pid $(cat "$PID_FILE"))."
        echo "Log: $LOG_FILE"
    else
        echo "CDA is not running."
        [ -f "$PID_FILE" ] && echo "(stale pid file present)" || true
    fi
}

case "${1:-start}" in
    start)   start ;;
    stop)    stop ;;
    restart) stop || true; start ;;
    status)  status ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}" >&2
        exit 2
        ;;
esac
