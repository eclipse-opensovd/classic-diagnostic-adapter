#!/bin/sh -e
SCRIPT_DIR=$(dirname "$(realpath "$0")")
TARGET_DIR=$(realpath "$SCRIPT_DIR/..")

echo "Building ecu-sim"
"$TARGET_DIR/gradlew" -p "$TARGET_DIR" build shadowJar

echo "Building docker container for ecu-sim"
docker build -f "$TARGET_DIR/docker/Dockerfile.run" "$TARGET_DIR" -t ecu-sim
