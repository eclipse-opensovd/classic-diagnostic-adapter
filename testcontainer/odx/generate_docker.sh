#/bin/sh -e
SCRIPT_DIR=$(dirname "$(realpath "$0")")
docker build -f "$SCRIPT_DIR/docker/Dockerfile" "$SCRIPT_DIR" -t cda-odx-gen
docker run -v "$SCRIPT_DIR:/data" -u $(id -u):$(id -g) -t cda-odx-gen
