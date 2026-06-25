#!/bin/bash
set -euo pipefail

deps_file=${DEPS_FILE:-"DEPS.txt"}
dash_jar=${DASH_JAR:-"/tmp/dash.jar"}
dash_summary=${DASH_SUMMARY:-"DASH_SUMMARY.txt"}
project=${PROJECT:-"automotive.opensovd"}
manifest_path=${MANIFEST_PATH:-"Cargo.toml"}
token=${1:-}

# Ensure the summary file exists even when checks fail early so CI can upload it as artifact.
: > "$dash_summary"

echo "creating 3rd party dependency list..."
cargo tree --manifest-path "$manifest_path" --workspace -e no-build,no-dev --prefix none --no-dedupe --locked \
  | sed -n '2~1p' \
  | sort -u \
  | grep -v '^[[:space:]]*$' \
  | grep -v '^cda-' \
  | grep -v '^opensovd-' \
  | grep -v '^mbedtls-' \
  | grep -v '^sovd-interfaces' \
  | grep -v '^integration-tests' \
  | sed -E 's|([^ ]+) v([^ ]+).*|crate/cratesio/-/\1/\2|' \
  > "$deps_file"

if [[ ! -r "$dash_jar" ]]; then
  echo "Eclipse Dash JAR file [${dash_jar}] not found, downloading latest version from GitHub..."
  wget_bin=$(which wget)
  if [[ -z "$wget_bin" ]]; then
    echo "wget command not available on path"
    exit 127
  else
    wget --quiet -O "$dash_jar" "https://repo.eclipse.org/service/local/artifact/maven/redirect?r=dash-licenses&g=org.eclipse.dash&a=org.eclipse.dash.licenses&v=LATEST"
  echo "successfully downloaded Eclipse Dash JAR to ${dash_jar}"
  fi
fi

args=(-jar "$dash_jar" -timeout 60 -batch 90 -summary "$dash_summary")
if [[ -n "$token" ]]; then
  args=("${args[@]}" -review -token "$token" -project "$project")
fi
args=("${args[@]}" "$deps_file")

echo "checking 3rd party licenses..."
java "${args[@]}"
