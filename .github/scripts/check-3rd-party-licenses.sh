#!/bin/bash
set -euo pipefail

deps_file=${DEPS_FILE:-"DEPS.txt"}
tmp_root=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
dash_jar=${DASH_JAR:-"${tmp_root}/dash.jar"}
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
  echo "Eclipse Dash JAR file [${dash_jar}] not found, downloading latest version from Eclipse repository..."
  dash_url="https://repo.eclipse.org/service/local/artifact/maven/redirect?r=dash-licenses&g=org.eclipse.dash&a=org.eclipse.dash.licenses&v=LATEST"

  if command -v wget >/dev/null 2>&1; then
    wget --quiet -O "$dash_jar" "$dash_url"
  elif command -v curl >/dev/null 2>&1; then
    curl --fail --silent --show-error --location --output "$dash_jar" "$dash_url"
  else
    echo "Neither wget nor curl is available on PATH"
    exit 127
  fi

  echo "successfully downloaded Eclipse Dash JAR to ${dash_jar}"
fi

args=(-jar "$dash_jar" -timeout 60 -batch 90 -summary "$dash_summary")
if [[ -n "$token" ]]; then
  args=("${args[@]}" -review -token "$token" -project "$project")
fi
args=("${args[@]}" "$deps_file")

echo "checking 3rd party licenses..."
java "${args[@]}"
