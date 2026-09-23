<!--
SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation

See the NOTICE file(s) distributed with this work for additional
information regarding copyright ownership.

This program and the accompanying materials are made available under the
terms of the Apache License Version 2.0 which is available at
https://www.apache.org/licenses/LICENSE-2.0

SPDX-License-Identifier: Apache-2.0
-->

# First Steps with the Classic Diagnostic Adapter

This guide walks you through running the CDA locally using Docker and making your first API calls to an ECU.

## Prerequisites

- Docker and Docker Compose
- `curl` and `jq`

## Step 1: Start the CDA with Docker Compose

`docker-compose.yml` starts the ECU simulator and the CDA, over DoIP by default; for CAN, see
[Local CAN Setup](#local-can-setup-optional). It is meant for trying the API by hand and for
local testing; the integration tests start their own containers, see
[Running the Integration Tests](#running-the-integration-tests).

The CDA runs with one of the integration test configurations (ECU and com-param settings,
fault handling, flash files), so every ECU of the simulator works:

| `CDA_TEST_CONFIG`                | Transports                      |
|----------------------------------|---------------------------------|
| `cda-test-config.toml` (default) | DoIP                            |
| `cda-test-config-can.toml`       | CAN, needs socketcand           |
| `cda-test-config-mixed.toml`     | DoIP and CAN, needs socketcand  |

The files are generated from `integration-tests/tests/util/config.rs` and committed; do not
edit them by hand. After changing the test configuration, regenerate them (no Docker needed):

```sh
make generate-test-config
```

`make check-test-config` fails if a committed file is out of date; the integration test
suite runs the same check.

Flash files are read from `testcontainer/flash_files/`. The test file `test_flash.bin` is
created there by `make generate-test-config`, `make check-test-config` or any integration test
run. The CDA logs at `debug` level.

```sh
cd testcontainer/

docker compose build
docker compose up
```

The CDA is ready when you see it respond to the health endpoint:

```sh
curl -s -o /dev/null -w "%{http_code}" http://localhost:20002/health/ready
# Expected: 204
```

## Step 2: Authorize and Store the Token

All protected endpoints require a Bearer token. Obtain one and store it in a shell variable:

```sh
TOKEN=$(curl -s -X POST http://localhost:20002/vehicle/v15/authorize \
  -H "Content-Type: application/json" \
  -d '{"client_id": "test", "client_secret": "test"}' \
  | jq -r '.access_token')
```

## Step 3: Discover Available Components

```sh
curl -s http://localhost:20002/vehicle/v15/components \
  -H "Authorization: Bearer $TOKEN" | jq .
```

Example response:

```json
{
  "items": [
    { "id": "flxc1000", "name": "flxc1000", "href": "..." },
    { "id": "flxcng1000", "name": "flxcng1000", "href": "..." },
    { "id": "fsnr2000", "name": "fsnr2000", "href": "..." }
  ]
}
```

## Step 4: Read Data from an ECU

List all available data identifiers for a component:

```sh
curl -s http://localhost:20002/vehicle/v15/components/flxc1000/data \
  -H "Authorization: Bearer $TOKEN" | jq .
```

Read a specific data identifier — for example, the VIN:

```sh
curl -s http://localhost:20002/vehicle/v15/components/flxc1000/data/VINDataIdentifier \
  -H "Authorization: Bearer $TOKEN" | jq .
```

```json
{
  "id": "vindataidentifier",
  "data": {
    "VIN": "SCEDT26T8BD005261"
  }
}
```

Or live sensor data like the Flux Capacitor power consumption:

```sh
curl -s http://localhost:20002/vehicle/v15/components/flxc1000/data/FluxCapacitorPowerConsumption \
  -H "Authorization: Bearer $TOKEN" | jq .
```

```json
{
  "id": "fluxcapacitorpowerconsumption",
  "data": {
    "PowerConsumption": 10
  }
}
```

## Step 5: Read Faults

```sh
curl -s http://localhost:20002/vehicle/v15/components/flxc1000/faults \
  -H "Authorization: Bearer $TOKEN" | jq .
```

This returns all DTCs stored in the ECU's fault memory, including their status flags (confirmed, pending, test failed, etc.).

## Stopping

```sh
docker compose down
```

## Running the Integration Tests

The integration tests do not use `docker-compose.yml`. They build the CDA, ECU simulator and
socketcand images on the first run (this takes a few minutes) and start their own containers
with [testcontainers](https://docs.rs/testcontainers).

```sh
cargo test --locked -p integration-tests --features integration-tests
```

A single test or module is selected like any other cargo test, e.g.
`cargo test --features integration-tests -- deferred_init`.

Every test runs in an environment of its own (Docker network, ECU simulator, CDA and, for CAN,
socketcand), so the tests run in parallel. Container output is printed prefixed with the test
name. Useful variables:

- `CDA_TEST_POOL_SIZE` (default `4`): environments per transport. Each needs about 1 GB of
  memory, so lower it on a small machine.
- `RUST_LOG`, `RUST_BACKTRACE`: passed through to the CDA containers, e.g. `RUST_LOG=debug`.
- `CDA_INTEGRATION_TEST_COVERAGE=true`: run a coverage-instrumented CDA; the profiles and the
  binary end up in `target/coverage/`.
- `CDA_TEST_IMAGE_NAME`/`_TAG`, `ECU_SIM_TEST_IMAGE_NAME`/`_TAG`,
  `SOCKETCAND_TEST_IMAGE_NAME`/`_TAG`: use prebuilt images instead of building them. A prebuilt
  CDA image must be built with the `can-socketcand` feature (and instrumented for coverage runs).

The containers and networks are removed when the test process exits. If it was killed, remove
the leftovers (containers by label, networks by name):

```sh
docker rm -f $(docker ps -aq --filter label=org.eclipse.opensovd.cda.test)
docker network rm $(docker network ls -q --filter name=cda-itest-)
```

## Local CAN Setup (Optional)

The CAN and mixed integration suites run against a virtual CAN bus, which needs the `vcan`
kernel module on the Docker host (requires root). Docker Desktop for MacOS and Windows do not provide
it, so these suites only run on Linux hosts.

```sh
sudo modprobe vcan
```

No `vcan0` has to be created on the host: every socketcand container creates its own `vcan0`
in its network namespace.

To use CAN with Docker Compose, start socketcand with the `can` profile, build the CDA with
the CAN transport, connect the ECU simulator to socketcand and pick a CAN configuration:

```sh
cd testcontainer/
export CDA_FEATURES=can-socketcand SIM_CAN_SOCKETCAND_HOST=socketcand \
  CDA_TEST_CONFIG=cda-test-config-mixed.toml
docker compose --profile can build
docker compose --profile can up
```

The pure-CAN and mixed integration suites are run with:

```sh
CDA_INTEGRATION_TEST_USE_CAN=true cargo test --locked -p integration-tests \
  --features can-integration-tests --test integration_tests
CDA_INTEGRATION_TEST_USE_MIXED=true cargo test --locked -p integration-tests \
  --features can-integration-tests --test integration_tests
```

## Quick API Access

Fetch a token and read data from an ECU of the compose stack:

```sh
TOKEN=$(curl -s -X POST http://localhost:20002/vehicle/v15/authorize \
  -H "Content-Type: application/json" \
  -d '{"client_id": "test", "client_secret": "test"}' | jq -r '.access_token')

curl -s http://localhost:20002/vehicle/v15/components/<ecu>/data \
  -H "Authorization: Bearer $TOKEN" | jq .
```
