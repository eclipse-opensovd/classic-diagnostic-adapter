<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)

See the NOTICE file(s) distributed with this work for additional
information regarding copyright ownership.

This program and the accompanying materials are made available under the
terms of the Apache License Version 2.0 which is available at
https://www.apache.org/licenses/LICENSE-2.0
-->

# First Steps with the Classic Diagnostic Adapter

This guide walks you through running the CDA locally using Docker and making your first API calls to an ECU.

## Prerequisites

- Docker and Docker Compose
- `curl` and `jq`

## Step 1: Run the Integration Tests Once

The integration tests generate the `testcontainer/cda-test-config.toml` file that the Docker setup depends on. Run them at least once before proceeding:

```sh
cargo test --package integration-tests --features integration-tests
```

After the tests complete, verify the config file exists:

```sh
ls testcontainer/cda-test-config.toml
```

## Step 2: Start the CDA with Docker Compose

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

## Step 3: Authorize and Store the Token

All protected endpoints require a Bearer token. Obtain one and store it in a shell variable:

```sh
TOKEN=$(curl -s -X POST http://localhost:20002/vehicle/v15/authorize \
  -H "Content-Type: application/json" \
  -d '{"client_id": "test", "client_secret": "test"}' \
  | jq -r '.access_token')
```

## Step 4: Discover Available Components

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

## Step 5: Read Data from an ECU

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

## Step 6: Read Faults

```sh
curl -s http://localhost:20002/vehicle/v15/components/flxc1000/faults \
  -H "Authorization: Bearer $TOKEN" | jq .
```

This returns all DTCs stored in the ECU's fault memory, including their status flags (confirmed, pending, test failed, etc.).

## Stopping

```sh
docker compose down
```
