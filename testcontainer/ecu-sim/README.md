<!--
SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation

See the NOTICE file(s) distributed with this work for additional
information regarding copyright ownership.

This program and the accompanying materials are made available under the
terms of the Apache License Version 2.0 which is available at
https://www.apache.org/licenses/LICENSE-2.0

SPDX-License-Identifier: Apache-2.0
-->

# CDA ECU SIM

## Intro

This is an ecu simulation intended to be used for integration tests with the classic-diagnostic-adapter in the Eclipse OpenSOVD project

## Features

- Simulates a DoIP/UDS topology of ECUs for testing with the CDA
- Mock for token creation
  - Used to create and verify tokens in the default security plugin
- Offers endpoints to:
  - Retrieve and modify the ECU state
  - Retrieve data transfer data
  - Record incoming UDS messages
  - Make a single DoIP gateway (by IP address) unreachable and reachable again

  This allows integration tests to verify that the request to the CDA are translated correctly for the target ECU.

## Stopping single gateways

`POST /network/addresses/{ip}/stop` makes the DoIP gateway at the address `{ip}` (the
`network_address` of its persisted topology entry) unreachable while the other gateways stay
reachable. It closes all active DoIP connections, also those of the other gateways, whose testers
reconnect. It is idempotent and answers `409` if the address is not a secondary `/32` address of the
interface. `POST /network/addresses/{ip}/start` makes a stopped address reachable again; for an
address that is not stopped it does nothing and answers `200`. It answers `409` if the address
cannot be added back.

The library `doip-sim-ecu-dsl` assigns each DoIP entity one IP address of the network interface, but
cannot stop a single binding. The simulator therefore stops a gateway by removing its IP address with
`ip address del` and closes the active DoIP connections (the library does not tell which entity a
connection belongs to, so the testers of the other gateways reconnect on their own). `start` adds the
address back with `ip address add`; the listening sockets stay bound, so no restart is needed.

Requirements: the `NET_ADMIN` capability (see `testcontainer/docker-compose.yml`),
`USE_MULTIPLE_IPS=true` (every gateway has its own `/32` address, a shared or primary address is
refused with `409`) and `SIM_NETWORK_INTERFACE` set to the interface name.

Note that the broadcast listener may still answer vehicle identification requests with the
announcements of all gateways, including a stopped one. A tester then still fails to connect over
TCP, because the address is gone.
