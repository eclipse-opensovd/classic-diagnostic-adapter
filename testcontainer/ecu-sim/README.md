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

  This allows integration tests to verify that the request to the CDA are translated correctly for the target ECU.

## DoIP broadcast address

Set `SIM_BROADCAST_ADDRESS` to override the simulator's DoIP broadcast address. If it is unset,
the library default `255.255.255.255` is retained. For example, on a native Mac Pi setup,
`SIM_BROADCAST_ADDRESS=192.168.7.255` can direct broadcasts to the Pi subnet instead of Wi-Fi.

This override is intended for test environments. Using a directed broadcast for vehicle announcements
deviates from ISO 13400-2:2025 requirement 8.DoIP-125, which specifies limited broadcast.
