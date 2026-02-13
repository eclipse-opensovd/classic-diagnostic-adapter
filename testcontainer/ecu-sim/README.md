<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)

See the NOTICE file(s) distributed with this work for additional
information regarding copyright ownership.

This program and the accompanying materials are made available under the
terms of the Apache License Version 2.0 which is available at
https://www.apache.org/licenses/LICENSE-2.0
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
