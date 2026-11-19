.. SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation
..
.. See the NOTICE file(s) distributed with this work for additional
.. information regarding copyright ownership.
..
.. This program and the accompanying materials are made available under the
.. terms of the Apache License Version 2.0 which is available at
.. https://www.apache.org/licenses/LICENSE-2.0
..
.. SPDX-License-Identifier: Apache-2.0

*************
Communication
*************

.. testset:: DoIP Vehicle Identification
    :id: testset~doip-vehicle-identification
    :links: test~doip-vam-connect-does-not-block-listener
    :status: draft

    Verifies that connecting to an announced gateway does not block the reception of
    further vehicle announcements.

.. testset:: DoIP Spontaneous VAM Handling Mode
    :id: testset~doip-vam-handling-mode
    :links: test~doip-vam-handling-mode
    :status: draft

    Verifies the configured handling of spontaneous vehicle announcement messages.

.. testset:: DoIP Connection Management
    :id: testset~doip-connection-management
    :links: test~doip-cancelled-connect-writes-nothing, test~doip-cancelled-session-reports-nothing
    :status: draft

    Verifies that a cancelled connect or gateway session leaves no partial state behind.

.. testset:: UDS Request Permit Timeout
    :id: testset~uds-request-permit-timeout
    :status: draft

    Verifies the bounded wait for the per-ECU request permit:

    - An explicit ``CP_RequestPermitTimeout`` (diagnostic database or configuration,
      according to the com param precedence) is used as a fixed limit and overrides the
      holder deadline.
    - Without an explicit value, a waiting request waits until the holder deadline plus
      grace margin, computed from the holder's ``CP_RepeatReqCountApp`` and ``CP_P6Max``
      or its caller supplied timeout.
    - Entering NRC 0x21/0x78/0x94 handling extends the holder deadline by the matching
      completion timeout, and waiting requests re-evaluate their wait.
    - When the permit is handed to the next queued request, waiting requests follow the
      new holder deadline.
    - The total wait is capped at the configured maximum (e.g. behind unlimited NRC
      handling).
    - A request that times out while waiting fails with a timeout error and is not sent.
    - Multi-ECU (functional group) acquisitions wait for the latest holder deadline of the
      involved ECUs.
