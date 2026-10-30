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
