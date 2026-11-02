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

*****************
Diagnostic Tester
*****************

.. testset:: Deferred Communication Startup
    :id: testset~deferred-communication-startup
    :links: test~deferred-communication-config, test~deferred-startup-policy, test~deferred-doip-passive-construction, itest~deferred-on-demand-pending, itest~deferred-on-demand-uds-silence, itest~deferred-disabled-uds-silence
    :status: draft

    Verifies that communication is only activated at startup when configured and that
    no UDS traffic is sent before an authorized trigger.

.. testset:: Deferred Communication Activation
    :id: testset~deferred-communication-activation
    :links: test~deferred-admitting-modes-activate, test~deferred-disabled-rejects-activation, test~deferred-request-activation-policy, test~deferred-activation-retry, test~deferred-sovd-admission
    :status: draft

    Verifies admission and activation of deferred communication triggered by SOVD requests.

.. testset:: Post-Update Deferred Communication
    :id: testset~deferred-post-update
    :links: test~deferred-communication-config, test~deferred-post-update-apply, test~deferred-post-update-rollback, itest~deferred-post-update
    :status: draft

    Verifies that communication stays disabled after a database update apply or rollback
    until it is reactivated.

.. testset:: Explicit Variant Detection
    :id: testset~variant-detection-explicit
    :links: itest~variant-detection-explicit
    :status: draft

    Verifies that an explicit ECU variant detection trigger works with automatic
    variant detection disabled.
