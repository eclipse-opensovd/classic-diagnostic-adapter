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

********
SOVD-API
********

.. testset:: HTTP Server Binding
    :id: testset~sovd-api-http-server
    :links: test~sovd-api-http-server-tcp-bind, test~sovd-api-http-server-unix-socket-bind, test~sovd-api-http-server-unix-socket-stale-cleanup, test~sovd-api-http-server-unix-socket-stale-cleanup-failure, itest~sovd-api-http-server-unix-socket
    :status: draft

    Verifies binding the SOVD-API to a TCP port or a Unix domain socket, including
    stale socket handling.

.. testset:: Version Endpoint
    :id: testset~sovd-api-version-endpoint
    :links: itest~sovd-api-version-endpoint
    :status: draft

    Verifies the version endpoint registered by the version registration function.

.. testset:: Component SDG/SDs
    :id: testset~sovd-api-component-sdgsd
    :links: itest~sovd-api-component-sdgsd, itest~sovd-api-component-alias-sdgsd, itest~sovd-api-component-data-sdgsd, itest~sovd-api-component-operations-sdgsd
    :status: draft

    Verifies retrieval of special data groups on ECU, data and operation level.

.. testset:: Authentication Modes
    :id: testset~sovd-api-authentication-modes
    :links: itest~sovd-api-authentication-modes-pki, itest~sovd-api-authentication-modes-pki-bidirectional, itest~sovd-api-authentication-modes-challenge-response, itest~sovd-api-authentication-modes-rejected, itest~sovd-api-authentication-modes-expiration, itest~sovd-api-authentication-modes-nrc, itest~sovd-api-authentication-modes-invalid
    :status: draft

    Verifies the authentication endpoints for all supported authentication modes
    and their error cases.

.. testset:: Lock Acquisition Policy
    :id: testset~sovd-api-lock-acquisition-policy
    :links: test~sovd-api-lock-acquisition-policy-config, test~sovd-api-lock-acquisition-policy-validation, test~sovd-api-lock-acquisition-policy-handlers, itest~sovd-api-lock-acquisition-policy
    :status: draft

    Verifies configuration and enforcement of the lock acquisition policy.
