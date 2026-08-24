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

Security Plugin
================

The security plugin is the primary plugin implementation within the CDA, responsible for
authentication, authorization, and access control.

.. arch:: Security Plugin - Core Traits
    :id: arch~plugin-security-core-traits
    :status: draft

    The security plugin system is built around a set of interfaces that a vendor-specific
    implementation must provide:

    - An authentication interface, giving access to the identity/claims associated with an
      incoming request.
    - An authorization interface, used to:

      - validate a resolved SOVD/HTTP diagnostic service request before it is executed (see
        :need:`arch~plugin-security-validate-service`), and
      - separately, authorize a resolved UDS request immediately before it is transmitted to the
        vehicle (see :need:`arch~plugin-security-validate-request-send`).
    - A loader/initializer interface, responsible for constructing a plugin instance from an
      incoming HTTP request (e.g. extracting and validating a bearer token) and for handling the
      authorization endpoint used to obtain credentials.

    A single vendor-provided implementation combines all of these interfaces and is configured
    once for the whole CDA instance.


Plugin Lifecycle
-----------------

.. arch:: Security Plugin - Lifecycle
    :id: arch~plugin-security-lifecycle
    :links: arch~plugin-security-core-traits
    :status: draft

    The security plugin follows this lifecycle during request processing:

    1. Middleware Registration: the security plugin middleware is registered during router setup.
    2. Request Interception: each incoming SOVD/HTTP request passes through the security
       middleware.
    3. Plugin Initialization: the plugin extracts authentication information from the request
       (e.g. headers) and creates a plugin instance for that request.
    4. Request Processing: the initialized plugin instance is made available to route handlers.
    5. Service Validation: before a diagnostic service is executed, it is validated against
       security policy (see :need:`arch~plugin-security-validate-service`).
    6. Request Send Authorization: immediately before a resolved UDS request is handed to the
       transport for transmission, it is authorized against vendor-specific state (see
       :need:`arch~plugin-security-validate-request-send`). This is a distinct checkpoint from
       step 5, and applies to every outgoing UDS request, whether addressed to a single ECU or
       sent functionally/broadcast to multiple ECUs.


.. arch:: Security Plugin - Service Validation
    :id: arch~plugin-security-validate-service
    :links: arch~plugin-security-core-traits
    :status: draft

    Before a diagnostic service is executed, the security plugin is given the resolved diagnostic
    service description and may reject it, preventing its execution. This validation happens once
    per requested diagnostic service, at the point where the service has been resolved from the
    SOVD-API request but before any UDS communication with the ECU has started.


.. arch:: Security Plugin - Request Send Authorization
    :id: arch~plugin-security-validate-request-send
    :links: arch~plugin-security-core-traits
    :status: draft

    In addition to service validation, the security plugin provides a second, independent
    authorization checkpoint that runs immediately before a fully resolved UDS request is
    transmitted to the vehicle.

    **Checkpoint location**

    This checkpoint sits at the transport boundary, after the UDS request has been fully resolved
    (service, sub-function, payload, and any pending diagnostic session or security-level
    transition associated with sending it are known), and before it is handed to the physical
    transport. It applies uniformly to:

    - Unicast requests addressed to a single ECU.
    - Functional/broadcast requests addressed to multiple ECUs at once.

    **Information available to the plugin**

    At this checkpoint, the plugin has access to:

    - The target ECU (or functional group, for broadcast requests).
    - The fully resolved UDS request (service identifier, sub-function, payload bytes, and
      addressing information).
    - Any diagnostic session or security-level transition that sending this request would trigger.
    - The authentication token/credentials associated with the caller that ultimately triggered
      this request, so the plugin can re-evaluate authorization using the same identity
      information available during :need:`arch~plugin-security-validate-service`.
    - The current holder of the relevant lock (vehicle, functional group, or ECU/component lock,
      see :need:`arch~sovd-api-lock-api`), if any, so the plugin can factor lock ownership into its
      decision (e.g. to allow or deny the request depending on whether the caller matches the lock
      holder).

    **Vendor customization**

    The authorization decision is delegated entirely to the vendor-provided plugin
    implementation, since it commonly depends on proprietary state that is external to the CDA
    (e.g. state obtained from a vendor-specific API, safety system, or ownership/lock mechanism
    not standardized by the CDA). The CDA core does not interpret or store this state itself; it
    only invokes the plugin and acts on its decision.

    **Outcome**

    If the plugin denies the request:

    - The request is not transmitted to the ECU; no bytes are sent to the transport.
    - The rejection is reported as a distinct "request not allowed" outcome, separate from the
      outcome of :need:`arch~plugin-security-validate-service`, so that callers and vendor
      integrations can distinguish "this operation is not permitted at all" from "this specific
      request cannot be sent right now".

    This checkpoint reuses the same security plugin instance and lifecycle described in
    :need:`arch~plugin-security-lifecycle`; it is not a separate plugin type.
