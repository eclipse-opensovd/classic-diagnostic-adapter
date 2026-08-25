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

Communication Lifecycle Plugin
------------------------------

.. arch:: Communication Lifecycle Plugin
    :id: arch~plugin-communication-lifecycle
    :links: req~plugin-communication-lifecycle
    :status: draft

    The communication lifecycle plugin decides **when** vehicle communication comes
    up and who is allowed to bring it up. It is selected at startup via
    ``Setup::with_communication_plugin``; the default implementation applies the
    ``[communication] init_mode`` policy (``Always`` / ``OnDemand`` / ``Disabled``).

    Consumers never receive the plugin itself. They receive narrowed capabilities:

    * ``CommunicationAccess`` - admit a diagnostic activity, request activation.
    * ``DisableCommunication`` - take exclusive ownership of the transport for the
      duration of an operation, returning a ``DisableGuard``. Used by the
      runtime-update plugin.

    Neither can register hooks, run detection, or lift another owner's HTTP
    protection.

    The design, the state machine, the disable-lease semantics and the rationale for
    the ``ComponentSlot`` capability split are specified in ADR-006,
    ``docs/04_adr/06_deferred_initialization.rst``. That ADR is the authoritative
    description; this page exists so the plugin is reachable from the architecture
    index rather than only from the ADR list.
