.. SPDX-License-Identifier: Apache-2.0
.. SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
..
.. See the NOTICE file(s) distributed with this work for additional
.. information regarding copyright ownership.
..
.. This program and the accompanying materials are made available under the
.. terms of the Apache License Version 2.0 which is available at
.. https://www.apache.org/licenses/LICENSE-2.0

DLT Logging Plugin
------------------

.. arch:: DLT Logging
    :id: arch~plugin-dlt-logging
    :links: dimpl~plugin-dlt-logging
    :status: draft

    The DLT logging integration adds an optional tracing output that forwards application log and trace events
    to the AUTOSAR Diagnostic Log and Trace (DLT) daemon via the DLT system library.

    **Integration into the Tracing Stack**

    The DLT output is realized as an additional subscriber layer within the existing layered tracing architecture.
    The tracing system composes multiple output layers (terminal, file, OpenTelemetry, DLT) into a single
    subscriber. When DLT is enabled, its layer receives the same tracing events as all other layers and translates
    them into DLT log messages.

    .. uml::

        @startuml
        skinparam componentStyle rectangle

        component "Application Code" as app
        component "Tracing Subscriber Registry" as registry
        component "Terminal Layer" as term
        component "File Layer" as file
        component "OpenTelemetry Layer" as otel
        component "DLT Layer" as dlt
        component "DLT System Library" as libdlt
        component "DLT Daemon" as daemon

        app -down-> registry : tracing events
        registry -down-> term
        registry -down-> file
        registry -down-> otel
        registry -down-> dlt
        dlt -down-> libdlt : FFI
        libdlt -down-> daemon : IPC
        @enduml

    **Compile-Time Feature Gating**

    The entire DLT integration is guarded by a compile-time feature flag. When the feature is not active:

    * The DLT system library is not linked.
    * The DLT subscriber layer is not compiled.
    * Context annotation macros evaluate to no-ops that the compiler optimizes away, resulting in zero runtime
      overhead.

    When the feature is active, the DLT layer is only added to the tracing subscriber if the runtime
    configuration also enables it.

    **Runtime Enablement**

    At startup, the tracing initialization checks the DLT configuration. If DLT support is compiled in but
    disabled in the configuration, the DLT layer is not registered, and no connection to the DLT daemon is
    established.

    **Log Level Mapping**

    Application trace levels are mapped to their DLT equivalents by the DLT subscriber layer, ensuring that
    severity-based filtering in DLT tooling works as expected.


.. arch:: DLT Logging - Configuration
    :id: arch~plugin-dlt-logging-configuration
    :links: dimpl~plugin-dlt-logging-configuration
    :status: draft

    The DLT logging configuration is part of the application-wide logging configuration and is deserialized from
    the configuration file.

    The configuration contains the following parameters:

    .. list-table:: DLT Logging Configuration Parameters
       :header-rows: 1

       * - Parameter
         - Description
         - Default

       * - Application ID
         - A short identifier (max 4 ASCII characters) registered with the DLT daemon to identify the
           application.
         - ``CDA``

       * - Application Description
         - A human-readable description registered with the DLT daemon.
         - ``Bridges SOVD to UDS for ECU communication.``

       * - Enabled
         - A boolean toggle that controls whether the DLT layer is registered at startup.
         - ``true``

    The application ID is validated against DLT protocol constraints during initialization. An invalid
    application ID (e.g. exceeding 4 characters) prevents the DLT layer from being created and results in a
    startup error.


.. arch:: DLT Logging - Context Annotation
    :id: arch~plugin-dlt-logging-context-annotation
    :links: dimpl~plugin-dlt-logging-context-annotation
    :status: draft

    Each subsystem of the CDA annotates its tracing spans with a DLT context identifier. The DLT subscriber
    layer reads the context identifier from the span metadata and uses it to route the log message to the
    appropriate DLT context.

    A helper macro is provided to annotate tracing spans with context identifiers. The macro is feature-gated:

    * When DLT support is compiled in, the macro expands to the context identifier string, which is attached
      to the span as metadata.
    * When DLT support is not compiled in, the macro expands to a no-op value that the tracing framework
      discards, ensuring that no DLT-related metadata is recorded.

    The following context identifiers are used by the CDA subsystems:

    .. list-table:: DLT Context Identifiers
       :header-rows: 1

       * - Context ID
         - Subsystem

       * - ``MAIN``
         - Application entry point and initialization

       * - ``CORE``
         - Diagnostic kernel (ECU management, variant detection, schema handling)

       * - ``DOIP``
         - DoIP communication layer

       * - ``UDS``
         - UDS protocol layer

       * - ``DB``
         - Diagnostic database loading and parsing

       * - ``SOVD``
         - SOVD web server layer
