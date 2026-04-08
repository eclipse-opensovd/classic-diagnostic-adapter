.. SPDX-License-Identifier: Apache-2.0
.. SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
..
.. See the NOTICE file(s) distributed with this work for additional
.. information regarding copyright ownership.
..
.. This program and the accompanying materials are made available under the
.. terms of the Apache License Version 2.0 which is available at
.. https://www.apache.org/licenses/LICENSE-2.0

.. _requirements-plugins:

Plugins
=======

API
---

The plugin system API must support the following use-cases.

* Plugins must be able to utilize all the APIs in the CDA.
* Plugins must be able to access and modify a SOVD-request-context, if applicable for the type/interception point of that plugin

.. _requirements-plugins-security:

Security
--------

A SOVD security plugin must be able to:

* Validate and verify the JWT token from incoming HTTP Requests
* Utilize additional headers from the request
* Reject the incoming request
* Enhance the SOVD-request-context with data, this context can then be used in other addons

Paths
-----

A SOVD plugin must be able to:

* Add paths to the SOVD-API, and handle them
* Restructure existing path structures
* Modify existing path structures to run different code

UDS
---

An UDS plugin must be able to:

* Intercept UDS requests before they are sent to the ECU
* Intercept UDS responses

DoIP
----

A DoIP plugin must be able to:

* Intercept DoIP requests before they are sent to the ECU
* Intercept DoIP responses



Diagnostic Database Update Plugin
---------------------------------

.. req:: Diagnostic Database Update Plugin
    :id: req~plugin-diagnostic-database-update
    :links: arch~plugin-diagnostic-database-update
    :status: draft

    A diagnostic database update plugin must be available. It must provide an SOVD-API allowing clients to
    update the diagnostic database of the CDA atomically, meaning all provided files for the update are updated at
    the same time, and any failure during the update process fails the entire update, rolling back to the previous
    state of the diagnostic database.

    The plugin must be able to update the diagnostic database without restarting the CDA.


.. req:: Diagnostic Database Update Plugin - Authentication
    :id: req~plugin-diagnostic-database-update-authentication
    :links: arch~plugin-diagnostic-database-update
    :status: draft

    The diagnostic database update plugin must ensure that only authorized clients can update the diagnostic database.

    The exact mechanism (i.e. are calls to the endpoints allowed) must be providable to the plugin.


.. req:: Diagnostic Database Update Plugin - Verification
    :id: req~plugin-diagnostic-database-update-verification
    :links: arch~plugin-diagnostic-database-update
    :status: draft

    The diagnostic database update plugin must be able to verify the integrity of the mdd files before they are
    being used by the CDA.

    The exact mechanism (e.g. signature & hash verification) must be providable to the plugin.


.. req:: Diagnostic Database Update Plugin - Downgrade Protection
    :id: req~plugin-diagnostic-database-update-downgrade-protection
    :links: arch~plugin-diagnostic-database-update
    :status: draft

    The diagnostic database update plugin must have the option to prevent downgrades of the diagnostic database,
    meaning that it can prevent applying an update which would lead to an older version of the diagnostic database
    being active than the currently active one.

    The exact mechanism (e.g. version determination, persistence of versions for deleted entries) must be
    providable to the plugin.

.. req:: Diagnostic Database Update Plugin - Safety
    :id: req~plugin-diagnostic-database-update-safety
    :links: arch~plugin-diagnostic-database-update
    :status: draft

    Updates to the diagnostic database must be safe, it must be ensured that the CDA can recover from
    power-cycles or crashes at any time during the update process, and that the CDA is not left in an unusable state.


DLT Logging Plugin
------------------

.. req:: DLT Logging
    :id: req~plugin-dlt-logging
    :links: arch~plugin-dlt-logging
    :status: draft

    The CDA must support logging to the AUTOSAR Diagnostic Log and Trace (DLT) system. When enabled, application
    tracing events must be forwarded to the DLT daemon running on the target system, allowing log capture and
    analysis with standard automotive DLT tooling.

    **Rationale**

    DLT is the standard logging mechanism used in automotive ECUs and HPCs. Supporting DLT output allows the CDA to
    integrate into existing vehicle logging infrastructure and enables field diagnostics with standard tools such as
    ``dlt-viewer``.


.. req:: DLT Logging - Compile-Time Feature Gate
    :id: req~plugin-dlt-logging-feature-gate
    :links: arch~plugin-dlt-logging
    :status: draft

    DLT logging support must be an optional compile-time feature. When the feature is not enabled, the DLT
    dependency must not be compiled, and DLT-related code must have zero runtime overhead.

    **Rationale**

    The DLT system library (``libdlt``) is not available on all target platforms. Compile-time gating ensures
    the CDA can be built and deployed on systems without DLT support, without any performance penalty.


.. req:: DLT Logging - Runtime Configuration
    :id: req~plugin-dlt-logging-runtime-configuration
    :links: arch~plugin-dlt-logging-configuration
    :status: draft

    When DLT logging support is compiled in, it must be possible to enable or disable DLT output at runtime
    through the application configuration. The following parameters must be configurable:

    * **Application ID** -- A short identifier (up to 4 characters) registered with the DLT daemon to identify this
      application.
    * **Application Description** -- A human-readable description of the application registered with the DLT daemon.
    * **Enabled** -- A toggle to enable or disable DLT output at startup.


.. req:: DLT Logging - Context Identification
    :id: req~plugin-dlt-logging-context-identification
    :links: arch~plugin-dlt-logging-context-annotation
    :status: draft

    Each subsystem of the CDA must be identifiable in the DLT output through a unique context identifier.
    The context identifiers must conform to the DLT protocol constraints (up to 4 ASCII characters) and allow
    DLT tooling to filter log messages by subsystem.

    **Rationale**

    DLT context IDs enable operators to filter and analyze logs for specific subsystems (e.g. communication,
    database loading, SOVD API) without having to parse log message content, which is a standard workflow in
    automotive log analysis.


.. req:: DLT Logging - Log Level Mapping
    :id: req~plugin-dlt-logging-log-level-mapping
    :links: arch~plugin-dlt-logging
    :status: draft

    Application log levels must be mapped to their corresponding DLT log levels, so that DLT-side filtering by
    severity works correctly.
