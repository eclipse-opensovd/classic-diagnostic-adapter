.. SPDX-License-Identifier: Apache-2.0
.. SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
..
.. See the NOTICE file(s) distributed with this work for additional
.. information regarding copyright ownership.
..
.. This program and the accompanying materials are made available under the
.. terms of the Apache License Version 2.0 which is available at
.. https://www.apache.org/licenses/LICENSE-2.0

Diagnostic Tester
=================

The Diagnostic Tester component provides the core functionality for communicating with vehicle ECUs
using UDS (Unified Diagnostic Services) over DoIP (Diagnostics over IP). This document defines its
architecture.


Startup Behavior
----------------

Startup Sequence
^^^^^^^^^^^^^^^^

.. arch:: Startup Sequence
    :id: arch~dt-startup-sequence
    :status: draft

    The CDA startup is orchestrated by the main application entry point, which coordinates
    initialization of all subsystems in a defined order to ensure proper dependency resolution
    and graceful degradation on partial failures.

    **Component Initialization Order**

    The startup sequence proceeds through the following phases:

    1. **Configuration Phase**: Load configuration from TOML file, apply CLI argument overrides,
       and validate configuration sanity before proceeding. If the configuration file cannot be
       loaded (e.g., file not found, parse error), the system falls back to default configuration
       values and logs a warning. Configuration validation failures after loading are fatal and
       prevent startup.

    2. **Tracing Phase**: Initialize logging and tracing subsystems based on configuration
       (terminal output, file logging, OpenTelemetry, DLT).

    3. **HTTP Server Phase**: Launch the web server with a dynamic router that supports
       deferred route registration.

    4. **Health Registration Phase** *(conditional, see* :need:`arch~dt-health-monitoring` *)*:
       Register component-specific health providers
       (main, database, doip) to enable granular health status reporting.
       Health monitoring is an optional build-time feature. When the health feature is
       disabled, the CDA starts without health endpoints and providers, and all
       health-related registration steps are skipped. Health status is only retrievable
       through the health endpoint when this feature is enabled.

    5. **Vehicle Data Loading Phase**: Load diagnostic databases (MDD files) and, depending on
       the configured initialization mode, initialize the communication layer.

       **Immediate mode (default)**:

       - Parallel MDD file loading
       - DoIP gateway creation (VIR/VAM exchange, TCP connections)
       - UDS manager creation
       - Asynchronous variant detection startup

       **Deferred mode** (see :need:`arch~dt-deferred-initialization`):

       - Parallel MDD file loading proceeds as normal
       - DoIP gateway creation, UDS manager creation, and variant detection are **not** performed
         during startup. Instead, these steps are postponed until a trigger event occurs
         (first diagnostic request or explicit plugin API activation)

    6. **Route Registration Phase**: Register SOVD API routes, version endpoints, and
       OpenAPI documentation routes on the dynamic router. In deferred mode, ECU-specific
       routes are registered with handlers that trigger initialization on first access
       (on-demand mode) or return a pending status until explicitly activated (plugin API mode).

    7. **Ready Phase**: When the health feature is enabled, update the main health status to
       "Up" indicating the CDA's HTTP API is operational. In deferred mode, the DoIP health
       provider remains in "Pending" state until communication initialization is triggered
       and completed (see :need:`arch~dt-deferred-initialization`). When the health feature
       is disabled, this phase is a no-op.

    **Shutdown Signal Handling**

    A shareable shutdown signal is created and propagated to all long-running tasks. This
    enables coordinated shutdown when receiving SIGTERM or Ctrl+C at any startup phase,
    including during database loading and DoIP initialization.

    .. uml::
        :caption: Startup Component Interaction

        @startuml
        skinparam backgroundColor #FFFFFF
        skinparam sequenceArrowThickness 2

        participant "main()" as Main
        participant "Configuration" as Config
        participant "Tracing" as Trace
        participant "HTTP Server" as HTTP
        participant "Health State" as Health
        participant "Database Loader" as DB
        participant "DoIP Gateway" as DoIP
        participant "UDS Manager" as UDS

        Main -> Config: load_config()
        activate Config
        Config -> Config: validate_sanity()
        Config --> Main: Configuration
        deactivate Config

        Main -> Trace: setup_tracing(config)
        activate Trace
        Trace --> Main: TracingGuards
        deactivate Trace

        Main -> HTTP: launch_webserver()
        activate HTTP
        HTTP --> Main: (DynamicRouter, ServerTask)
        note right: Server running, no routes yet

        opt Health feature enabled
            Main -> Health: add_health_routes()
            activate Health
            Health -> Health: register main provider (Starting)
            Health --> Main: HealthState
            deactivate Health
        end

        Main -> DB: load_databases()
        activate DB
        note right: See arch~dt-database-loading
        DB --> Main: Databases loaded
        deactivate DB

        alt Immediate communication initialization (default)
            Main -> DoIP: create_diagnostic_gateway()
            activate DoIP
            note right: See arch~dt-doip-gateway-init
            DoIP --> Main: DoipDiagGateway
            deactivate DoIP

            Main -> UDS: create_uds_manager()
            activate UDS
            UDS -> UDS: spawn variant detection task
            UDS --> Main: UdsManager
            deactivate UDS
        else Deferred communication (on-demand or plugin API)
            note over Main,UDS
                DoIP gateway creation, UDS manager
                creation, and variant detection are
                postponed until triggered
                (see arch~dt-deferred-initialization)
            end note
        end

        Main -> HTTP: add_vehicle_routes()
        Main -> HTTP: add_static_data_endpoint() (version)
        Main -> HTTP: add_openapi_routes()

        opt Health feature enabled
            Main -> Health: update_status(Up)
            note right: HTTP API operational.\nDoIP remains "Pending"\nin deferred mode.
        end

        Main -> Main: await shutdown_signal
        deactivate HTTP
        @enduml


Database Loading
^^^^^^^^^^^^^^^^

.. arch:: Database Loading
    :id: arch~dt-database-loading
    :status: draft

    Diagnostic databases (MDD files) are loaded in parallel to minimize startup time,
    with careful handling of duplicates and failures to ensure robust operation.

    .. note::

       Database loading always occurs during startup, regardless of the initialization mode.
       Even when deferred initialization is configured, MDD files are loaded immediately so
       that the SOVD API can expose ECU metadata (names, capabilities) before communication
       is established. Only the DoIP gateway creation and variant detection are deferred.

    **Parallel Loading Strategy**

    The database loader discovers all ``.mdd`` files in the configured directory and sorts them
    by file size in descending order. Files are then distributed into chunks for parallel processing.
    The chunk size is calculated as:

    .. code-block:: text

        chunk_size = file_count / (parallel_load_tasks + 1)

    The number of parallel load tasks is configurable. Processing larger files first ensures
    optimal utilization of parallel workers, as smaller files naturally fill remaining capacity.

    **Per-File Processing**

    For each MDD file, the loader:

    1. Extracts the diagnostic description chunk from the MDD container
    2. Creates a diagnostic database from the FlatBuffer payload
    3. Creates an ECU manager with protocol settings and communication parameters
    4. Extracts embedded file chunks (JAR files, partial files) for the file manager

    **Duplicate ECU Handling**

    When multiple MDD files define the same ECU name:

    - **Same logical address**: The database with the highest revision is retained; others are discarded
      with a warning log.
    - **Different logical addresses**: Both databases are marked as invalid and excluded from the
      final database map, as this represents an inconsistent configuration.

    After loading, ECUs sharing the same logical address (from different database files with different
    ECU names) are identified and tracked for variant detection disambiguation.

    **Health Status Integration**

    When health monitoring is enabled (see :need:`arch~dt-health-monitoring`), a database
    health provider is registered with initial status "Starting". After loading completes:

    - Status transitions to "Up" if at least one database was loaded successfully
    - Status transitions to "Failed" if no databases could be loaded

    **Failure Isolation**

    Individual MDD file loading failures are logged but do not prevent other files from loading.
    The loader continues processing all discovered files regardless of individual failures.


DoIP Gateway Initialization
^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. arch:: DoIP Gateway Initialization
    :id: arch~dt-doip-gateway-init
    :status: draft

    The DoIP gateway establishes communication with vehicle DoIP entities through a discovery
    and connection establishment protocol defined in ISO 13400.

    .. note::

       When deferred initialization is configured (see :need:`arch~dt-deferred-initialization`),
       the entire DoIP gateway initialization described below is postponed until a trigger event
       occurs. When health monitoring is enabled, the health provider for the DoIP component
       remains in "Pending" state until initialization is triggered.

    **Socket Creation**

    A UDP socket is created and bound to the configured tester address and gateway port.
    The socket is configured with:

    - Broadcast capability enabled
    - Address reuse enabled (and port reuse on Unix systems)
    - Non-blocking mode for async operation

    **Vehicle Identification**

    The gateway broadcasts a Vehicle Identification Request (VIR) to ``255.255.255.255`` on the
    configured gateway port. It then collects Vehicle Announcement Messages (VAM) from responding
    DoIP entities within a timeout window.

    **Subnet Filtering**

    VAM responses are filtered based on the configured subnet mask. Only responses from IP addresses
    within the tester's subnet (determined by ``tester_address AND tester_subnet``) are accepted.
    This prevents discovery of DoIP entities on unrelated networks.

    **Gateway-to-ECU Mapping**

    For each discovered gateway (identified by its logical address in the VAM), the system:

    1. Establishes a TCP connection to the gateway's IP address
    2. Performs routing activation to enable diagnostic communication
    3. Creates send/receive channels for each ECU associated with that gateway
    4. Maps ECU logical addresses to their gateway connection index

    **Spontaneous VAM Listener**

    After initial discovery, a background task continuously listens for spontaneous VAM broadcasts.
    This handles scenarios where:

    - A gateway comes online after initial startup
    - An existing gateway reconnects after temporary disconnection

    When a new VAM is received, the system establishes a connection (if not already connected)
    and triggers variant detection for the associated ECUs.

    .. uml::
        :caption: DoIP Gateway Discovery and Connection

        @startuml
        skinparam backgroundColor #FFFFFF
        skinparam sequenceArrowThickness 2

        participant "CDA" as CDA
        participant "UDP Socket" as UDP
        participant "Gateway 1" as GW1
        participant "Gateway 2" as GW2
        participant "TCP Connection" as TCP

        note over CDA,TCP
            When deferred initialization is configured,
            this entire sequence is postponed until a
            trigger event (first request or plugin API call).
        end note

        == Discovery Phase ==
        CDA -> UDP: create_socket(tester_ip, gateway_port)
        CDA -> UDP: broadcast VIR to 255.255.255.255

        UDP -> GW1: VIR
        UDP -> GW2: VIR

        GW1 --> UDP: VAM (logical_address=0x1010)
        GW2 --> UDP: VAM (logical_address=0x2020)

        CDA -> CDA: filter VAMs by subnet mask
        CDA -> CDA: match VAM addresses to MDD databases

        == Connection Phase (per gateway) ==
        CDA -> TCP: connect(gateway_ip, port)
        activate TCP
        TCP --> CDA: connected

        CDA -> TCP: Routing Activation Request
        TCP --> CDA: Routing Activation Response
        note right: Connection ready for diagnostics
        deactivate TCP

        == Continuous Listening ==
        CDA -> UDP: listen_for_vams() (background task)
        note right: Handle late/reconnecting gateways
        @enduml

        .. note:: In case of a TLS required activation response, the connection is reestablished with TLS enabled.


Deferred Initialization
^^^^^^^^^^^^^^^^^^^^^^^

.. arch:: Deferred Initialization
    :id: arch~dt-deferred-initialization
    :status: draft

    The CDA supports deferred initialization of ECU communication to enable scenarios where
    the HTTP API must be available before vehicle communication begins.

    **Dynamic Router Architecture**

    The HTTP server is launched with a dynamic router that supports adding routes after the server
    has started. This enables:

    1. Immediate availability of health endpoints during startup (when health feature is enabled)
    2. Deferred registration of SOVD API routes after ECU discovery
    3. Hot-reloading of routes when the diagnostic database is updated at runtime

    **Initialization Triggers**

    When deferred initialization is configured, DoIP gateway creation and ECU discovery are
    postponed until one of the following triggers:

    - **On-demand**: First diagnostic request to any ECU endpoint triggers initialization
    - **Plugin API**: A custom plugin calls the initialization API based on application-specific
      conditions (e.g., security unlock, session establishment)

    **Pre-initialization State**

    While initialization is deferred:

    - When health monitoring is enabled, health endpoints report status for available components
      (configuration, HTTP server)
    - ECU-specific endpoints return an appropriate status code indicating pending initialization
    - The dynamic router is prepared to receive SOVD routes once initialization completes

    **Initialization Sequence**

    Once triggered, initialization proceeds identically to the immediate initialization path:
    DoIP gateway creation, TCP connection establishment, UDS manager creation, and variant
    detection. Upon completion, SOVD routes are registered and, when health monitoring is
    enabled, health status transitions to "Up".


Health Monitoring
^^^^^^^^^^^^^^^^^

.. arch:: Health Monitoring
    :id: arch~dt-health-monitoring
    :status: draft

    Health monitoring is an optional build-time feature that provides an HTTP endpoint for
    querying the aggregate and per-component health status of the CDA. Health status is only
    retrievable through the health endpoint when this feature is enabled at build time.

    **Feature Enabled Behavior**

    When the health feature is enabled:

    1. During the HTTP Server Phase, health routes are registered on the dynamic router
       immediately after the server starts, making health status queryable before any
       SOVD API routes are available.

    2. During the Health Registration Phase, component-specific health providers are
       registered for each major subsystem (main, database, doip). Each provider
       reports granular status for its component.

    3. The health endpoint returns an aggregate status derived from all registered
       component providers:

       - **Starting**: At least one component is in Pending or Starting state
       - **Up**: All components have successfully initialized
       - **Failed**: At least one component has failed

    4. Health status transitions occur as components progress through their
       initialization lifecycle (see health status transitions below).

    **Feature Disabled Behavior**

    When the health feature is disabled at build time:

    - No health endpoints are registered on the HTTP server
    - No health providers are created for any component
    - Health status is not retrievable through any endpoint or API
    - All health-related registration steps in the startup sequence are skipped
    - The CDA operates normally without any health monitoring overhead

    **Component Health Providers**

    When enabled, the following component health providers are registered:

    .. list-table:: Health Providers
       :header-rows: 1

       * - Component
         - Key
         - Failure Condition
       * - Main
         - ``main``
         - Fatal startup error
       * - Database
         - ``database``
         - No databases loaded
       * - DoIP
         - ``doip``
         - Gateway creation failed

    **Health Status Transitions**

    .. uml::
        :caption: Component Health State Transitions

        @startuml
        skinparam backgroundColor #FFFFFF
        skinparam stateArrowThickness 2

        [*] --> Pending : Component registered\n(initialization not yet started)

        Pending --> Starting : Initialization begins
        Starting --> Up : Initialization successful
        Starting --> Failed : Initialization failed

        state Pending {
        }

        state Starting {
        }

        state Up {
        }

        state Failed {
        }

        note right of Pending
          Used for components whose initialization
          is deferred (e.g., DoIP gateway when
          deferred initialization is configured).
          Pending and Starting both contribute to
          an overall "Starting" aggregate status.
        end note
        @enduml


ECU Detection and Variant Detection
-----------------------------------

ECU Discovery
^^^^^^^^^^^^^

.. arch:: ECU Discovery
    :id: arch~dt-ecu-discovery
    :status: draft

    ECU discovery establishes the mapping between diagnostic database definitions (MDD files)
    and physical DoIP communication endpoints.

    **Database-to-Gateway Mapping**

    During database loading, each ECU's logical gateway address is extracted from the MDD.
    A mapping structure is built that associates each gateway logical address with the list
    of ECU logical addresses accessible through it.

    **VAM Matching**

    When a VAM is received, its logical address is matched against the ECU addresses from loaded
    databases. A match indicates that the ECU defined in the MDD is physically present and
    reachable through the responding gateway.

    **Connection Association**

    For discovered ECUs, the system maintains:

    - A mapping from ECU logical addresses to their gateway connection index
    - A list of active gateway connections with per-ECU send/receive channels

    This structure enables routing diagnostic messages to the correct gateway and ECU.

    **ECU Name Mapping**

    A secondary mapping tracks ECU names to logical addresses for supporting SOVD API requests
    that reference ECUs by name rather than address. This associates each gateway logical
    address with the list of ECU names accessible through it.

    **Duplicate Address Detection**

    ECUs sharing the same logical address (from different MDD files with different ECU names)
    are tracked as potential duplicates. Each ECU manager stores references to other ECU
    names that share the same address. Variant detection determines which ECU definition
    is correct for the physical ECU.


Variant Detection
^^^^^^^^^^^^^^^^^

.. arch:: Variant Detection
    :id: arch~dt-variant-detection
    :status: draft

    Variant detection identifies the correct ECU software variant from multiple possible
    definitions by querying the ECU and matching responses against defined patterns.

    **Detection Request Channel**

    A message channel connects the DoIP gateway to the UDS manager for
    variant detection coordination. When a VAM is received (either during startup or from
    spontaneous announcements), the gateway sends a list of ECU names requiring variant
    detection through this channel.

    **Asynchronous Detection**

    Variant detection runs asynchronously to avoid blocking startup. A dedicated task
    receives ECU names from the channel and spawns individual detection tasks per ECU.
    This enables parallel variant detection across multiple ECUs.

    **Detection Process**

    For each ECU requiring variant detection:

    1. **Prepare**: Extract the set of diagnostic services required for variant identification
       from the MDD variant patterns (services referenced in ``matching_parameter`` elements)

    2. **Execute**: Send each diagnostic service request to the ECU and collect responses

    3. **Evaluate**: Match response parameter values against variant patterns. A variant matches
       when all its ``matching_parameter`` conditions are satisfied (expected value equals
       received value for the specified output parameter)

    4. **Update State**: Set the ECU state based on detection result (Online, Offline,
       NoVariantDetected, or Duplicate)

    **Duplicate Resolution**

    When multiple ECU definitions share the same logical address, variant detection determines
    which definition matches the physical ECU. The matching ECU transitions to Online state;
    non-matching ECUs with the same address transition to Duplicate state and their databases
    are effectively disabled.

    **Fallback Behavior**

    When variant detection fails to find a matching pattern:

    - If ``fallback_to_base_variant`` is enabled: The ECU uses the base variant definition
      and transitions to NoVariantDetected state
    - If disabled: The ECU remains in NotTested state with an error logged


ECU States
^^^^^^^^^^

.. arch:: ECU States
    :id: arch~dt-ecu-states
    :status: draft

    ECU state management tracks the lifecycle of each ECU from registration through
    variant detection and ongoing communication.

    **States**

    The following states are maintained:

    - **NotTested**: Initial state after registration; variant detection has not yet been performed
    - **Online**: ECU is reachable and variant has been successfully detected
    - **NoVariantDetected**: ECU is reachable but no matching variant pattern was found
    - **Duplicate**: ECU shares its logical address with another ECU identified as the correct variant
    - **Offline**: ECU was tested but could not be reached; it has never been successfully online
      since registration or last re-detection
    - **Disconnected**: ECU was previously online but communication has been lost

    The distinction between Offline and Disconnected reflects whether the ECU has ever been
    successfully communicated with. An ECU that fails its first contact attempt transitions to
    Offline; an ECU that was previously Online, NoVariantDetected, or Disconnected and loses
    communication transitions to Disconnected.

    **State Storage**

    ECU state is maintained within the ECU manager structure, which wraps the diagnostic
    database and adds runtime state information. The state is queryable through the SOVD API
    component endpoints.

    **State Transitions**

    State transitions are triggered by:

    - **DoIP Events**: VAM reception, connection establishment/loss, routing activation
      success/failure
    - **Variant Detection**: Detection success, failure, or duplicate identification
    - **API Requests**: Explicit re-detection requests via POST to ECU endpoint
    - **Communication Errors**: Timeout, NACK, or connection closure during diagnostic requests

    **Concurrent Access**

    ECU state is protected by a read-write lock to enable concurrent read access from
    multiple API handlers while ensuring exclusive write access during state transitions.
    The database map associates each ECU name with its concurrency-protected state manager.

    **State Query**

    The SOVD API exposes ECU state through the component collection endpoint. Clients can
    query individual ECU status or list all ECUs with their current states. The state is
    included in the component response to inform clients of ECU availability.


Error Handling
--------------

.. arch:: Startup Error Handling
    :id: arch~dt-error-handling
    :status: draft

    The CDA implements graceful degradation during startup to maximize availability even
    when individual components fail.

    **Error Type Hierarchy**

    Application errors are categorized through a structured error type hierarchy.
    The following error types are relevant during startup:

    - ``InitializationFailed``: Critical startup failure (e.g., socket creation failed)
    - ``ConfigurationError``: Invalid configuration (prevents startup)
    - ``ConnectionError``: DoIP connection issues (per-gateway, non-fatal)
    - ``ResourceError``: Database loading issues (per-file, non-fatal)
    - ``DataError``: MDD parsing issues (per-file, non-fatal)

    Additionally, the following error types may occur during runtime after startup has completed:

    - ``RuntimeError``: Errors during diagnostic operations (e.g., UDS communication failures,
      variant detection errors)
    - ``NotFound``: Requested resource (ECU, service, parameter) could not be found
    - ``ServerError``: Internal server errors during request processing

    **Component Health Integration**

    When health monitoring is enabled (see :need:`arch~dt-health-monitoring`), component
    failures are reflected through health provider status transitions. Health providers
    and their status transitions are defined in the health monitoring architecture.

    **Graceful Degradation Behaviors**

    - **No databases loaded**: Configurable via ``exit_no_database_loaded``. When true, the
      application exits with an error. When false, the CDA continues with an empty ECU list.

    - **Individual database failure**: Logged and skipped; other databases continue loading.

    - **DoIP connection failure**: The affected gateway's ECUs are marked as Offline;
      other gateways and ECUs remain operational.

    - **Variant detection failure**: ECU transitions to Offline (if unreachable) or
      NoVariantDetected state; diagnostic operations may still be attempted with base variant.

    - **Deferred initialization failure**: When deferred initialization is triggered
      (by first request or plugin API) and the subsequent DoIP gateway creation or
      UDS manager creation fails, the error is reported to the caller. When health
      monitoring is enabled, the DoIP health provider transitions to "Failed" state.
      The HTTP server and non-ECU endpoints remain operational. Subsequent trigger
      attempts may retry initialization.

    - **Configuration file load failure**: The system falls back to default configuration values
      and logs a warning. Startup continues with defaults, which may be overridden by CLI arguments.

    - **Configuration validation failure**: Startup is aborted with a descriptive error message.

    **Shutdown Handling**

    Shutdown signals (SIGTERM, Ctrl+C) are handled gracefully at any startup phase:

    - During database loading: Loading tasks are aborted and the process exits
    - During DoIP initialization: Connections are not established and the process exits
    - During deferred initialization: If initialization was triggered but not yet complete,
      in-progress connections are aborted and the process exits
    - After full initialization: The HTTP server completes pending requests before shutdown

    All shutdown paths ensure resources are properly released through structured cleanup
    and tracing guards that flush logs on drop.
