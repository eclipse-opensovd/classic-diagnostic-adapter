.. SPDX-FileCopyrightText: 2025 Copyright (c) Contributors to the Eclipse Foundation
..
.. See the NOTICE file(s) distributed with this work for additional
.. information regarding copyright ownership.
..
.. This program and the accompanying materials are made available under the
.. terms of the Apache License Version 2.0 which is available at
.. https://www.apache.org/licenses/LICENSE-2.0
..
.. SPDX-License-Identifier: Apache-2.0

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
    :links: dimpl~deferred-communication-startup, dimpl~deferred-doip-transport, test~deferred-startup-policy, test~deferred-doip-passive-construction, itest~deferred-on-demand-pending, itest~deferred-on-demand-uds-silence, itest~deferred-disabled-uds-silence
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
       the configured ``init_mode``, initialize the communication layer.

       **Always / WhenNotPersisted mode** (``Always`` is the default):

       - Parallel MDD file loading
       - DoIP gateway creation -- a full VIR/VAM broadcast exchange for ``Always``, or for
         ``WhenNotPersisted``, either a full broadcast exchange (no persisted topology available) or a
         direct reconnect to persisted gateway addresses
       - TCP connections established, UDS manager creation
       - Asynchronous variant detection startup

       **OnDemand / Disabled mode** (see :need:`arch~dt-deferred-initialization`):

       - Parallel MDD file loading proceeds as normal
       - DoIP gateway creation, UDS manager creation, and variant detection are **not** performed
         during startup. Instead, these steps are postponed until a trigger event occurs: in
         **OnDemand** mode, either a whole-vehicle plugin-API activation, or a first diagnostic request to
         a specific ECU (scoped to just that ECU's gateway when a persisted topology exists, or triggering
         a full broadcast otherwise); in **Disabled** mode, only an explicitly initiated detection run --
         typically via ``networkreset``, but potentially via a plugin or other custom code -- applies

    6. **Route Registration Phase**: Register SOVD API routes, version endpoints, and
       OpenAPI documentation routes on the dynamic router. In on-demand/disabled mode, ECU-specific
       routes are registered with handlers that trigger initialization on first access (single-ECU scope,
       **OnDemand** only) or return a pending status until a detection run is explicitly initiated
       (whole-vehicle scope: plugin API in **OnDemand**, or the equivalent explicit trigger in
       **Disabled** mode).

    7. **Ready Phase**: When the health feature is enabled, update the main health status to
       "Up" indicating the CDA's HTTP API is operational. In deferred/disabled mode, the DoIP health
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
        else OnDemand / Disabled communication (postponed until triggered)
            Main -> HTTP: register SOVD routes
            note over Main,UDS
                DoIP gateway creation, UDS manager
                creation, and variant detection are
                postponed until triggered
                (see arch~dt-deferred-initialization)
            end note
            note over HTTP,DoIP
                HTTP API is operational while
                communication remains disabled
            end note
        end

        opt Immediate communication initialization
            Main -> HTTP: add_vehicle_routes()
        end
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


Communication Initialization Mode
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. arch:: Communication Initialization Mode
    :id: arch~dt-deferred-initialization
    :links: test~ecu-topology-reconnect-search, test~doip-aborted-discovery-finishes, dimpl~doip-persisted-reconnect, dimpl~doip-reconnect-discovery-mode, test~doip-vam-only-reconnect-without-search, dimpl~doip-failed-announcement-connect-reported, test~doip-failed-announcement-connect-reported, test~doip-unreachable-reported-after-state-change, dimpl~ecu-topology-restore, dimpl~ecu-state-restore, test~doip-plan-reconnect, dimpl~communication-control-contracts, dimpl~communication-control-access, dimpl~communication-control-operations, dimpl~communication-lifecycle-controller, dimpl~default-communication-policy, dimpl~deferred-communication-startup, dimpl~deferred-sovd-admission, dimpl~deferred-doip-transport, test~deferred-communication-config, test~deferred-startup-policy, test~deferred-admitting-modes-activate, test~deferred-disabled-rejects-activation, test~deferred-request-activation-policy, test~deferred-activation-retry, test~deferred-sovd-admission, test~deferred-doip-passive-construction, itest~deferred-on-demand-pending, itest~deferred-on-demand-uds-silence, itest~deferred-disabled-uds-silence, test~doip-reconnect-plan-reconnect-rejects-renamed-gateway, test~ecu-state-restore-without-assume-online-only-last-seen-is-restored, test~ecu-state-restore-variant-missing-from-the-database-is-detected-again, test~ecu-state-restore-address-mismatch-restores-nothing, test~ecu-state-restore-can-pinned-ecu-is-not-assumed-online, test~ecu-state-restore-inconsistent-duplicate-group-is-detected-again, test~doip-vam-during-reconnect-does-not-connect-twice, dimpl~doip-vam-during-connect-connects-after-failure, test~doip-vam-during-connect-connects-after-failure, dimpl~doip-discovery-connect-waits-for-direct-connect, test~doip-discovery-connect-waits-for-direct-connect, dimpl~doip-cancelled-connect-reverts-ecu-states, test~doip-cancelled-connect-reverts-ecu-states, dimpl~doip-stop-reverts-aborted-connects, test~doip-stop-reverts-aborted-connects, test~doip-vam-only-reconnect-reports-unusable, test~ecu-state-restore-independent-of-discovery-mode
    :status: draft

    The CDA supports a configurable ``[communication] init_mode`` to enable scenarios where
    the HTTP API must be available before vehicle communication begins, or where communication must remain
    fully quiet until explicitly authorized.

    **Configuration**

    ``init_mode`` accepts ``"Always"`` (default), ``"WhenNotPersisted"``, ``"OnDemand"`` and ``"Disabled"``.
    Reusing a persisted topology additionally requires ``[communication.ecu_list_persistence] enabled = true``
    (see :need:`arch~dt-ecu-list-persistence`). Enabling persistence alone keeps the default ``Always``
    behavior of a full broadcast discovery at every startup; startup without re-detection requires
    ``init_mode = "WhenNotPersisted"`` (or ``OnDemand``/``Disabled`` once triggered). The CDA logs a warning
    when ``WhenNotPersisted`` is configured while persistence is disabled, since the mode then behaves like
    ``Always``.

    For ``WhenNotPersisted``, the default communication plugin applies the same activation policy as for
    ``Always``; the two modes only differ in how the transport discovers gateways.

    **Dynamic Router Architecture**

    The HTTP server is launched with a dynamic router that supports adding routes after the server
    has started. This enables:

    1. Immediate availability of health endpoints during startup (when health feature is enabled)
    2. Deferred registration of SOVD API routes after ECU discovery
    3. Hot-reloading of routes when the diagnostic database is updated at runtime

    **``init_mode`` Values**

    - **Always** (default): DoIP gateway creation and ECU discovery proceed immediately at startup, as
      described in :need:`arch~dt-startup-sequence`, always performing a full VIR/VAM broadcast discovery
      regardless of whether a persisted topology exists (see :need:`arch~dt-ecu-list-persistence`). If ECU
      list persistence is enabled, results are still persisted afterward (topology, states, ``last_seen``),
      but the persisted topology is never consulted to skip or replace the broadcast discovery itself. This
      matches the CDA's established default behavior prior to the introduction of ECU list persistence.
    - **WhenNotPersisted**: DoIP gateway creation and ECU discovery proceed immediately at startup, but a
      full VIR/VAM broadcast discovery is only performed when no persisted topology is available (e.g. on
      the first-ever startup, or any time after the persisted topology has been cleared). Whenever a
      persisted topology exists, the CDA instead attempts a direct (unicast) DoIP connection to each
      persisted gateway's known network address, skipping the broadcast VIR step; if a gateway cannot be
      reached at its persisted address, the CDA falls back to broadcast-based discovery for that specific
      gateway, as described in :need:`arch~doip-vehicle-identification`, before marking its ECUs as Offline.
      Requires ECU list persistence to be enabled; behaves identically to **Always** if persistence is
      disabled, since no persisted topology can ever exist in that configuration.
    - **OnDemand**: DoIP gateway creation and ECU discovery are postponed until one of the following
      triggers, which intentionally differ in scope:

      - **Plugin API** (whole-vehicle scope): a custom plugin calls the initialization API based on
        application-specific conditions (e.g., security unlock, session establishment). This triggers a
        full initialization of all gateways/ECUs at once, applying the same persisted-vs-broadcast
        behavior as **WhenNotPersisted** described above.
      - **On-demand** (single-ECU scope): the first diagnostic request to a specific ECU endpoint triggers
        initialization. If a persisted topology exists, this establishes a connection only to that ECU's
        gateway (direct reconnect, with broadcast fallback for that gateway alone, as in
        **WhenNotPersisted**); other persisted gateways remain unconnected until their own first request.
        If no persisted topology exists, no gateway network address is yet known, so this necessarily
        triggers a full, vehicle-wide VIR broadcast, discovering and connecting all gateways at once,
        since VIR-based discovery is inherently broadcast-based and cannot be scoped to a single ECU.

    - **Disabled**: DoIP gateway creation and ECU discovery are postponed exactly as in **OnDemand** mode,
      except that only an explicitly initiated detection run applies -- typically via the ``networkreset``
      operation executed with ``trigger_detection=true`` (see
      :need:`arch~plugin-vehicle-topology-reset-persistence`), but a plugin or other custom code may
      equally initiate it directly; the on-demand (first-request) and plugin-API triggers are not
      recognized in this mode. No socket is opened and no VIR is broadcast until that detection run is
      explicitly initiated. Once triggered, this always initializes all gateways/ECUs at once (there is no
      per-ECU auto-trigger in this mode), applying the same persisted-vs-broadcast behavior as
      **WhenNotPersisted**.

    **OnDemand** and **Disabled** always behave like **WhenNotPersisted** once triggered (at whichever
    scope applies), rather than offering their own **Always**/**WhenNotPersisted** choice, since these
    modes exist specifically to minimize vehicle network traffic until explicitly authorized.

    .. uml::
        :caption: Communication Initialization Mode State Flow

        @startuml
        skinparam backgroundColor #FFFFFF
        skinparam state {
            BackgroundColor #F8F8F8
            BorderColor #333333
        }

        [*] --> SelectingMode

        state SelectingMode <<choice>>
        SelectingMode --> Enabling : Always / startup
        SelectingMode --> Deferred : OnDemand
        SelectingMode --> Disabled : Disabled

        Deferred --> Enabling : first diagnostic request\nor explicit activation
        Deferred --> Deferred : request returns 503\nwith Retry-After

        Disabled --> Disabled : diagnostic request\nreturns 503
        Disabled --> Enabling : explicit detection trigger

        Enabling --> Enabled : transport, lifecycle hooks,\nvariant detection complete
        Enabling --> Failed : initialization failure
        Failed --> Enabling : authorized retry

        Enabled --> Enabled : diagnostic requests served
        @enduml

    **Reconnect Realization**

    - The persisted ECU states are restored while the vehicle data is loaded, before communication starts:
      ECUs last known Online get their persisted variant and are registered AssumedOnline, so they are not
      detected again until contacted (see :need:`arch~dt-ecu-states`). This does not depend on
      ``doip.discovery``. Everything else (ECUs not last known Online, variants no longer in the database,
      changed addresses, ECUs pinned to CAN, inconsistently persisted duplicate groups) gets a regular
      variant detection.
    - On transport start, the persisted gateways with a usable network address (inside the tester subnet,
      known protocol version, same name in the database) are connected directly. A persisted gateway without
      network address was not found by the last full broadcast and is not searched again. Gateways of the
      databases that are not persisted at all, and persisted gateways that cannot be reached at their address,
      are searched by one broadcast VIR sent from a separate, ephemeral socket (the VAM listener owns the
      socket on the DoIP port); only announcements of these gateways are used.
    - The ECUs of gateways that are still not found are reported as unreachable. The discovery then counts
      as complete for :need:`arch~dt-ecu-list-persistence`, which writes the result.
    - ``doip.discovery`` restricts the reconnect like the full discovery (see
      :need:`req~doip-discovery-mode`). With ``VamOnly`` no broadcast VIR is sent, neither for the gateways
      to be searched nor as the fallback of a failed connect: the gateways whose direct connect failed and
      the persisted gateways without a usable address are reported unreachable, so their ECUs become
      Disconnected, unless an announcement connected them meanwhile (a connect of them still in flight is
      waited for first); the gateways that are not persisted are connected by their spontaneous
      announcement.
      With ``Disabled`` no persisted gateway is reconnected and no announcement is handled; gateways are
      only connected through ``doip-connect-ecu``.
    - The broadcast fallback belongs to the persisted reconnect only: the gateways it could not reach are
      searched by one VIR together. A connect started for any other reason does not search a gateway it
      could not reach.
    - A spontaneous announcement of an unconnected gateway starts its connect in the background: the VAM
      listener does not wait for it and handles the next announcement meanwhile. If that connect fails, the
      gateway is reported unreachable without a broadcast: it has just announced its address itself.
    - A gateway whose connect failed is not retried automatically in the same transport session; it is
      connected again by its spontaneous announcement (subject to ``vam_handling_mode``) or the next
      transport start.
    - With ``init_mode = Always``, only ``last_seen`` is restored and the full broadcast discovery runs.
    - Every connect of a gateway (startup discovery, persisted reconnect, spontaneous announcement, direct
      connect) holds the gateway's connect lock while it runs, so connects of one gateway never overlap. A
      connect that gets the lock connects only if the gateway is not connected by then. Connect state
      belongs to one transport start; work left over from an earlier start does not change it. A connect
      that sees the transport stop's cancel after its ECUs were reported connected, before its task is
      aborted, reports them disconnected again. If the stop aborts the task in that window, the stop reports
      them disconnected instead. A connect aborted before it reported its ECUs connected leaves their states
      unchanged, so ``AssumedOnline`` ECUs keep their restored variant.
    - An announcement of a gateway with a connect in flight (of any kind, at the same or another address)
      opens no parallel connection. One task per gateway waits for the lock; further announcements only
      replace the address it connects. If the gateway is connected by then, the connection is kept and a
      different announced address is logged as a warning. Otherwise the task connects the newest announced
      address like a new announcement.
    - A direct connect through ``doip-connect-ecu`` (see :need:`arch~plugin-vehicle-topology-connect-ecu`) is
      rejected if a connect of the gateway holds its lock or the gateway is connected. It is not recorded in
      the topology, so its address is not persisted and the next start does not reconnect to it.
    - A discovery connect (startup VIR result, persisted reconnect) that finds a direct connect in flight
      does not take its result, since the direct address may be wrong: it waits for the lock and, if the
      direct connect did not connect, connects itself. A gateway found by the startup VIR is recorded at its
      announced address once it is connected, also if the direct connect connected it.
    - After a runtime database update, the gateways are reconnected the same way, but ECU states are not
      restored, since the variants may have changed with the databases.

    .. uml::
        :caption: WhenNotPersisted -- Reconnect to a Persisted Gateway

        @startuml
        skinparam backgroundColor #FFFFFF
        skinparam sequenceArrowThickness 2

        participant "CDA" as Startup
        participant "DoIP Entity\n(persisted address)" as GW

        Startup -> Startup: restore last known variants;\nECUs last known Online -> AssumedOnline
        Startup -> GW: unicast connect (known IP/logical address)
        alt connection succeeds
            GW --> Startup: connected
            Startup -> Startup: AssumedOnline ECUs keep their variant\n(no variant detection);\nother ECUs: regular variant detection
        else connection fails / timeout
            GW --> Startup: unreachable
            note right: Fallback to broadcast VIR\n(see arch~doip-vehicle-identification)
            Startup -> Startup: mark gateway's ECUs Disconnected (AssumedOnline)\nor Offline if still not found;\nthe state is persisted\n(see arch~dt-ecu-list-persistence)
        end
        @enduml

    **Pre-initialization State**

    While initialization is deferred (``OnDemand`` or ``Disabled``, before their respective trigger fires):

    - When health monitoring is enabled, health endpoints report status for available components
      (configuration, HTTP server)
    - ECU-specific endpoints return an appropriate status code indicating pending initialization
    - The dynamic router is prepared to receive SOVD routes once initialization completes
    - No spontaneous VAM listener is started (see :need:`arch~doip-vam-handling-mode`)

    **Initialization Sequence**

    Once triggered, initialization proceeds identically to the immediate initialization path (subject to
    the **Always**/**WhenNotPersisted** distinction described above, and, for **OnDemand**, scoped to a
    single gateway or all gateways depending on which trigger fired): DoIP gateway creation (broadcast
    discovery or direct reconnect), TCP connection establishment, UDS manager creation, and variant
    detection. Upon completion, SOVD routes are registered and, when health monitoring is enabled, health
    status transitions to "Up" (for **OnDemand**'s single-ECU trigger, this refers to the routes/health of
    the affected gateway only). The resulting topology is persisted as described in
    :need:`arch~dt-ecu-list-persistence`, so that subsequent startups can reuse it (unless ``init_mode`` is
    ``Always``).


Post-Update Deferred Communication
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. arch:: Post-Update Deferred Communication
    :id: arch~dt-post-update-deferred-communication
    :links: dimpl~communication-control-contracts, dimpl~communication-lifecycle-controller, dimpl~post-update-deferred-communication, test~deferred-communication-config, test~deferred-post-update-apply, test~deferred-post-update-rollback, itest~deferred-post-update
    :status: draft

    Runtime database updates acquire the communication lifecycle controller's exclusive disable lease
    before replacing vehicle data. When ``post_update_mode`` is ``Deferred``, a successful apply or rollback
    drops that lease without requesting transport resumption. The communication lifecycle therefore returns
    to its deferred state while the registered ECU routes remain available.

    ECU-related requests are rejected with ``503 Service Unavailable`` and ``Retry-After`` while
    communication is disabled. Under ``init_mode = OnDemand``, such a request submits a new activation
    request to the communication lifecycle controller. Diagnostic requests can proceed after transport
    activation and variant detection complete.

    .. uml::
        :caption: Deferred Communication After a Runtime Update

        @startuml
        skinparam backgroundColor #FFFFFF
        skinparam sequenceArrowThickness 2

        actor Client
        participant "Runtime Update" as Update
        participant "Communication Lifecycle" as Lifecycle
        participant "Diagnostic Transport" as Transport
        participant "SOVD API" as API

        Client -> Update: Apply or Rollback
        Update -> Lifecycle: acquire exclusive disable lease
        Lifecycle -> Transport: disable
        Transport --> Lifecycle: disabled
        Update -> Update: install and reload vehicle data

        alt post_update_mode = Enabled
            Update -> Lifecycle: release lease
            Lifecycle -> Transport: resume
        else post_update_mode = Deferred
            Update -> Lifecycle: drop lease
            note over Lifecycle,Transport: Communication remains disabled
            Client -> API: ECU diagnostic request
            API --> Client: 503 Service Unavailable\nRetry-After
            API -> Lifecycle: request activation
            Lifecycle -> Transport: enable and detect
            Transport --> Lifecycle: enabled
            Client -> API: retry ECU request
            API --> Client: diagnostic response
        end
        @enduml


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
    :links: dimpl~default-communication-policy, itest~variant-detection-explicit
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

    2. **Execute**: Send each diagnostic service request to the ECU and collect responses.
       A connectivity failure aborts detection and marks the ECU (and its duplicates)
       unreachable. Partial responses are discarded. Other per-request failures are logged
       and the remaining requests are still sent. For duplicate groups, each member's own
       detection services are sent and evaluated separately. A negative UDS response to an
       unsupported service is still a response and does not block another member from
       matching. Send or decoding errors leave incomplete evidence and prevent the group
       from selecting a member.

    3. **Evaluate**: Match response parameter values against variant patterns. A variant matches
       when all its ``matching_parameter`` conditions are satisfied (expected value equals
       received value for the specified output parameter)

    4. **Update State**: Set the ECU state based on detection result (Online, Offline,
       NoVariantDetected, or Duplicate)

    **ECUs Without Detection Services**

    ECUs whose MDD defines no variant detection services always run their base variant. Only
    reachability is checked by reading the ``UDSVersionDataIdentifier`` (``22 FF 00``). Any
    response, positive or negative, sets the ECU Online with its base variant. No response
    marks it unreachable.

    **Duplicate Resolution**

    When multiple ECU definitions share the same logical address, variant detection determines
    which definition matches the physical ECU. The matching ECU transitions to Online state;
    non-matching ECUs with the same address transition to Duplicate state and their databases
    are effectively disabled.

    A member that cannot be reached during detection, for example because it has no route on
    the active transport, is left out of the evaluation. The group is only marked unreachable
    when no member returns any response.

    If no member with detection services matches a specific variant and the group contains
    members without detection services, the ECU is probed once with ``22 FF 00`` (all members
    share one logical address). If it responds and exactly one member has no detection
    services, that member is set Online with its base variant and all other members become
    Duplicate. With several such members the group cannot be resolved and all members become
    NoVariantDetected. Without a response the regular group result applies, or the group is
    marked unreachable when no member defines detection services.

    **Fallback Behavior**

    When variant detection fails to find a matching pattern:

    - If ``fallback_to_base_variant`` is enabled: The ECU uses the base variant definition
      and transitions to NoVariantDetected state
    - If disabled: The ECU remains in NotTested state with an error logged


ECU States
^^^^^^^^^^

.. arch:: ECU States
    :id: arch~dt-ecu-states
    :links: dimpl~ecu-state-restore, dimpl~ecu-state-assumed-online, test~ecu-last-seen, dimpl~uds-ecu-reply-contact, test~uds-ecu-reply-contact, test~uds-gateway-disconnect-applied-before-return, test~uds-suppressed-response-no-contact, test~uds-state-assumed-online-becomes-online-on-response, test~uds-state-restored-duplicate-survives-connect-but-real-reconnect-redetects, test~ecu-state-assumed-online-keeps-state-without-gateway, test~ecu-state-assumed-online-reported-as-online
    :status: draft

    ECU state management tracks the lifecycle of each ECU from registration through
    variant detection and ongoing communication.

    **States**

    The following states are maintained:

    - **NotTested**: Initial state after registration; variant detection has not yet been performed
    - **Online**: ECU is reachable and variant has been successfully detected, or restored from a persisted
      ECU topology and confirmed reachable by a reply of the ECU
    - **AssumedOnline**: ECU was registered from a persisted ECU topology (see
      :need:`arch~dt-ecu-list-persistence`) with a last known state of Online, but has not yet been
      contacted in the current session
    - **NoVariantDetected**: ECU is reachable but no matching variant pattern was found
    - **Duplicate**: ECU shares its logical address with another ECU identified as the correct variant
    - **Offline**: ECU was tested but could not be reached; it has never been successfully online
      since registration or last re-detection
    - **Disconnected**: ECU was previously online but communication has been lost

    The distinction between Offline and Disconnected reflects whether the ECU has ever been
    successfully communicated with. An ECU that fails its first contact attempt transitions to
    Offline; an ECU that was previously Online, NoVariantDetected, Disconnected, or AssumedOnline and
    loses (or fails to establish) communication transitions to Disconnected -- since, in all of these
    cases, the ECU is known to have been reachable at some point (either in the current session, or, for
    AssumedOnline, according to the persisted topology from a previous session).

    **External Representation**

    The AssumedOnline state is an internal-only distinction. Externally, via the SOVD API (see
    :need:`arch~sovd-api-components-entity-collection` and
    :need:`arch~plugin-vehicle-topology-retrieval`), an ECU in the AssumedOnline state is reported with
    connectivity state ``Online``, so that clients do not need to be aware of whether the ECU has actually
    been contacted in the current session. The ``last_seen`` timestamp (see State Storage below) allows
    clients to judge how current that information is.

    **State Storage**

    ECU state is maintained within the ECU manager structure, which wraps the diagnostic
    database and adds runtime state information. The state is queryable through the SOVD API
    component endpoints.

    In addition to the state enum, each ECU manager stores a ``last_seen`` timestamp, the time of the last
    reply of the ECU. For ECUs registered in the AssumedOnline state, the initial value of ``last_seen`` is
    taken from the persisted topology (see :need:`arch~dt-ecu-list-persistence`) and reflects the last reply
    of the ECU in a previous session.

    Any UDS message the ECU sends while a request to it is in progress counts, positive or negative,
    including the pending NRCs 0x78, 0x21 and 0x94. It counts whether or not the request succeeds as a
    whole (e.g. 0x78 followed by a timeout), and also if the message is not the answer to the request
    (e.g. a late answer to an earlier request). For a functional request, each responding ECU counts.

    A physical request with a suppressed positive response (``suppressPosRspMsgIndicationBit`` set) never
    counts. The CDA does not wait for a UDS reply to such a request: the request ends with the transport
    acknowledgement, which for DoIP comes from the gateway and does not prove that the ECU is reachable.
    An NRC that the ECU still sends afterwards (allowed for physical requests) arrives after the request
    has ended and is not read. For a functional request with a suppressed positive response, every
    response the CDA still receives (e.g. an NRC) counts for the ECU that sent it. On DoIP, a negative
    response to a tester present message (``7F 3E``) counts for the ECU that sent it, also when the tester
    present request was sent with a suppressed positive response.

    ``last_seen`` is wall-clock time, and the newest write always wins, even if it is older than the stored
    value. Vehicle clocks are often wrong at boot and corrected later by time synchronization. Keeping the
    maximum would pin a wrong future timestamp that later contacts could never replace; with the newest
    write, ``last_seen`` can go backwards once after such a correction.

    ``last_seen`` is persisted with the ECU list when the topology is written and at shutdown, and restored
    at the next start (see :need:`arch~dt-ecu-list-persistence`). Each update also marks the value as
    changed since it was last persisted, which selects the ECUs written back at shutdown (see
    :need:`arch~dt-ecu-list-persistence-shutdown`).

    **AssumedOnline Handling**

    - The first reply of the ECU transitions an AssumedOnline ECU to Online. The transition is serialized
      with connect and disconnect events of that ECU. The restored variant is kept and not verified, see
      :need:`arch~dt-ecu-list-persistence`.
    - Connecting the ECU's gateway does not change the AssumedOnline state and does not reset the restored
      variant, unlike the Offline to Online transition of a reconnected ECU, which clears the variant for
      re-detection.
    - A request timeout transitions it to Offline with the variant kept, which is reported as
      Disconnected. A request that cannot be sent because the gateway of the ECU has no connection does
      not change the state: the gateway may still be reconnecting in the background, and only the
      gateway reporting its ECUs unreachable marks them Disconnected. The restored variant is thus kept
      when the gateway connects afterwards.
    - The variant detection of an activation skips AssumedOnline ECUs, so they are not marked Offline while
      their gateway is still connecting. An explicit whole-vehicle re-detection first resets AssumedOnline
      ECUs to NotTested and then detects them; an explicit re-detection of a single ECU runs regardless.

    **State Transitions**

    State transitions are triggered by:

    - **DoIP Events**: VAM reception, connection establishment/loss, routing activation
      success/failure
    - **Variant Detection**: Detection success, failure, or duplicate identification
    - **API Requests**: Explicit re-detection requests via PUT to ECU endpoint
    - **Communication Errors**: Timeout, NACK, or connection closure during diagnostic requests
    - **Persisted Topology Load**: Registration of an ECU from a persisted topology with last known state
      Online transitions it directly to AssumedOnline instead of NotTested

    **Concurrent Access**

    ECU state is protected by a read-write lock to enable concurrent read access from
    multiple API handlers while ensuring exclusive write access during state transitions.
    The database map associates each ECU name with its concurrency-protected state manager.

    **State Query**

    The SOVD API exposes ECU state through the component collection endpoint. Clients can
    query individual ECU status or list all ECUs with their current states. The state (with AssumedOnline
    mapped to Online) and the ``last_seen`` timestamp are included in the component response to inform
    clients of ECU availability.


ECU List Persistence
--------------------

ECU List Persistence
^^^^^^^^^^^^^^^^^^^^

.. arch:: ECU List Persistence
    :id: arch~dt-ecu-list-persistence
    :links: dimpl~ecu-topology-store, dimpl~ecu-topology-store-spawn-locked-write, dimpl~doip-direct-connect-not-recorded, test~doip-direct-connect-not-recorded, test~ecu-topology-store-cancelled-call-keeps-lock, test~detection-tracker-undelivered-request-released, test~detection-tracker-idle-after-receiver-drop, test~ecu-list-persistence-snapshot-name-case, dimpl~ecu-topology-persist-after-detection, dimpl~ecu-topology-prune, test~ecu-topology-persist-after-detection, test~ecu-topology-prune, dimpl~ecu-topology-persist-serialized, test~ecu-topology-persist-serialized, dimpl~ecu-topology-persist-when-idle, dimpl~ecu-topology-persist-unreachable, itest~ecu-list-persistence-unreachable, itest~ecu-list-persistence-unreachable-gateway, dimpl~ecu-list-persistence-requires-doip, test~ecu-list-persistence-requires-doip, itest~ecu-list-persistence-disabled, itest~ecu-list-persistence-reuse, test~ecu-list-persistence-reuse-plan, test~detection-tracker-queued-requests-and-tickets-keep-tracker-busy, test~ecu-list-persistence-runs-during-write-coalesce-into-one-more-write, test~ecu-list-persistence-settle-budget-is-shared-between-discovery-and-detection, test~ecu-list-persistence-persisted-state-follows-sovd-mapping, test~ecu-topology-store-unreadable-entries-are-skipped, test~ecu-topology-store-persist-gateways-keeps-other-entries, test~ecu-list-persistence-unchanged-restart-writes-nothing, test~ecu-list-persistence-only-changed-gateways-written
    :status: draft

    The detected ECU/gateway topology is persisted on top of the generic Persistence API (see
    :need:`arch~system-persistence-api`), so that the CDA does not have to unconditionally rediscover it on
    every startup.

    **Enable/Disable Configuration**

    A configuration flag (``communication.ecu_list_persistence.enabled``, default ``false``) gates this
    entire feature. When left at ``false`` (the default), the ``ecu-topology`` bucket is never read at
    startup and never written (neither after a detection run nor at shutdown, see
    :need:`arch~dt-ecu-list-persistence-shutdown`). The CDA startup path always takes the "no persisted
    topology" branch in that configuration (see :need:`arch~dt-deferred-initialization`), and the
    AssumedOnline state can never be entered.

    **Bucket Layout**

    A dedicated Bucket ``ecu-topology`` is used. One entry is stored per gateway, keyed by the gateway's
    logical address as zero-padded hexadecimal (e.g. ``0x1000``). Each value serializes:

    - The gateway's network address and logical address
    - The list of ECUs reachable through that gateway, each with its logical address, name, last known
      variant, last known state, and ``last_seen`` timestamp (see :need:`arch~dt-ecu-states`)

    The persisted topology covers DoIP gateways. With DoIP disabled, persistence behaves as disabled even if
    ``ecu_list_persistence.enabled`` is ``true``: the stored data is neither read nor written (it is kept and
    used again once DoIP is enabled), and a warning is logged at startup. In mixed DoIP/CAN configurations,
    persistence covers the DoIP gateways; ECUs pinned to CAN are not restored AssumedOnline (see Reconnect
    Realization).

    The value is a JSON document. ``last_seen`` is an RFC 3339 UTC timestamp with second
    precision. The network address is absent for a gateway that is defined in the diagnostic databases but
    was not found by the last full broadcast discovery, so that a gateway which is not fitted does not force
    a new broadcast on every startup. Such a gateway is found again by its spontaneous announcement (subject
    to ``vam_handling_mode``) or at a later start that runs the full broadcast discovery; with
    ``vam_handling_mode = Never`` only the latter.
    The internal AssumedOnline state is persisted as ``Online``.

    .. code-block:: json

        {
          "name": "FLXC1000",
          "logical_address": 4096,
          "network_address": "10.2.1.10",
          "doip_protocol_version": 3,
          "ecus": [{
            "name": "FLXC1000",
            "logical_address": 4096,
            "variant": {"name": "FLXC1000_App_0101", "is_base_variant": false, "is_fallback": false},
            "state": "Online",
            "last_seen": "2026-10-09T08:15:00Z"
          }]
        }

    Every write replaces the entries of the gateways it covers (see Write Timing) and leaves all
    other entries unchanged. An entry that cannot be read (invalid JSON, key not matching its logical
    address) is skipped with a warning; its gateway is then handled as if it were not persisted, and the
    entry is replaced by the next write of its gateway or removed by the next prune.

    .. uml::
        :caption: ECU Topology Persistence

        @startuml
        skinparam backgroundColor #FFFFFF
        skinparam sequenceArrowThickness 2

        participant "CDA Startup" as Startup
        participant "Persistence API" as Persist
        participant "DoIP Gateway" as DOIP
        participant "UDS Manager" as UDS

        == Startup ==
        alt communication.ecu_list_persistence.enabled = false
            note over Startup: skip persistence entirely,\nalways take "no persisted topology" branch
        else communication.ecu_list_persistence.enabled = true
            Startup -> Persist: load bucket "ecu-topology"
            alt bucket present
                Persist --> Startup: persisted topology
                note right: See arch~dt-deferred-initialization\n(WhenNotPersisted/OnDemand/Disabled reuse)
            else bucket absent
                Persist --> Startup: not found
                note right: See arch~dt-deferred-initialization
            end
        end

        == Detection completes (startup or networkreset) ==
        DOIP -> UDS: ECUs registered, states updated
        opt communication.ecu_list_persistence.enabled = true
            UDS -> Persist: set bucket "ecu-topology" (per gateway)
            UDS -> Persist: flush
        end
        @enduml

    **Write Timing**

    The persisted topology is written after a detection run completes -- both after the initial startup
    detection (unless deferred/disabled without a trigger having fired yet, see
    :need:`arch~dt-deferred-initialization`) and after a ``networkreset`` execution that triggers detection
    (see :need:`arch~plugin-vehicle-topology-reset-persistence`). This applies regardless of whether
    ``init_mode`` is ``Always`` or ``WhenNotPersisted`` -- a detection run's results are always persisted
    when it occurs; only ``WhenNotPersisted`` additionally uses the persisted data to decide whether to skip
    that detection run in the first place. A ``flush`` is issued to guarantee durability of the persisted
    data. This write is skipped entirely when ``communication.ecu_list_persistence.enabled`` is ``false``.

    The write is performed by a communication lifecycle hook registered after the UDS manager hooks:

    - When communication is enabled, it waits until the gateway discovery has settled (all initial gateway
      connection attempts finished) and until no variant detection is queued or running, bounded by
      ``communication.ecu_list_persistence.detection_settle_timeout_seconds`` (one budget for both waits;
      a value of 0 is rejected as a configuration error).
    - It then writes one entry per connected gateway with the current ECU states and ``last_seen``
      timestamps, unless the entry is unchanged (see below). After a full broadcast discovery, database
      gateways that were not found and are not persisted yet are written without network address.
    - A persisted gateway whose connection was attempted and failed (direct reconnect and broadcast
      fallback, see :need:`arch~dt-deferred-initialization`) is also written, so
      the persisted state is the last known state: its network address, protocol version and ECU variants
      are kept, and its ECUs are written with their current state (``Disconnected``). Gateways that were not
      attempted (without network address) are not covered. If no gateway is
      connected at the time of the write, failed gateways are not written either: the vehicle is then
      presumably not awake, and demoting the whole topology would force a full variant detection on the next
      startup. As a consequence,
      ECUs of such a gateway are not restored AssumedOnline on the next startup and get a regular variant
      detection once their gateway is reachable again.
    - Every later detection run (explicit re-detection, an ECU reconnecting, a gateway announcing itself) and
      every gateway reported unreachable after a failed connect is persisted the same way as soon as no
      variant detection is queued or running. Writes are sequential; detection runs that finish during a write
      are combined into one further write.
    - Each gateway entry is compared with its entry in the store, not with an earlier write of the running
      process, so the first write after a restart is covered as well. A gateway entry is not written if it
      would only change ``last_seen`` timestamps, which are written back at shutdown instead (see
      :need:`arch~dt-ecu-list-persistence-shutdown`), to minimize writes to flash storage. If no entry
      changed, the write is skipped.
    - Disabling communication cancels a pending write.
    - Starting, restarting and cancelling the write task and the shutdown write-back are serialized by one
      lock, and every read-modify-write of the ``ecu-topology`` bucket runs to its commit even if its caller
      is dropped. No write task is started after the shutdown write-back.
    - Before each write, entries that are no longer in the loaded diagnostic databases are pruned: gateway
      entries whose logical address is not a physical database gateway, and ECUs no longer reached through
      their gateway. This is independent of the replace-per-gateway rule: an entry is pruned because it is missing from the
      databases, never because it was not seen by the last detection run. Nothing is written if nothing is
      pruned. Pruned entries are not restored by a later rollback of a runtime database update; the affected
      gateways are then detected again.

    **Read Timing**

    The persisted topology is read once, early during the Vehicle Data Loading Phase of
    :need:`arch~dt-startup-sequence`, before deciding whether to perform a full broadcast discovery or reuse
    the persisted data (relevant for ``init_mode = WhenNotPersisted``, or once triggered for
    ``OnDemand``/``Disabled``, see :need:`arch~dt-deferred-initialization`). This read is skipped entirely
    when ``communication.ecu_list_persistence.enabled`` is ``false``, in which case a full broadcast
    discovery unconditionally applies with no persisted topology available.

    When ECUs are registered from a persisted topology, an ECU whose persisted state was Online is
    registered in the AssumedOnline state (see :need:`arch~dt-ecu-states`), with its ``last_seen``
    timestamp initialized from the persisted value.

    The restored variant is not verified against the ECU. Any reply of the ECU, including a negative
    response, confirms it as Online with the restored variant, and only an explicit re-detection (PUT to
    the ECU endpoint, or a detection run, e.g. via ``networkreset``) detects its variant again. A variant
    change that happened while the CDA was not running therefore remains undetected; see the limitation in
    :need:`req~dt-ecu-list-persistence`.

    With ``init_mode = Always``, only the persisted ``last_seen`` timestamps are restored. ECU states and
    variants are not restored and the AssumedOnline state is not entered, because an assumed state would
    suppress the full detection run that ``Always`` guarantees at every startup.
    This follows :need:`req~dt-deferred-initialization`, which forbids using the persisted topology to skip any
    detection with ``Always``; it takes precedence over the AssumedOnline registration of
    :need:`req~dt-ecu-list-persistence`.


ECU List Persistence - Shutdown Update
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. arch:: ECU List Persistence - Shutdown Update
    :id: arch~dt-ecu-list-persistence-shutdown
    :links: dimpl~ecu-topology-persist-after-detection, itest~ecu-list-persistence-shutdown, test~ecu-list-persistence-shutdown-with-running-detection-writes-last-seen-only, test~ecu-list-persistence-shutdown-snapshot
    :status: draft

    The ``last_seen`` timestamp maintained per ECU (see :need:`arch~dt-ecu-states`) changes far more
    frequently than the rest of the persisted topology (on every successful diagnostic response), so it is
    not flushed to the Persistence API on every update.

    Instead, the in-memory ``last_seen`` values are written back to the ``ecu-topology`` bucket as part of
    the graceful shutdown sequence (triggered by the shared shutdown signal, see
    :need:`arch~dt-startup-sequence`), immediately before the persistence provider is closed. A final
    ``flush`` is issued after this update to guarantee durability. This shutdown write-back is skipped
    entirely when ``communication.ecu_list_persistence.enabled`` is ``false`` (see
    :need:`arch~dt-ecu-list-persistence`), since there is no persisted bucket to update in that
    configuration.

    Only ECUs contacted since their entry was last written are updated, and the ``last_seen`` update never
    creates entries. The write-back runs before communication is shut down (and so before the persistence
    provider is closed). Detection results that were not written yet (and no detection is still running)
    are written as a full snapshot in addition, so a detection run finished shortly before shutdown is not
    lost. The write is not time-bounded, like the other shutdown steps.

    .. uml::
        :caption: last_seen Persistence at Shutdown

        @startuml
        skinparam backgroundColor #FFFFFF
        skinparam sequenceArrowThickness 2

        participant "Shutdown Signal" as Signal
        participant "UDS Manager" as UDS
        participant "Persistence API" as Persist

        Signal -> UDS: shutdown requested
        alt communication.ecu_list_persistence.enabled = true
            UDS -> UDS: collect current last_seen\nper ECU
            UDS -> Persist: update last_seen in\nbucket "ecu-topology"
            UDS -> Persist: flush
            Persist --> UDS: durable
        else communication.ecu_list_persistence.enabled = false
            note over UDS: nothing to persist, skip
        end
        UDS --> Signal: shutdown complete
        @enduml

    **Rationale**

    Deferring the persistence of ``last_seen`` to shutdown avoids a flush (and associated flash write) on
    every diagnostic response, while still ensuring that, barring an unclean shutdown (e.g. power loss), the
    timestamp available after a restart reflects the most recent contact from the previous session.
    In case of an unclean shutdown, the persisted ``last_seen`` simply remains at its last successfully
    flushed value, which is still a valid (if slightly stale) lower bound on the actual last contact time.


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
