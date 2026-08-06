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

Diagnostic Tester
=================

This document defines the requirements for the diagnostic tester functionality of the Classic Diagnostic Adapter (CDA),
including startup behavior, ECU detection, variant detection, and state management.


Startup Behavior
----------------

Startup Sequence
^^^^^^^^^^^^^^^^

.. req:: Startup Sequence
    :id: req~dt-startup-sequence
    :links: arch~dt-startup-sequence
    :status: draft

    The CDA must execute startup in a defined sequence to ensure proper initialization of all components.

    The startup sequence must include the following phases in order:

    1. Load and validate configuration (from file, environment variables, and CLI arguments)
    2. Initialize logging and tracing subsystems
    3. Start HTTP server (in a starting/not-ready state)
    4. Load diagnostic databases (MDD files)
    5. Initialize DoIP gateway (unless deferred initialization is enabled)
    6. Create UDS manager and register ECUs
    7. Start variant detection (asynchronous, unless deferred)
    8. Register SOVD API routes
    9. Transition to ready state

    **Rationale**

    A well-defined startup sequence ensures predictable initialization behavior and allows external systems
    to monitor startup progress via health endpoints when health monitoring is enabled
    (see :need:`req~sovd-api-health-endpoint`).

    .. uml::
        :caption: CDA Startup Sequence

        @startuml
        skinparam backgroundColor #FFFFFF
        skinparam sequenceArrowThickness 2

        participant "CDA Main" as CDA
        participant "Configuration" as CFG
        participant "HTTP Server" as HTTP
        participant "Database Loader" as DB
        participant "DoIP Gateway" as DOIP
        participant "UDS Manager" as UDS

        CDA -> CFG: Load configuration
        activate CFG
        CFG --> CDA: Configuration validated
        deactivate CFG

        CDA -> CDA: Setup tracing/logging

        CDA -> HTTP: Launch server
        activate HTTP
        HTTP --> CDA: Server running (Starting state)
        note right: Health endpoint returns "Starting"\n(when health feature is enabled)

        CDA -> DB: Load MDD files
        activate DB
        note right: Parallel loading for performance
        DB --> CDA: Databases loaded
        deactivate DB

        alt Immediate communication initialization (default)
            CDA -> DOIP: Initialize gateway
            activate DOIP
            DOIP -> DOIP: Broadcast VIR
            DOIP -> DOIP: Collect VAM responses
            DOIP -> DOIP: Establish TCP connections
            DOIP --> CDA: Gateway ready
            deactivate DOIP

            CDA -> UDS: Create UDS manager
            activate UDS
            UDS -> UDS: Register ECUs
            UDS -> UDS: Start variant detection (async)
            UDS --> CDA: Manager ready
            deactivate UDS
        else Deferred communication until first request (on-demand)
            note over CDA,UDS: DoIP and ECU discovery
        else Deferred until explicit activation through api
            note over CDA,UDS: DoIP and ECU discovery
        end

        CDA -> HTTP: Register SOVD routes
        CDA -> HTTP: Transition to Ready state
        note right: Health endpoint returns "Up"\n(when health feature is enabled)
        deactivate HTTP
        @enduml



Database Loading
^^^^^^^^^^^^^^^^

.. req:: Database Loading
    :id: req~dt-database-loading
    :links: arch~dt-database-loading
    :status: draft

    The CDA must load diagnostic databases (MDD files) at startup.

    The following requirements apply:

    - MDD files must be discovered from a configurable directory path
    - Loading must support parallel execution to improve startup performance
    - Larger files should be prioritized in the loading queue to optimize parallel resource utilization
    - Duplicate ECU names with the same logical address must resolve to the database with the newest revision
    - Duplicate ECU names with different logical addresses must be marked as invalid and excluded
    - Loading failures for individual MDD files must not prevent other databases from loading
    - The total number of parallel loading tasks should be configurable

    **Rationale**

    Parallel database loading significantly reduces startup time in deployments with many ECU definitions.
    Graceful handling of duplicates and failures ensures robust operation in real-world environments where
    database files may be inconsistent or corrupted.


DoIP Gateway Initialization
^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. req:: DoIP Gateway Initialization
    :id: req~dt-doip-gateway-init
    :links: arch~dt-doip-gateway-init
    :status: draft

    The CDA must initialize the DoIP gateway to enable communication with vehicle ECUs.

    The initialization must include:

    - Broadcasting a Vehicle Identification Request (VIR) on the configured network interface
    - Collecting Vehicle Announcement Messages (VAM) from responding DoIP entities
    - Establishing TCP connections to discovered DoIP entities
    - Activating routing for diagnostic communication

    The following must be configurable:

    - Tester address
    - VIR broadcast parameters (source port range, net mask)
    - Fallback connection timeouts and retry behavior (if not defined through diagnostic description)

    **Rationale**

    DoIP gateway initialization establishes the communication path to vehicle ECUs. Configurable parameters
    allow adaptation to different network topologies and timing requirements.


Communication Initialization Mode
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. req:: Communication Initialization Mode
    :id: req~dt-deferred-initialization
    :links: arch~dt-deferred-initialization
    :status: draft

    The CDA must support a configurable ``[communication] init_mode``, controlling when DoIP gateway
    initialization and ECU discovery are allowed to begin, and, once begun, whether they always perform a
    full VIR/VAM broadcast discovery or reuse a previously persisted topology when available:

    - **Always** (default) -- DoIP gateway initialization and ECU discovery proceed immediately at
      startup, as defined in :need:`req~dt-startup-sequence`, always performing a full VIR/VAM broadcast
      discovery, regardless of whether a persisted topology exists (see
      :need:`req~dt-ecu-list-persistence`). If ECU list persistence is enabled, results are still persisted
      afterward (updating the stored topology, states, and ``last_seen`` timestamps), but the persisted
      topology is never used to skip or replace the broadcast discovery itself. This matches the CDA's
      established default behavior of always performing a full detection run at startup.
    - **WhenNotPersisted** -- DoIP gateway initialization and ECU discovery proceed immediately at startup,
      but a full VIR/VAM broadcast discovery is only performed when no persisted topology exists (e.g. on
      the first-ever startup, or any time after the persisted topology has been cleared, see
      :need:`req~dt-ecu-list-persistence`). Whenever a persisted topology exists, the CDA must instead
      attempt a direct (unicast) DoIP connection to each persisted gateway's known network address,
      skipping the broadcast VIR step; if a gateway cannot be reached at its persisted address, the CDA
      must fall back to broadcast-based discovery for that specific gateway, as defined in
      :need:`req~doip-vehicle-identification`, before marking its ECUs as Offline. This mode requires ECU
      list persistence to be enabled; it is equivalent to **Always** if persistence is disabled, since no
      persisted topology can ever exist in that configuration.
    - **OnDemand** -- DoIP gateway initialization and ECU discovery are postponed until one of the
      following triggers occurs:

      - **Explicit activation via the plugin API** -- a custom plugin may trigger the activation of ECU
        communication based on specific conditions (e.g., security unlock, session establishment). This
        triggers a full initialization of all gateways/ECUs at once, applying the same
        persisted-vs-broadcast behavior as **WhenNotPersisted** described above.
      - **First diagnostic request to a specific ECU** (on-demand initialization) -- if a persisted
        topology exists, this establishes a connection only to that ECU's gateway (direct reconnect, with
        broadcast fallback for that gateway alone, as in **WhenNotPersisted**); other persisted gateways
        remain unconnected until their own first request. If no persisted topology exists, no gateway
        network address is yet known, so this necessarily triggers a full, vehicle-wide VIR broadcast
        discovering and connecting all gateways at once, since VIR-based discovery is inherently
        broadcast-based and cannot be scoped to a single ECU.

    - **Disabled** -- DoIP gateway initialization and ECU discovery are postponed like in **OnDemand**
      mode, but neither the first-diagnostic-request nor the plugin-API trigger apply. Communication only
      starts once a detection run is explicitly initiated -- typically via the ``networkreset`` operation
      with ``trigger_detection=true`` (see :need:`req~plugin-vehicle-topology-reset-clear-persisted`), but
      a plugin or other custom code may equally initiate a detection run directly. Once triggered, this
      always initializes all gateways/ECUs at once (there is no per-ECU auto-trigger in this mode),
      applying the same persisted-vs-broadcast behavior as **WhenNotPersisted**.

    In both **OnDemand** and **Disabled** mode:

    - The HTTP server and SOVD API must be available before ECU communication is initialized
    - ECU endpoints must return an appropriate status indicating pending initialization
    - Once triggered, initialization must proceed as defined in :need:`req~dt-startup-sequence`, scoped to
      either a single gateway or all gateways as described above

    Once a detection run has completed (regardless of the triggering ``init_mode``), the resulting
    topology is persisted as described in :need:`req~dt-ecu-list-persistence`, so that subsequent startups
    may reuse it (unless ``init_mode`` is configured as **Always**).

    **Rationale**

    Configurable initialization supports use cases where the CDA must start quickly without immediately
    consuming network resources, or where ECU communication should only begin after explicit
    authorization (e.g., security unlock, session establishment, or plugin-controlled activation). The
    **Disabled** mode additionally supports deployments that require the CDA to be reachable via its SOVD
    API immediately, without generating any vehicle network traffic, until a detection run is explicitly
    initiated (typically via ``networkreset``, but potentially by a plugin or other custom code) -- as
    opposed to **OnDemand** mode, where the first diagnostic request to any ECU implicitly authorizes
    (at least that ECU's) communication.

    Distinguishing **Always** from **WhenNotPersisted** avoids leaving the choice between "always
    rebroadcast, but keep tracking state/``last_seen`` across restarts" and "skip rebroadcasting whenever
    possible" as an implicit side effect of whether a persisted topology happens to exist. Some deployments
    may want the freshness/robustness guarantees of always rebroadcasting while still benefiting from
    persisted state across restarts (e.g. ``last_seen`` history); others may prioritize minimizing startup
    time and vehicle network traffic once an initial topology has been established.

    **OnDemand** and **Disabled** always behave like **WhenNotPersisted** once triggered, rather than
    offering their own **Always**/**WhenNotPersisted** choice: these modes exist specifically to avoid
    vehicle network traffic until explicitly authorized, so unconditionally rebroadcasting even when a
    persisted topology is already available would be counter to their purpose. Within **OnDemand**, the two
    triggers intentionally differ in scope: the plugin-API trigger is a deliberate, whole-vehicle "start
    communication now" signal and must activate every gateway, matching what a plugin expects after an
    explicit authorization event; the first-diagnostic-request trigger, by contrast, is an implicit,
    incidental signal tied to one specific ECU, so it should only establish what is strictly needed to
    serve that request when a persisted topology makes this possible.


ECU Detection and Variant Detection
-----------------------------------

ECU Discovery
^^^^^^^^^^^^^

.. req:: ECU Discovery
    :id: req~dt-ecu-discovery
    :links: arch~dt-ecu-discovery
    :status: draft

    The CDA must discover and register ECUs based on loaded databases and DoIP gateway responses.

    The following requirements apply:

    - ECUs defined in MDD files must be registered with their logical addresses
    - ECUs must be associated with their corresponding DoIP gateway connections
    - ECUs sharing the same logical address (from different MDD files) must be tracked for variant detection
    - ECU availability must be determined based on successful DoIP entity responses
    - The list of available ECUs and their status must be queryable via the SOVD API

    **Rationale**

    ECU discovery establishes the mapping between diagnostic descriptions (MDD) and physical vehicle
    communication endpoints, enabling the SOVD API to expose the correct ECU capabilities.


Variant Detection
^^^^^^^^^^^^^^^^^

.. req:: Variant Detection
    :id: req~dt-variant-detection
    :links: arch~dt-variant-detection
    :status: draft

    The CDA must perform variant detection to identify the correct ECU variant from potentially multiple definitions.

    The following requirements apply:

    - Variant detection must be initiated automatically after startup (unless deferred initialization is enabled)
    - Variant detection requests must be sent as defined in the MDD variant detection configuration
    - Responses must be evaluated against variant patterns defined in the MDD
    - For ECUs with duplicate definitions (same logical address), variant detection must determine which definition applies
    - Fallback to base variant must be configurable when variant detection fails to find a matching pattern
    - Clients must be able to trigger variant detection explicitly via a PUT to the ECU endpoint
    - Variant detection must be retriggerable to handle ECU software changes

    **Rationale**

    ECUs may have multiple software variants with different diagnostic capabilities. Variant detection
    ensures the CDA exposes the correct services and parameters for the actually installed variant.


ECU States
^^^^^^^^^^

.. req:: ECU States
    :id: req~dt-ecu-states
    :links: arch~dt-ecu-states
    :status: draft

    ECUs must maintain defined states throughout their lifecycle to reflect their current availability and detection status.

    The following states must be supported:

    - **NotTested**: ECU is registered but variant detection has not been performed
    - **Online**: ECU is reachable and variant has been successfully detected
    - **AssumedOnline**: ECU was known to be Online according to a persisted ECU list (see
      :need:`req~dt-ecu-list-persistence`), but has not yet been contacted in the current session
    - **NoVariantDetected**: ECU is reachable but no matching variant pattern was found (using fallback if enabled)
    - **Duplicate**: ECU shares its logical address with another ECU that was identified as the correct variant; this ECU's database is unloaded
    - **Offline**: ECU was tested but could not be reached; the ECU has never been successfully online since registration or last re-detection
    - **Disconnected**: ECU was previously online but communication has been lost

    State transitions must occur as follows:

    - Registration --> NotTested
    - Registration from a persisted ECU list, for an ECU last known to be Online --> AssumedOnline
    - NotTested --> Online (successful variant detection)
    - NotTested --> NoVariantDetected (detection failed, fallback enabled)
    - NotTested --> Duplicate (another ECU with same logical address detected as correct variant)
    - NotTested --> Offline (variant detection attempted but ECU unreachable)
    - Offline --> NotTested (reconnection attempt or explicit re-detection requested)
    - Online --> Disconnected (connection lost)
    - Online --> NotTested (explicit re-detection requested)
    - AssumedOnline --> Online (successfully contacted, e.g. first diagnostic request or re-detection)
    - AssumedOnline --> Disconnected (contact attempted but ECU unreachable)
    - AssumedOnline --> NotTested (explicit re-detection requested)
    - NoVariantDetected --> Online (successful re-detection)
    - NoVariantDetected --> Duplicate (another ECU with same logical address detected as correct variant)
    - NoVariantDetected --> Disconnected (connection lost)
    - Duplicate --> NotTested (explicit re-detection requested)
    - Disconnected --> NotTested (reconnection attempt)

    The current ECU state must be queryable via the SOVD API. Externally, the AssumedOnline state must be
    reported as ``Online``, so that clients are not required to be aware of this internal distinction (see
    :need:`arch~sovd-api-components-entity-collection`).

    In addition to the state, the SOVD API must expose a ``last_seen`` timestamp for each ECU, indicating
    the time of the last successful diagnostic contact with that ECU. This timestamp must be preserved
    across CDA restarts by persisting it together with the ECU list (see :need:`req~dt-ecu-list-persistence`
    and :need:`req~dt-ecu-list-persistence-shutdown`).

    .. uml::
        :caption: ECU State Chart

        @startuml
        skinparam backgroundColor #FFFFFF
        skinparam stateArrowThickness 2

        [*] --> NotTested : ECU registered
        [*] --> AssumedOnline : ECU registered from\npersisted list (was Online)

        state NotTested {
        }

        state Online {
        }

        state AssumedOnline {
        }

        state NoVariantDetected {
        }

        state Duplicate {
        }

        state Offline {
        }

        state Disconnected {
        }

        NotTested --> Online : Variant detected\nsuccessfully
        NotTested --> NoVariantDetected : Detection failed\n(fallback enabled)
        NotTested --> Duplicate : Another ECU with same\nlogical address is correct
        NotTested --> Offline : Variant detection attempted\nbut ECU unreachable

        Offline --> NotTested : Reconnection attempt /\nRe-detection requested

        Online --> Disconnected : Connection lost
        Online --> NotTested : Re-detection\nrequested

        AssumedOnline --> Online : Successfully\ncontacted
        AssumedOnline --> Disconnected : Contact attempted\nbut unreachable
        AssumedOnline --> NotTested : Re-detection\nrequested

        NoVariantDetected --> Online : Variant\nre-detected
        NoVariantDetected --> Duplicate : Another ECU with same\nlogical address is correct
        NoVariantDetected --> Disconnected : Connection lost

        Duplicate --> NotTested : Re-detection\nrequested

        Disconnected --> NotTested : Reconnection\nattempt
        @enduml

    **Rationale**

    Explicit state management provides clients with visibility into ECU availability and allows
    appropriate error handling based on the current state. The AssumedOnline state allows the CDA to
    immediately report ECUs as reachable based on prior knowledge (e.g. in
    :need:`req~dt-deferred-initialization`'s **OnDemand** mode, before its per-ECU trigger has fired) while
    still internally tracking that this assumption has not yet been confirmed in the current session. The
    ``last_seen`` timestamp gives clients visibility into how stale that assumption might be, which is
    especially relevant while an ECU remains in the AssumedOnline state.


ECU List Persistence
--------------------

ECU List Persistence
^^^^^^^^^^^^^^^^^^^^

.. req:: ECU List Persistence
    :id: req~dt-ecu-list-persistence
    :links: arch~dt-ecu-list-persistence
    :status: draft

    The CDA must be able to persist the detected ECU/gateway topology, so that it does not necessarily need
    to re-run full ECU detection (VIR/VAM discovery and variant detection) on every startup.

    This is a core diagnostic-tester capability, usable purely through ``[communication]`` configuration
    (``ecu_list_persistence.enabled``, ``init_mode``); it does not require the Vehicle Topology Plugin (see
    :need:`req~plugin-vehicle-topology`) to be loaded. For example, with ``ecu_list_persistence.enabled =
    true`` and ``init_mode = WhenNotPersisted`` (see :need:`req~dt-deferred-initialization`), the
    first-ever startup (or any startup without a persisted topology) performs a full detection run and
    persists its results; every subsequent startup then reconnects directly to the persisted gateways
    without needing a full VIR/VAM broadcast again, and without any plugin involvement. When the Vehicle
    Topology Plugin is loaded, it additionally exposes the ``networkreset`` SOVD operation to explicitly
    (re-)trigger detection or clear the persisted topology at runtime (see
    :need:`req~plugin-vehicle-topology-reset-clear-persisted`).

    This capability must be configurable via an ``enabled`` flag, defaulting to ``false``. With persistence
    disabled, no persisted topology can ever exist, so the default ``init_mode = Always`` (see
    :need:`req~dt-deferred-initialization`) always performs a full VIR/VAM broadcast detection at every
    startup -- matching CDA behavior prior to the introduction of this feature. When disabled (the
    default):

    - The persisted topology must not be read at startup, and must not be written after a detection run
      or at shutdown (see :need:`req~dt-ecu-list-persistence-shutdown`).
    - The CDA must behave exactly as if no persisted topology exists, i.e. ``init_mode = WhenNotPersisted``
      (see :need:`req~dt-deferred-initialization`) becomes equivalent to ``Always``, and the AssumedOnline
      state (see :need:`req~dt-ecu-states`) can never occur.

    The following requirements apply when persistence is enabled:

    - The persisted topology must include, per gateway: its network address and logical address, and the
      ECUs reachable through it (logical address, name, last known variant, last known state, and
      ``last_seen`` timestamp, see :need:`req~dt-ecu-states`)
    - Persisted data must be written using the persistence API (see :need:`req~system-persistence-api`)
      after any detection run completes, regardless of what triggered it -- the initial startup detection
      alone is sufficient; if the Vehicle Topology Plugin is loaded, a detection run triggered via its
      ``networkreset`` operation (see :need:`req~plugin-vehicle-topology-reset`) is persisted identically.
      This applies for both ``init_mode = Always`` and ``init_mode = WhenNotPersisted`` (see
      :need:`req~dt-deferred-initialization`); the persisted data is only ever used to skip rebroadcasting
      when ``init_mode = WhenNotPersisted`` (or, once triggered, for ``OnDemand``/``Disabled``).
    - On startup, the CDA must check whether a persisted topology exists and, combined with the configured
      ``init_mode``, select the applicable startup behavior (see :need:`req~dt-deferred-initialization`)
    - When an ECU is loaded from a persisted topology with a last known state of Online, it must be
      registered in the AssumedOnline state (see :need:`req~dt-ecu-states`) rather than NotTested
    - When the Vehicle Topology Plugin is loaded, it must be possible to clear the persisted topology
      independently of triggering a new detection run (see
      :need:`req~plugin-vehicle-topology-reset-clear-persisted`); this has no observable effect when
      persistence is disabled, since there is nothing stored to clear. Without the plugin loaded, no
      runtime clearing mechanism is required by this specification.

    **Rationale**

    Full ECU detection involves broadcasting a VIR, waiting for VAM responses, and running variant
    detection for every discovered ECU, which can take a noticeable amount of time in vehicles with many
    ECUs. Persisting the previously detected topology allows the CDA to skip or defer this work on
    subsequent startups, improving startup time and reducing unnecessary vehicle network traffic. This is
    an opt-in capability (disabled by default), preserving the CDA's established default behavior of always
    performing a full VIR/VAM broadcast detection at startup when left unconfigured (see the **Always** vs
    **WhenNotPersisted** distinction in :need:`req~dt-deferred-initialization`).


ECU List Persistence - Shutdown Update
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. req:: ECU List Persistence - Shutdown Update
    :id: req~dt-ecu-list-persistence-shutdown
    :links: arch~dt-ecu-list-persistence-shutdown
    :status: draft

    In addition to persisting the topology after a detection run (see
    :need:`req~dt-ecu-list-persistence`), the CDA must, as part of a graceful shutdown, update the persisted
    ``last_seen`` timestamp of each ECU that was contacted since the last time the topology was persisted,
    so that this information survives a restart. This shutdown update must be skipped entirely when ECU
    list persistence is disabled (see :need:`req~dt-ecu-list-persistence`).

    **Rationale**

    The ``last_seen`` timestamp is updated frequently during normal operation (on every successful
    diagnostic response), which is not practical to persist and flush on every single occurrence without
    impacting performance and flash wear. Persisting the latest value at shutdown ensures the timestamp
    surviving a restart is reasonably up to date, without requiring a flush on every diagnostic response.


Error Handling
--------------

.. req:: Startup Error Handling
    :id: req~dt-error-handling
    :links: arch~dt-error-handling
    :status: draft

    The CDA must handle startup failures gracefully to maximize availability.

    The following error handling behaviors must be supported:

    - **No databases loaded**: Behavior must be configurable (exit with error or continue with empty ECU list)
    - **Individual database load failure**: Must not prevent other databases from loading; failures must be logged
    - **DoIP connection failure**: Must not prevent startup for other DoIP entities; affected ECUs must be marked as Offline
    - **Variant detection failure**: Must not prevent ECU registration; ECU must remain in NotTested, Offline, or NoVariantDetected state
    - **Configuration validation failure**: Must prevent startup with a clear error message

    All errors must be logged with sufficient detail for troubleshooting.

    **Rationale**

    Graceful degradation ensures the CDA remains partially operational even when some components fail,
    which is critical for diagnostic scenarios where partial functionality may still be useful.


.. todo:: mapping mdd to parameters

.. todo:: state charts and transitions

.. todo:: security?

.. todo:: logging and tracing (general?)

.. todo:: error handling
