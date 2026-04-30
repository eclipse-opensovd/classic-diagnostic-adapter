.. SPDX-License-Identifier: Apache-2.0
.. SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
..
.. See the NOTICE file(s) distributed with this work for additional
.. information regarding copyright ownership.
..
.. This program and the accompanying materials are made available under the
.. terms of the Apache License Version 2.0 which is available at
.. https://www.apache.org/licenses/LICENSE-2.0

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


Deferred Initialization
^^^^^^^^^^^^^^^^^^^^^^^

.. req:: Deferred Initialization
    :id: req~dt-deferred-initialization
    :links: arch~dt-deferred-initialization
    :status: draft

    The CDA must support deferred initialization of ECU discovery and communication.

    When deferred initialization is enabled:

    - DoIP gateway initialization must be postponed until one of the following triggers:

      - First diagnostic request to any ECU (on-demand initialization)
      - Explicit activation via the plugin API
      - The plugin API may be used by a custom plugin to trigger the activation of ECU communication based on specific conditions

    - The HTTP server and SOVD API must be available before ECU communication is initialized
    - ECU endpoints must return an appropriate status indicating pending initialization
    - Once triggered, initialization must proceed as defined in :need:`req~dt-startup-sequence`

    **Rationale**

    Deferred initialization supports use cases where the CDA must start quickly without immediately
    consuming network resources, or where ECU communication should only begin after explicit
    authorization (e.g., security unlock, session establishment, or plugin-controlled activation).
    This is particularly useful in diagnostic scenarios where the tester must be fully operational
    before any vehicle communication occurs.


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
    - Clients must be able to trigger variant detection explicitly via a POST to the ECU endpoint
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
    - **NoVariantDetected**: ECU is reachable but no matching variant pattern was found (using fallback if enabled)
    - **Duplicate**: ECU shares its logical address with another ECU that was identified as the correct variant; this ECU's database is unloaded
    - **Offline**: ECU was tested but could not be reached; the ECU has never been successfully online since registration or last re-detection
    - **Disconnected**: ECU was previously online but communication has been lost

    State transitions must occur as follows:

    - Registration --> NotTested
    - NotTested --> Online (successful variant detection)
    - NotTested --> NoVariantDetected (detection failed, fallback enabled)
    - NotTested --> Duplicate (another ECU with same logical address detected as correct variant)
    - NotTested --> Offline (variant detection attempted but ECU unreachable)
    - Offline --> NotTested (reconnection attempt or explicit re-detection requested)
    - Online --> Disconnected (connection lost)
    - Online --> NotTested (explicit re-detection requested)
    - NoVariantDetected --> Online (successful re-detection)
    - NoVariantDetected --> Duplicate (another ECU with same logical address detected as correct variant)
    - NoVariantDetected --> Disconnected (connection lost)
    - Duplicate --> NotTested (explicit re-detection requested)
    - Disconnected --> NotTested (reconnection attempt)

    The current ECU state must be queryable via the SOVD API.

    .. uml::
        :caption: ECU State Chart

        @startuml
        skinparam backgroundColor #FFFFFF
        skinparam stateArrowThickness 2

        [*] --> NotTested : ECU registered

        state NotTested {
        }

        state Online {
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

        NoVariantDetected --> Online : Variant\nre-detected
        NoVariantDetected --> Duplicate : Another ECU with same\nlogical address is correct
        NoVariantDetected --> Disconnected : Connection lost

        Duplicate --> NotTested : Re-detection\nrequested

        Disconnected --> NotTested : Reconnection\nattempt
        @enduml

    **Rationale**

    Explicit state management provides clients with visibility into ECU availability and allows
    appropriate error handling based on the current state.


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
