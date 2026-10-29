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

Vehicle Topology Plugin
-----------------------

.. arch:: Vehicle Topology Plugin - Retrieval
    :id: arch~plugin-vehicle-topology-retrieval
    :links: dimpl~plugin-vehicle-topology-retrieval-protection, dimpl~networkstructure-last-seen, testset~plugin-vehicle-topology-retrieval
    :status: draft

    The vehicle topology plugin provides the SOVD API with information about the network structure of the
    vehicle, exposed via the following endpoint:

    .. list-table:: Vehicle Topology Endpoint
       :header-rows: 1

       * - Method
         - Path
         - Description

       * - GET
         - ``/apps/sovd2uds/data/networkstructure``
         - Returns the network structure of the vehicle, consisting of functional groups and gateways.

    The response data consists of:

    - **Functional groups** -- a qualifier, and the list of ECUs belonging to that functional group.
    - **Gateways** -- a name, network address, logical address, and the list of ECUs reachable through
      that gateway.
    - **ECUs** -- a qualifier (name), current variant/connectivity state (with the internal AssumedOnline
      state, see :need:`arch~dt-ecu-states`, reported as ``Online``), a ``last_seen`` timestamp, logical
      address, and logical link name, for each ECU listed under a functional group or a gateway.
      The timestamp as RFC 3339 in UTC with second precision, and omitted for an ECU that was never contacted.

    While a ``networkreset`` execution is in progress, and until a rediscovery it started has finished, this
    endpoint must respond with ``409 Conflict``, to avoid returning stale or partially updated topology data
    during the reset.

.. arch:: Vehicle Topology Plugin - Reset
    :id: arch~plugin-vehicle-topology-reset
    :links: dimpl~plugin-vehicle-topology-reset, dimpl~plugin-vehicle-topology-reset-http, testset~plugin-vehicle-topology-reset
    :status: draft

    The plugin must provide a ``networkreset`` operation, following the standard SOVD operations semantics
    used elsewhere in the CDA (e.g. ``runtimefilesupdate``):

    .. list-table:: Vehicle Topology Reset Operation
       :header-rows: 1

       * - Method
         - Path
         - Description

       * - GET
         - ``/apps/sovd2uds/operations``
         - Includes ``networkreset`` in the list of available operations.

       * - GET
         - ``/apps/sovd2uds/operations/networkreset``
         - Returns the operation description. With ``include-schema=true``, includes the response
           schema.

       * - GET
         - ``/apps/sovd2uds/operations/networkreset/docs``
         - Returns the online capability description, a self-contained OpenAPI document describing
           execution, status and termination, including parameter defaults.

       * - GET
         - ``/apps/sovd2uds/operations/networkreset/executions``
         - Returns the list of current execution identifiers. Always contains at most one entry.

       * - POST
         - ``/apps/sovd2uds/operations/networkreset/executions``
         - Starts a new execution of the network reset. Returns 202 Accepted with the execution ID and
           its URI in ``Location``. Requires the caller's independently acquired, unexpired exclusive
           vehicle lock, like ``doip-connect-ecu``: ``409`` (``lock-required``) without it, ``409``
           (``lock-broken``) if it was preempted, ``423`` if another client holds the vehicle lock.
           In-progress diagnostic operations, including those under component or functional group locks,
           or a running execution prevent the reset from starting (``409`` with ``Retry-After``); locks
           held by the vehicle lock owner do not themselves prevent it.

       * - GET
         - ``/apps/sovd2uds/operations/networkreset/executions/{id}``
         - Returns the status and current capability (``execute``) of a specific execution. Failures
           include a standard ``error`` array with path ``/``. With ``include-schema=true``, includes
           the response schema. An unknown ID returns ``404`` with an SOVD error body.

       * - DELETE
         - ``/apps/sovd2uds/operations/networkreset/executions/{id}``
         - Terminates the execution (if possible, and not yet stopped) and removes it. Returns 204 No Content.
           Requires the caller's exclusive vehicle lock (``409``/``423`` otherwise, as for POST). An
           unknown ID returns ``404`` with an SOVD error body.

    A reset with detection causes the plugin to re-discover and re-report the vehicle's network structure,
    so that subsequent reads of ``GET /apps/sovd2uds/data/networkstructure`` reflect the up-to-date
    topology once the execution has completed.

    The vehicle lock is checked again after admission. If it was lost or changed owner during admission,
    the execution is stopped and removed and the request returns the lock error of the current lock state
    (``409`` ``lock-broken`` after a takeover by priority, ``409`` with the vendor code ``lock-required``
    without a lock, ``423`` when another client holds it), noting that steps already started may not be
    reversible, so the persisted topology may already have been cleared.

    .. uml::

        @startuml
        actor Client
        participant "Vehicle Lock" as lock
        participant "Vehicle Topology Plugin" as plugin

        == Precondition (acquired independently, before reset is called) ==
        Client -> lock : acquire exclusive vehicle lock
        lock --> Client : lock acquired

        == Reset ==
        Client -> plugin : POST /apps/sovd2uds/operations/networkreset/executions
        plugin -> lock : check caller holds exclusive vehicle lock
        alt lock not held by caller
            lock --> plugin : not held
            plugin --> Client : error (lock required)
        else lock held by caller
            lock --> plugin : held
            plugin -> plugin : start reset
            plugin --> Client : 202 Accepted (execution id, status: running)
            Client -> plugin : GET .../executions/{id}
            plugin --> Client : 200 OK (status: running)
            plugin -> plugin : reset finished
            Client -> plugin : GET .../executions/{id}
            plugin --> Client : 200 OK (status: completed)
            Client -> plugin : DELETE .../executions/{id}
            plugin --> Client : 204 No Content
        end

        == Postcondition (released independently, after reset completes) ==
        Client -> lock : release exclusive vehicle lock
        @enduml


.. arch:: Vehicle Topology Plugin - Reset with Persisted List Control
    :id: arch~plugin-vehicle-topology-reset-persistence
    :links: dimpl~plugin-vehicle-topology-reset, testset~plugin-vehicle-topology-reset-persistence
    :status: draft

    The ``parameters`` object in the ``POST /apps/sovd2uds/operations/networkreset/executions`` request
    body accepts two independent, optional boolean fields, both defaulting to ``true``:

    .. list-table:: networkreset Request Body
       :header-rows: 1

       * - Field
         - Default
         - Description
       * - ``clear_persisted``
         - ``true``
         - Clear the persisted ECU topology (see :need:`arch~dt-ecu-list-persistence`) as part of this
           execution.
       * - ``trigger_detection``
         - ``true``
         - Perform a live ECU detection run (VIR/VAM discovery and variant detection) as part of this
           execution.

    Without ``Content-Type`` an empty or whitespace only body is treated as no body and the defaults
    apply; a non-empty body without ``Content-Type`` is rejected with ``400``, so a body that is not
    understood never selects the destructive defaults. With a JSON ``Content-Type`` the body is parsed;
    omitted fields use the defaults; unknown fields, invalid JSON and wrong types are rejected with
    ``400``. An empty body with a JSON ``Content-Type``, and any other ``Content-Type``, are rejected with
    ``400`` before execution. The standard SOVD field ``timeout`` (at least 1 second, ``0`` is
    rejected with ``400``) stops a running execution when it elapses (see
    :need:`arch~plugin-vehicle-topology-reset`); a timeout too large to represent as a deadline is
    rejected with ``400``. ``proximity_response`` is accepted and ignored. The body is checked
    completely before the vehicle lock, including the flag combination and the timeout, so a caller
    without the lock gets ``400`` and not ``409`` for an invalid body; the plugin repeats the flag and
    timeout checks on admission.

    Handling of the four flag combinations:

    - ``clear_persisted=true``, ``trigger_detection=true``: the persisted "ecu-topology" bucket is cleared
      first, then a full detection run is performed and its results are persisted -- functionally
      equivalent to the previously specified ``networkreset`` behavior.
    - ``clear_persisted=true``, ``trigger_detection=false``: the persisted "ecu-topology" bucket is cleared
      and no detection is performed; no vehicle communication occurs. Subsequent CDA behavior (until the
      next ``networkreset`` or restart) follows :need:`arch~dt-deferred-initialization` as if no persisted
      topology had ever existed.
    - ``clear_persisted=false``, ``trigger_detection=true``: a detection run is performed and its results
      are written per-gateway into the existing persisted topology; entries for gateways/ECUs not observed
      during this run are left unchanged in the persisted bucket.
    - ``clear_persisted=false``, ``trigger_detection=false``: rejected with ``400``, as this
      combination would perform no observable action.

    When ``communication.ecu_list_persistence.enabled`` is ``false`` (see :need:`arch~dt-ecu-list-persistence`), there is
    no ``ecu-topology`` bucket to operate on (also when DoIP is disabled, which persistence requires);
    ``clear_persisted`` is then a no-op regardless of its value,
    and only ``trigger_detection`` has an observable effect (running or skipping a live detection).

    **Clearing**

    Clearing cancels a pending topology write first, so it cannot bring the cleared data back. The next
    transport start runs a full broadcast discovery, unless a later detection has been persisted again meanwhile
    (e.g. by a reconnect that resumed after the clear). ECUs still assumed online from the cleared topology (not
    contacted since startup) are reset to NotTested, so they are no longer reported Online, as if the topology
    had never been persisted. The persist task restarted after the clear does not write the results the clear
    removed; later detection runs are persisted again as usual.

    Every execution takes the exclusive disable lease first, which stops communication and guarantees that no
    diagnostic operation is in progress (``409`` otherwise, see :need:`arch~plugin-vehicle-topology-reset`).
    The clear therefore runs with the transport down: no diagnostic request, gateway connect or discovery can
    overlap it. A clear-only execution then ends the lease depending on ``init_mode``, so communication
    continues as if no topology had ever been persisted:

    - **Always** / **WhenNotPersisted**: the lease is released and communication returns to its state before
      the reset. If it was up, it is brought up again right away with a full broadcast discovery.
    - **OnDemand** / **Disabled**: the lease is finished without resuming. Communication stays down until the
      trigger of the respective mode (see :need:`arch~dt-deferred-initialization`) brings it up.

    A ``DELETE`` or an expired ``timeout`` during the clear of a clear-only execution takes effect once the
    clear has finished: the lease ends as above and the execution reports ``stopped``.

    **Detection**

    A detection run first takes the exclusive disable lease, which stops communication and guarantees that
    no diagnostic operation is in progress. It then resets all ECU states (keeping ``last_seen``), plans a full
    broadcast discovery, and hands the lease over directly to a full activation with variant detection
    (``DisableGuard::release_with_detection``, through the communication plugin's ``release_with_detection``
    hook, which the default plugin forwards), in every ``init_mode`` (including ``Disabled``) and whatever
    the automatic detection policy. Exclusivity ends only as that activation starts, so nothing else can
    bring communication up in between and no diagnostic guard can hold off the detection: communication comes
    up exactly once, with one broadcast and one detection run. The execution
    completes when the discovery and variant detection have settled and, with persistence enabled, the result
    has been persisted.

    Completion is tied to the new discovery generation, not to an arbitrary storage write. If the requested
    run does not settle within the rediscovery timeout, or writing its result fails, the execution reports
    ``failed``. On CAN-only configurations, no DoIP gateway discovery is awaited: completion follows
    the current UDS detector.

    The rediscovery timeout (``communication.network_reset_rediscovery_timeout_seconds``, default 60 seconds,
    must be greater than 0) applies twice. It first bounds the hand-over to the activation, including its
    variant detection, and starts right before the lease is handed over. It then bounds the settling of the
    rediscovery: the persist task
    publishes its verdict on the new discovery generation (settled or persist failed) and the network reset
    waits for that verdict, which nothing else bounds. Without persistence the network reset waits for the
    discovery and detection itself, bounded by the same timeout. The SOVD ``timeout`` of an execution starts
    when it is admitted, so it also covers waiting for the exclusive disable lease.
    If the clear fails, the lease is given back (communication returns to its previous state) and the
    execution fails. ``DELETE`` interrupts both phases; steps already started (clearing, the lifecycle
    worker's enable) complete in the background. A ``DELETE`` or expired timeout during the clear gives the
    lease back before the ECU states are reset; once they are reset, the execution always hands the lease over
    to the rediscovery, which alone restores a consistent state. A rediscovery started by the
    execution always runs to its end, also after a ``DELETE`` or an expired timeout, and keeps the network
    structure protected (``409``) until it has settled. A rediscovery that has not returned after four times
    the rediscovery timeout is given up, so it cannot keep the network structure protected forever. If the
    rediscovery fails, communication is usually in a failed state (unless the CDA is shutting down) and
    may not be fully available; a new ``networkreset`` with ``trigger_detection=true`` brings it up in
    every ``init_mode``, also from a failed communication state, whose lease tears the transport down first.
    If the communication plugin refuses the hand-over, the execution reports the refusal without that
    retry hint, since a new ``networkreset`` would be refused again. A failed execution carries a typed
    reason (``NetworkResetFailure``), reported as the execution's error message.

    .. uml::
        :caption: networkreset with Persisted List Control

        @startuml
        actor Client
        participant "Vehicle Topology Plugin" as plugin
        participant "Persistence API\n(ecu-topology bucket)" as Persist
        participant "DoIP/UDS Detection" as Detect

        Client -> plugin : POST .../executions\n{parameters: {clear_persisted, trigger_detection}}
        plugin -> plugin : validate flag combination
        alt clear_persisted = false and trigger_detection = false
            plugin --> Client : error (no-op combination rejected)
        else valid combination
            plugin --> Client : 202 Accepted (execution id)
            opt clear_persisted = true
                plugin -> Persist : clear bucket "ecu-topology"
            end
            opt trigger_detection = true
                plugin -> Detect : run VIR/VAM discovery + variant detection
                Detect --> plugin : detection results
                plugin -> Persist : set bucket "ecu-topology"
                plugin -> Persist : flush
            end
            Client -> plugin : GET .../executions/{id}
            plugin --> Client : 200 OK (status: completed)
        end
        @enduml


.. arch:: Vehicle Topology Plugin - Connect ECU
    :id: arch~plugin-vehicle-topology-connect-ecu
    :status: draft
    :links: dimpl~plugin-vehicle-topology-connect-ecu

    The plugin provides a ``doip-connect-ecu`` operation to connect an ECU directly to an IP address,
    without waiting for it to be discovered via VIR/VAM. It follows the standard SOVD operations
    semantics, with a synchronous execution:

    .. list-table:: Vehicle Topology Connect ECU Operation
       :header-rows: 1

       * - Method
         - Path
         - Description

       * - GET
         - ``/apps/sovd2uds/operations/doip-connect-ecu``
         - Describes the operation (its collection entry, with a synchronous execution; with
           ``include-schema=true`` also the response schema).

       * - GET
         - ``/apps/sovd2uds/operations/doip-connect-ecu/docs``
         - Returns the online capability description, a self-contained OpenAPI document describing
           the synchronous ``POST`` of an execution with its request and response parameters.

       * - POST
         - ``/apps/sovd2uds/operations/doip-connect-ecu/executions``
         - Connects the given ECU to the given IP address. Returns 200 OK once the connection has been
           established.

    The request body contains the following ``parameters``:

    .. list-table:: doip-connect-ecu Request Body
       :header-rows: 1

       * - Field
         - Default
         - Description
       * - ``ecu``
         - --
         - Identifier of the ECU to connect, as used in ``/components/{ecu}``.
       * - ``ip``
         - --
         - IP address of the DoIP entity of the ECU.
       * - ``protocol_version``
         - ``0x02``
         - Raw DoIP protocol version byte (``0x02``: ISO 13400-2:2012).

    The operation is only offered in builds with the ``doip-direct-connect`` feature, and if
    ``doip.direct_connect_enabled`` is set, which is not the case by default. If it is set in a build
    without the feature, the CDA logs an error and leaves the operation unavailable. Calling it
    requires authentication and the vehicle lock, as it changes which ECUs are connected. Only
    ECUs that are a gateway (their
    logical address is also their gateway address) can be connected, other ECUs are rejected with
    ``400 Bad Request``.

    The operation only replaces the trigger of the connection: the logical addresses are taken from the
    diagnostic database, and routing activation, TLS upgrade and ECU identification are performed as for a
    gateway that was discovered via VIR/VAM.

    The mechanism can never change an existing connection. If the ECU already has a connection, the request
    is rejected with ``409 Conflict``, even if that connection is not active at the time of the call (e.g.
    because the gateway is offline). The same applies if a connection for the ECU is being established at
    that moment, be it by another direct connect or by VIR/VAM handling: only one connection attempt runs
    per gateway at a time. A VAM that arrives for a directly connected gateway does not replace the
    connection, a warning is logged if it comes from a different address. A direct connection is not
    persisted, it is lost when the transport is disabled or the CDA is restarted.

    The connection is established by a task of its own, so that a client that gives up on the request
    (disconnect, HTTP timeout) cannot leave it half done. It is limited to the connect timeout plus the
    routing activation timeout of the ECU plus a fixed margin, which covers the TLS handshake, and is
    cancelled when communication is disabled. It does not hold the lifecycle lock of the transport while
    connecting, so that disabling communication and shutdown do not have to wait for it.

    The SOVD layer only has access to a connect-only capability of the transport, not to its lifecycle
    control.

    The operation is preliminary: it is implemented in the SOVD layer for now and expected to be taken over
    by the vehicle topology plugin.
