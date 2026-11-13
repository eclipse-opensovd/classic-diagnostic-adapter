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

    While a ``networkreset`` execution is in progress, this endpoint must respond with ``409 Conflict``, to
    avoid returning stale or partially updated topology data during the reset.

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
         - Returns the operation description. With ``include-schema=true``, includes a capability
           PathItem describing execution, status and termination, including parameter defaults.

       * - GET
         - ``/apps/sovd2uds/operations/networkreset/executions``
         - Returns the list of current execution identifiers. Always contains at most one entry.

       * - POST
         - ``/apps/sovd2uds/operations/networkreset/executions``
         - Starts a new execution of the network reset. Returns 202 Accepted with the execution ID.

       * - GET
         - ``/apps/sovd2uds/operations/networkreset/executions/{id}``
         - Returns the status and current capability (``execute``) of a specific execution. Failures
           include a standard ``error`` array with path ``/``. With ``include-schema=true``, includes
           the response schema.

       * - DELETE
         - ``/apps/sovd2uds/operations/networkreset/executions/{id}``
         - Terminates the execution (if possible, and not yet stopped) and removes it. Returns 204 No Content.
           Requires the caller's exclusive vehicle lock (``403`` otherwise).

    Triggering a reset must cause the plugin to start re-discovering/re-reporting the vehicle's network
    structure, so that subsequent reads of ``GET /apps/sovd2uds/data/networkstructure`` reflect the
    up-to-date topology once the execution has completed.

    **Realization**

    - The plugin is a separate crate (``cda-plugin-vehicle-topology``) and can be replaced via
      ``Setup::with_vehicle_topology_plugin``. It works on narrow interfaces only: the persisted topology and
      ECU states, a rediscovery trigger handled by the communication plugin
      (``DetectionCause::TopologyRediscovery``), the exclusive transport disable lease and the exclusive quiesce
      lease, the lock state, and the HTTP protection registry.
    - The ``409 Conflict`` of the network structure endpoint is an HTTP protection installed for the duration
      of the execution, limited to ``GET /apps/sovd2uds/data/networkstructure``.
    - All preconditions are checked before ``202 Accepted`` is returned: a running execution or ECU or
      functional group locks are rejected with ``409``, and a missing or foreign vehicle lock with ``403``.
      For an execution that triggers detection, the exclusive transport disable lease is acquired up front;
      a clear-only execution acquires the exclusive quiesce lease instead. If diagnostic operations are using
      communication, the request is rejected with ``409``.
    - ``DELETE`` on a running execution cancels the wait for the rediscovery to come up and to settle; steps
      already started (clearing, enabling communication) complete. A ``DELETE`` before the exclusive lease
      is finished releases it, so communication returns to what it was. The execution is removed by its own task once it has
      finished, and ``DELETE`` returns ``204`` only after that. Concurrent ``DELETE`` requests wait for the
      same execution, and a ``POST`` is rejected with ``409`` until the execution is gone. A panic inside the
      execution is reported as a failed execution and releases the protection.
      A stopped execution is removed by its ``DELETE``, so after a ``DELETE`` ``stopped`` is not
      observable over HTTP; it is logged.
    - The standard SOVD execution ``timeout`` (seconds, optional) stops an execution that is still running
      when it elapses, counted from the ``POST``. It interrupts the same steps as a ``DELETE``, but the
      execution is kept with status ``stopped`` until it is deleted, and a new ``POST`` is accepted. Without
      ``timeout`` the execution has no timeout of its own; the rediscovery timeout still applies.
    - ``DELETE`` requires the caller's exclusive vehicle lock exactly like ``POST`` (``403`` otherwise), so a
      client cannot stop another client's reset. The ``GET`` endpoints are not restricted.
    - The vehicle lock is checked when the execution is started and is not bound to it: an execution that is
      running when the lock is released or expires runs to its end.
    - ``GET /apps/sovd2uds/operations`` lists ``networkreset`` (and ``runtimefilesupdate`` when the runtime
      update plugin is mounted, and ``doip-connect-ecu``, with a synchronous execution, when its route is
      mounted). ``GET /apps/sovd2uds/operations/doip-connect-ecu`` describes that operation and is mounted
      under the same condition as its executions route.

    Starting a ``networkreset`` execution requires the caller to already hold an exclusive vehicle lock,
    acquired independently beforehand, to ensure that no diagnostic operations are in progress while the
    network structure is being reset. This includes functional and component locks -- the reset must not be
    started while any diagnostic operation is in progress.

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

    The ``POST /apps/sovd2uds/operations/networkreset/executions`` request body accepts two independent,
    optional boolean fields, both defaulting to ``true``:

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

    Without ``Content-Type`` the request is treated as having no body (the body is not read) and the
    defaults apply. With a JSON ``Content-Type`` the body is parsed; omitted fields use the defaults;
    unknown fields, invalid JSON and wrong types are rejected with ``400``. An empty body with a JSON
    ``Content-Type``, and any other ``Content-Type``, are rejected with ``400``. Nothing is executed when a
    request is rejected. The body is checked before the vehicle lock. The standard SOVD field ``timeout``
    stops a running execution when it elapses (see :need:`arch~plugin-vehicle-topology-reset`);
    ``proximity_response`` is accepted and ignored.

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
    - ``clear_persisted=false``, ``trigger_detection=false``: rejected with an error response, as this
      combination would perform no observable action.

    When ``communication.ecu_list_persistence.enabled`` is ``false`` (see :need:`arch~dt-ecu-list-persistence`), there is
    no ``ecu-topology`` bucket to operate on (also when DoIP is disabled, which persistence requires); ``clear_persisted`` is then a no-op regardless of its value,
    and only ``trigger_detection`` has an observable effect (running or skipping a live detection).

    **Clearing**

    Clearing cancels a pending topology write first, so it cannot bring the cleared data back. The next
    transport start runs a full broadcast discovery. ECUs still assumed online from the cleared topology (not
    contacted since startup) are reset to NotTested, so they are no longer reported Online, as if the topology
    had never been persisted. A clear-only execution takes an exclusive quiesce lease instead of the disable
    lease because clearing changes this live discovery strategy and ECU state as well as deleting stored data.
    The lease keeps diagnostic requests and gateway connects from starting partway through those live changes;
    the persist task and store separately serialize the storage clear and prevent an older write from restoring
    the deleted data. Quiesce is refused with ``409`` while diagnostic requests are in progress, and new
    requests are answered as not ready (retry later) until the clear has finished. The transport is not
    stopped or restarted: its gate stays closed for the duration of the lease, so no new send or gateway
    connect starts either. The guard is dropped immediately after the clear, without waiting for discovery;
    a clear-only execution does not trigger discovery. It still requires the exclusive vehicle lock and no ECU
    or functional group locks. Connected gateways stay connected. If the closed gate refuses a gateway during
    a persisted reconnect, that gateway stays unconnected until its next announcement or the next transport
    start (see :need:`arch~dt-post-update-deferred-communication`). The persist task restarted after the clear
    does not write the results the clear removed; later detection runs are persisted again as usual.

    **Detection**

    A detection run first takes the exclusive disable lease, which stops communication and guarantees that
    no diagnostic operation is in progress. It then resets all ECU states (keeping ``last_seen``), plans a full
    broadcast discovery, and finishes the lease without resuming communication. The rediscovery trigger then
    brings communication up exactly once, in every ``init_mode`` (including ``Disabled``). The execution
    completes when the discovery and variant detection have settled and, with persistence enabled, the result
    has been persisted.

    Completion is tied to the new discovery generation, not to an arbitrary storage write. If the requested
    run does not settle within the rediscovery timeout, or writing its result fails, the execution reports
    ``failed``. On CAN-only configurations, no DoIP gateway discovery is awaited: completion follows
    the current UDS detector.

    The rediscovery timeout (60 seconds, ``REDISCOVERY_TIMEOUT``) applies twice. It bounds the bring-up, i.e.
    finishing the lease and the rediscovery trigger, and starts right before the lease is finished; if it
    expires before, the lease is released and the execution fails. It then bounds the settling of the
    rediscovery: the persist task publishes its verdict on the new discovery generation (settled or persist
    failed) and the network reset waits for that verdict, which nothing else bounds. Without persistence the network reset
    waits for the discovery and detection itself, bounded by the same timeout.
    If the clear fails, the lease is given back (communication returns to its previous state) and the
    execution fails. ``DELETE`` interrupts both phases; steps already started (clearing, the lifecycle
    worker's enable) complete in the background. If the rediscovery fails after the lease was finished,
    communication stays disabled; a new ``networkreset`` with ``trigger_detection=true`` brings it up in
    every ``init_mode``.

    .. uml::
        :caption: networkreset with Persisted List Control

        @startuml
        actor Client
        participant "Vehicle Topology Plugin" as plugin
        participant "Persistence API\n(ecu-topology bucket)" as Persist
        participant "DoIP/UDS Detection" as Detect

        Client -> plugin : POST .../executions\n{clear_persisted, trigger_detection}
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
           ``include-schema=true`` also the schema of its request body).

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
