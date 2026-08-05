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

    While a ``networkreset`` execution is in progress, this endpoint must respond with ``409 Conflict``, to
    avoid returning stale or partially updated topology data during the reset.

.. arch:: Vehicle Topology Plugin - Reset
    :id: arch~plugin-vehicle-topology-reset
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
         - ``/apps/sovd2uds/operations/networkreset/executions``
         - Returns the list of current execution identifiers. Always contains at most one entry.

       * - POST
         - ``/apps/sovd2uds/operations/networkreset/executions``
         - Starts a new execution of the network reset. Returns 202 Accepted with the execution ID.

       * - GET
         - ``/apps/sovd2uds/operations/networkreset/executions/{id}``
         - Returns the status of a specific execution by its ID.

       * - DELETE
         - ``/apps/sovd2uds/operations/networkreset/executions/{id}``
         - Terminates the execution (if possible, and not yet stopped) and removes it. Returns 204 No Content.

    Triggering a reset must cause the plugin to start re-discovering/re-reporting the vehicle's network
    structure, so that subsequent reads of ``GET /apps/sovd2uds/data/networkstructure`` reflect the
    up-to-date topology once the execution has completed.

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


Reset with Persisted List Control
----------------------------------

.. arch:: Vehicle Topology Plugin - Reset with Persisted List Control
    :id: arch~plugin-vehicle-topology-reset-persistence
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

    Handling of the four flag combinations:

    - ``clear_persisted=true``, ``trigger_detection=true``: the persisted "ecu-topology" bucket is cleared
      first, then a full detection run is performed and its results are persisted -- functionally
      equivalent to the previously specified ``networkreset`` behavior.
    - ``clear_persisted=true``, ``trigger_detection=false``: the persisted "ecu-topology" bucket is cleared
      and no detection is performed; no vehicle communication occurs. Subsequent CDA behavior (until the
      next ``networkreset`` or restart) follows :need:`arch~dt-startup-detection-mode` as if no persisted
      topology had ever existed.
    - ``clear_persisted=false``, ``trigger_detection=true``: a detection run is performed and its results
      are upserted per-gateway into the existing persisted topology; entries for gateways/ECUs not observed
      during this run are left unchanged in the persisted bucket.
    - ``clear_persisted=false``, ``trigger_detection=false``: rejected with an error response, as this
      combination would perform no observable action.

    When ``ecu_list_persistence.enabled`` is ``false`` (see :need:`arch~dt-ecu-list-persistence`), there is
    no ``ecu-topology`` bucket to operate on; ``clear_persisted`` is then a no-op regardless of its value,
    and only ``trigger_detection`` has an observable effect (running or skipping a live detection).

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
                plugin -> Persist : set/upsert bucket "ecu-topology"
                plugin -> Persist : flush
            end
            Client -> plugin : GET .../executions/{id}
            plugin --> Client : 200 OK (status: completed)
        end
        @enduml
