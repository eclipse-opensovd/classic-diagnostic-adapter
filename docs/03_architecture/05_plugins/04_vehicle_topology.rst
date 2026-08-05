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
    - **ECUs** -- a qualifier (name), current variant/connectivity state, logical address, and logical link
      name, for each ECU listed under a functional group or a gateway.

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
