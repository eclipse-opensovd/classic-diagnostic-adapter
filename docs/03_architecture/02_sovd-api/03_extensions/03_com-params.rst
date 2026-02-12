.. Copyright (c) 2025-2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
..
.. See the NOTICE file(s) distributed with this work for additional
.. information regarding copyright ownership.
..
.. This program and the accompanying materials are made available under the
.. terms of the Apache License Version 2.0 which is available at
.. https://www.apache.org/licenses/LICENSE-2.0
..
.. SPDX-License-Identifier: Apache-2.0

.. _architecture-sovd-api-comparams:

Communication Parameters (ComParams)
------------------------------------

.. arch:: Communication Parameters API
    :id: arch~sovd-api-comparams
    :links: arch~sovd-api-comparams-without-lock

    .. note::
       Communication parameter handling is exposed through a ``comparam`` endpoint in ``operations``.

    **Motivation**

    When using the CDA to communicate with classic ECUs, a client needs the ability to modify the communication parameters like timeouts and retries on-the-fly. This API provides a way to do this.

    **Retrieving & Modifying with a lock**

    .. list-table:: ComParam operations
       :header-rows: 1

       * - Method
         - Path
         - Description
       * - POST
         - /operations/comparam/executions
         - Creates an id, can also directly contain parameters to be modified
       * - GET
         - /operations/comparam/executions/{id}
         - Returns the current communication parameters
       * - PUT
         - /operations/comparam/executions/{id}
         - Modifies the communication parameters
       * - DELETE
         - /operations/comparam/executions/{id}
         - Resets the communication parameters to their original state

    These operations require a lock on the entity. Only one execution of communication parameters per entity is allowed.

.. arch:: Retrieve Communication Parameters without Lock
    :id: arch~sovd-api-comparams-without-lock

    .. note::
       This is a small extension to the ISO standard

    To allow retrieving the communication parameters without a lock, a GET on ``/operations/comparam?todo`` must
    also return the current parameters.

    .. todo:: this conflicts with the SOVD standard standard of returning a list of items below that path - define additional query parameter for data?

    **Rationale**

    Clients without a lock might want to log the current communication parameters for informational
    purposes, so they should be able to retrieve them.

    Handling this with the POST/GET semantic with only a single execution would make the handling
    extremely complicated for parallel clients with & without locks.

    Example for directly retrieving communication parameters:

    .. code:: json

       {
         "item": {
           "id": "comparam",
           "name": "Communication parameters",
           "asynchronous_execution": true,
           "proximity_proof_required": false
         },
         "parameters": {
           "CP_P6Max": {
             "value": "4500000",
             "unit": {
               "factor_to_si_unit": 1e-06
             }
           },
           "CP_RC78Handling": {
             "value": "Continue until RC78 timeout"
           },
           "...": {
             "...": "..."
           }
         }
       }

.. todo:: openapi schema

.. todo:: Maybe move unit/types into schema with include-schema?
