.. Copyright (c) 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
..
.. See the NOTICE file(s) distributed with this work for additional
.. information regarding copyright ownership.
..
.. This program and the accompanying materials are made available under the
.. terms of the Apache License Version 2.0 which is available at
.. https://www.apache.org/licenses/LICENSE-2.0
..
.. SPDX-License-Identifier: Apache-2.0

Single ECU Jobs
---------------

.. arch:: Single ECU Jobs Extension
    :id: arch~sovd-api-single-ecu-jobs

    **Motivation**

    When a client wants to replace the classical single-ecu-jobs defined in the odx description, it could need the original input/output parameters from those jobs. This API provides access to the data for the single-ecu-jobs, which were present in the original odx at the time of conversion.

    **Retrieving data**

    .. note::
       The available data may depend on the currently detected variant, since the ecu jobs are defined for variants.

    The following paths will be available within the ``/components/{ecuName}`` path:

    .. list-table:: Single ECU Jobs endpoints
       :header-rows: 1

       * - Method
         - Path
         - Description
       * - GET
         - /x-single-ecu-jobs
         - Retrieves a list of single ecu job items
       * - GET
         - /x-single-ecu-jobs/{id}
         - Reads the data for an entry

    Read the Single ECU Jobs OpenAPI specification for details: :download:`Single ECU Jobs Specification <02_sovd-api/openapi/single-ecu-jobs.yaml>`
