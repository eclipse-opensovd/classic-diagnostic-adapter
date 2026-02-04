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

MDD Embedded Files API
----------------------

.. arch:: MDD Embedded Files API
    :id: arch~sovd-api-mdd-embedded-files

    .. note::
       This is a SOVD-API extension.

    **Motivation**

    When an additional private SOVD-Server is tasked with providing functionality that replaces classic offboard-tester
    functionality, additional data from the single-ecu-jobs embedded in the original ``pdx``-file can be required.

    The odx-converter offers an option to include code-files from the pdx, as well as partial contents from those files.
    This API allows the retrieval of these files.

    **Embedded Content Retrieval**

    The API to retrieve embedded files utilizes a bulk-data endpoint, as defined in :ref:`architecture_bulk_data`

    Endpoints within ``/components/{ecuName}``:

    .. list-table:: MDD embedded files endpoints
       :header-rows: 1

       * - Method
         - Path
         - Description
       * - GET
         - /x-sovd2uds-bulk-data/mdd-embedded-files
         - Returns a list of items which represent the files and their metadata
       * - GET
         - /x-sovd2uds-bulk-data/mdd-embedded-files/{id}
         - Returns an item, which is the data that was embedded

    Other methods are not allowed (e.g. data can't be modified), and will return an HTTP 405 error code.

.. todo:: OpenAPI?

.. todo:: maybe move to a general bulk-data endpoint?
