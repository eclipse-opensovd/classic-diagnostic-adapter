.. SPDX-License-Identifier: Apache-2.0
.. SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
..
.. See the NOTICE file(s) distributed with this work for additional
.. information regarding copyright ownership.
..
.. This program and the accompanying materials are made available under the
.. terms of the Apache License Version 2.0 which is available at
.. https://www.apache.org/licenses/LICENSE-2.0

Flash-API
---------

Introduction
^^^^^^^^^^^^

Flashing via UDS generally follows the following sequence. OEMs might choose to call additional services or modify the sequence.

.. uml:: /03_architecture/02_sovd-api/03_extensions/01_flashing_sequence.puml

To allow the flashing functionality shown above, the SOVD-API from ISO 17978-3 needs to be extended with the functionality defined in this document.

The standard doesn't define how the required services should be mapped in the Classic Diagnostic Adapter.

API
^^^

.. arch:: Management of flash files
    :id: arch~sovd-api-flash-file-management

    **Motivation**

    To flash an ECU, the CDA needs to have access to the files that should be flashed. This API allows listing the files that are available for flashing.

    **Endpoints**

    .. list-table:: Flash file management
       :header-rows: 1

       * - Method
         - Path
         - Description
         - Notes
       * - GET
         - /apps/sovd2uds/bulk-data/flashfiles
         - Returns a list of entries that represent files in the configured flash folder and its subfolders.
         - Flash folder needs to be configured


.. arch:: Flash data transfer
    :id: arch~sovd-api-flash-data-transfer

    **Motivation**

    To flash an ECU, the CDA needs to be able to transfer the flash data to the ECU. This API allows transferring the
    data in block-sized chunks, as required by UDS.

    **Endpoints**

    All paths are prefixed with ``/components/{ecu-name}``.

    .. list-table:: Flash data transfer endpoints
       :header-rows: 1

       * - Method
         - Path
         - Description
         - Notes
       * - PUT
         - /x-sovd2uds-download/requestdownload
         - Calls the RequestDownload service 34~16~
         - Returns the response of the RequestDownload service
       * - POST
         - /x-sovd2uds-download/flashtransfer
         - Transfers data in the file given by ``id`` from an offset for a given length, using configurable
           chunk sizes (block size), and a configurable starting sequence number. It uses repeated calls
           to service 36~16~ to transfer the data.
         - Returns an object with an ``id`` to be used to retrieve status
           Plans: The API will be extended to also allow starting the transfer directly with absolute file paths
       * - GET
         - /x-sovd2uds-download/flashtransfer
         - Retrieve the ids of the running flash transfers
         - --
       * - GET
         - /x-sovd2uds-download/flashtransfer/{id}
         - Retrieve the status of the transfer with ``id``
         - --
       * - PUT
         - /x-sovd2uds-download/transferexit
         - Calls the RequestTransferExit service 37~16~
         - Returns the response of the RequestTransferExit service

Configuration
^^^^^^^^^^^^^

.. arch:: Flash folder configuration
    :id: arch~sovd-api-flash-folder-configuration

    **Motivation**

    The CDA needs to know where to find the files that should be flashed to the ECUs. This configuration allows setting
    the flash folder.

    **Configuration Parameter**

    The following configuration parameter must be available in the CDA configuration:

    - ``flash_files_path``: Path to the folder where flash files are stored. The CDA must search this folder and its
        subfolders for files available through the ``bulk-data/flashfiles`` endpoints.
