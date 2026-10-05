.. SPDX-FileCopyrightText: 2025 Copyright (c) Contributors to the Eclipse Foundation
..
.. See the NOTICE file(s) distributed with this work for additional
.. information regarding copyright ownership.
..
.. This program and the accompanying materials are made available under the
.. terms of the Apache License Version 2.0 which is available at
.. https://www.apache.org/licenses/LICENSE-2.0
..
.. SPDX-License-Identifier: Apache-2.0

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
    :links: arch~sovd-api-flash-folder-configuration
    :status: draft

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

    .. uml:: /03_architecture/02_sovd-api/03_extensions/images/flash_file_management.puml


.. arch:: Flash data transfer
    :id: arch~sovd-api-flash-data-transfer
    :links: arch~sovd-api-flash-functional-class, arch~sovd-api-flash-folder-configuration
    :status: draft

    **Motivation**

    To flash an ECU, the CDA needs to be able to transfer the flash data to the ECU. This API allows transferring the
    data in block-sized chunks, as required by UDS.

    **Endpoints**

    All paths are prefixed with ``/components/{ecu-name}``. The UDS services used by these endpoints are resolved
    through their functional class, see :need:`arch~sovd-api-flash-functional-class`.

    .. list-table:: Flash data transfer endpoints
       :header-rows: 1

       * - Method
         - Path
         - Description
         - Notes
       * - PUT
         - /x-sovd2uds-download/requestdownload
         - Calls the RequestDownload service 0x34
         - Returns ``200 OK`` with the response of the RequestDownload service
       * - POST
         - /x-sovd2uds-download/flashtransfer
         - Starts a background transfer of the data in the file given by ``id`` from an offset for a given length,
           using configurable chunk sizes (block size), and a configurable starting sequence number. It uses
           repeated calls to service 0x36 to transfer the data.
         - Returns ``200 OK`` with an object containing an ``id`` to be used to retrieve the status.
           Plans: The API will be extended to also allow starting the transfer directly with absolute file paths.
       * - GET
         - /x-sovd2uds-download/flashtransfer
         - Retrieve the ids of the flash transfers
         - --
       * - GET
         - /x-sovd2uds-download/flashtransfer/{id}
         - Retrieve the status of the transfer with ``id``
         - --
       * - DELETE
         - /x-sovd2uds-download/flashtransfer/{id}
         - Removes a finished or aborted transfer with ``id``, so that new transfers can be started
         - Returns ``204 No Content``
       * - PUT
         - /x-sovd2uds-download/transferexit
         - Calls the RequestTransferExit service 0x37
         - Returns ``204 No Content`` on success

    **Request bodies**

    Field names are matched case-insensitively.

    .. list-table:: Request body fields
       :header-rows: 1

       * - Endpoint
         - Field
         - Type
         - Required
         - Description
       * - requestdownload
         - ``requestdownload``
         - object
         - yes
         - Request parameters of the RequestDownload service, keyed by parameter name
       * - requestdownload
         - ``flashClass``
         - string
         - no
         - Functional class used to resolve the service, see :need:`arch~sovd-api-flash-functional-class`
       * - flashtransfer
         - ``id``
         - string
         - yes
         - Id of the flash file (see :need:`arch~sovd-api-flash-file-management`)
       * - flashtransfer
         - ``offset``
         - integer
         - yes
         - Offset in bytes within the file at which the transfer starts
       * - flashtransfer
         - ``length``
         - integer
         - yes
         - Number of bytes to transfer
       * - flashtransfer
         - ``blocksize``
         - integer
         - yes
         - Size of the individual TransferData blocks
       * - flashtransfer
         - ``blocksequencecounter``
         - integer (0-255)
         - yes
         - Block sequence counter of the first TransferData request
       * - flashtransfer
         - ``flashClass``
         - string
         - no
         - Functional class used to resolve the service, see :need:`arch~sovd-api-flash-functional-class`
       * - transferexit
         - ``flashClass``
         - string
         - no
         - Functional class used to resolve the service, see :need:`arch~sovd-api-flash-functional-class`.
           The body itself is optional.

    .. uml:: /03_architecture/02_sovd-api/03_extensions/images/flash_data_transfer.puml


.. arch:: Flash service selection via functional class
    :id: arch~sovd-api-flash-functional-class
    :links: arch~sovd-api-flash-functional-class-configuration
    :status: draft

    **Motivation**

    Diagnostic descriptions can contain multiple RequestDownload (0x34), TransferData (0x36) and
    RequestTransferExit (0x37) services with the same short name, which are distinguished only by their ODX
    functional class (e.g. different memory areas or flash procedures). The client must be able to select which of
    these services is used.

    **Service lookup**

    The services for the endpoints ``requestdownload`` (SID 0x34), ``flashtransfer`` (SID 0x36) and
    ``transferexit`` (SID 0x37) are resolved as follows:

    1. The functional class is taken from the optional request body field ``flashClass``. If the field is not
       present, the configured default functional class is used
       (see :need:`arch~sovd-api-flash-functional-class-configuration`).
    2. The CDA searches the services of the ECU variant (including inherited services) for a service whose
       functional class short name equals the functional class (case-insensitive) and whose request SID matches
       the endpoint.
    3. The first matching service is used.

    **Error handling**

    - If no service matches the functional class and SID, the request is rejected with ``404 Not Found``. The error
      message names the functional class and the SID.
    - If ``flashClass`` is present but empty, the request is rejected with ``400 Bad Request``.

    **Consistency**

    The CDA does not keep the functional class between requests; each request is resolved on its own. It is
    recommended that clients use the same ``flashClass`` for all requests of one download sequence
    (RequestDownload, TransferData, RequestTransferExit), but the CDA does not enforce this.

    **Examples**

    .. code-block:: text

       PUT /components/{ecu-name}/x-sovd2uds-download/requestdownload
       {
         "flashClass": "flash_download_upload_bootloader",
         "requestdownload": { "<parameter>": "<value>" }
       }

    .. code-block:: text

       POST /components/{ecu-name}/x-sovd2uds-download/flashtransfer
       {
         "id": "<file-id>",
         "offset": 0,
         "length": 4096,
         "blocksize": 1024,
         "blocksequencecounter": 1,
         "flashClass": "flash_download_upload_bootloader"
       }

    .. code-block:: text

       PUT /components/{ecu-name}/x-sovd2uds-download/transferexit
       {
         "flashClass": "flash_download_upload_bootloader"
       }


Configuration
^^^^^^^^^^^^^

.. arch:: Flash folder configuration
    :id: arch~sovd-api-flash-folder-configuration
    :status: draft

    **Motivation**

    The CDA needs to know where to find the files that should be flashed to the ECUs. This configuration allows setting
    the flash folder.

    **Configuration Parameter**

    The following configuration parameter must be available in the CDA configuration:

    - ``flash_files_path``: Path to the folder where flash files are stored. The CDA must search this folder and its
        subfolders for files available through the ``bulk-data/flashfiles`` endpoints.


.. arch:: Flash functional class configuration
    :id: arch~sovd-api-flash-functional-class-configuration
    :status: draft

    **Motivation**

    Functional class names differ between diagnostic descriptions. The functional class used to resolve the flash
    services when the client does not provide ``flashClass`` must therefore be configurable
    (see :need:`arch~sovd-api-flash-functional-class`).

    **Configuration Parameter**

    The following configuration parameter must be available in the CDA configuration, next to ``flash_files_path``:

    - ``flash_functional_class``: Default functional class used to resolve the services 0x34, 0x36 and 0x37
      when no ``flashClass`` is provided in the request. Defaults to ``flash_download_upload``. Compared
      case-insensitively.

    .. code-block:: toml

       flash_files_path = "/app/flash"
       flash_functional_class = "flash_download_upload"
