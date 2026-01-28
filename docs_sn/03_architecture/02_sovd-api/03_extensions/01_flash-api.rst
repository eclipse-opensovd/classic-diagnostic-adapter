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

Flash-API
---------

.. note::
   [.specitem, oft-sid="arch~sovd.api.flash-api~1" oft-covers="req~sovd.api.flash-api~1"]

Introduction
^^^^^^^^^^^^

Flashing via UDS generally follows the following sequence, OEMs might choose to call additional services or modify the sequence.

.. uml:: /03_architecture/02_sovd-api/03_extensions/01_flashing_sequence.puml

To allow the flashing functionality as shown, the SOVD-API from ISO 17978-3 needs to be extended with the functionality defined in this document.

The standard doesn't define how the required services should be mapped in the Classic Diagnostic Adapter.

API
^^^

Management of flash-files
^^^^^^^^^^^^^^^^^^^^^^^^^

.. list-table:: Flash files management
   :header-rows: 1

   * - Method
     - Path
     - Description
     - Notes
   * - GET
     - /apps/sovd2uds/bulk-data/flashfiles
     - Returns a list of entries which represent files in the configured flash folder and its subfolders.
     - Flash folder needs to be configured

Data Transfer
^^^^^^^^^^^^^

All paths are prefixed with ``/components/{ecu-name}``.

.. list-table:: Flash data transfer endpoints
   :header-rows: 1

   * - Method
     - Path
     - Description
     - Notes
   * - PUT
     - /x-sovd2uds-download/requestdownload
     - Calls the RequestDownload Service 34~16~
     - Returns an object with an ``id``
   * - POST
     - /x-sovd2uds-download/flashtransfer
     - Transfers data in file given by id from an offset for a given length in settable chunk-sizes. It uses repeated calls to service 36~16~ to transfer the data.
     - Plans: API will be extended to also allow starting the transfer directly with absolute file paths
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
     - Calls the transfer exit service 37~16~
     - --

Configuration
^^^^^^^^^^^^^

TODO: Configuration
