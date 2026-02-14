.. SPDX-License-Identifier: Apache-2.0
.. SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
..
.. See the NOTICE file(s) distributed with this work for additional
.. information regarding copyright ownership.
..
.. This program and the accompanying materials are made available under the
.. terms of the Apache License Version 2.0 which is available at
.. https://www.apache.org/licenses/LICENSE-2.0

SOVD (ISO 17978-1)
==================

The guiding principle behind this document is to specify the requirements for an ISO 17978-1 compatible API in the Eclipse OpenSOVD Classic Diagnostic Adapter (CDA).

General
-------

Paths and parameter names should be case-insensitive, unless otherwise mentioned.

HTTP(S)
-------

.. req:: HTTP-Server
    :id: req~sovd-api-http-server
    :links: arch~sovd-api-http-server

    The CDA must provide an HTTP- or HTTPS-server.

    The HTTP Server has to support multiple connections, and calls should be handled asynchronously.

    **Rationale**

    Multiple clients might use the CDA at the same time, and asynchronous handling generally improves performance due to reduced thread count.


.. req:: HTTP-Server-Port
    :id: req~sovd-api-http-server-port

    The HTTP- or HTTPS-Server port must be configurable.


.. req:: HTTPS-Server configuration
    :id: req~sovd-api-https-server-configuration

    In case of HTTPS, the certificate/key must be providable through the configuration, or a plugin.

    **Rationale**

    Certificates/Keys might be stored in an HSM, therefore platform specific code might be needed for access.

    .. todo:: Maybe connection establishment/encryption also needs to be done through HSM?


API
---

Entities
^^^^^^^^

.. req:: Entity Data Types
    :id: req~sovd-api-data-types-mapping-iso17978
    :links: arch~sovd-api-data-types-mapping-iso17978

    Data types must be mapped as specified by ISO 17978-3.

    Additionally, for the data type ``A_BYTEFIELD``, the format ``hex`` must be supported - see :ref:`requirements_sovd_api_bytefield_as_hex`.

Paths
^^^^^

.. req:: Standardized Resource Collection Mapping
    :id: req~sovd-api-standardized-resource-collection-mapping
    :links: arch~sovd-api-standardized-resource-collection-mapping

    The standardized resource collection for ``/components/{ecu-name}`` must be mapped as follows:

    .. list-table:: UDS SID to REST path mapping
       :header-rows: 1
       :widths: 15 45 40

       * - SID (base 16)
         - REST path
         - Comment
       * - 10
         - /modes/session
         -
       * - 11
         - | /operations/reset
           | /status/restart
         -
       * - | 14
           | 19
         - /faults/
         -
       * - | 22
           | 2E
         - | /data/{data-identifier}
           | /configurations/{data-identifier}
         - category & classification between paths is handled by the functional class with configuration
       * - 27
         - /modes/security
         -
       * - 28
         - /modes/commctrl
         -
       * - 29
         - /modes/authentication
         -
       * - 31
         - /operations/{routine-identifier}
         -
       * - | 34
           | 36
           | 37
         - | /x-sovd2uds-download/requestdownload
           | /x-sovd2uds-download/flashtransfer
           | /x-sovd2uds-download/transferexit
         - ``flashtransfer`` handles the whole transfer, not for individual calls
       * - 3E
         - --
         - handled internally by CDA
       * - 85
         - /modes/dtcsetting
         -

    NOTE: The mapping in ISO standard is inconsistent w.r.t. ``/modes/security`` and ``/modes/authentication``


.. req:: Explicit ECU Variant Detection
    :id: req~sovd-api-ecu-variant-detection
    :links: arch~sovd-api-ecu-variant-detection

    The CDA must support ECU variant detection through a ``POST`` on the ``/components/{ecu-name}`` endpoint.
    An additional endpoint under operations may be provided to trigger the detection.

    **Rationale**

    Some ECUs have different variants, which support different functionality. To provide the correct functionality,
    the CDA needs to be able to detect the variant in use. This variant may change at any point due to the nature of
    the ECUs software. Clients may need to trigger this explicitly to ensure correct functionality.


Operations
""""""""""

.. req:: Operations Handling
    :id: req~sovd-api-operations-handling
    :links: arch~sovd-api-operations-handling

    Operations (Routines SID 31\ :sub:`16`) can be synchronous or asynchronous. Asynchronous routines are routines, for which the ``RequestResults`` and/or ``Stop`` subfunctions are defined.

    The order of operations:

    1. ``POST /executions`` for *Start* (subfunction 01)
    2. ``GET /executions/{id}`` for *RequestResults* (subfunction 03)
    3. ``DELETE /executions/{id}`` for *Stop* (subfunction 02).

    Synchronous routines:

    The `POST` to executions will directly return the result - either a 200 with the data, or an error.

    Example of a successful call:

    .. code:: javascript

        {
          "parameters": {
              "key": "value"
          }
        }


    Asynchronous routines:

    Since the response of the ``Start`` subfunction, as well as an id for polling the ``RequestResults``
    subfunction are required, both must be returned.

    Example of a successful call:

    .. code:: javascript

        {
          "id": "<id of created execution>",
          "status": "running",
          "parameters": {
              "key": "value"
          }
        }


    Should the call to the ``Start`` subfunction return an error (e.g. NRC), no ``id`` for polling is created.

    There are however use-cases, in which you may want to call ``RequestResults`` or ``Stop`` independently, or there could
    only be partial definitions (e.g. only Stop). For this use case the extension :ref:`requirements_sovd_api_operation_order` is required.

Faults
""""""

.. req:: Faults Endpoint
    :id: req~sovd-api-faults-endpoint
    :links: arch~sovd-api-faults-endpoint

    The CDA must provide a ``/faults`` endpoint to retrieve DTCs in accordance with ISO 17978-3.


Extensions to the ISO specification
-----------------------------------

.. _requirements_sovd_api_bytefield_as_hex:

Data Type A_BYTEFIELD as Hex
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. req:: Data Type A_BYTEFIELD as Hex
    :id: req~sovd-api-bytefield-as-hex

    For the data type ``A_BYTEFIELD`` the json output type ``string`` with the format ``hex`` must be supported
    through an optional query-parameter. Using ``hex`` means, that the binary data must be base16-encoded,
    either with or without preceding ``0x`` prefixes.

    **Rationale**

    Handling base64 encoded binary directly can be a compatibility challenge for offboard testers accessing the
    CDA. Manual debugging can also be simplified by directly seeing the hexadecimal encoded data, since it's
    easier to process for humans.

.. _requirements_sovd_api_mimetype_octet_stream:

Support for mimetype application/octet-stream
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. req:: Support for mimetype application/octet-stream
    :id: req~sovd-api-octet-stream-support

    The ``/data/{data-identifier}`` and ``/operations/{routine-identifier}`` endpoints must support the additional mimetype octet-stream where applicable, to allow clients to send and receive payloads as binary data.

    NOTE: Only the payload is sent/received. The SID & DID/RID are derived from the path, and in case of NRCs only the NRC code (single byte) is sent back with a HTTP 502.

    **Rationale**

    This requirement simplifies the use of the CDA as a diagnostic tester and in migration scenarios.

Version endpoint
^^^^^^^^^^^^^^^^

.. req:: Version Endpoint
    :id: req~sovd-api-version-endpoint

    The CDA must provide a standardized version endpoint ``/apps/sovd2uds/data/version`` which returns the current
    version of the CDA in use, its SOVD api version, and implementation name.


.. _requirements_sovd_api_operation_order:

Support for non-standard operation order
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. req:: Support for non-standard operation order
    :id: req~sovd-api-routine-operation-out-of-order

    To support the use-case of calling ``RequestResults`` and ``Stop``, without having to call ``Start``,
    the following boolean query parameters must be supported:

    .. list-table:: UDS SID to REST path mapping
       :header-rows: 1
       :widths: 20 40 40

       * - Method
         - Parameter
         - Description

       * - All
         - x-sovd2uds-suppressService
         - Suppresses sending the routine to the ECU

       * - DELETE
         - x-sovd2uds-force
         - Forces a DELETE operation to delete the id, regardless of an error the ecu might have reported for the `Stop` routine


    When a REST call is initiated that needs to call the service on the ECU, but is missing the required
    definition in the diagnostic description, and ``x-sovd2uds-suppressService`` isn't set to true,
    the REST call must fail.


.. _requirements_sovd_api_vehicle_api:

Vehicle
^^^^^^^

A vehicle must support operations as a whole, to allow for operations which affect the whole vehicle, like updating
mdd-files, or to prepare for operations which affect the whole vehicle (e.g. disabling vehicle communication).

.. req:: Vehicle Level Operations
    :id: req~sovd-api-vehicle-level-operations

    Vehicle level operations must be supported in the CDA.
    This requires a standardized resource collection in the exposed root path ``/``.

    The standardized resource collection must provide the following resources:

    .. list-table:: Standardized resource collection
       :header-rows: 1
       :widths: 30 70

       * - Resource
         - Description
       * - locks
         - Locks affecting the whole vehicle
       * - functions
         - Functions affecting the whole vehicle (i.e. communication disable/enable)


.. _requirements_sovd_api_functional_communication:

Functional communication
^^^^^^^^^^^^^^^^^^^^^^^^

.. req:: Functional Communication
    :id: req~sovd-api-functional-communication
    :links: arch~functional-communication-dd-configuration

    Functional communications needs to be possible. A standardized resource collection must be made available within the
    ``/functions/functionalgroups/{groupName}`` resource.

    The available functionality must be defined in an additional diagnostic description used solely for defining functional communication services. Since this file may contain multiple logical link definitions, a configuration option can be provided to filter the available links.

    The following entities must be available in the functional groups resource collection:

    .. list-table:: Functional groups entities
       :header-rows: 1
       :widths: 30 70

       * - Entity
         - Function
       * - locks
         - Locking a functional group (also controls functional tester present)
       * - operations
         - Calling functional routines
       * - data
         - Calling functional data services
       * - modes
         - Setting modes for the ecus in the functional group

    **Rationale**

    Clients require functional communication to ECUs for use-cases, in which they want to control communication or dtcsettings for all ecus.

.. _requirements_sovd_api_flash_api:

Flash API
^^^^^^^^^

.. req:: Flash API
    :id: req~sovd-api-flashing
    :links: arch~sovd-api-flash-file-management, arch~sovd-api-flash-data-transfer

    A Flash-API is required to support flashing of ECUs, utilizing SIDs 34\ :sub:`16`, 36\ :sub:`16` & 37\ :sub:`16`. It needs to enable efficient transfer of the data, without sending the individual data transfers via REST.

    Flashing is the process of updating the firmware of an ECU.

    **Rationale**

    Handling for the aforementioned SIDs isn't defined in the ISO specification, it is however an important use-case to be able to update the firmware on ECUs.

.. req:: Flash API - Data Source Restriction
    :id: req~sovd-api-flashing-security

    The source of the data to be sent for flashing, must be restrictable to a path and its subdirectories via configuration.

    **Rationale**

    Without restrictions to the path, an attacker could exfiltrate arbitrary accessible data.

Communication Parameters API
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. req:: Communication Parameters API
    :id: req~sovd-api-comparams
    :links: arch~sovd-api-comparams

    An API to retrieve and modify communication parameters must be provided

    **Rationale**

    Clients need the ability to modify communication parameters on-the-fly to communicate with classic ECUs.

MDD Embedded files
^^^^^^^^^^^^^^^^^^

.. req:: MDD Embedded files
    :id: req~sovd-api-mdd-embedded-files
    :links: arch~sovd-api-mdd-embedded-files

    The CDA must support reading embedded files from the mdd file, and provide them via the ``/components/{ecu-name}/files/{file-name}`` endpoint.

    **Rationale**

    Some data required for communication with ECUs might be embedded in the mdd file. To allow clients to retrieve this data, it must be made available via the API.


OpenAPI-Documentation
---------------------

.. req:: OpenAPI Documentation
    :id: req~sovd-api-openapi-documentation

    An OpenAPI documentation of the provided API must be available for every endpoint of the CDA when ``/docs`` is appended.

    **Rationale**

    Required by the standard.


.. req:: OpenAPI Schema
    :id: req~sovd-api-openapi-schema

    An OpenAPI schema description of retrieved data must be available when the query parameter ``include-schema=true``
    is appended to any endpoint with returned data.

    **Rationale**

    Required by the standard.


Security
^^^^^^^^

Since vendors have different requirements and systems regarding security, security related functionality has to be
implemented in a plugin, see :ref:`requirements-plugins-security`.

Token validation
""""""""""""""""

Audiences
"""""""""
