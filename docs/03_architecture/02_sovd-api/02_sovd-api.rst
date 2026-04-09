.. SPDX-License-Identifier: Apache-2.0
.. SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
..
.. See the NOTICE file(s) distributed with this work for additional
.. information regarding copyright ownership.
..
.. This program and the accompanying materials are made available under the
.. terms of the Apache License Version 2.0 which is available at
.. https://www.apache.org/licenses/LICENSE-2.0

SOVD-API
--------

Data Types
^^^^^^^^^^

.. arch:: ODX to JSON data type mapping
    :id: arch~sovd-api-data-types-mapping-iso17978
    :status: draft

    Data types must be mapped as follows:

    .. list-table:: ODX to JSON data type mapping
       :header-rows: 1

       * - ODX data type
         - JSON data type (format)
         - Comment
       * - A_ASCIISTRING
         - string
         -
       * - A_BOOLEAN
         - boolean
         -
       * - A_BYTEFIELD
         - string (byte | hex)
         - see :ref:`requirements_sovd_api_bytefield_as_hex`
       * - A_FLOAT32
         - number (float)
         -
       * - A_FLOAT64
         - number (double)
         -
       * - A_INT32
         - integer (int32)
         -
       * - A_UINT32
         - integer (int64)
         -
       * - A_UNICODE2STRING
         - string
         -
       * - A_UTF8STRING
         - string
         -

    **Primitive JSON types**

    All primitive JSON types (string, array, number, integer, boolean, and object) can be used.

    For strings, the following format identifiers can be used:

    .. list-table:: JSON string formats
       :header-rows: 1

       * - JSON type
         - JSON format
         - Comment
       * - string
         - byte
         - Base64-encoded binary data
       * - string
         - hex
         - Hexadecimal-encoded binary data (e.g. f0cacc1a). Can be prefixed with 0x and contain spaces.
       * - string
         - uuid
         - UUID identifier according to RFC 4122 (https://www.rfc-editor.org/rfc/rfc4122)
       * - string
         - uri
         - Absolute URI according to RFC 3986 (https://www.rfc-editor.org/rfc/rfc3986)
       * - string
         - uri-reference
         - Relative URI according to RFC 3986 (https://www.rfc-editor.org/rfc/rfc3986)
       * - string
         - json-pointer
         - Pointer to a specific value within the JSON according to RFC 6901 (https://www.rfc-editor.org/rfc/rfc6901)

    .. note:: TODO More string formats required?

    **Mapping of complex data types**

    .. note:: TODO Mapping of complex data types

.. _architecture_bulk_data:

Bulk Data
^^^^^^^^^

.. arch:: Bulk-Data Endpoints
    :id: arch~sovd-api-bulk-data
    :status: draft

    Bulk-data endpoints allow the management of bulk data, like files that are to be used for flashing.

    Paths are required to be in the following structure: ``/bulk-data/{category}/{id}``. For extensions, the name ``bulk-data`` may only be used at the end of a path element.

    .. list-table:: Bulk Data endpoints
       :header-rows: 1

       * - Method
         - Path
         - Description
       * - GET
         - ``/bulk-data/{category}``
         - Retrieves a list of entries in that category and their IDs
       * - GET
         - ``/bulk-data/{category}/{entry-id}``
         - Downloads the data for the entry. The MIME type is determined by the server and the content of the data.
       * - POST
         - ``/bulk-data/{category}``
         - Uploads data to the category. Additional metadata (e.g. filename) can be provided through Content-Disposition: form-data
       * - DELETE
         - ``/bulk-data/{category}``
         - Requests the deletion of all data for that category
       * - DELETE
         - ``/bulk-data/{category}/{entry-id}``
         - Requests the deletion of a specific entry

    .. note::
       IMPORTANT: All calls to the aforementioned endpoints can fail with reasonable HTTP status codes (e.g. 401, 403, 409, 501), depending on the context and state.

Entities
^^^^^^^^

.. arch:: Components Entity Collection
    :id: arch~sovd-api-components-entity-collection
    :status: draft

    The ``/components`` endpoint serves as the entry point for discovering available ECU entities.

    **GET /components**

    Returns a list of all ECU entities that have been loaded from diagnostic descriptions (MDD files). Each item in
    the list contains the ECU name, a lowercase identifier, and a URI reference to the individual component resource.

    The response may include additional fields beyond the standard ``items`` list. These additional fields group
    ECUs based on configurable conditions evaluated against the diagnostic description metadata. The names and
    filter criteria for these additional fields are defined in the application configuration.

    **GET /components/{ecu-name}**

    Returns detailed information about a specific ECU entity, including:

    - The ECU identifier and name
    - Variant information (name, base variant flag, connectivity state, and logical address)
    - URI references to the standardized resource collection endpoints: data, operations, configurations, faults, modes, locks, and extension endpoints

    The connectivity state of an ECU reflects its current diagnostic reachability and variant detection status:

    .. list-table:: ECU connectivity states
       :header-rows: 1

       * - State
         - Description
       * - Online
         - The ECU is reachable and has a detected variant
       * - Offline
         - The ECU has not been contacted since startup
       * - NotTested
         - Variant detection has not yet been performed
       * - Duplicate
         - Multiple variants match the ECU response, superseded by a more specific match
       * - Disconnected
         - The ECU was previously reachable but is no longer responding
       * - NoVariantDetected
         - The ECU responded but no matching variant was found

    Optionally, diagnostic description metadata (SDGs) for the ECU can be included in the response through a query parameter.

.. arch:: Standardized Resource Collection Mapping
    :id: arch~sovd-api-standardized-resource-collection-mapping
    :status: draft

    Every ECU with a ``mdd`` file is an entity within the ``/components`` entity collection.

    This doesn't include the ``mdd`` files used for functional communication (see :ref:`architecture_functional_communication`).

ECU resource collection
^^^^^^^^^^^^^^^^^^^^^^^

.. arch:: ECU Resource Collection
    :id: arch~sovd-api-ecu-resource-collection
    :status: draft

    Each ECU entity must provide a standardized resource collection as defined in ISO 17978-3, chapter 5.4.2.

    The resource collection for ECUs is defined in an OpenAPI Specification: :download:`ECU Resource Collection Specification <02_sovd-api/openapi/ecu_resource_collection.yaml>`


SDG/SD Metadata
^^^^^^^^^^^^^^^

.. arch:: Component SDG/SDs
    :id: arch~sovd-api-component-sdgsd
    :status: draft

    Special Data Groups (SDGs) and Special Data (SDs) from the diagnostic description can be retrieved through an
    opt-in query parameter ``x-sovd2uds-includesdgs`` (with alias ``x-include-sdgs``). When set to ``true``, the
    response includes the SDG/SD metadata instead of or in addition to the normal response data.

    **ECU-level SDGs**

    On the ``GET /components/{ecu-name}`` endpoint, including SDGs adds an ``sdgs`` property to the ECU response
    object. The SDGs returned are those associated with the ECU entity in the diagnostic description (retrieved
    without a specific service context).

    **Service-level SDGs**

    On the ``GET /components/{ecu-name}/data/{data-identifier}`` endpoint, when SDGs are requested, the endpoint
    returns the SDGs associated with the diagnostic service instead of the normal data response. The response
    contains an ``items`` map keyed by a combination of the service name and its action type, where each entry
    holds the list of SDGs for that service action.

    **Operation-level SDGs**

    On the ``GET /components/{ecu-name}/operations/{operation-identifier}`` endpoint, when SDGs are requested, the endpoint
    returns the SDGs associated with the diagnostic service instead of the normal data response. The response
    contains an ``items`` map keyed by a combination of the service name and its action type, where each entry
    holds the list of SDGs for that service action.

    .. note::

        TODO We need to define handling for asynchronous operations, since they consist of multiple services
        with (possibly conflicting) SDGs/SDs - current idea would be add dummy SDGs at the top, with the si set
        to the "original" type of the operation

    **Data format**

    The SDG/SD structure is recursive. Each entry in the list is one of two types:

    .. list-table:: SD entry fields
       :header-rows: 1

       * - Field
         - Type
         - Description
       * - ``value``
         - string (optional)
         - The value of the SD
       * - ``si``
         - string (optional)
         - Semantic information -- a descriptor or key for the entry
       * - ``ti``
         - string (optional)
         - Text information -- the textual content of the entry

    .. list-table:: SDG entry fields
       :header-rows: 1

       * - Field
         - Type
         - Description
       * - ``caption``
         - string (optional)
         - The name of the group
       * - ``si``
         - string (optional)
         - Semantic information -- a descriptor or key for the group
       * - ``sdgs``
         - list (optional)
         - A nested list of SD and SDG entries, allowing arbitrary nesting depth

    SD and SDG entries are distinguished by their structure -- an entry with a ``sdgs`` or ``caption`` field is
    an SDG, while an entry with ``value`` or ``ti`` fields is an SD.


Data Resources -- SID 22\ :sub:`16` & 2E\ :sub:`16`
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^


.. arch:: Data Resources
    :id: arch~sovd-api-data-resources
    :status: draft

    Data resources for ECUs are available in the standardized resource collection within the path ``/components/{ecu-name}/data``.

    The data main path returns a list of the data identifiers available as ``/data/{data-identifier}``, as well as metadata.

    A data identifier in the list is described with the following attributes (all strings):

    .. list-table:: Data identifier attributes
       :header-rows: 1

       * - Attribute
         - Description
       * - id
         - Path element ID (i.e. short name)
       * - name
         - Name of the element (i.e. long name)
       * - category
         - Category of the element

    **Naming**

    Names for data resources are determined by taking all diag-services defined for 22\ :sub:`16` and 2E\ :sub:`16` -- their short name is taken as a base and processed by removing configurable prefixes/suffixes, to determine the data identifier within the ``/data/{data-identifier}`` path.

Categories
^^^^^^^^^^

.. arch:: Data Identifier Categories
    :id: arch~sovd-api-data-identifier-categories
    :status: draft

    The category of a data identifier must be mappable with configuration, in which the functional class name is mapped to a category name.

    The following standard categories are defined by the standard:

    .. list-table:: Standard categories
       :header-rows: 1

       * - Name
         - Description
       * - identData
         - Identification data -- everything related to the identification of an ECU/vehicle
       * - currentData
         - Measurement data that can dynamically change
       * - storedData
         - Parameters stored in the ECU
       * - sysInfo
         - System information - data related to system resources that can change dynamically (e.g. memory consumption)

    Additional custom categories must be prefixed with ``x-sovd2uds-``, or, in custom vendor configuration, with a vendor-specific prefix different from ``x-sovd2uds``.

    Services without a mapping should be ignored to allow a separation between configuration and data services.


Configurations -- SID 22\ :sub:`16` & 2E\ :sub:`16`
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. arch:: Configuration Resources
    :id: arch~sovd-api-configuration-resources
    :status: draft

    Names for data resources are determined by taking all diag-services defined for 22\ :sub:`16` and 2E\ :sub:`16`, and filtering
    them for a configurable functional class name. Their short name is taken as a base and processed by removing
    configurable prefixes/suffixes, to determine the data identifier within the ``/configurations/{data-identifier}`` path.

    The returned item properties for the ``/configurations`` item list are:

    .. list-table:: Configuration item properties
       :header-rows: 1

       * - Attribute
         - Description
       * - id
         - Path element ID (i.e. short name)
       * - name
         - Name of the element (i.e. long name)
       * - type
         - Always ``parameter``
       * - x-sovd2uds-serviceAbstract
         - Array of strings containing the SIDs and data identifier as a hexadecimal string (e.g. ["2E1234", "221234"])

    .. note::
       ``x-sovd2uds-serviceAbstract`` is an extension to the standard.

    **Rationale for serviceAbstract**

    Coding data files might not include the matching name for a service, or detailed JSON parameters that would
    be required to code an ECU. Therefore, a "reverse lookup" to the name can be required, so a client without
    access to the diagnostic description is able to code an ECU just with the ``2E 1234 <payload>`` data,
    utilizing the ``application/octet-stream`` extension for a ``PUT /configurations/{data-identifier}`` call.


Operations
----------

.. arch:: Synchronous and Asynchronous Operations
    :id: arch~sovd-api-operations-handling
    :status: draft

    Operations in the CDA are Routines (31\ :sub:`16`), Reset (11\ :sub:`16`), and an extension to configure
    communication parameters (:ref:`architecture-sovd-api-comparams`).

    **Reset -- SID 11**\ :sub:`16`

    For compatibility with SOVD version 1.0 and earlier, the operations ``/operations/ecureset`` and
    ``/operations/reset`` to reset an ECU must be supported.

    **Routines -- SID 31**\ :sub:`16`

    All services with the SID 31\ :sub:`16` are considered for operations -- as with data, their short names are
    preprocessed by removing configurable prefixes/suffixes to determine routine identifiers available as
    the ``/operations/{routine-identifier}`` path.

    The items in the list of items available under ``/operations`` must include the following attributes:

    .. list-table:: Operation list item attributes
       :header-rows: 1

       * - Attribute
         - Type
         - Description
       * - id
         - string
         - Path element for the routine identifier (i.e. short name)
       * - name
         - string
         - Name of the routine (long name)
       * - proximity_proof_required
         - boolean
         - Always ``false``
       * - asynchronous_execution
         - boolean
         - Either ``true`` or ``false``, depending on the defined subfunctions for the routine

    **Synchronous -- Start only**

    When a routine only defines the ``Start`` (0x01) subfunction, it is considered synchronous. This means
    that the return for ``asynchronous_execution`` in the list will be ``false``, and that a call to
    execute the routine with ``POST /operations/{routine-name}/executions`` is executed synchronously
    and will directly return the response from the ECU with HTTP status ``200 OK``.

    .. note::
       Operations without a ``Start`` subfunction can exist in the operations list but will fail
       execution with an error unless the ``x-sovd2uds-suppressService`` query parameter is set to ``true``.

    **Asynchronous -- Stop and/or RequestResults**

    When a routine has ``Stop`` (0x02) and/or ``RequestResults`` (0x03) subfunctions defined, it is
    considered asynchronous. This means that the return for ``asynchronous_execution`` in the list will
    be ``true``, and that a call to execute the routine with ``POST /operations/{routine-name}/executions``
    is executed on the ECU and will return the response from the ECU, as well as an ``id`` and the other
    asynchronous properties required by the standard for calling the RequestResults subfunction with
    ``GET /operations/{routine-name}/executions/{id}``.

    The POST request returns HTTP status ``202 ACCEPTED`` with an execution identifier.

    Additionally, by calling ``DELETE /operations/{routine-name}/executions/{id}``, it's possible to
    call the Stop subfunction of the routine.

    **Subfunction Requirements**

    If any of the required subfunctions are not available in the diagnostic database, the call will
    result in an error:

    - ``POST`` requires the ``Start`` (0x01) subfunction to be defined
    - ``GET`` requires the ``RequestResults`` (0x03) subfunction to be defined
    - ``DELETE`` requires the ``Stop`` (0x02) subfunction to be defined

    These requirements can be bypassed using the ``x-sovd2uds-suppressService`` query parameter.
    Since an entry in the list is still required, as well as the operation being asynchronous,
    the definition of either ``RequestResults`` or ``Stop`` is a prerequisite.

    **Force Parameter**

    If DELETE is called and an ECU error is encountered, the ``id`` will not be deleted unless the
    query parameter ``x-sovd2uds-force`` is set to true. This allows the client to handle
    returned errors and to call the Stop subfunction again.

    When ``x-sovd2uds-force=true``, the execution is removed from tracking even if the Stop
    request fails or returns a negative response.

    **Stop Response Data**

    When a Stop subfunction returns non-empty response data, the DELETE endpoint returns HTTP status
    ``200 OK`` with the response data in the body, instead of the standard ``204 NO CONTENT``.
    This allows clients to access any data returned by the Stop operation.

    .. note::
       This is an extension to the standard to support Stop operations that return response data.

    **Rationale for POST Response Data**

    When executing an asynchronous function, there's no good way to return the response of the
    routine with the GET to the id-endpoint, since that endpoint should only return the status of
    the RequestResults call. Therefore, the response of the routine is returned directly when
    executing the routine with POST in addition to the id.

    .. note::
       This is a deviation from the standard, but is required to allow clients to handle
       routine responses properly.


IOControl -- SID 2A\ :sub:`16`
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. note::
   Not supported at this time

Modes
-----

Session -- SID 10\ :sub:`16`
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. arch:: Session Endpoints
    :id: arch~sovd-api-session-management
    :status: draft

    The endpoint ``/modes/session`` can be used to determine the current ECU session,
    as well as trying to switch into a different session.

    .. list-table:: Session endpoints
       :header-rows: 1

       * - Method
         - Path
         - Description
       * - GET
         - ``/modes/session``
         - Returns the current session
       * - PUT
         - ``/modes/session``
         - Tries to switch into the specified session

    The format for the request body is::

       {
         "value": "<session name>",
         "mode_expiration": 3600
       }

    The names of the sessions for the field ``value`` are determined by the short name for the state in the
    ECU's state chart for the SID 10\ :sub:`16` services. It is case-insensitive.

    The field ``mode_expiration`` is optional. If set, it determines the time in seconds that the session
    should be active. Once that time expires, the session is automatically reset to the default session.

    In the response body, ``id`` and ``value`` must be included.

    See also chapter 7.16 in ISO 17978-3.


Security -- SID 27\ :sub:`16`
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. arch:: Security Access Endpoints
    :id: arch~sovd-api-security-access-modes
    :status: draft

    The endpoints are available under the path ``/modes/security``.

    Works similarly to Session defined in the previous chapter. The names of the security access levels are
    determined through the state charts for the SID 27\ :sub:`16` services.


Authentication -- SID 29\ :sub:`16`
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. arch:: Authentication Endpoints
    :id: arch~sovd-api-authentication-modes
    :status: draft

    .. note::
       This is technically a deviation from Table 343 in the ISO API. The table in the ISO is misleading, since 8.3.2 and 8.3.3 describe them separately.

    The endpoints are available under ``/modes/authentication``. A ``PUT`` call needs to provide a request body containing
    ``value`` with the desired subfunction (names are determined by the UDS standard), and a ``parameters`` field containing all request parameters.

    Diagnostic data descriptions have to specify the used services including the subfunction individually, so the
    request parameters can be converted into UDS payloads.


Communication Control -- SID 28\ :sub:`16`
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. arch:: Communication Control Endpoints
    :id: arch~sovd-api-communication-control-modes
    :status: draft

    To control the communication parameters of an ECU, the path ``/modes/commctrl`` is offered, which can be called
    similarly to Session (without expiration).

    The attribute ``value`` allows the following subfunction names based on the UDS standard:

    * ``enableRxAndEnableTx``
    * ``enableRxAndDisableTx``
    * ``disableRxAndEnableTx``
    * ``disableRxAndDisableTx``

    Matching 28\ :sub:`16` service entries must be present in the diagnostic description. Parameters can be provided
    through an additional ``parameters`` attribute.

    .. note::
       Other values are not supported.


DTC Setting -- SID 85\ :sub:`16`
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. arch:: DTC Setting Endpoints
    :id: arch~sovd-api-dtc-setting-modes
    :status: draft

    To control the DTC settings of an ECU, the path ``/modes/dtcsetting`` is offered, which can be called
    similarly to Session (without expiration).

    The attribute ``value`` allows the values ``off`` and ``on``, to call the corresponding subfunctions on the ECU.

    Matching 85\ :sub:`16` service entries must be present in the diagnostic description. Parameters can be provided
    through an additional ``parameters`` attribute.

    .. note::
       Other specific extensions to the values are not supported.


Faults -- SID 14\ :sub:`16` & 19\ :sub:`16`
-------------------------------------------

.. arch:: Faults endpoint
    :id: arch~sovd-api-faults-endpoint
    :status: draft

    The following operations must be implemented:

    .. list-table:: Faults endpoints
       :header-rows: 1

       * - Method
         - Path
         - Description
       * - GET
         - ``/faults``
         - Retrieves a list of DTCs stored in the ECU:

           - To filter the DTCs, the query parameter ``status`` can be used.
       * - GET
         - ``/faults/<dtc>``
         - Retrieves detailed information about the DTC:

           - Can include snapshot and extended data within the ``environment_data`` object, when the query parameter
             ``include-extended-data`` or ``include-snapshot`` are set to true.
       * - DELETE
         - ``/faults``
         - Clears all DTCs stored in the ECU
       * - DELETE
         - ``/faults/<dtc>``
         - Clears the provided DTC from the ECU

    The query parameter ``status[<key>]=<value>`` can be used to query/filter the returned DTCs based on their status.
    It can be used multiple times to combine different status flags. The values correspond to the DTC status bits
    defined in ISO 14229-1.

    Available keys:

    - confirmedDtc
    - pendingDtc
    - testFailed
    - testFailedSinceLastClear
    - testFailedThisOperationCycle
    - testNotCompletedSinceLastClear
    - testNotCompletedThisOperationCycle
    - warningIndicatorRequested

    All values are either boolean values (true/false), or a bit value (0/1).

    Additionally, a special key called ``mask`` is available, which takes a hexadecimal mask as a value
    to allow filtering by the complete status byte. Using other keys together with ``mask`` is not supported.


Error Codes & Messages
----------------------

.. todo:: define
