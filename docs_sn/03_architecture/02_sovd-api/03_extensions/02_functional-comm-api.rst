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

Functional communication
------------------------

.. swarch:: Diagnostic description & Configuration
    :id: swarch~functional-communication-dd-configuration

    Information about the available functional groups, the available services in those groups, and their communication parameters must be provided in a separate diagnostic description.

    The diagnostic descriptions mdd filename, in which the information for functional communication is contained, must be configurable. When no file is configured, functional communication is not available.

    A configuration option in the CDA can further filter the available functional groups from the diagnostic description.

    **Rationale**

    Extracting a standardized resource collection for functional communication from individual ECU descriptions is challenging and non-transparent when extracting common functional services from all ECU files. Therefore we chose to do this via a separate diagnostic description file.

    This also follows the general pattern of one mdd file to an available standardized resource collection.

API
^^^

.. swarch:: Functional Communication API
    :id: swarch~functional-communication-api
    :links: swarch~functional-communication-locks, swarch~functional-communication-data, swarch~functional-communication-operations, swarch~functional-communication-modes

    Functional group functionality - if available - must be available in the ``/functions/functionalgroups/{group-name}`` path.

    Within that path, a standardized resource collection (chapter 5.4.2 in ISO/DIS 17978-3) must be available, with the linked semantics.


.. swarch:: Functional Communication ECU-Lock behavior
    :id: swarch~functional-communication-locks

    Locking a functionalgroup will start the sending of functional Tester Presents to the functional DoIP addresses of all DoIP Entities, and stop sending of non-functional tester-presents.

    **Lock Options**

    There can be an option to restore the previous ECU-Locks (and their tester presents).


.. swarch:: Functional Communication - Data
    :id: swarch~functional-communication-data

    **Data**

    Since functional communication returns data from multiple ECUs, the ``/data/{data-identifier}`` endpoint must return within the top-level of ``data`` the name of the ECU as key, and only then its returned data (if any) as value.

    In case of errors, the ``errors`` structures must still return the type ``DataError[]``. Inside a ``DataError``, the json-pointer must always point to the ``data/{ecu-name}/...`` element (including the ECU-Name), or in case of communication/timeout errors, just to the ECU-Entry ``/data/{ecu-name}``. A regular GenericError response with a failing HTTP Status Code (4xx, 5xx) is only acceptable, when no communication was performed, and the request failed beforehand.

    .. note::
       The content-type ``application/octet-stream`` is only supported for requests.


.. swarch:: Functional Communication - Operations
    :id: swarch~functional-communication-operations

    Same principle as with data, except that the top level element name is ``parameters``.

    .. note::
       The content-type ``application/octet-stream`` is only supported for requests.


.. swarch:: Functional Communication - Modes
    :id: swarch~functional-communication-modes

    The following modes must be supported for functional groups, when the underlying diagnostic description contains them:

     1. session,
     2. dtcsetting
     3. commctrl
