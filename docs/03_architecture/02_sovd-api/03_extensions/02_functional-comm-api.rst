.. SPDX-License-Identifier: Apache-2.0
.. SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
..
.. See the NOTICE file(s) distributed with this work for additional
.. information regarding copyright ownership.
..
.. This program and the accompanying materials are made available under the
.. terms of the Apache License Version 2.0 which is available at
.. https://www.apache.org/licenses/LICENSE-2.0

.. _architecture_functional_communication:

Functional communication
------------------------

.. arch:: Diagnostic description & Configuration
    :id: arch~functional-communication-dd-configuration

    Information about the available functional groups, the available services in those groups, and their communication parameters must be provided in a separate diagnostic description.

    The diagnostic description's MDD filename, in which the information for functional communication is contained, must be configurable. When no file is configured, functional communication is not available.

    A configuration option in the CDA can further filter the available functional groups from the diagnostic description.

    **Rationale**

    Extracting a standardized resource collection for functional communication from individual ECU descriptions is challenging and non-transparent when extracting common functional services from all ECU files. Therefore, we chose to do this via a separate diagnostic description file.

    This also follows the general pattern of one MDD file to an available standardized resource collection.

API
^^^

.. arch:: Functional Communication API
    :id: arch~functional-communication-api
    :links: arch~functional-communication-locks, arch~functional-communication-data, arch~functional-communication-operations, arch~functional-communication-modes

    Functional group functionality - if available - must be available in the ``/functions/functionalgroups/{group-name}`` path.

    Within that path, a standardized resource collection (chapter 5.4.2 in ISO/DIS 17978-3) must be available, with the linked semantics.


.. arch:: Functional Communication ECU-Lock behavior
    :id: arch~functional-communication-locks

    Locking a functional group will start sending functional Tester Presents to the functional DoIP addresses of all DoIP Entities, and stop sending non-functional Tester Presents.

    **Lock Options**

    There can be an option to restore the previous ECU locks (and their Tester Presents).


.. arch:: Functional Communication - Data
    :id: arch~functional-communication-data

    **Data**

    Since functional communication returns data from multiple ECUs, the ``/data/{data-identifier}`` endpoint must return, within the top level of ``data``, the name of the ECU as the key, and only then its returned data (if any) as the value.

    In case of errors, the ``errors`` structures must still return the type ``DataError[]``. Inside a ``DataError``, the JSON pointer must always point to the ``data/{ecu-name}/...`` element (including the ECU name), or, in case of communication/timeout errors, just to the ECU entry ``/data/{ecu-name}``. A regular GenericError response with a failing HTTP status code (4xx, 5xx) is only acceptable when no communication was performed and the request failed beforehand.

    .. note::
       The content-type ``application/octet-stream`` is only supported for requests.


.. arch:: Functional Communication - Operations
    :id: arch~functional-communication-operations

    Same principle as with data, except that the top-level element name is ``parameters``.

    .. note::
       The content-type ``application/octet-stream`` is only supported for requests.


.. arch:: Functional Communication - Modes
    :id: arch~functional-communication-modes

    The following modes must be supported for functional groups when the underlying diagnostic description contains them:

     1. session
     2. dtcsetting
     3. commctrl
