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

ECU Variant Detection
---------------------

.. arch:: ECU Variant Detection via SOVD-API
    :id: arch~sovd-api-ecu-variant-detection
    :status: draft
    :links: dimpl~sovd-api-ecu-variant-detection

    **Motivation**

    Some ECUs have different variants, which support different functionality. To provide the correct functionality,
    the CDA needs to be able to detect the variant in use. This variant may change at any point due to the nature of
    the ECUs software. Clients may need to trigger this explicitly to ensure correct functionality.

    **Variant Detection Trigger**

    A PUT on the path ``/components/{ecuName}`` must trigger a variant detection

    .. uml:: /03_architecture/02_sovd-api/03_extensions/images/ecu_variant_detection.puml

Binary Encoding
---------------

.. arch:: Configurable Binary Encoding of A_BYTEFIELD Values
    :id: arch~sovd-api-binary-encoding
    :status: draft
    :links: dimpl~sovd-api-binary-encoding-type, dimpl~sovd-api-binary-encoding-selection, dimpl~sovd-api-binary-encoding-config, testset~sovd-api-binary-encoding

    **Motivation**

    ISO 17978-3 represents binary data (``A_BYTEFIELD``) as base64 (format ``byte``). Some offboard testers
    and humans debugging the API prefer hexadecimal data, see :ref:`requirements_sovd_api_bytefield_as_hex`.

    **Encodings**

    .. list-table:: Binary encodings
       :header-rows: 1

       * - Encoding
         - JSON schema format
         - Output
         - Accepted input
       * - ``base64`` (default)
         - ``byte``
         - RFC 4648 standard alphabet with padding, e.g. ``AQI=``
         - Standard or URL safe alphabet, padding optional
       * - ``hex``
         - ``hex``
         - Upper case, ``0x`` prefixed bytes separated by spaces, e.g. ``0x01 0x02``
         - Tokens separated by spaces or commas, ``0x`` prefix optional, e.g. ``0102``, ``01,02``

    **Selection**

    The default encoding is configured in the server section, independent of the transport (TCP or Unix
    domain socket):

    .. code-block:: toml

       [server]
       binary_encoding = "base64"  # or "hex"

    A client can override the default per request with the query parameter
    ``x-sovd2uds-binary-encoding=base64|hex`` (value case-insensitive). An unknown or repeated value is
    rejected with ``400 Bad Request``. The configured default is attached to every request by the HTTP server,
    so routes registered later (e.g. by plugins via the dynamic router) use it as well.

    .. uml:: /03_architecture/02_sovd-api/03_extensions/images/binary_encoding.puml

    **Scope**

    The selected encoding applies to all ``A_BYTEFIELD`` values the SOVD-API exchanges with the client:

    * Request parameters, including nested structures, multiplexers and fields
    * Response parameters, including nested and repeating structures
    * Security access seeds and keys, authentication parameters
    * DTC extended and snapshot data
    * JSON schemas: ``A_BYTEFIELD`` values are described as ``string`` with the format of the selected encoding,
      their ``default`` values are converted into that encoding

    Values originating from the diagnostic database (physical default values, coded constants, variant
    detection patterns) are always interpreted as hex, independent of the selected encoding. Internal callers
    that build parameters programmatically use hex as well.

    **Asynchronous Executions**

    Results of asynchronous operations are stored and may be queried later with a different encoding than the
    request that started the execution. Since ``A_BYTEFIELD`` values cannot be identified in already mapped
    JSON, the decoded UDS response is stored instead and mapped to JSON when it is read, in the encoding of the
    reading request. Each request maps the response once, independent of the number of supported encodings.
