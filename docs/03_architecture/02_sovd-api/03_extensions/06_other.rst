.. SPDX-License-Identifier: Apache-2.0
.. SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
..
.. See the NOTICE file(s) distributed with this work for additional
.. information regarding copyright ownership.
..
.. This program and the accompanying materials are made available under the
.. terms of the Apache License Version 2.0 which is available at
.. https://www.apache.org/licenses/LICENSE-2.0

Version Endpoint
----------------

.. arch:: API Version Endpoint
    :id: arch~sovd-api-version-endpoint
    :links: req~sovd-api-version-endpoint; dimpl~sovd-api-version-endpoint; itest~sovd-api-version-endpoint
    :status: draft

    The CDA provides a static data endpoint that returns version information about the running instance.

    **Paths**

    The version data is served on two paths:

    - ``/apps/sovd2uds/data/version`` -- application-scoped version endpoint
    - ``/data/version`` -- global version endpoint

    Both endpoints return the same data and behave identically.

    **Response Structure**

    The response contains the following fields:

    .. list-table:: Version response fields
       :header-rows: 1

       * - Field
         - Description
       * - id
         - Always ``version``
       * - data.name
         - The implementation name of the CDA
       * - data.api.version
         - The SOVD API version supported by this instance
       * - data.implementation.version
         - The software version of the CDA
       * - data.implementation.commit
         - The Git commit hash of the build
       * - data.implementation.build_date
         - The date the binary was built

    The endpoint is registered as a static data endpoint during initialization and does not require
    any ECU communication. It is available immediately after the HTTP server starts.


ECU Variant Detection
---------------------

.. arch:: ECU Variant Detection via SOVD-API
    :id: arch~sovd-api-ecu-variant-detection
    :status: draft

    **Motivation**

    Some ECUs have different variants, which support different functionality. To provide the correct functionality,
    the CDA needs to be able to detect the variant in use. This variant may change at any point due to the nature of
    the ECUs software. Clients may need to trigger this explicitly to ensure correct functionality.

    **Variant Detection Trigger**

    A POST on the path ``/components/{ecuName}`` must trigger a variant detection
