.. SPDX-License-Identifier: Apache-2.0
.. SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
..
.. See the NOTICE file(s) distributed with this work for additional
.. information regarding copyright ownership.
..
.. This program and the accompanying materials are made available under the
.. terms of the Apache License Version 2.0 which is available at
.. https://www.apache.org/licenses/LICENSE-2.0

ECU Variant Detection
---------------------

.. arch:: ECU Variant Detection via SOVD-API
    :id: arch~sovd-api-ecu-variant-detection

    **Motivation**

    Some ECUs have different variants, which support different functionality. To provide the correct functionality,
    the CDA needs to be able to detect the variant in use. This variant may change at any point due to the nature of
    the ECUs software. Clients may need to trigger this explicitly to ensure correct functionality.

    **Variant Detection Trigger**

    A POST on the path ``/components/{ecuName}`` must trigger a variant detection
