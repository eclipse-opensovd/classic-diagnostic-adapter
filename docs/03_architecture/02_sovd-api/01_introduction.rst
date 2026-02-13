.. SPDX-License-Identifier: Apache-2.0
.. SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
..
.. See the NOTICE file(s) distributed with this work for additional
.. information regarding copyright ownership.
..
.. This program and the accompanying materials are made available under the
.. terms of the Apache License Version 2.0 which is available at
.. https://www.apache.org/licenses/LICENSE-2.0

Introduction
------------

Eclipse OpenSOVD Classic Diagnostic Adapter aims to be compatible with the ISO/DIS 17978-3:2025 SOVD standard.

This chapter specifies the specific implementation of that standard, as well as extensions to it, which are required for some use-cases.

HTTP
----

.. arch:: SOVD-API over HTTP
    :id: arch~sovd-api-http-server
    :links: dimpl~sovd-api-http-server

    The SOVD-API is based on HTTP/1.1 as transport protocol, and available through an configurable TCP port.
