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

Introduction
------------

Eclipse OpenSOVD Classic Diagnostic Adapter aims to be compatible with the ISO/DIS 17978-3:2025 SOVD standard.

This chapter specifies the specific implementation of that standard, as well as extensions to it, which are required for some use-cases.

HTTP
----

.. arch:: SOVD-API over HTTP
    :id: arch~sovd-api-http-server
    :links: dimpl~sovd-api-http-server
    :status: draft

    The SOVD-API is based on HTTP/1.1 as transport protocol, and is available through a
    configurable TCP port, or alternatively through a Unix domain socket path. The two
    transports are mutually exclusive: when a Unix domain socket path is configured, it
    takes priority over the TCP host/port.
