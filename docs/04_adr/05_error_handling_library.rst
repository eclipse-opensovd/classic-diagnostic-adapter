.. SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation
..
.. See the NOTICE file(s) distributed with this work for additional
.. information regarding copyright ownership.
..
.. This program and the accompanying materials are made available under the
.. terms of the Apache License Version 2.0 which is available at
.. https://www.apache.org/licenses/LICENSE-2.0
..
.. SPDX-License-Identifier: Apache-2.0

ADR-005: Use thiserror as error handling library
================================================

Status
------

**Accepted**

Date: 2026-07-28

Context
-------

The Classic Diagnostic Adapter needs to provide detailed error information, both via its HTTP endpoints and when used as a library by OEMs to implement their concrete distribution.

The different error cases need to be programmatically matchable, so that consumers can decide whether to retry operations or abort them altogether.


Decision
--------

We will use **thiserror** as the error handling library for the Classic Diagnostic Adapter.

We will explicitly not use **anyhow**, even though it is commonly paired with **thiserror** for use in application code,
because virtually all production code in Classic Diagnostic Adapter can used as a library, when OEMs implement their distribution.


Rationale
---------

Other error handling libraries
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Other error handling libraries such as **snafu** or **eyre** were not evaluated in this decision.


References
----------

- `thiserror <https://crates.io/crates/thiserror>`_
- `anyhow <https://crates.io/crates/anyhow>`_
