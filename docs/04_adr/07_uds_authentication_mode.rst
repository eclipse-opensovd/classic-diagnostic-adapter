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

ADR-007: UDS Authentication as Separate, Client-Driven Mode
===========================================================

Status
------

**Accepted**

Date: 2026-10-09

.. note::
   This decision was discussed and accepted previously. It was recorded as an ADR on the date above.

Context
-------

UDS Authentication (SID 29\ :sub:`16`, ISO 14229-1 clause 10.6) authenticates a client towards an
ECU using either a PKI certificate exchange or a challenge-response procedure. Both procedures
consist of several request/response steps and require a private key on the client side.

ISO 17978-3 maps SID 27\ :sub:`16` and SID 29\ :sub:`16` to ``/modes/security`` in Table 343,
while clauses 8.3.2 and 8.3.3 describe security access and authentication separately. Clause
8.3.3 further leaves open whether the SOVD server or the client drives the authentication
procedure.

The authenticated state of the ECU is independent of the diagnostic session and the security
access level (ISO 14229-1 clause 10.6.4).

The externally visible behavior is specified by :need:`req~sovd-api-authentication-modes`.

Decision
--------

1. SID 29\ :sub:`16` is exposed as a separate mode ``/modes/authentication``. SID 27\ :sub:`16`
   remains at ``/modes/security``.
2. The procedure is client-driven: each ``PUT`` is translated into exactly one UDS
   Authentication request. The client provides and verifies all certificates, challenges and
   proofs of ownership. The CDA neither stores nor uses private keys.
3. The CDA tracks the authentication state confirmed by the ECU, including an optional
   expiration requested by the client (``mode_expiration``, as for sessions). It sends
   ``deAuthenticate`` when the expiration elapses, when the lock is released or expires, and
   during ECU cleanup.
4. ``PUT /modes/authentication`` requires the ECU lock, like other write operations.

Alternatives Considered
-----------------------

**Map SID 29**\ :sub:`16` **to** ``/modes/security`` **(ISO 17978-3 Table 343)**
    Rejected. Security access is modeled as levels with RequestSeed/SendKey pairs. The
    authentication sub-functions and procedures do not fit this model, and the resulting
    ``value`` semantics would be ambiguous.

**CDA-driven procedure with credentials provided by a plugin**
    Rejected for now. It requires secret storage and signing in the CDA or a plugin, and fixes
    the supported procedures in the CDA. It can be added later as an extension without changing
    the endpoint defined here.

**No state tracking in the CDA**
    Rejected. Without tracking, the CDA cannot deauthenticate on lock release, and a following
    client could inherit the authenticated state of the previous one.

Consequences
------------

* Clients must implement the multi-step procedures and the cryptographic operations.
* The diagnostic description must contain a separate service for every used sub-function.
* The tracked state is informational: authentication timeouts or ECU internal events may end
  the authenticated state without the CDA noticing it immediately.
* The deviation from ISO 17978-3 Table 343 must be documented for clients.
* ``GET`` reports ``offline`` for unreachable ECUs. Extension fields use the ``x-sovd2uds-``
  prefix.
