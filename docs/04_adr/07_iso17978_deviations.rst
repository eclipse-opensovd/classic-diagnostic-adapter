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

ADR-007: Deliberate Deviations from ISO 17978-3
================================================

Status
------

**Proposed**

Date: 2026-10-27

Context
-------

The CDA implements the SOVD API as specified in ISO 17978-3. The conformance
audit in classic-diagnostic-adapter#553 compares the wire model and routes with
the standard table by table. Most departures it found are defects and are
tracked for fixing in classic-diagnostic-adapter#600.

A small number of departures are intentional. Each one is a point where the
project has decided, for a stated reason, to keep behaviour the standard does
not specify or specifies differently. Without a single record, such a departure
is indistinguishable from an oversight: it is re-reported in every audit,
re-argued in every review, and at risk of being "fixed" by a contributor who
does not know the history.

This ADR is that record. It lists every deliberate deviation, what the
standard says, what the CDA does instead, why, and what a client has to expect.
A departure that is not listed here is a defect.

Decision
--------

The CDA conforms to ISO 17978-3 except for the deviations recorded in this
ADR. Each entry names the clause or table it departs from and the requirement
that specifies the CDA behaviour, so that the requirement, the implementation
and this record cannot drift apart silently.

Adding a deviation requires a change to this ADR in the same pull request as
the behaviour. Removing one requires removing it here as well.

Deviation 1: HTTP 423 for lock conflicts
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Standard.** §7.17.1: a client accessing a resource that requires a lock it
does not hold receives 409 (Conflicted). The same status is used when a lock
cannot be acquired because the scope is already locked by a different client
(Table 241).

**CDA.** Both cases answer **423 (Locked)** with ``error_code:
precondition-not-fulfilled`` and, when a vendor policy denied the request,
``vendor_code: lock-priority-denied``.

**Reason.** Existing clients depend on 423. It is also the more specific
signal: it separates "locked by another client" from the other 409 causes in
Table 241 without the client having to inspect ``vendor_code``.

**Client impact.** A generic SOVD client that handles only 409 will treat 423
as an unexpected status. Clients written for the CDA should handle both.

**Record.** :need:`req~sovd-api-lock-exclusivity`,
:need:`req~sovd-api-lock-priority`.

Deviation 2: Custom properties are not prefixed
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Standard.** §5.4.5 requires custom resources, collections and top-level
resources to be named ``x-<ext>-<name>``, where ``<ext>`` identifies the
source of the extension. §7.9.1 requires custom data categories to carry the
prefix ``x-<ext>-``. The standard's own extension attributes
(``x-sovd-unit``, ``x-sovd-tags``) follow the same form, which makes it the
document's pattern for custom body attributes as well, although no clause
mandates it there.

**CDA.** The ``x-sovd2uds-`` prefix is used where it already exists and is
not enforced on custom or free-text properties. Unprefixed or partially
prefixed names remain: ``sdgs`` and ``x-errorsource`` as body attributes, the
``x-single-ecu-jobs`` collection, and the ``parameters`` / ``errors``
attributes added to the asynchronous operation start response. Custom data
categories are accepted as given.

**Reason.** Renaming is a breaking change for every client that reads these
names, and the prefix does not change what a generic client can do with a
property it does not know: it ignores it either way.

**Client impact.** A client cannot rely on the ``x-`` prefix to recognise CDA
extensions. The capability description and the OpenAPI document are the
authoritative list of what the CDA serves.

**Record.** This ADR. The affected names are listed in
classic-diagnostic-adapter#553 under "Accepted deviations".

Rationale
---------

A single register is cheaper than the alternatives. Scattering the decisions
across requirement rationales leaves no place to answer "where does the CDA
deviate from the standard" in one read. Treating them as open defects keeps
re-reporting what has already been decided. Not recording them at all is how
the 423 question reached a pull-request review a second time.

Tying each entry to a requirement means the deviation has an owner in the
requirements model and shows up in traceability, not only in prose.

Consequences
------------

* The conformance statement for the CDA becomes "ISO 17978-3 except ADR-007".
* Audits against the standard compare against this list first; a departure
  listed here is not a finding.
* Each new deviation costs one ADR edit, which is intended: the cost is the
  review.
* Clients targeting the CDA get one document that tells them where a generic
  SOVD client would misbehave.

References
----------

* ISO 17978-3, §5.4.5, §7.9.1, §7.17.1, Table 241
* classic-diagnostic-adapter#553 (conformance audit), #600 (P0 work list)
