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

Traceability
============

Traceability in software development refers to the ability to link various artifacts and components
of a software project throughout its lifecycle. This includes requirements, architecture, design documents,
code and tests.

In this project, traceability is achieved through the use of `sphinx-needs`_ tools.

.. _sphinx-needs: https://sphinx-needs.readthedocs.io


Traceability Conventions
------------------------

Types
^^^^^

.. list-table:: Need Types and ID Patterns
   :header-rows: 1

   * - Need Type
     - Description
     - ID Pattern
   * - req
     - Software Requirement
     - ``req~<short-description>``
   * - arch
     - Software Architecture
     - ``arch~<short-description>``
   * - impl
     - Implementation
     - ``impl~<short-description>``
   * - dimpl
     - Detailed Design & Implementation
     - ``dimpl~<short-description>``
   * - dsgn
     - Detailed Design
     - ``dsgn~<short-description>``
   * - testset
     - Test Set (group of unit and integration tests)
     - ``testset~<short-description>``
   * - test
     - Unit Test
     - ``test~<short-description>``
   * - itest
     - Integration Test
     - ``itest~<short-description>``

Short description must only contain letters, numbers, and hyphens.

Generally speaking every requirement should be traced through architecture, design, implementation and tests. The
design and implementation can be combined if desired. In trivial cases, it is acceptable to skip architecture and/or
design.

**Link direction**

Links always point from the higher abstraction level to the lower one; the reverse direction is derived automatically
by sphinx-needs:

.. code:: text

    req -> arch -> dsgn -> impl/dimpl
           arch/dsgn -> testset -> test/itest

Tests (``test``/``itest``) are not linked individually from requirements, architecture or design. They are grouped in
``testset`` items in ``docs/05_verification/``, which link down to the tests. Architecture and design items link to
the test set(s) verifying them. Requirements may also link to test sets (allowed, but not enforced at this time). Implementation items (``impl``/``dimpl``) must not link to test sets; link the test set
from the ``arch`` or ``dsgn`` item instead, so verification is readable next to the architecture/design. Same-level links are allowed, but must not form cycles. This is enforced
by ``check_link_direction`` in ``docs/conf.py``; violations fail the ``-W`` documentation build.

**Rationale**

Combining design and implementation reduces overhead, and is acceptable when the design is straightforward, and
it's easier to show the design in code comments than in separate documents.

Properties
^^^^^^^^^^

This section documents the metadata properties used on sphinx-needs items to support
Automotive SPICE (ASPICE) process compliance. These properties enable consistent
classification, maturity tracking, and review workflows across all documentation artifacts.


Status
""""""

The ``:status:`` option tracks the maturity of each documentation item through its lifecycle.
It applies to all need types (``req``, ``arch``, ``dsgn``, ``impl``, ``dimpl``, ``testset``, ``test``, ``itest``).

.. list-table:: Allowed Status Values
   :header-rows: 1
   :widths: 15 60 25

   * - Status
     - Description
     - Applies To
   * - ``draft``
     - Item is being written or is incomplete. Content may change significantly.
       This is the default status for newly created items.
     - All need types
   * - ``valid``
     - Item has been reviewed and is considered correct and complete.
       Content accurately reflects the intended behavior or design.
     - All need types
   * - ``approved``
     - Item has been formally approved by a reviewer or stakeholder.
       Content is frozen and may only change through a formal change request.
     - All need types
   * - ``rejected``
     - Item has been reviewed and rejected. The item needs rework before
       it can be accepted.
     - All need types
   * - ``obsolete``
     - Item is no longer applicable. It is retained for historical reference
       but should not be relied upon.
     - All need types

Items without an explicit ``:status:`` should be treated as ``draft``.

Lifecycle
"""""""""

The typical status progression for an item is:

.. code-block:: text

    draft --> valid --> approved

Items may transition to ``rejected`` from ``draft`` or ``valid`` during review.
Items may transition to ``obsolete`` from any status when they are superseded or no longer needed.

**Usage Example**

.. code-block:: rst

    .. req:: Example Requirement
        :id: req~example
        :status: draft

        The system must do something.


Requirement Type
^^^^^^^^^^^^^^^^

The ``:type:`` option classifies requirements by their nature. This is primarily relevant
for ``req`` needs, but may optionally be applied to ``arch`` and ``dsgn`` items for
additional classification.

.. list-table:: Allowed Requirement Type Values
   :header-rows: 1
   :widths: 20 80

   * - Type
     - Description
   * - ``functional``
     - Describes a behavior or capability the system must provide.
       Functional requirements define *what* the system does in response to inputs or conditions.
   * - ``non-functional``
     - Describes a quality attribute such as performance, reliability, availability, security,
       or maintainability. Non-functional requirements define *how well* the system performs.
   * - ``interface``
     - Describes an external interface or API contract. Interface requirements define the
       boundaries and communication protocols between the system and external entities.
   * - ``constraint``
     - Describes a design or implementation constraint imposed by the environment, standards,
       or organizational policies. Constraints limit the solution space without describing
       system behavior.

**Usage Example**

.. code-block:: rst

    .. req:: HTTP-Server
        :id: req~sovd-api-http-server
        :status: valid
        :type: functional

        The CDA must provide an HTTP- or HTTPS-server.




Code
""""

Code can be added to the traceability by utilizing sphinx-codelinks. The short format in a comment is as follows:

``[[ <ID of the need>, <title>, <type>, <links> ]]``

One-Line Example:

.. code:: rust

    /// [[ dimpl~sovd-api-https-certificates, Handle HTTPS Certificates, dimpl ]]
    /// description of the function
    fn handle_certificates() {
        ...
    }

The matching ``arch`` (or ``dsgn``) item links to both the implementation and the test set verifying it:

.. code:: rst

    .. arch:: HTTPS Certificates
        :id: arch~sovd-api-https-certificates
        :links: dimpl~sovd-api-https-certificates, testset~sovd-api-https-certificates
        :status: draft

Test example (tests carry no links, they are referenced from a ``testset``):

.. code:: rust

    /// [[ test~sovd-api-https-certificates-expired, Expired certificates are rejected, test ]]
    #[test]
    fn expired_certificates_are_rejected() {
        ...
    }

.. note::
   type and links are optional, if left empty, type will be ``dimpl``. Links must only point downwards, see the
   link direction rules above.

   multi-line definitions are not supported at the time of writing by the ``src-trace`` directive.


Overviews
^^^^^^^^^

**Software Requirements**

.. needtable:: Software Requirements overview
   :types: req
   :columns: id, title, status

**Software Architecture**

.. needtable:: Software Architecture overview
   :types: arch
   :columns: id, title, status

**Detailed Design**

.. needtable:: Detailed Design
   :types: dsgn, dimpl
   :columns: id, title, status

**Implementation**

.. needtable:: Implementation
   :types: impl, dimpl
   :columns: id, title, status

**Test Sets**

.. needtable:: Test Sets
   :types: testset
   :columns: id, title, status

**Unit Tests**

.. needtable:: Unit-Tests
   :types: test
   :columns: id, title, status

**Integration Tests**

.. needtable:: Integration-Tests
   :types: itest
   :columns: id, title, status


Traceability Gaps
^^^^^^^^^^^^^^^^^

**Requirements without Architecture (SWE.2)**

.. needtable:: Requirements without architecture
   :filter: type == 'req' and not any(link.startswith('arch~') for link in links)
   :columns: id, title, status

**Architecture not traced to any requirement (SWE.2)**

.. needtable:: Architecture without requirement
   :filter: type == 'arch' and not any(link.startswith('req~') for link in links_back)
   :columns: id, title, status

**Architecture without detailed design or implementation (SWE.3)**

.. needtable:: Architecture without design or implementation
   :filter: type == 'arch' and not any(link.startswith('dsgn~') or link.startswith('dimpl~') or link.startswith('impl~') for link in links)
   :columns: id, title, status

**Requirements without tests (SWE.4/SWE.5)**

Requirements are covered if they, or an architecture item linked from them, link to at least one test set.

.. needtable:: Requirements without test set
   :filter: type == 'req' and not any(link.startswith('testset~') for link in links)
   :columns: id, title, status

**Architecture without tests (SWE.4/SWE.5)**

.. needtable:: Architecture without test set
   :filter: type == 'arch' and not any(link.startswith('testset~') for link in links)
   :columns: id, title, status

**Tests not part of any test set (SWE.4/SWE.5)**

.. needtable:: Tests without test set
   :filter: (type == 'test' or type == 'itest') and not any(link.startswith('testset~') for link in links_back)
   :columns: id, title, status

**Test sets not linked from any requirement, architecture or design (SWE.4/SWE.5)**

.. needtable:: Unreferenced test sets
   :filter: type == 'testset' and not any(link.startswith('req~') or link.startswith('arch~') or link.startswith('dsgn~') for link in links_back)
   :columns: id, title, status

**Test sets without tests (SWE.4/SWE.5)**

.. needtable:: Empty test sets
   :filter: type == 'testset' and not any(link.startswith('test~') or link.startswith('itest~') for link in links)
   :columns: id, title, status
