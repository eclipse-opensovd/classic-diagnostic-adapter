.. SPDX-License-Identifier: Apache-2.0
.. SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
..
.. See the NOTICE file(s) distributed with this work for additional
.. information regarding copyright ownership.
..
.. This program and the accompanying materials are made available under the
.. terms of the Apache License Version 2.0 which is available at
.. https://www.apache.org/licenses/LICENSE-2.0

Traceability
============

Traceability in software development refers to the ability to link various artifacts and components
of a software project throughout its lifecycle. This includes requirements, architecture, design documents,
code and tests.

In this project, traceability is achieved through the use of `sphinx-needs`_ tools.

.. _sphinx-needs: https://sphinx-needs.readthedocs.io


Conventions
===========

Types
-----

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

**Rationale**

Combining design and implementation reduces overhead, and is acceptable when the design is straightforward, and
it's easier to show the design in code comments than in separate documents.

Properties
----------

This section documents the metadata properties used on sphinx-needs items to support
Automotive SPICE (ASPICE) process compliance. These properties enable consistent
classification, maturity tracking, and review workflows across all documentation artifacts.


Status
^^^^^^

The ``:status:`` option tracks the maturity of each documentation item through its lifecycle.
It applies to all need types (``req``, ``arch``, ``dsgn``, ``impl``, ``dimpl``, ``test``, ``itest``).

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
^^^^^^^^^

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
----------------

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
^^^^

Code can be added to the traceability by utilizing sphinx-codelinks. The short format in a comment is as follows:

``[[ <ID of the need>, <title>, <type>, <links> ]]``

One-Line Example:

.. code:: rust

    /// [[ dimpl~sovd.api.https.certificates, Handle HTTPS Certificates, dimpl, test~sovd.api.https.certificates ]]
    /// description of the function
    fn test {
        ...
    }

.. note::
   type and links are optional, if left empty, type will be ``dimpl``

   multi-line definitions are not supported at the time of writing by the ``src-trace`` directive.


Overviews
---------

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

**Unit Tests**

.. needtable:: Unit-Tests
   :types: test
   :columns: id, title, status

**Integration Tests**

.. needtable:: Integration-Tests
   :types: itest
   :columns: id, title, status
