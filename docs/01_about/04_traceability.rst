Traceability
============

Traceability in software development refers to the ability to link various artifacts and components
of a software project throughout its lifecycle. This includes requirements, architecture, design documents,
code and tests.

In this project, traceability is achieved through the use of `sphinx-needs`_ tools.

.. _sphinx-needs: https://sphinx-needs.readthedocs.io


Conventions
-----------

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


**Code**

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
