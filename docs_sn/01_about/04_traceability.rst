Traceability
============

Traceability in software development refers to the ability to link various artifacts and components
of a software project throughout its lifecycle. This includes requirements, architecture, design documents,
code and tests.

In this project, traceability is achieved through the use of `sphinx-needs`_ tools.

.. _sphinx-needs: https://sphinx-needs.readthedocs.io


Conventions
-----------

Software Requirements need to be documented using the `swreq` need type.

Software Architecture components need to be documented using the `swarch` need type.



Overviews
---------

**Software Requirements**

.. needtable:: Software Requirements overview
   :types: swreq
   :columns: id, title, status

**Software Architecture**

.. needtable:: Software Architecture overview
   :types: swarch
   :columns: id, title, status

**Implementation**

.. needtable:: Implementation
   :types: impl
   :columns: id, title, status
