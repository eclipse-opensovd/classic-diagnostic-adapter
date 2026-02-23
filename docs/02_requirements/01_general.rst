.. SPDX-License-Identifier: Apache-2.0
.. SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
..
.. See the NOTICE file(s) distributed with this work for additional
.. information regarding copyright ownership.
..
.. This program and the accompanying materials are made available under the
.. terms of the Apache License Version 2.0 which is available at
.. https://www.apache.org/licenses/LICENSE-2.0

General
=======

Tracing
-------

Tracing between requirements, architecture, design, implementation & tests is facilitated with `sphinx-needs`_.

.. _sphinx-needs: https://sphinx-needs.readthedocs.io


Configuration
-------------

The CDA must support a configuration file that allows it to be configured to the use-cases of different users.

This includes, but is not limited to:

* network interfaces
* ports
* communication behaviour

  * communication parameters (includes timeouts)
  * initial discovery/detection of ecus


Performance
-----------

The CDAs primary target is an embedded HPC that runs on the vehicle with Linux. Primary target architectures are
aarch64, and x86_64. It should be noted, that those HPCs typically have lower memory and worse cpu performance
compared to desktop machines, and might run other (higher prioritized) software in parallel.

CPU & Memory
^^^^^^^^^^^^

CPU and memory consumption need to be minimal to allow other tasks on that HPC to perform well.

Parallelity
^^^^^^^^^^^

The CDA must be able to communicate at least with 50 DoIP entities, and up to 200 ECUs behind those entities.

The maximum number of parallel threads used in the asynchronous communication should be configurable.

Modularity
^^^^^^^^^^

The architecture must allow parts of it to be reusable for other use-cases. It's also required that the internal
modules can be interchanged at compile time with other ones, by implementing the well-defined API of that module.

Logging
^^^^^^^

The CDA must provide logging capabilities, which allow tracing of events, errors, and debug information.
The logging system must be configurable in terms of log levels and outputs, to adapt to different deployment scenarios.

System
------

Storage Access
^^^^^^^^^^^^^^

.. req:: Storage Access Abstraction
    :id: req~system-storage-access-abstraction
    :links: arch~system-storage-access-abstraction

    The CDA must provide an abstraction layer for storage access, which allows it to interact with different types of
    storage systems (e.g., local file system, databases) without being tightly coupled to a specific implementation.

    This abstraction layer should provide a consistent API for reading and writing data, as well as handling errors
    and exceptions related to storage operations. The semantics of the API must be well-defined, to ensure atomicity of
    its operations, and to allow for consistent behavior across different storage implementations.


.. req:: Local File System Storage Access Implementation
    :id: req~system-default-local-file-system-storage-access

    A default implementation for local file system access, utilizing the Storage Access Abstraction must be provided.



Extensibility
-------------

Plugin system
^^^^^^^^^^^^^

A comprehensive plugin API must be provided, which allows vendors to extend the functionality.
See :ref:`requirements-plugins` for details.
