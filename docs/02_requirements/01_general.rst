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

Parallelism
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
The logging system must be an configurable in terms of log levels and outputs, to adapt to different deployment scenarios.

System
------

Storage Access
^^^^^^^^^^^^^^

.. req:: Storage Access Abstraction
    :id: req~system-storage-access-abstraction
    :links: arch~system-storage-access-abstraction
    :status: draft

    The CDA must provide an abstraction layer for storage access, which allows it to interact with different types of
    storage systems (e.g., local file system, databases) without being tightly coupled to a specific implementation.

    This abstraction layer should provide a consistent API for reading and writing data, as well as handling errors
    and exceptions related to storage operations. The semantics of the API must be well-defined, to ensure atomicity of
    its operations, and to allow for consistent behavior across different storage implementations.


.. req:: Local File System Storage Access Implementation
    :id: req~system-default-local-file-system-storage-access
    :status: draft

    A default implementation for local file system access, utilizing the Storage Access Abstraction must be provided.


Persistence
^^^^^^^^^^^

.. req:: Persistence API
    :id: req~system-persistence-api
    :links: arch~system-persistence-api
    :reqtype: functional
    :status: draft

    The CDA shall provide a persistence API for durable key-value storage. Data shall be organized into Buckets, where
    each Bucket represents a named, logically separated collection of key-value pairs. The API shall support
    creating and opening Buckets, as well as performing get, set, delete, and contains operations on entries within
    a Bucket.

    The API shall provide a flush operation that explicitly persists all buffered data to the underlying storage media.
    This allows callers to guarantee durability at defined points, such as during shutdown or for security-critical
    data that must not be lost.

    The concrete persistence implementation shall be provided by an exchangeable provider, allowing different storage
    backends to be used without changing consuming code.


.. req:: Default redb Persistence Provider
    :id: req~system-default-redb-persistence-provider
    :links: arch~system-default-redb-persistence-provider
    :reqtype: functional
    :status: draft

    A default persistence provider implementation using `redb`_ shall be provided. This provider shall implement the
    persistence API, mapping Buckets to redb tables and storing key-value pairs with ACID transaction guarantees.

    .. _redb: https://www.redb.org

    Writes to the underlying storage media shall be minimized to reduce wear on flash-based storage typically found
    in embedded devices.


Systemd Watchdog Integration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. req:: Systemd Watchdog Integration
    :id: req~system-sd-notify-watchdog-integration
    :links: arch~system-sd-notify-watchdog-integration
    :status: draft

    When the CDA is running as a systemd service with watchdog enabled, it must periodically aggregate the health status
    of all registered health providers and send appropriate sd_notify notifications to systemd:

    * **Ready** - when the aggregated health transitions from starting to healthy.
    * **Watchdog** - while the aggregated health remains healthy.
    * **WatchdogTrigger** - when the aggregated health degrades to failed, causing systemd to restart the service.

    The notification interval must be derived from the systemd-configured watchdog timeout to ensure timely delivery.

    When systemd is not detected or the watchdog is not enabled, the CDA must operate normally without watchdog
    integration.


Extensibility
-------------

Plugin system
^^^^^^^^^^^^^

A comprehensive plugin API must be provided, which allows vendors to extend the functionality.
See :ref:`requirements-plugins` for details.
