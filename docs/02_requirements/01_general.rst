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

Extensibility
-------------

Plugin system
^^^^^^^^^^^^^

A comprehensive plugin API must be provided, which allows vendors to extend the functionality.
See :ref:`requirements-plugins` for details.
