.. SPDX-License-Identifier: Apache-2.0
.. SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
..
.. See the NOTICE file(s) distributed with this work for additional
.. information regarding copyright ownership.
..
.. This program and the accompanying materials are made available under the
.. terms of the Apache License Version 2.0 which is available at
.. https://www.apache.org/licenses/LICENSE-2.0

ADR-001: Use mimalloc as Default Memory Allocator
==================================================

Status
------

**Accepted**

Date: 2026-03-06

Context
-------

The Classic Diagnostic Adapter requires efficient memory allocation to handle diagnostic communication workloads. The choice of memory allocator significantly impacts both runtime performance and memory footprint. Two options were evaluated:

1. **mimalloc**: A performance-oriented general-purpose allocator developed by Microsoft Research, which uses arena-based pooling strategies
2. **System allocator**: The native platform allocator (macOS system allocator in this evaluation)

Profiling was conducted on macOS / Apple Silicon (arm64) using Xcode Instruments to compare the two allocators under realistic workload conditions.

Decision
--------

We will use **mimalloc** as the default memory allocator for the Classic Diagnostic Adapter.

The performance advantages of mimalloc outweigh the increased memory overhead. While the system allocator demonstrates better memory efficiency, the ~29% execution time improvement provided by mimalloc is critical for diagnostic operations where response time directly impacts user experience and system throughput.

Rationale
---------

Performance Comparison
^^^^^^^^^^^^^^^^^^^^^^

Comprehensive profiling revealed the following metrics:

.. list-table:: Allocator Performance Comparison
   :header-rows: 1
   :widths: 30 20 20 20

   * - Metric
     - mimalloc
     - System (macOS)
     - Winner
   * - CPU Time
     - 3.35 s
     - 4.33 s
     - mimalloc (29% faster)
   * - Real Memory
     - 400.22 MiB
     - 329.78 MiB
     - System (17% less)
   * - Heap & Anon VM
     - 1.24 GiB
     - 434.01 MiB
     - System (65% less)
   * - Total Allocated
     - 4.29 GiB
     - 3.19 GiB
     - System (26% less)
   * - Allocation Count
     - 7,896
     - 2,273,227
     - mimalloc (287x fewer)
   * - Persistent Allocs
     - 1,084
     - 202,138
     - mimalloc (186x fewer)
   * - Dirty Memory
     - 60.73 MiB
     - 60.01 MiB
     - ~ Tie
   * - Thread Count
     - 15
     - 15
     - Tie
   * - Fragmentation Ratio
     - 0.34% / 0.83%
     - 0.16% / 1.02%
     - Mixed

mimalloc Advantages
^^^^^^^^^^^^^^^^^^^

1. **Execution Speed**: ~29% faster execution time (3.35s vs 4.33s)

   - Fewer, larger allocations with arena-based pooling reduce per-allocation overhead
   - Critical for diagnostic operations requiring low latency

2. **Reduced System Calls**: Drastically fewer allocation syscalls (~8K vs ~2.3M)

   - Batches allocations into large arenas, reducing kernel interaction
   - Approximately 287x fewer allocations significantly reduces context switching overhead
   - 186x fewer persistent allocations simplify memory management

System Allocator Advantages
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

1. **Virtual Memory Usage**: ~65% less virtual memory (434 MiB vs 1.24 GiB)

   - Does not pre-reserve large arenas; allocates only what is needed
   - More conservative approach to address space usage

2. **Resident Memory**: ~17% lower physical memory footprint (329.78 MiB vs 400.22 MiB)

   - Tighter memory utilization for current working set

3. **Total Allocation Efficiency**: ~26% less total bytes allocated (3.19 GiB vs 4.29 GiB)

   - Tighter lifetime tracking and faster release to OS

Trade-offs
^^^^^^^^^^

mimalloc trades memory for speed by pre-allocating large memory areas (arenas). This leads to faster throughput but higher memory overhead. The system allocator is more memory-efficient but pays for it with more frequent, fine-grained allocations and ~1 second slower total runtime.

For the Classic Diagnostic Adapter use case:

- **Performance is prioritized** over memory efficiency in typical deployment scenarios
- Diagnostic operations are latency-sensitive
- Alternative memory optimization strategies exist (e.g., mmap for mdd files and other large data structures)

Consequences
------------

Positive
^^^^^^^^

- **Improved Response Times**: 29% faster execution directly improves diagnostic operation latency
- **Reduced System Overhead**: 287x fewer allocation calls minimize kernel involvement and context switching
- **Better Throughput**: Arena-based pooling enables handling of concurrent diagnostic sessions more efficiently
- **Predictable Performance**: Pre-allocated arenas provide more consistent allocation times

Negative
^^^^^^^^

- **Higher Memory Footprint**: ~65% more virtual memory and ~17% more physical memory consumption
- **Increased Total Allocations**: ~26% more bytes allocated over time due to arena pre-allocation strategy

Mitigation Strategies
^^^^^^^^^^^^^^^^^^^^^

The memory overhead can be mitigated through:

1. **mmap Usage**: Large data structures can use memory-mapped files to reduce heap pressure. Other memory optimizations like pooling memory for the databases could further reduce the memory overhead of mimalloc, and bring it closer to the system allocator, while maintaining its performance benefits.
2. **memory pooling and LRU caching**: Implementing custom pooling strategies for frequently used data structures can further optimize memory usage while leveraging mimalloc's performance advantages.

Alternatives Considered
-----------------------

System Allocator
^^^^^^^^^^^^^^^^

The native platform allocator was evaluated as the primary alternative. While it offers superior memory efficiency (17-65% less memory usage), the performance penalty (~29% slower execution and 287x more allocation syscalls) makes it unsuitable as the default choice.

The system allocator remains a viable option for:

- Extremely memory-constrained embedded deployments
- Scenarios where memory footprint is more critical than latency
- Development/debugging when allocator-specific behavior needs to be isolated

Further optimization of the CDA might make this obsolete, as these will bring a larger benefit compared to taking the performance cost
of the system allocator.

Other Allocators
^^^^^^^^^^^^^^^^

Other allocators such as jemalloc or tcmalloc were not formally evaluated in this decision.

References
----------

- `mimalloc GitHub Repository <https://github.com/microsoft/mimalloc>`_
- Profiling conducted using Xcode Instruments on macOS / Apple Silicon (arm64)
