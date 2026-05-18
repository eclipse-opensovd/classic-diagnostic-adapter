.. SPDX-License-Identifier: Apache-2.0
.. SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
..
.. See the NOTICE file(s) distributed with this work for additional
.. information regarding copyright ownership.
..
.. This program and the accompanying materials are made available under the
.. terms of the Apache License Version 2.0 which is available at
.. https://www.apache.org/licenses/LICENSE-2.0

ADR-003: Memory-Map Uncompressed MDD Files for FlatBuffers Access
=================================================================

Status
------

**Accepted**

Date: 2026-03-10

Context
-------

The Classic Diagnostic Adapter loads ECU diagnostic databases stored as MDD
files.  Each MDD file is a protobuf container whose chunks hold FlatBuffers
data compressed with LZMA.  At startup every MDD file must be read, the
protobuf parsed, the FlatBuffers payload decompressed, and the resulting data
kept available for the lifetime of the process.

The main target platform is **Linux** (onboard automotive ECUs), where RAM is
limited and the system may reclaim memory aggressively under pressure via the
kernel page cache.

Three strategies were evaluated:

1. **Heap** -- decompress into heap-allocated ``Vec<u8>`` buffers.
2. **MmapSidecar** -- decompress into separate ``.fb`` sidecar files next to the
   MDD files, then memory-map those sidecar files.
3. **MmapMdd (in-place)** -- decompress the MDD files themselves once (i.e. during a
   software update), rewriting them with uncompressed chunk data, then
   memory-map the MDD files directly with zero-copy protobuf decoding.

Decision
--------

We will use the **MmapMdd (in-place)** strategy: MDD files are decompressed
once and are subsequently used **read-only** via
``mmap``.  The protobuf layer uses prost's ``Bytes`` support
(``Bytes::from_owner(mmap)``) so that chunk data fields are zero-copy slices
into the memory-mapped file -- no heap allocation is required for the
FlatBuffers payload.

Before the atomic rename of a rewritten MDD file, the written data is verified
by re-parsing the temporary file and comparing SHA-512 checksums of every chunk
against the expected values.

Rationale
---------

Performance Comparison
^^^^^^^^^^^^^^^^^^^^^^

Benchmarking was conducted on **Linux 6.18.2-arch2-1** (x86_64, i5-7200U CPU)
with 32 GB RAM using 68 MDD files (~47 MB compressed, 242 MB uncompressed),
Rust 1.92.0, ``--release`` profile, ~3 minutes idle warm-up, and swap disabled.

.. list-table:: RSS Comparison (KB)
   :header-rows: 1
   :widths: 30 20 20 20

   * - Strategy
     - Idle
     - Under Pressure
     - Disk Usage
   * - Heap (baseline)
     - 486,900
     - 469,320
     - 47 MB
   * - MmapSidecar
     - 307,552
     - 171,904
     - ~282 MB
   * - **MmapMdd (in-place)**
     - **152,780**
     - **118,988**
     - **242 MB**

.. note::
   The MmapMdd implementation uses ``memmap2::Advice::Random``
   (``MADV_RANDOM``) immediately after ``mmap()`` to disable read-ahead for
   the sparse FlatBuffers vtable lookups that dominate runtime access.  This
   avoids a ``libc`` dependency -- the hint is set directly via ``memmap2``
   before ownership is transferred to ``Bytes::from_owner()``.

MmapMdd Advantages over Heap
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

1. **RSS under pressure: -75 %** (119 MB vs 469 MB)

   All FlatBuffers data is backed by the MDD file on disk.  Under memory
   pressure the kernel cleanly drops those pages and re-reads them on demand --
   no swap I/O required.  On the heap strategy, anonymous pages can only be
   compressed or swapped, incurring significant I/O overhead with a modest
   -3.7 % reduction.

2. **Idle RSS: -69 %** (153 MB vs 487 MB)

   The zero-copy protobuf decode (``Bytes::from_owner(mmap)``) avoids copying
   every ``bytes`` field to the heap.  Chunk data fields are slices into the
   mmap, so there is no second copy of the decompressed data in memory.

   Setting ``MADV_RANDOM`` via ``memmap2`` prevents the kernel from
   prefetching adjacent pages during random-access FlatBuffers queries,
   keeping idle RSS well below the heap baseline.

MmapMdd Advantages over MmapSidecar
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

1. **Simpler file management**

   No additional ``.fb`` sidecar files to create, track, or clean up.  The MDD
   files are the single source of truth.  This eliminates an entire class of
   consistency bugs (stale sidecar, missing sidecar, partial write).

2. **Lower RSS under pressure** (119 MB vs 172 MB)

   The in-place strategy benefits from zero-copy protobuf decoding
   (``Bytes::from_owner``) which the sidecar approach did not use.  All data --
   protobuf metadata and FlatBuffers payloads -- lives in the single mmap,
   giving the kernel a unified region to evict.

3. **Lower idle RSS** (153 MB vs 308 MB)

   Zero-copy decoding avoids duplicating chunk data on the heap, resulting in
   50 % lower idle RSS than the sidecar approach.

4. **Less extra disk space** (+195 MB vs +235 MB)

   Sidecar files duplicated the FlatBuffers payload alongside the original
   compressed MDD.  In-place rewriting replaces the compressed data, so the
   growth is only the difference between compressed and uncompressed sizes.

Runtime CPU Performance (``perf`` Profiling)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In addition to the RSS benchmarks above, ``perf`` profiling was conducted under
a realistic end-to-end workload on the target Linux system to compare the
**MmapMdd** implementation against the ``main`` (heap/compressed) branch.

**Test setup**

- Platform: Linux target (i5-7200U), Release build
- Workload: CDA started, 20s idle warm-up, then ``perf`` attached for
  profiling, followed by filling ~54 GB of memory with garbage data (two
  27 GB ``bytearray`` allocations in parallel to induce memory pressure), then
  a full ECU flash session via DoIP.
- Tool: ``perf stat`` attached to the running process (after warm-up) with
  events: ``cycles``, ``instructions``, ``faults``, ``cache-references``,
  ``cache-misses``.

.. list-table:: ``perf stat`` Results -- Main vs MmapMdd (under load)
   :header-rows: 1
   :widths: 32 22 22 24

   * - Metric
     - Main (compressed)
     - MmapMdd (decompressed)
     - Delta
   * - cycles
     - 448,473,942
     - 437,102,422
     - **-2.5 %**
   * - instructions
     - 194,934,031
     - 194,316,925
     - -0.3 %
   * - IPC (insn/cycle)
     - 0.43
     - 0.44
     - +2.3 %
   * - page faults
     - 340
     - 1,206
     - +255 % (see note)
   * - cache-references
     - 25,838,457
     - 26,031,415
     - +0.7 %
   * - cache-misses
     - 18,142,040 (70.21 %)
     - 18,478,329 (70.98 %)
     - -0.77 pp
   * - wall time
     - 42.19 s
     - 42.19 s
     - negligible

.. note::
   The higher page-fault count in MmapMdd (1,206 vs 340) reflects the
   kernel mapping mmap pages on first access rather than heap pages already
   loaded in at startup.  The absolute numbers are negligible (< 1,500
   faults over ~42 s) and have no measurable impact on wall time.

**Runtime profiling conclusions**

Under realistic ECU-flash load with concurrent memory pressure both
implementations are effectively equivalent in CPU efficiency (within 2.5 %
of each other) and identical in wall time.  The workload is dominated by
network I/O (DoIP) rather than database access, so the expected RSS savings
of MmapMdd (-75 % under pressure) are realized without any runtime CPU
regression.

``perf report`` call-graph analysis confirmed that the top hotspots
(``alloc::vec::in_place_collect``, ``flatbuffers::vtable::VTable::get``,
``cda_database::datatypes::DiagService::find_request``, mimalloc
internals) are present in both branches with similar weights, confirming
that no new hot paths were introduced by the MmapMdd implementation.

Trade-offs
^^^^^^^^^^

- **Disk usage increases**: MDD files grow from ~47 MB to 242 MB (~5.1x).  This
  is a one-time cost during the software update and is acceptable on the target
  platform where storage is less constrained than RAM.

- **MDD files are modified**: The original compressed MDD files are replaced
  with uncompressed versions.  This is acceptable because:

  - Decompression happens once during a controlled update step, not at runtime.
    - This will be implemented at a later point in time in the update plugin, for now the CDA does this at runtime.
  - SHA-512 verification ensures data integrity before the atomic rename.


Consequences
------------

Positive
^^^^^^^^

- **75 % RSS reduction under memory pressure** compared to the heap baseline
  (119 MB vs 469 MB), critical for embedded Linux targets with limited RAM.
- **69 % lower idle RSS** (153 MB vs 487 MB) due to zero-copy protobuf
  decoding and ``MADV_RANDOM`` via ``memmap2`` to suppress wasteful
  read-ahead during sparse FlatBuffers lookups.
- **Zero-copy data path**: mmap --> ``Bytes`` --> FlatBuffers -- no intermediate
  heap allocations for the diagnostic payload.
- **Single file, single source of truth**: no sidecar files to manage,
  eliminating consistency and cleanup issues.
- **Atomic, verified writes**: SHA-512 checksums and temp-file + rename ensure
  data integrity even if the update is interrupted.
- **Read-only at runtime**: after the initial update, MDD files are opened
  read-only, compatible with read-only filesystems or integrity-checked
  partitions.
- **No libc dependency**: ``MADV_RANDOM`` is set via ``memmap2`` before
  ownership transfer, avoiding the need for direct ``libc::madvise()`` calls.

Negative
^^^^^^^^

- **5.1x disk usage increase** for the MDD database directory.
- **One-time decompression cost** i.e. during software update or first startup
- **Platform dependency**: relies on OS-level mmap, page cache behaviour, and
  ``madvise(2)`` support (POSIX systems), although the latter is guarded by a cfg flag, so the CDA still
  works on platforms without ``MADV_RANDOM`` support (e.g. Windows) possibly with higher idle RSS.

Alternatives Considered
-----------------------

Heap (Baseline)
^^^^^^^^^^^^^^^

Decompress FlatBuffers data into heap-allocated ``Vec<u8>`` buffers.  Simplest
implementation but RSS remains high (~487 MB idle, ~469 MB under pressure).
Anonymous heap pages cannot be cleanly evicted by the kernel -- they must be
compressed or swapped, incurring I/O overhead.  Unsuitable for
memory-constrained targets.

Separate Flatbuffer file (Sidecar)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Decompress into separate ``.fb`` files and memory-map those.  Achieves good
pressure behaviour (~172 MB) but introduces additional file management
complexity: sidecar files must be created, kept in sync with MDD files, and
cleaned up on updates.  Uses more disk space (+235 MB) because both compressed
MDD and uncompressed sidecar exist side by side.  The sidecar approach was
prototyped and benchmarked but rejected in favour of the simpler in-place
strategy.

References
----------

- `memmap2 crate <https://crates.io/crates/memmap2>`_
- `bytes crate -- Bytes::from_owner <https://docs.rs/bytes/latest/bytes/struct.Bytes.html#method.from_owner>`_
- `prost Bytes support <https://docs.rs/prost-build/latest/prost_build/struct.Config.html#method.bytes>`_
