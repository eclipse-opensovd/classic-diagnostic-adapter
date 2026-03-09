.. SPDX-License-Identifier: Apache-2.0
.. SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
..
.. See the NOTICE file(s) distributed with this work for additional
.. information regarding copyright ownership.
..
.. This program and the accompanying materials are made available under the
.. terms of the Apache License Version 2.0 which is available at
.. https://www.apache.org/licenses/LICENSE-2.0

ADR-002: Memory-Map Uncompressed MDD Files for FlatBuffers Access
=================================================================

Status
------

**Accepted**

Date: 2026-03-09

Context
-------

The Classic Diagnostic Adapter loads ECU diagnostic databases stored as MDD
files.  Each MDD file is a protobuf container whose chunks hold FlatBuffers
data compressed with LZMA.  At startup every MDD file must be read, the
protobuf parsed, the FlatBuffers payload decompressed, and the resulting data
kept available for the lifetime of the process.

The target platform is **Linux** (embedded automotive ECUs), where RAM is
limited and the system may reclaim memory aggressively under pressure via the
kernel page cache.

Three strategies were evaluated:

1. **Heap** — decompress into heap-allocated ``Vec<u8>`` buffers.
2. **MmapSidecar** — decompress into separate ``.fb`` sidecar files next to the
   MDD files, then memory-map those sidecar files.
3. **MmapMdd (in-place)** — decompress the MDD files themselves once (during a
   software update), rewriting them with uncompressed chunk data, then
   memory-map the MDD files directly with zero-copy protobuf decoding.

Decision
--------

We will use the **MmapMdd (in-place)** strategy: MDD files are decompressed
once during a software update and are subsequently used **read-only** via
``mmap``.  The protobuf layer uses prost's ``Bytes`` support
(``Bytes::from_owner(mmap)``) so that chunk data fields are zero-copy slices
into the memory-mapped file — no heap allocation is required for the
FlatBuffers payload.

Before the atomic rename of a rewritten MDD file, the written data is verified
by re-parsing the temporary file and comparing SHA-256 checksums of every chunk
against the expected values.

Rationale
---------

Performance Comparison
^^^^^^^^^^^^^^^^^^^^^^

Benchmarking was conducted on macOS / Apple Silicon (arm64) with 36 GB RAM
using 68 MDD files (53 MB compressed, 242 MB uncompressed), ``--release``
profile, 3-minute warm-up, and ``sudo memory_pressure -S -l critical -s 30``
applied twice.  Linux behaviour is expected to be comparable or better, since
the Linux kernel page cache uses a similar eviction strategy for file-backed
pages.

.. list-table:: RSS Comparison (KB)
   :header-rows: 1
   :widths: 25 18 18 18 15

   * - Strategy
     - Idle
     - Pressure
     - Recovery (3 min)
     - Extra disk
   * - Heap
     - 440,128
     - 420,432
     - —
     - None
   * - MmapSidecar
     - 191,680
     - 70,672
     - —
     - ~236 MB
   * - **MmapMdd (in-place)**
     - **35,264**
     - **35,264**
     - **35,520**
     - **+189 MB**

.. note::
   The MmapMdd implementation includes ``madvise(2)`` hints to optimize kernel
   page cache behavior:

   - ``MADV_SEQUENTIAL`` after ``mmap()`` enables aggressive read-ahead during
     protobuf decode.
   - ``MADV_RANDOM`` after protobuf decode disables read-ahead for the
     subsequent sparse FlatBuffers vtable lookups.

   These hints reduced idle RSS from 194,064 KB (baseline mmap without hints) to
   **35,264 KB** (−81.8 %), with stable behavior under memory pressure.
   This introduces a libc dependency for the optimal performance case, but the code is
   isolated to a small unsafe block and falls back gracefully if the hints cannot be set.

MmapMdd Advantages over Heap
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

1. **RSS under pressure: −92 %** (35 MB vs 420 MB)

   All FlatBuffers data is backed by the MDD file on disk.  Under memory
   pressure the kernel cleanly drops those pages and re-reads them on demand —
   no swap I/O required.  On the heap strategy, anonymous pages can only be
   compressed or swapped, incurring significant I/O overhead with a modest
   −4.5 % reduction.

   With ``madvise(2)`` hints (``MADV_SEQUENTIAL`` during decode,
   ``MADV_RANDOM`` thereafter), RSS remains stable at ~35 MB even under
   pressure, as the kernel avoids wasteful read-ahead for sparse FlatBuffers
   lookups.

2. **Idle RSS: −92 %** (35 MB vs 440 MB)

   The zero-copy protobuf decode (``Bytes::from_owner(mmap)``) avoids copying
   every ``bytes`` field to the heap.  Chunk data fields are slices into the
   mmap, so there is no second copy of the decompressed data in memory.

   The ``MADV_SEQUENTIAL`` hint enables efficient read-ahead during the
   initial protobuf decode, then ``MADV_RANDOM`` prevents the kernel from
   prefetching adjacent pages during subsequent random-access FlatBuffers
   queries, reducing idle RSS by an additional 159 MB (−81.8 %) compared to
   mmap without hints.

3. **Recovery stability**

   Three minutes after pressure ended, RSS remained at ~35 MB — pages are only
   faulted back in on actual access and do not eagerly repopulate.  This is
   ideal for long-running processes that may experience intermittent
   memory contention.

MmapMdd Advantages over MmapSidecar
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

1. **Simpler file management**

   No additional ``.fb`` sidecar files to create, track, or clean up.  The MDD
   files are the single source of truth.  This eliminates an entire class of
   consistency bugs (stale sidecar, missing sidecar, partial write).

2. **Lower RSS under pressure** (35 MB vs 71 MB)

   The in-place strategy benefits from zero-copy protobuf decoding
   (``Bytes::from_owner``) which the sidecar approach did not use.  All data —
   protobuf metadata and FlatBuffers payloads — lives in the single mmap,
   giving the kernel a unified region to evict.

   Additionally, the use of ``madvise(2)`` hints (``MADV_SEQUENTIAL`` →
   ``MADV_RANDOM``) optimizes the kernel's page cache eviction strategy for
   the two-phase access pattern (sequential decode, then sparse lookups),
   reducing RSS by 50 % compared to the sidecar approach.
   (``Bytes::from_owner``) which the sidecar approach did not use.  All data —
   protobuf metadata and FlatBuffers payloads — lives in the single mmap,
   giving the kernel a unified region to evict.

3. **Less extra disk space** (+189 MB vs +236 MB)

   Sidecar files duplicated the FlatBuffers payload alongside the original
   compressed MDD.  In-place rewriting replaces the compressed data, so the
   growth is only the difference between compressed and uncompressed sizes.

Trade-offs
^^^^^^^^^^

- **Disk usage increases**: MDD files grow from 53 MB to 242 MB (x4.6).  This
  is a one-time cost during the software update and is acceptable on the target
  platform where storage is less constrained than RAM.

- **MDD files are modified**: The original compressed MDD files are replaced
  with uncompressed versions.  This is acceptable because:

  - Decompression happens once during a controlled update step, not at runtime.
  - SHA-256 verification ensures data integrity before the atomic rename.


Consequences
------------

Positive
^^^^^^^^

- **92 % RSS reduction under memory pressure** compared to the heap baseline
  (35 MB vs 420 MB), critical for embedded Linux targets with limited RAM.
- **Stable RSS across idle and pressure phases** (~35 MB) due to optimized
  ``madvise(2)`` hints that align with the two-phase access pattern
  (sequential protobuf decode → sparse FlatBuffers lookups).
- **Zero-copy data path**: mmap → ``Bytes`` → FlatBuffers — no intermediate
  heap allocations for the diagnostic payload.
- **Single file, single source of truth**: no sidecar files to manage,
  eliminating consistency and cleanup issues.
- **Atomic, verified writes**: SHA-256 checksums and temp-file + rename ensure
  data integrity even if the update is interrupted.
- **Read-only at runtime**: after the initial update, MDD files are opened
  read-only, compatible with read-only filesystems or integrity-checked
  partitions.

Negative
^^^^^^^^

- **4.6× disk usage increase** for the MDD database directory.
- **One-time decompression cost** during software update (not at runtime).
- **Platform dependency**: relies on OS-level mmap, page cache behaviour, and
  ``madvise(2)`` support (POSIX systems).
- **libc dependency for optimal performance**: the two-phase ``madvise(2)``
  hint strategy (``MADV_SEQUENTIAL`` → ``MADV_RANDOM``) requires calling
  ``libc::madvise()`` after the ``Mmap`` object is consumed by
  ``Bytes::from_owner()``. Using only ``memmap2::Advice::Random`` from the
  start results in ~103 MB idle RSS (3× worse) due to suboptimal read-ahead
  during the sequential protobuf decode phase.

Implementation Details
^^^^^^^^^^^^^^^^^^^^^^

Two-Phase madvise(2) Strategy
""""""""""""""""""""""""""""""

The MDD loading process has two distinct access patterns:

1. **Sequential protobuf decode** (~1 second): The file is read linearly from
   start to end. ``MADV_SEQUENTIAL`` enables aggressive kernel read-ahead,
   minimizing page faults during this phase.

2. **Random FlatBuffers queries** (runtime): FlatBuffers structures are
   accessed via vtable pointer-chasing, resulting in sparse, unpredictable page
   access. ``MADV_RANDOM`` disables wasteful read-ahead that would load
   neighboring pages that are unlikely to be accessed soon.

Because the ``Mmap`` object must be consumed by ``Bytes::from_owner()`` to
enable zero-copy protobuf decoding, we cannot use ``mmap.advise()`` after the
decode completes. Instead:

1. After ``mmap()``: call ``mmap.advise(Sequential)``
2. Capture ``mmap_ptr`` and ``mmap_len`` before ownership transfer
3. Call ``Bytes::from_owner(mmap)`` to enable zero-copy prost decode
4. After ``MddFile::decode()``: call ``libc::madvise(mmap_ptr, ..., MADV_RANDOM)``

This two-phase approach achieved **35 MB idle RSS** compared to:

- **194 MB** with mmap but no hints (baseline)
- **103 MB** with ``MADV_RANDOM`` only (suboptimal for sequential decode)

Alternatives Considered
-----------------------

Heap (Baseline)
^^^^^^^^^^^^^^^

Decompress FlatBuffers data into heap-allocated ``Vec<u8>`` buffers.  Simplest
implementation but RSS remains high (~440 MB idle, ~420 MB under pressure).
Anonymous heap pages cannot be cleanly evicted by the kernel — they must be
compressed or swapped, incurring I/O overhead.  Unsuitable for
memory-constrained targets.

Separate Flatbuffer file (Sidecar)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Decompress into separate ``.fb`` files and memory-map those.  Achieves good
pressure behaviour (~71 MB) but introduces additional file management
complexity: sidecar files must be created, kept in sync with MDD files, and
cleaned up on updates.  Uses more disk space (+236 MB) because both compressed
MDD and uncompressed sidecar exist side by side.  The sidecar approach was
prototyped and benchmarked but rejected in favour of the simpler in-place
strategy.

References
----------

- `memmap2 crate <https://crates.io/crates/memmap2>`_
- `bytes crate — Bytes::from_owner <https://docs.rs/bytes/latest/bytes/struct.Bytes.html#method.from_owner>`_
- `prost Bytes support <https://docs.rs/prost-build/latest/prost_build/struct.Config.html#method.bytes>`_
