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

ADR-004: Binary WAL Format for Crash-Safe Storage Transactions
==============================================================

Status
------

**Accepted**

Date: 2026-05-19

Context
-------

The ``cda-storage`` crate provides a crash-safe, transactional storage backend
for diagnostic data (MDD files, configuration).  Mutations are journaled to a
Write-Ahead Log (WAL) before being applied to the filesystem.  The WAL must:

- Record operations durably before they are applied.
- Support crash recovery: detect incomplete transactions and roll back partial
  commits.
- Minimize I/O overhead on flash-based storage where write amplification matters.

The key decision is the WAL's on-disk encoding: binary (e.g., rkyv, wincode) vs text-based
(e.g., JSON, TOML).

Decision
--------

Use a **binary WAL format** with `rkyv <https://rkyv.org/>`_ (zero-copy
deserialization) for operation payloads and CRC32 checksums per entry.

Commit Strategy
^^^^^^^^^^^^^^^

The WAL uses a **one-phase commit with checksums (1PC+C)** strategy:

1. Operations are appended to the WAL during the transaction without ``fsync``.
2. Before applying, the header status is flipped from ``RECORDING`` to
   ``COMMITTING`` via an in-place write to the file header.
3. A single ``fsync`` makes both the status change and all entries durable.
4. Operations are applied to the filesystem.
5. The WAL file is deleted (point of no return).

On-Disk Format
^^^^^^^^^^^^^^

.. code-block:: text

   [u8 magic][u8 status][u16 reserved][u32 header_crc32] [u32 crc32][u32 len][payload] ...
   |-------------- 8-byte file header -----------------| |------ per-entry data -----|

- **File header** (8 bytes): magic ``0xCA``, status byte (``0x00`` = recording,
  ``0x01`` = committing), 2 bytes reserved padding, CRC32 over the header fields.
- **Entry envelope** (8 + N bytes): CRC32 checksum of the payload, ``u32``
  payload length, followed by the rkyv-serialized ``Operation`` enum.
- All fields are little-endian.  The 8-byte header and 8-byte entry headers
  maintain 4-byte alignment as required by rkyv deserialization.

Recovery
^^^^^^^^

On startup, ``LocalStorage::new()`` inspects the WAL:

- **No WAL**: clean state, nothing to do.
- **RECORDING**: transaction never reached commit. discard WAL and staging.
- **COMMITTING**: commit was in progress. read entries, undo applied
  operations via ``.bak`` file restoration and new-artifact removal.
- **Truncated COMMITTING WAL with no evidence of application**: discard WAL, no
  operations were applied.
- **Truncated COMMITTING WAL with evidence of partial application**: return
  ``StorageError::Corruption`` so the caller can decide how to handle it.

Rationale
---------

Why Binary over Text
^^^^^^^^^^^^^^^^^^^^

1. **Zero-copy deserialization**.  rkyv deserializes directly from the
   memory-mapped / read buffer without parsing or allocating.  Text formats
   (JSON, TOML) require a full parse pass and allocate intermediate
   structures.

2. **Simple deserialization**.  The serialized bytes are the payload directly.
   No text encoding layer (escaping, quoting, base64) sits between the raw
   operation data and its on-disk representation.

3. **Compact**.  Typical ``Operation`` payloads are < 1 KiB.  A JSON
   equivalent with escaped strings, keys, and formatting would be 2-5x
   larger, increasing flash write amplification for no benefit.

4. **Checksumming is simpler**.  CRC32 over raw bytes.  With text, checksums
   would need to account for encoding differences (line endings, whitespace
   normalization).

Why u32 Payload Length
^^^^^^^^^^^^^^^^^^^^^^

The payload length field is ``u32``:

- The WAL is an on-disk format.  Using ``usize`` would make files
  non-portable between 32-bit and 64-bit targets.
- ``u32`` fits the 4-byte alignment rkyv requires. ``u16`` would need 2
  bytes of padding for no benefit.
- ``u64`` (and ``usize`` on 64-bit) would waste 4 bytes per entry as with
  the current operation sizes, the length will never even reach ``u16::MAX``.
- Actual payloads are well under 1 KiB (the largest variant,
  ``Operation::Write``, contains three short strings bounded by filesystem
  ``NAME_MAX``). ``u32`` provides ~6 orders of magnitude of headroom.

Why rkyv over Other Binary Formats
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- **Zero-copy**: unlike bincode or postcard, rkyv does not need a
  deserialization pass. The archived data is accessed in-place.
  Bincode was a contender, but is discontinued and should not be used
  for new projects.
- **Derive-based**: ``#[derive(rkyv::Archive, rkyv::Serialize,
  rkyv::Deserialize)]`` on the ``Operation`` enum. No manual codec.
- **Deterministic layout**: same input always produces the same bytes,
  making CRC32 checksums reliable.
- **Alignment-aware**: produces 4-byte aligned output, matching the WAL
  entry header layout without additional padding logic.

Consequences
------------

Positive
^^^^^^^^

- Single ``fsync`` per transaction commit minimizes flash wear.
- CRC32 per entry detects partial writes and corruption during recovery.
- Zero-copy deserialization keeps recovery fast even with many entries.
- Fixed-size headers simplify sequential reading and offset arithmetic.

Negative
^^^^^^^^

- The WAL is not human-readable. Debugging requires tooling (e.g., a
  ``wal-dump`` utility or logging during recovery).
- rkyv's archive format is not stable across major versions.  A rkyv
  version upgrade may require a WAL migration or version field in the
  header.  The reserved header bytes can be used for this purpose.

References
----------

- `rkyv documentation <https://rkyv.org/>`_
- ``cda-storage/src/wal.rs``: WAL implementation
- ``cda-storage/src/recovery.rs``: startup recovery logic
