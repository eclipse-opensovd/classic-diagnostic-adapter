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

*******
General
*******

.. testset:: Storage Commit Cancel Safety
    :id: testset~storage-commit-cancel-safe
    :links: test~storage-commit-cancel-safe
    :status: draft

    Verifies that a started commit completes and releases the transaction flag even
    if the caller is dropped.

.. testset:: Storage Crash Recovery
    :id: testset~storage-crash-recovery
    :links: test~storage-atomicity-recovery-discards-recording-phase-crash, test~storage-atomicity-recovery-restores-overwritten-file, test~storage-atomicity-recovery-removes-new-file, test~storage-atomicity-recovery-removes-new-collection, test~storage-atomicity-recovery-cleans-orphaned-backups, test~storage-atomicity-recovery-discards-corrupt-wal, test~storage-atomicity-recovery-removes-orphaned-collection-dir
    :status: draft

    Verifies that recovery rolls back or completes interrupted storage transactions
    and cleans up leftover artifacts.

.. testset:: Storage WAL Journaling
    :id: testset~storage-wal-journaling
    :links: test~storage-wal-checksum-round-trip, test~storage-wal-truncation-detection
    :status: draft

    Verifies checksum-protected encoding of WAL entries and detection of truncated entries.

.. testset:: Systemd Watchdog Integration
    :id: testset~system-sd-notify-watchdog
    :links: test~system-sd-notify-watchdog-integration
    :status: draft

    Verifies the aggregation of health states into systemd watchdog notifications.
