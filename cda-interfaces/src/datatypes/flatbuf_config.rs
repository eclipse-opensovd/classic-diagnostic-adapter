/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct FlatbBufConfig {
    pub verify: bool,
    pub max_depth: usize,
    pub max_tables: usize,
    pub max_apparent_size: usize,
    pub ignore_missing_null_terminator: bool,
    /// Decompressed `FlatBuffers` blobs larger than this threshold (in bytes)
    /// are offloaded to a temporary file and memory-mapped instead of being
    /// kept on the heap. The OS can then page out unused regions to disk
    /// automatically, keeping resident memory low.
    ///
    /// Set to `0` to always use mmap, or `usize::MAX` to never offload.
    /// Default is 10 MiB.
    pub mmap_threshold: usize,
    /// Directory where temporary files for mmap offloading are created.
    ///
    /// **Important:** This directory must reside on a **real, disk-backed
    /// filesystem** (e.g. ext4, APFS, XFS). If it is on a RAM-backed
    /// filesystem such as `tmpfs` or `ramfs` (commonly mounted at `/tmp`
    /// on Linux), the offloaded data will still consume physical RAM through
    /// the page cache, defeating the purpose of mmap-based memory management.
    ///
    /// Safe defaults per platform:
    /// - **Linux:** `/var/tmp` (almost always disk-backed, survives reboots).
    /// - **macOS:** The system `$TMPDIR` (APFS-backed).
    ///
    /// Verify with `df -T <path>` — the filesystem type must **not** be
    /// `tmpfs` or `ramfs`.
    ///
    /// When `None`, defaults to `/var/tmp` on Linux and the OS default
    /// temporary directory on other platforms.
    pub mmap_tmpdir: Option<String>,
}

const DEFAULT_MMAP_THRESHOLD: usize = 10 * 1024 * 1024;

impl Default for FlatbBufConfig {
    fn default() -> Self {
        FlatbBufConfig {
            verify: false,
            max_depth: 64,
            max_tables: 100_000_000,
            max_apparent_size: usize::MAX,
            ignore_missing_null_terminator: false,
            mmap_threshold: DEFAULT_MMAP_THRESHOLD,
            mmap_tmpdir: None,
        }
    }
}
