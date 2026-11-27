/*
 * SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//! Userfaultfd based demand pager for MDD files.
//!
//! A single, process-wide `PagerHub` lazily faults in file pages on
//! demand and evicts cold pages once a global resident-page budget is
//! exceeded, regardless of which MDD file the pages belong to. Which page is
//! evicted is decided by a pluggable [`ReplacementPolicy`].
//!
//! Use [`init`] once at startup and [`open_file`] to obtain a byte view of a
//! file that is paged by the hub. When the pager is not enabled, [`open_file`]
//! returns `Ok(None)` and callers are expected to fall back to `mmap`.

mod config;
mod error;
#[cfg(target_os = "linux")]
mod hub;
pub mod replacement;

pub use config::PagerConfig;
pub use error::PagerError;
#[cfg(target_os = "linux")]
pub use hub::{PagedRegionHandle, PagerHub, PagerStats};
pub use replacement::EvictionKind;

#[cfg(not(target_os = "linux"))]
mod unsupported;
#[cfg(not(target_os = "linux"))]
pub use unsupported::PagedRegionHandle;

#[cfg(target_os = "linux")]
mod global {
    use std::sync::{Arc, OnceLock};

    use crate::{PagedRegionHandle, PagerConfig, PagerError, PagerHub};

    static HUB: OnceLock<Arc<PagerHub>> = OnceLock::new();

    pub fn init(config: &PagerConfig) -> Result<(), PagerError> {
        if !config.enabled {
            return Ok(());
        }
        let hub = PagerHub::new(*config)?;
        HUB.set(hub).map_err(|_| PagerError::AlreadyInitialized)?;
        tracing::info!(
            pool_size_bytes = config.pool_size_bytes,
            page_size = config.page_size,
            prefetch_pages = config.prefetch_pages,
            eviction = config.eviction.as_str(),
            "Userfaultfd pager enabled"
        );
        Ok(())
    }

    pub fn open_file(path: &str) -> Result<Option<PagedRegionHandle>, PagerError> {
        HUB.get().map(|hub| hub.open_file(path)).transpose()
    }

    pub fn stats() -> Option<crate::PagerStats> {
        HUB.get().map(|hub| hub.stats())
    }
}

#[cfg(not(target_os = "linux"))]
mod global {
    use crate::{PagedRegionHandle, PagerConfig, PagerError};

    pub fn init(config: &PagerConfig) -> Result<(), PagerError> {
        if config.enabled {
            Err(PagerError::Unsupported)
        } else {
            Ok(())
        }
    }

    #[allow(
        clippy::unnecessary_wraps,
        reason = "Signature must match the Linux implementation"
    )]
    pub fn open_file(_path: &str) -> Result<Option<PagedRegionHandle>, PagerError> {
        Ok(None)
    }
}

/// Creates the process-wide pager hub. Does nothing if `config.enabled` is
/// `false`.
///
/// # Errors
/// Returns an error if the configuration is invalid, userfaultfd is not
/// available, the pager was already initialized, or the platform is not Linux.
pub fn init(config: &PagerConfig) -> Result<(), PagerError> {
    global::init(config)
}

/// Opens `path` through the global pager.
///
/// Returns `Ok(None)` if the pager is not enabled, in which case the caller
/// should load the file by other means.
///
/// # Errors
/// Returns an error if the file cannot be opened or registered with the pager.
pub fn open_file(path: &str) -> Result<Option<PagedRegionHandle>, PagerError> {
    global::open_file(path)
}

/// Snapshot of the global pager counters, `None` if the pager is not active.
#[cfg(target_os = "linux")]
#[must_use]
pub fn stats() -> Option<PagerStats> {
    global::stats()
}
