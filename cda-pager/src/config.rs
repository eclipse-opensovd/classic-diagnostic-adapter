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

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{PagerError, replacement::EvictionKind};

/// Default speculative read-ahead per fault, in bytes. Converted to pages
/// via the configured page size (e.g. 32 pages at 4 KiB).
const DEFAULT_PREFETCH_BYTES: usize = 128 * 1024;

const DEFAULT_PAGE_SIZE: usize = 4096;

/// Tunables for the global pager. All values are process-wide: a single hub
/// serves every opened MDD file and `pool_size_bytes` caps the number of
/// resident pages across all of them combined.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(default)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "Configuration struct legitimately has multiple independent boolean fields"
)]
pub struct PagerConfig {
    /// Load MDD files through the userfaultfd based pager instead of plain
    /// `mmap`. Linux only; enabling it on other platforms is an error.
    /// Defaults to `true` on Linux and `false` elsewhere (plain `mmap`).
    pub enabled: bool,
    /// Global budget for resident pages across all open MDD files, in bytes.
    pub pool_size_bytes: usize,
    /// Pager page size in bytes. Must be a power of two and at least 4096.
    pub page_size: usize,
    /// Number of contiguous pages speculatively loaded per fault. Capped at
    /// the pool size in pages.
    pub prefetch_pages: usize,
    /// Load the prefetch batch preceding the faulting page instead of the
    /// pages following it.
    pub prefetch_backward: bool,
    /// Page replacement strategy used to pick eviction victims: `fifo`,
    /// `random` or `prefetch-first`.
    pub eviction: EvictionKind,
    /// Minimum fraction (0.0..=1.0) of the pool to evict whenever eviction
    /// is triggered. Batching amortizes the eviction overhead.
    pub eviction_batch_fraction: f64,
    /// Read file data with `O_DIRECT`, bypassing the kernel page cache.
    /// Falls back to buffered reads if the filesystem rejects it.
    pub direct_io: bool,
}

impl PagerConfig {
    /// Checks the configuration for values the pager cannot work with.
    ///
    /// # Errors
    /// Returns [`PagerError::InvalidConfig`] if the page size is not a power
    /// of two of at least 4096, the prefetch batch is empty or its byte size
    /// overflows, or the eviction batch fraction is outside `0.0..=1.0`.
    pub fn validate(&self) -> Result<(), PagerError> {
        // Power-of-two is required, not just a multiple of 4096: addresses are
        // floored to page boundaries with `addr & !(page_size - 1)`, which is
        // only a correct floor for powers of two.
        if self.page_size < DEFAULT_PAGE_SIZE || !self.page_size.is_power_of_two() {
            return Err(PagerError::InvalidConfig(format!(
                "page size must be a power of two of at least {DEFAULT_PAGE_SIZE}, got {}",
                self.page_size
            )));
        }
        if self.prefetch_pages == 0 {
            return Err(PagerError::InvalidConfig(
                "prefetch batch must be at least 1 page".to_owned(),
            ));
        }
        let batch_bytes = self.prefetch_pages.checked_mul(self.page_size);
        if batch_bytes.is_none_or(|bytes| isize::try_from(bytes).is_err()) {
            return Err(PagerError::InvalidConfig(format!(
                "prefetch batch of {} pages of {} bytes is too large",
                self.prefetch_pages, self.page_size
            )));
        }
        if !(0.0..=1.0).contains(&self.eviction_batch_fraction) {
            return Err(PagerError::InvalidConfig(format!(
                "eviction batch fraction must be between 0 and 1, got {}",
                self.eviction_batch_fraction
            )));
        }
        Ok(())
    }
}

impl Default for PagerConfig {
    fn default() -> Self {
        Self {
            enabled: cfg!(target_os = "linux"),
            pool_size_bytes: 100 * 1024 * 1024,
            page_size: DEFAULT_PAGE_SIZE,
            prefetch_pages: DEFAULT_PREFETCH_BYTES
                .checked_div(DEFAULT_PAGE_SIZE)
                .unwrap_or(1),
            prefetch_backward: false,
            eviction: EvictionKind::default(),
            eviction_batch_fraction: 0.0,
            direct_io: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        assert!(PagerConfig::default().validate().is_ok());
    }

    #[test]
    fn rejects_bad_page_sizes() {
        for page_size in [0, 1, 2048, 4095, 6144, 4096 + 1] {
            let config = PagerConfig {
                page_size,
                ..PagerConfig::default()
            };
            assert!(config.validate().is_err(), "page size {page_size}");
        }
        let config = PagerConfig {
            page_size: 16384,
            ..PagerConfig::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_zero_prefetch() {
        let config = PagerConfig {
            prefetch_pages: 0,
            ..PagerConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_overflowing_prefetch() {
        for prefetch_pages in [usize::MAX, usize::MAX / 4096 + 1, usize::MAX / 2] {
            let config = PagerConfig {
                prefetch_pages,
                ..PagerConfig::default()
            };
            assert!(config.validate().is_err(), "prefetch {prefetch_pages}");
        }
    }

    #[test]
    fn rejects_bad_eviction_fraction() {
        for fraction in [-0.1, 1.1, f64::NAN, f64::INFINITY] {
            let config = PagerConfig {
                eviction_batch_fraction: fraction,
                ..PagerConfig::default()
            };
            assert!(config.validate().is_err(), "fraction {fraction}");
        }
    }
}
