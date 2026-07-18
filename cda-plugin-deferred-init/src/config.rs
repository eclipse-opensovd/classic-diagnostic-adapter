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

//! Configuration types for deferred initialization plugins.
//!
//! Provides configuration structs and traits for customizing deferred
//! initialization behavior.

use serde::{Deserialize, Serialize};

/// Configuration trait for deferred initialization.
///
/// This trait defines the configuration interface for deferred init plugins,
/// allowing different configuration sources (files, environment, etc.) to
/// provide initialization parameters.
///
/// # Example
///
/// ```rust,ignore
/// use cda_plugin_deferred_init::config::DeferredInitConfig;
///
/// #[derive(Debug, Clone, Deserialize)]
/// struct MyConfig {
///     timeout_secs: u64,
///     max_retries: u32,
/// }
///
/// impl DeferredInitConfig for MyConfig {
///     fn timeout_secs(&self) -> u64 {
///         self.timeout_secs
///     }
///
///     fn max_retries(&self) -> u32 {
///         self.max_retries
///     }
/// }
/// ```
pub trait DeferredInitConfig: Send + Sync + 'static {
    /// Returns the timeout duration in seconds for initialization attempts.
    fn timeout_secs(&self) -> u64 {
        60
    }

    /// Returns the maximum number of retry attempts.
    fn max_retries(&self) -> u32 {
        3
    }

    /// Returns the retry interval in seconds between attempts.
    fn retry_interval_secs(&self) -> u64 {
        5
    }

    /// Returns true if initialization should happen automatically on startup.
    fn auto_init(&self) -> bool {
        false
    }

    /// Validates the configuration.
    ///
    /// # Errors
    /// Returns an error string if the configuration is invalid.
    fn validate(&self) -> Result<(), String> {
        Ok(())
    }
}

/// Default configuration for on-demand initialization.
///
/// This configuration triggers initialization on the first HTTP request
/// and uses sensible defaults for timeouts and retries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnDemandInitConfig {
    /// Timeout for initialization in seconds.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,

    /// Maximum number of retry attempts.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Retry interval in seconds.
    #[serde(default = "default_retry_interval_secs")]
    pub retry_interval_secs: u64,

    /// Whether to trigger initialization automatically on startup.
    #[serde(default)]
    pub auto_init: bool,
}

fn default_timeout_secs() -> u64 {
    60
}

fn default_max_retries() -> u32 {
    3
}

fn default_retry_interval_secs() -> u64 {
    5
}

impl Default for OnDemandInitConfig {
    fn default() -> Self {
        Self {
            timeout_secs: default_timeout_secs(),
            max_retries: default_max_retries(),
            retry_interval_secs: default_retry_interval_secs(),
            auto_init: false,
        }
    }
}

impl DeferredInitConfig for OnDemandInitConfig {
    fn timeout_secs(&self) -> u64 {
        self.timeout_secs
    }

    fn max_retries(&self) -> u32 {
        self.max_retries
    }

    fn retry_interval_secs(&self) -> u64 {
        self.retry_interval_secs
    }

    fn auto_init(&self) -> bool {
        self.auto_init
    }

    fn validate(&self) -> Result<(), String> {
        if self.timeout_secs == 0 {
            return Err("timeout_secs must be greater than 0".to_string());
        }
        if self.retry_interval_secs == 0 {
            return Err("retry_interval_secs must be greater than 0".to_string());
        }

        let total_retry_time = u64::from(self.max_retries).saturating_mul(self.retry_interval_secs);
        if total_retry_time > self.timeout_secs {
            tracing::warn!(
                timeout_secs = self.timeout_secs,
                max_retries = self.max_retries,
                retry_interval_secs = self.retry_interval_secs,
                total_retry_time_secs = total_retry_time,
                "Deferred init: total retry time ({total_retry_time}s) exceeds timeout ({}s); \
                 later retries will be cut short by the global timeout",
                self.timeout_secs
            );
        }

        Ok(())
    }
}
