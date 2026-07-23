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

use serde::{Deserialize, Serialize};

const DEFAULT_LOG_FILE_NAME: &str = "opensovd-cda.log";
const DEFAULT_LOG_FILE_PATH: &str = "/var/log/opensovd-cda";

/// Top-level logging and tracing configuration.
#[derive(Deserialize, Serialize, Clone, Debug, schemars::JsonSchema)]
pub struct LoggingConfig {
    /// strftime-compatible format string for log timestamps.
    pub timestamp_format: String,
    /// File-based logging configuration.
    pub log_file_config: LogFileConfig,
    /// OpenTelemetry tracing and metrics export configuration.
    pub otel: OtelConfig,
    /// tokio-console runtime tracing configuration.
    #[cfg(feature = "tokio-tracing")]
    pub tokio_tracing: TokioTracingConfig,
    /// AUTOSAR DLT (Diagnostic Log and Trace) output configuration.
    #[cfg(feature = "dlt-tracing")]
    pub dlt_tracing: DltTracingConfig,
}

/// Configuration for file-based log output.
#[derive(Deserialize, Serialize, Clone, Debug, schemars::JsonSchema)]
pub struct LogFileConfig {
    /// Whether file logging is enabled.
    pub enabled: bool,
    /// Log file name.
    pub name: String,
    /// Directory path for log files.
    pub path: String,
    /// strftime-compatible date format used in log file entries.
    pub date_format: String,
    /// Whether to append to existing log files instead of rotating.
    pub append_enabled: bool,
}

/// OpenTelemetry exporter configuration.
#[derive(Deserialize, Serialize, Clone, Debug, schemars::JsonSchema)]
pub struct OtelConfig {
    /// Whether OpenTelemetry tracing and metrics export is enabled.
    pub enabled: bool,
    /// OTLP collector endpoint URL (e.g. `http://localhost:4317`).
    pub endpoint: String,
}

/// tokio-console runtime debugging configuration.
#[cfg(feature = "tokio-tracing")]
#[derive(Deserialize, Serialize, Clone, Debug, schemars::JsonSchema)]
pub struct TokioTracingConfig {
    /// How long to retain runtime tracing data.
    pub retention: std::time::Duration,
    /// Socket address for the tokio-console gRPC server (e.g. "127.0.0.1:6669").
    pub server: String,
    /// Optional file path to record trace data to disk.
    pub recording_path: Option<String>,
}

/// AUTOSAR DLT (Diagnostic Log and Trace) output configuration.
#[cfg(feature = "dlt-tracing")]
#[derive(Deserialize, Serialize, Clone, Debug, schemars::JsonSchema)]
pub struct DltTracingConfig {
    /// DLT application ID, max 4 characters
    pub app_id: String,
    /// DLT application description string, max 256 characters.
    pub app_description: String,
    /// Whether DLT tracing output is enabled.
    pub enabled: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            timestamp_format: "%T%.3f".to_owned(),
            log_file_config: LogFileConfig::default(),
            otel: OtelConfig::default(),
            #[cfg(feature = "tokio-tracing")]
            tokio_tracing: TokioTracingConfig::default(),
            #[cfg(feature = "dlt-tracing")]
            dlt_tracing: DltTracingConfig::default(),
        }
    }
}

impl Default for LogFileConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            name: DEFAULT_LOG_FILE_NAME.to_owned(),
            path: DEFAULT_LOG_FILE_PATH.to_owned(),
            date_format: "%F %T%.3f".to_owned(),
            append_enabled: false,
        }
    }
}

impl Default for OtelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: "http://localhost:4317".to_owned(),
        }
    }
}

#[cfg(feature = "tokio-tracing")]
impl Default for TokioTracingConfig {
    fn default() -> Self {
        Self {
            #[cfg_attr(nightly, allow(unknown_lints, clippy::duration_suboptimal_units))]
            retention: std::time::Duration::from_secs(60 * 60), // 1h
            server: "127.0.0.1:6669".to_owned(),
            recording_path: None,
        }
    }
}

#[cfg(feature = "dlt-tracing")]
impl Default for DltTracingConfig {
    fn default() -> Self {
        Self {
            app_id: "CDA".to_string(),
            app_description: "Bridges SOVD to UDS for ECU communication.".to_string(),
            enabled: true,
        }
    }
}
