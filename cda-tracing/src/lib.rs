/*
 * Copyright (c) 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
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
use std::ops::Deref;

use opentelemetry::trace::TracerProvider;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    EnvFilter, Layer, Registry,
    layer::{Layered, SubscriberExt},
    registry::LookupSpan,
    util::SubscriberInitExt,
};

mod otel;
pub use otel::{OtelConfig, OtelGuard};
pub mod subscriber;

const DEFAULT_LOG_FILE_NAME: &str = "opensovd-cda.log";
const DEFAULT_LOG_FILE_PATH: &str = "/var/log/opensovd-cda";

#[derive(Error, Debug)]
pub enum TracingSetupError {
    #[error("Failed to create tracing resource: `{0}`")]
    ResourceCreationFailed(String),
    #[error("Failed to initialize tracing subscriber: `{0}`")]
    SubscriberInitializationFailed(String),
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct LoggingConfig {
    pub timestamp_format: String,
    pub log_file_config: LogFileConfig,
    pub otel: OtelConfig,
    #[cfg(feature = "tokio-tracing")]
    pub tokio_tracing: TokioTracingConfig,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct LogFileConfig {
    pub enabled: bool,
    pub name: String,
    pub path: String,
    pub date_format: String,
    pub append_enabled: bool,
}

#[cfg(feature = "tokio-tracing")]
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct TokioTracingConfig {
    pub retention: std::time::Duration,
    pub server: String,
    pub recording_path: Option<String>,
}

type BoxedLayer<T> = Box<dyn Layer<T> + Send + Sync + 'static>;

pub struct TracingWorkerGuard(WorkerGuard);

impl Deref for TracingWorkerGuard {
    type Target = WorkerGuard;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[must_use]
pub fn new() -> Layered<EnvFilter, Registry> {
    if std::env::var("RUST_LOG").is_err() {
        #[cfg(feature = "tokio-tracing")]
        let defaults = "info,tokio=trace,runtime=trace";
        #[cfg(not(feature = "tokio-tracing"))]
        let defaults = "info";

        // set default to info if none is set already
        // unsafe as env vars are inherently not threadsafe in linux
        // and we need to be sure to not access them concurrently.
        unsafe { std::env::set_var("RUST_LOG", defaults) }
    }
    tracing_subscriber::registry().with(EnvFilter::from_default_env())
}

pub fn new_term_subscriber<S: tracing_core::Subscriber + for<'a> LookupSpan<'a>>(
    config: &LoggingConfig,
) -> BoxedLayer<S> {
    // Ensure tracing is initialized
    let term_subscriber = tracing_subscriber::fmt::layer::<S>()
        .with_file(false)
        .with_line_number(false)
        .with_target(true)
        .event_format(
            subscriber::CdaFormatter::new(tracing_subscriber::fmt::time::ChronoUtc::new(
                config.timestamp_format.clone(),
            ))
            .with_nested_context_fields(false)
            .with_span_id(false),
        )
        .with_writer(std::io::stdout);

    #[cfg(feature = "tokio-tracing")]
    let term_subscriber = {
        let filter_fn = tracing_subscriber::filter::FilterFn::new(
            console_filter as for<'r, 's> fn(&'r tracing_core::Metadata<'s>) -> bool,
        );
        term_subscriber.with_filter(filter_fn)
    };

    term_subscriber.boxed()
}

/// Creates a new file subscriber layer.
/// # Errors
/// Returns a string error if the file subscriber cannot be created.
pub fn new_file_subscriber<S: tracing_core::Subscriber + for<'a> LookupSpan<'a>>(
    config: &LogFileConfig,
) -> Result<(TracingWorkerGuard, BoxedLayer<S>), TracingSetupError> {
    let appender = subscriber::file_log_writer(
        config.path.clone(),
        config.name.clone(),
        config.append_enabled,
    )
    .map_err(|e| {
        TracingSetupError::ResourceCreationFailed(format!("failed to setup log file {e}"))
    })?;
    let (non_blocking_appender, guard) = tracing_appender::non_blocking(appender);

    let file_subscriber = tracing_subscriber::fmt::layer()
        .with_file(false)
        .with_line_number(false)
        .with_span_events(
            tracing_subscriber::fmt::format::FmtSpan::NEW
                | tracing_subscriber::fmt::format::FmtSpan::CLOSE,
        )
        .event_format(
            subscriber::CdaFormatter::new(
                // todo: make this configurable
                tracing_subscriber::fmt::time::ChronoUtc::new("%F %T%.3f".to_owned()),
            )
            .with_nested_context_fields(true)
            .with_color(false),
        )
        .with_writer(non_blocking_appender);

    #[cfg(feature = "tokio-tracing")]
    let file_subscriber = {
        let filter_fn = tracing_subscriber::filter::FilterFn::new(
            console_filter as for<'r, 's> fn(&'r tracing_core::Metadata<'s>) -> bool,
        );
        file_subscriber.with_filter(filter_fn)
    };

    Ok((TracingWorkerGuard(guard), file_subscriber.boxed()))
}

/// Creates a new OpenTelemetry subscriber layer.
/// # Errors
/// Returns a string error if the OpenTelemetry subscriber cannot be created.
pub fn new_otel_subscriber<
    S: tracing_core::Subscriber + for<'a> LookupSpan<'a> + Send + Sync + 'static,
>(
    config: &OtelConfig,
) -> Result<(OtelGuard, BoxedLayer<S>, BoxedLayer<S>), TracingSetupError> {
    let guard = otel::init_tracing_subscriber(config)?;
    let tracer = guard.tracer_provider.tracer("CDA");

    let metrics_layer = tracing_opentelemetry::MetricsLayer::new(guard.meter_provider.clone());
    #[cfg(feature = "tokio-tracing")]
    let metrics_layer = {
        let filter_fn = tracing_subscriber::filter::FilterFn::new(
            console_filter as for<'r, 's> fn(&'r tracing_core::Metadata<'s>) -> bool,
        );
        metrics_layer.with_filter(filter_fn)
    };
    let otel_layer = tracing_opentelemetry::OpenTelemetryLayer::new(tracer);
    #[cfg(feature = "tokio-tracing")]
    let otel_layer = {
        let filter_fn = tracing_subscriber::filter::FilterFn::new(
            console_filter as for<'r, 's> fn(&'r tracing_core::Metadata<'s>) -> bool,
        );
        otel_layer.with_filter(filter_fn)
    };
    Ok((guard, metrics_layer.boxed(), otel_layer.boxed()))
}

#[cfg(feature = "tokio-tracing")]
pub fn new_tokio_tracing<S: tracing_core::Subscriber + for<'a> LookupSpan<'a>>(
    config: &TokioTracingConfig,
) -> Result<BoxedLayer<S>, String> {
    use std::net::SocketAddr;

    let server_addr: SocketAddr = config
        .server
        .parse()
        .map_err(|e| format!("Invalid server address: {e}"))?;

    println!("Starting tokio tracing server at {}", server_addr);
    let mut builder = console_subscriber::ConsoleLayer::builder()
        .retention(config.retention)
        .server_addr(server_addr);
    if let Some(recording_path) = &config.recording_path {
        builder = builder.recording_path(recording_path);
    }
    Ok(builder.spawn().boxed())
}

#[cfg(feature = "tokio-tracing")]
fn console_filter(meta: &tracing_core::Metadata<'_>) -> bool {
    // events will have *targets* beginning with "runtime"
    if meta.is_event() {
        return !(meta.target().starts_with("runtime") || meta.target().starts_with("tokio"));
    }

    // spans will have *names* beginning with "runtime". for backwards
    // compatibility with older Tokio versions, enable anything with the `tokio`
    // target as well.
    !(meta.name().starts_with("runtime.") || meta.target().starts_with("tokio"))
}

/// Initializes the logging system for the application.
/// # Errors
/// Returns a string error if initialization fails.
pub fn init_tracing<T: SubscriberInitExt>(subscriber: T) -> Result<(), TracingSetupError> {
    subscriber.try_init().map_err(|e| {
        TracingSetupError::SubscriberInitializationFailed(format!(
            "Failed to initialize tracing subscriber: {e}"
        ))
    })
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            timestamp_format: "%T%.3f".to_owned(),
            log_file_config: LogFileConfig::default(),
            otel: OtelConfig::default(),
            #[cfg(feature = "tokio-tracing")]
            tokio_tracing: TokioTracingConfig::default(),
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

#[cfg(feature = "tokio-tracing")]
impl Default for TokioTracingConfig {
    fn default() -> Self {
        Self {
            retention: std::time::Duration::from_secs(60 * 60), // 1h
            server: "127.0.0.1:6669".to_owned(),
            recording_path: None,
        }
    }
}
