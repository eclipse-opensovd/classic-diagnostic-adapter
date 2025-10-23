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

use opentelemetry::{KeyValue, global};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    Resource,
    metrics::{MeterProviderBuilder, PeriodicReader, SdkMeterProvider},
    trace::{RandomIdGenerator, Sampler, SdkTracerProvider},
};
use opentelemetry_semantic_conventions::{
    SCHEMA_URL,
    resource::{DEPLOYMENT_ENVIRONMENT_NAME, SERVICE_VERSION},
};
use serde::{Deserialize, Serialize};

use crate::TracingSetupError;

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct OtelConfig {
    pub enabled: bool,
    pub endpoint: String,
}

impl Default for OtelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: "http://localhost:4317".to_owned(),
        }
    }
}

// Create a Resource that captures information about the entity for which telemetry is recorded.
fn resource() -> Resource {
    Resource::builder()
        .with_service_name(env!("CARGO_PKG_NAME"))
        .with_schema_url(
            [
                KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION")),
                KeyValue::new(
                    DEPLOYMENT_ENVIRONMENT_NAME,
                    option_env!("DEPLOYMENT_ENV").unwrap_or_else(|| "develop"),
                ),
            ],
            SCHEMA_URL,
        )
        .build()
}

// Construct MeterProvider for MetricsLayer
fn init_meter_provider(config: &OtelConfig) -> Result<SdkMeterProvider, TracingSetupError> {
    let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .with_temporality(opentelemetry_sdk::metrics::Temporality::default())
        .with_endpoint(&config.endpoint)
        .build()
        .map_err(|e| {
            TracingSetupError::ResourceCreationFailed(format!(
                "Failed to create OTLP metric exporter: {e}"
            ))
        })?;

    let reader = PeriodicReader::builder(exporter)
        .with_interval(std::time::Duration::from_secs(30))
        .build();

    let meter_provider = MeterProviderBuilder::default()
        .with_resource(resource())
        .with_reader(reader)
        .build();

    global::set_meter_provider(meter_provider.clone());

    Ok(meter_provider)
}

// Construct TracerProvider for OpenTelemetryLayer
fn init_tracer_provider(config: &OtelConfig) -> Result<SdkTracerProvider, TracingSetupError> {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(&config.endpoint)
        .build()
        .map_err(|e| {
            TracingSetupError::ResourceCreationFailed(format!(
                "Failed to create OTLP span exporter: {e}"
            ))
        })?;

    Ok(SdkTracerProvider::builder()
        // Customize sampling strategy
        .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
            1.0,
        ))))
        .with_id_generator(RandomIdGenerator::default())
        .with_resource(resource())
        .with_batch_exporter(exporter)
        .build())
}

// Initialize tracing-subscriber and return OtelGuard
// for opentelemetry-related termination processing
pub(crate) fn init_tracing_subscriber(config: &OtelConfig) -> Result<OtelGuard, TracingSetupError> {
    let tracer_provider = init_tracer_provider(config)?;
    let meter_provider = init_meter_provider(config)?;

    Ok(OtelGuard {
        tracer_provider,
        meter_provider,
    })
}

pub struct OtelGuard {
    pub(crate) tracer_provider: SdkTracerProvider,
    pub(crate) meter_provider: SdkMeterProvider,
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        if let Err(err) = self.tracer_provider.shutdown() {
            eprintln!("{err:?}");
        }
        if let Err(err) = self.meter_provider.shutdown() {
            eprintln!("{err:?}");
        }
    }
}
