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

//! The health providers.
//!
//! There are two ways to report, and the difference is who does the work:
//!
//! - **Pull** ([`PolledVehicleStatusHealth`]): implement [`HealthStatus`] and
//!   answer on demand. The registry calls [`status`](HealthStatus::status) each
//!   time `/health` is queried, so the answer is never stale - but the endpoint
//!   is only as fast as your check. Use it when the check is cheap and local.
//!
//! - **Push** ([`ReportedVehicleStatusHealth`]): keep a cached value and update
//!   it from wherever the truth changes - a connection callback, a poller, a
//!   message handler. `/health` reads the cache. Use it when the check is slow
//!   or remote, which is the common case for an OEM backend: an HTTP probe on
//!   every `/health` hit would make the readiness probe as unreliable as the
//!   dependency it is describing.
//!
//! Both are registered the same way and are indistinguishable to a caller. This
//! example registers both, and drives the pushed one from a background task
//! standing in for the real service's notifications.

use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};

use cda_interfaces::health::{HealthStatus, Status};
use opensovd_cda_lib::{AppError, extensions::ExtensionContext};

/// Vendor-prefixed so it cannot collide with a CDA component name (`main`,
/// `doip`, `database`). Registration fails on a duplicate rather than silently
/// replacing, so a collision is a startup error, not a wrong health answer.
const POLLED_COMPONENT: &str = "x-example-oem-vehicle-status";
const REPORTED_COMPONENT: &str = "x-example-oem-vehicle-status-cached";

/// Stand-in for the OEM service being described.
///
/// A real one would hold a client to whatever it talks to. `reachable` is what
/// this example flips to show a health answer changing at runtime.
struct VehicleStatusProvider {
    reachable: std::sync::atomic::AtomicBool,
}

impl VehicleStatusProvider {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            reachable: std::sync::atomic::AtomicBool::new(true),
        })
    }

    /// Where a real implementation would issue its request. Called on every
    /// `/health` query by the pull-style provider below, which is exactly why a
    /// slow or remote check does not belong here.
    async fn ping(&self) -> bool {
        self.reachable.load(Ordering::Relaxed)
    }
}

/// Pull: answers from the live service, every time `/health` is queried.
struct PolledVehicleStatusHealth {
    service: Arc<VehicleStatusProvider>,
}

#[async_trait::async_trait]
impl HealthStatus for PolledVehicleStatusHealth {
    async fn status(&self) -> Status {
        if self.service.ping().await {
            Status::Up
        } else {
            // `Failed` marks the component unhealthy. Use `Starting` while a
            // dependency is still coming up, so readiness waits instead of
            // reporting a failure it will recover from on its own.
            Status::Failed
        }
    }
}

/// Push: answers from a cached value that the owner updates.
///
/// The cache is an atomic rather than a lock: `/health` must never block behind
/// whoever is publishing an update.
struct ReportedVehicleStatusHealth {
    status: AtomicU8,
}

impl ReportedVehicleStatusHealth {
    const STARTING: u8 = 0;
    const UP: u8 = 1;
    const FAILED: u8 = 2;

    fn new() -> Arc<Self> {
        // Start as `Starting`, not `Up`: until the first real observation the
        // honest answer is "not known yet", and reporting `Up` would let
        // readiness pass before the dependency has been checked once.
        Arc::new(Self {
            status: AtomicU8::new(Self::STARTING),
        })
    }

    /// Called by whoever learns the truth - a callback, a poller, a message
    /// handler. Cheap and non-blocking, so it is safe to call from anywhere.
    fn report(&self, status: Status) {
        let encoded = match status {
            Status::Up => Self::UP,
            Status::Failed => Self::FAILED,
            _ => Self::STARTING,
        };
        self.status.store(encoded, Ordering::Relaxed);
    }
}

#[async_trait::async_trait]
impl HealthStatus for ReportedVehicleStatusHealth {
    async fn status(&self) -> Status {
        match self.status.load(Ordering::Relaxed) {
            ReportedVehicleStatusHealth::UP => Status::Up,
            ReportedVehicleStatusHealth::FAILED => Status::Failed,
            _ => Status::Starting,
        }
    }
}

/// Registers both providers and starts the task that keeps the pushed one current.
///
/// # Errors
/// Returns [`AppError`] if a provider with the same name is already registered.
pub async fn register(context: ExtensionContext) -> Result<(), AppError> {
    // Vendor settings come from the `[oem]` section of CDA's own configuration
    // file, which CDA passes through without interpreting.
    let endpoint = context
        .oem_config()
        .get("endpoint")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("https://vendor.example/api");
    tracing::info!(endpoint, "vehicle status provider configured");

    let service = VehicleStatusProvider::new();

    context
        .health()
        .register(
            POLLED_COMPONENT,
            Arc::new(PolledVehicleStatusHealth {
                service: Arc::clone(&service),
            }),
        )
        .await
        .map_err(|error| AppError::InitializationFailed(error.to_string()))?;

    let reported = ReportedVehicleStatusHealth::new();
    context
        .health()
        .register(
            REPORTED_COMPONENT,
            Arc::clone(&reported) as Arc<dyn HealthStatus>,
        )
        .await
        .map_err(|error| AppError::InitializationFailed(error.to_string()))?;

    // Stands in for the real service's notifications. A production integration
    // would update from its own event source instead of polling on a timer.
    tokio::spawn(async move {
        loop {
            let status = if service.ping().await {
                Status::Up
            } else {
                Status::Failed
            };
            reported.report(status);
            cda_interfaces::util::tokio_ext::sleep_for(std::time::Duration::from_secs(5)).await;
        }
    });

    Ok(())
}
