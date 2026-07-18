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

//! [`RequestGuard`] implementation that gates HTTP requests while a runtime
//! database update is in progress.

use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use cda_interfaces::guard::{
    ExemptRoute, ExemptRoutes, GuardDecision, GuardDenial, HttpMethod, RequestGuard, StatusCode,
};

/// A [`RequestGuard`] that blocks HTTP requests while a runtime update is in progress.
///
/// When an update starts the guard is activated by setting the `busy` flag to `true`
/// (via [`UpdateGuard::busy_handle`]). All incoming requests receive HTTP 409 until the
/// flag is cleared, except for routes registered via [`ExemptRoutes::extend_exempt`].
///
/// # Fast-path
///
/// [`is_active`](Self::is_active) performs a single atomic load. When no update is
/// running the guard adds zero overhead to every request.
#[derive(Clone)]
pub struct UpdateGuard {
    busy: Arc<AtomicBool>,
    exempt_routes: Arc<tokio::sync::RwLock<Vec<ExemptRoute>>>,
}

impl UpdateGuard {
    /// Creates a new guard in the non-busy (inactive) state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            busy: Arc::new(AtomicBool::new(false)),
            exempt_routes: Arc::new(tokio::sync::RwLock::new(Vec::new())),
        }
    }

    /// Creates a guard that shares an existing `busy` flag.
    ///
    /// Use this when an `Arc<AtomicBool>` has already been allocated (e.g. received
    /// from the [`VehicleComponentFactory`](cda_interfaces::runtime_update_api::VehicleComponentFactory)
    /// trait) and must be reused so that the update-in-progress state remains
    /// consistent across both the caller and the new guard.
    #[must_use]
    pub fn from_arc(busy: Arc<AtomicBool>) -> Self {
        Self {
            busy,
            exempt_routes: Arc::new(tokio::sync::RwLock::new(Vec::new())),
        }
    }

    /// Returns `true` if an update is currently in progress.
    #[must_use]
    pub fn is_busy(&self) -> bool {
        self.busy.load(Ordering::Acquire)
    }

    /// Returns a cloned handle to the underlying `busy` flag.
    ///
    /// Pass this handle to the component that drives the update so it can set
    /// `true` when the update begins and `false` when it ends.
    #[must_use]
    pub fn busy_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.busy)
    }

    /// Sets the busy state directly.
    pub fn set_busy(&self, busy: bool) {
        self.busy.store(busy, Ordering::Release);
    }
}

impl Default for UpdateGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl RequestGuard for UpdateGuard {
    fn is_active(&self) -> bool {
        self.is_busy()
    }

    fn evaluate<'a>(
        &'a self,
        path: &'a str,
        method: HttpMethod,
    ) -> Pin<Box<dyn Future<Output = GuardDecision> + Send + 'a>> {
        let exempt_routes = Arc::clone(&self.exempt_routes);
        let busy = Arc::clone(&self.busy);

        Box::pin(async move {
            if !busy.load(Ordering::Acquire) {
                return GuardDecision::Pass;
            }

            let routes = exempt_routes.read().await;
            let is_exempt = routes
                .iter()
                .any(|exempt| path.starts_with(&exempt.prefix) && exempt.methods.contains(&method));

            if is_exempt {
                GuardDecision::Pass
            } else {
                // ErrorCode::UpdateProcessInProgress = 4096 (from sovd_interfaces)
                GuardDecision::Deny(GuardDenial {
                    status: StatusCode::CONFLICT,
                    message: "Update in progress".to_owned(),
                    error_code: 4096,
                    retry_after_seconds: None,
                })
            }
        })
    }
}

impl ExemptRoutes for UpdateGuard {
    fn extend_exempt<'a>(
        &'a self,
        routes: Vec<ExemptRoute>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        let exempt_routes = Arc::clone(&self.exempt_routes);
        Box::pin(async move {
            exempt_routes.write().await.extend(routes);
        })
    }
}
