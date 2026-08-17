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

//! The communication plugin.
//!
//! [`ServiceModeCommunicationPlugin`] wraps the default rather than
//! reimplementing it. That is the shape to copy: the lifecycle state machine,
//! the disable leases and the hook registry are intricate and not the part an
//! OEM wants to own. Overriding [`activate`] and [`request_activate`] adds a
//! precondition; everything else delegates.
//!
//! Note which method is *not* widened here: [`trigger_detection`] never brings a
//! transport up, so a detection request cannot be used to sidestep the
//! precondition. Guarding activation is enough.
//!
//! [`activate`]: CommunicationPlugin::activate
//! [`request_activate`]: CommunicationPlugin::request_activate
//! [`trigger_detection`]: CommunicationPlugin::trigger_detection

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use cda_interfaces::communication_control::{
    ActivationCause, CommunicationError, CommunicationGuard, CommunicationInitMode,
    CommunicationLifecycle, CommunicationOperationFailure, CommunicationState,
    CommunicationVariantDetection, DetectionCause, VariantDetectionMode,
};
use cda_plugin_communication_management::{
    lifecycle::disable::{DisableError, DisableLease, DisableReason},
    plugin::{
        CommunicationHandle, CommunicationPlugin, CommunicationPluginBuilder,
        default::DefaultCommunicationPlugin,
    },
};
use opensovd_cda_lib::AppError;

/// Stand-in for whatever tells this integration the vehicle may be talked to.
///
/// A real one reads an ignition line, a body-controller signal, or a workshop
/// authorisation. Kept trivially flippable here so the policy below is the part
/// worth reading.
pub struct ServiceMode {
    engaged: AtomicBool,
}

impl ServiceMode {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            engaged: AtomicBool::new(true),
        })
    }

    fn is_engaged(&self) -> bool {
        self.engaged.load(Ordering::Relaxed)
    }
}

/// Communication plugin that refuses to bring the vehicle network up unless the
/// OEM precondition holds.
pub struct ServiceModeCommunicationPlugin {
    inner: DefaultCommunicationPlugin,
    service_mode: Arc<ServiceMode>,
}

impl ServiceModeCommunicationPlugin {
    /// Startup is the cause worth singling out: it is the one activation nobody
    /// explicitly asked for, so an integration that must not touch the network
    /// unattended gates it here. Diagnostic requests carry their own causes and
    /// are still subject to the precondition below.
    fn precondition_holds(&self, cause: ActivationCause) -> bool {
        if self.service_mode.is_engaged() {
            return true;
        }
        tracing::warn!(
            ?cause,
            "refusing to activate communication: vehicle is not in service mode"
        );
        false
    }
}

#[async_trait::async_trait]
impl cda_interfaces::Shutdown for ServiceModeCommunicationPlugin {
    async fn shutdown(&self) {
        self.inner.shutdown().await;
    }
}

#[async_trait::async_trait]
impl CommunicationPlugin for ServiceModeCommunicationPlugin {
    fn state(&self) -> CommunicationState {
        self.inner.state()
    }

    fn acquire(&self) -> Result<CommunicationGuard, CommunicationError> {
        self.inner.acquire()
    }

    async fn activate(
        &self,
        cause: ActivationCause,
    ) -> Result<CommunicationState, CommunicationOperationFailure> {
        if !self.precondition_holds(cause) {
            // Reporting the current state rather than an error keeps this the
            // same shape as `init_mode` declining a cause: the caller learns
            // communication is not up, not that something went wrong.
            return Ok(self.inner.state());
        }
        self.inner.activate(cause).await
    }

    fn request_activate(&self, cause: ActivationCause) -> CommunicationState {
        // The non-blocking path needs the same guard. Overriding only `activate`
        // would leave the precondition bypassable by every diagnostic request,
        // since those take this path.
        if !self.precondition_holds(cause) {
            return self.inner.state();
        }
        self.inner.request_activate(cause)
    }

    async fn trigger_detection(
        &self,
        cause: DetectionCause,
    ) -> Result<CommunicationState, CommunicationOperationFailure> {
        // Deliberately unguarded: detection runs against a live transport and
        // never raises one, so it cannot bypass the precondition above.
        self.inner.trigger_detection(cause).await
    }

    async fn disable(&self, reason: DisableReason) -> Result<DisableLease, DisableError> {
        self.inner.disable(reason).await
    }

    async fn register_lifecycle_hook(
        &self,
        initializer: Arc<dyn CommunicationLifecycle>,
    ) -> Result<(), CommunicationOperationFailure> {
        self.inner.register_lifecycle_hook(initializer).await
    }

    async fn register_variant_detection(
        &self,
        detector: Arc<dyn CommunicationVariantDetection>,
    ) -> Result<(), CommunicationOperationFailure> {
        self.inner.register_variant_detection(detector).await
    }

    fn variant_detection(&self) -> VariantDetectionMode {
        self.inner.variant_detection()
    }
}

/// Builds the plugin once the passive transport and communication handle exist.
pub struct ServiceModeCommunicationPluginBuilder {
    pub service_mode: Arc<ServiceMode>,
}

impl CommunicationPluginBuilder for ServiceModeCommunicationPluginBuilder {
    type Plugin = ServiceModeCommunicationPlugin;
    type Error = AppError;

    async fn build(
        self,
        handle: CommunicationHandle,
        mode: CommunicationInitMode,
    ) -> Result<Self::Plugin, Self::Error> {
        Ok(ServiceModeCommunicationPlugin {
            // `init_mode` policy still applies: this plugin adds a precondition
            // on top of the default's rules, it does not replace them.
            inner: DefaultCommunicationPlugin::new(handle, mode),
            service_mode: self.service_mode,
        })
    }
}
