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

//! The values CDA components hand each other.
//!
//! Each type here is one value with one owner. A component that needs it names
//! its type and receives it built; nothing is handed out empty and filled in
//! later. What orders the components is
//! [`CdaStage`](cda_lifecycle::CdaStage), not these types: an ordering that
//! exists without a value flowing is an edge in that graph, and never a type
//! invented to stand in for one.

use std::sync::Arc;

use cda_comm_uds::VehicleEcuData;
use cda_core::EcuManager;
use cda_interfaces::{
    Reloadable,
    runtime_update_api::{ExclusiveRuntimePlugin, RuntimeFileTransaction},
};
use cda_lifecycle::{CdaEvent, WeakLifecycleHandle};
use cda_plugin_security::SecurityPlugin;

use crate::vehicle::{CanReloadHandle, CanTopologyPayload, UdsManagerType};

/// The vehicle's ECU data, in the owner every reader already holds.
///
/// Built empty, so the gateway and the UDS manager exist before any database
/// does and a load replaces what they read rather than what they are.
pub struct EcuDataCell<SP: SecurityPlugin>(pub(crate) Reloadable<VehicleEcuData<EcuManager<SP>>>);

/// The payload the version endpoints serve.
///
/// Mounted once and rewritten in place, so `/version` keeps answering across a
/// reload and only what it answers with changes.
pub struct VersionData(pub(crate) cda_sovd::StaticData);

/// The UDS manager the SOVD vehicle routes are built over.
pub struct UdsManagerHandle<SP: SecurityPlugin>(pub(crate) UdsManagerType<SP>);

/// The built runtime-update plugin, absent when the application is configured
/// without one.
pub struct UpdatePlugin<P>(pub(crate) Option<Arc<ExclusiveRuntimePlugin<P>>>);

/// The apply / rollback / cleanup transaction the update plugin owns.
///
/// Absent together with the plugin: with no plugin there is no execution to
/// move files for.
pub struct FileTransaction(pub(crate) Option<Arc<dyn RuntimeFileTransaction>>);

/// The authority to replace the live CAN topology.
///
/// Produced by building the gateway that owns it, so it is never handed out
/// before there is something behind it. Carries nothing on a build without CAN
/// support, or when the application is configured without CAN.
pub struct CanReload(pub(crate) CanReloadHandle);

impl CanReload {
    /// Installs the derived topology into the gateway that owns it.
    #[cfg(feature = "can")]
    pub(crate) async fn install(&self, topology: Option<CanTopologyPayload>) {
        match (self.0.as_ref(), topology) {
            (Some(owner), Some(topology)) => owner.apply(topology).await,
            (None, None) => {}
            _ => tracing::error!("Prepared CAN topology does not match the configured CAN owner"),
        }
    }

    #[cfg(not(feature = "can"))]
    #[allow(
        clippy::unused_self,
        clippy::unused_async,
        reason = "no CAN support: there is no topology to install"
    )]
    pub(crate) async fn install(&self, _topology: Option<CanTopologyPayload>) {}
}

/// The way back into the lifecycle manager, for a component that dispatches.
///
/// Weak: a strong handle inside a component the manager owns would keep the
/// actor alive for as long as the manager itself, so it could never stop. The
/// strong handle goes to the process owner, as `Arc<LifecycleHandle<CdaEvent>>`.
pub struct CdaLifecycle(pub(crate) WeakLifecycleHandle<CdaEvent>);

impl CdaLifecycle {
    /// A handle that dispatches but does not keep the manager running.
    #[must_use]
    pub fn handle(&self) -> WeakLifecycleHandle<CdaEvent> {
        self.0.clone()
    }
}
