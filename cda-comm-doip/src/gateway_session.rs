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

//! Gateway connect state of one transport start; see [`connect`] for how
//! connects are coordinated.

mod connect;

use std::sync::{Arc, Mutex};

use cda_interfaces::{
    EcuAddresses, EcuConnectivityHandler, HashMap, HashMapExtensions, VariantDetectionSender,
    util::std_ext::lock_mutex,
};
pub(crate) use connect::{ConnectFailure, DirectRejection, GatewayConnectGuard, PendingConnect};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use crate::{ConnectionTasks, DiscoveredGateway, DoipTransportConfig, config::DiscoveryMode};

/// Gateway logical address -> logical addresses of the ECUs reached through it.
pub(crate) async fn ecu_addresses_by_gateway<T: EcuAddresses>(
    ecus: &HashMap<String, RwLock<T>>,
) -> HashMap<u16, Vec<u16>> {
    let mut gateway_ecu_map: HashMap<u16, Vec<u16>> = HashMap::new();
    for ecu_lock in ecus.values() {
        let ecu = ecu_lock.read().await;
        gateway_ecu_map
            .entry(ecu.logical_gateway_address())
            .or_default()
            .push(ecu.logical_address());
    }
    gateway_ecu_map
}

/// Gateway logical address -> lowercase names of the ECUs reached through it.
pub(crate) async fn ecu_names_by_gateway<T: EcuAddresses>(
    ecus: &HashMap<String, RwLock<T>>,
) -> HashMap<u16, Vec<String>> {
    let mut gateway_ecu_name_map: HashMap<u16, Vec<String>> = HashMap::new();
    for ecu_lock in ecus.values() {
        let ecu = ecu_lock.read().await;
        gateway_ecu_name_map
            .entry(ecu.logical_gateway_address())
            .or_default()
            .push(ecu.ecu_name().to_lowercase());
    }
    gateway_ecu_name_map
}

/// Gateway connect state of one transport start. Replaced on every start, so
/// work left over from an earlier start cannot change the current one.
pub(crate) struct GatewaySession {
    /// The connect lock of each gateway, see [`connect`].
    connect_mutexes: Mutex<HashMap<u16, Arc<tokio::sync::Mutex<()>>>>,
    /// Gateways with an announcement waiting for their connect lock, with the
    /// newest announcement: one task per gateway waits, see
    /// [`vir_vam::handle_announcement`](crate::vir_vam::handle_announcement).
    pending_announcements: Mutex<HashMap<u16, DiscoveredGateway>>,
    /// Awaited, not aborted, by the transport stop: the commits of connects,
    /// which report ECUs connected and revert that themselves if the stop
    /// came first.
    pub(crate) commit_tasks: Arc<ConnectionTasks>,
    /// Transport-level settings shared by all gateway connections of this start.
    pub(crate) transport_config: DoipTransportConfig,
    /// Owns the connection tasks of this start, so they stop together.
    pub(crate) connection_tasks: Arc<ConnectionTasks>,
    /// Cancelled when this start is stopped; ends all work bound to it.
    pub(crate) cancel_token: CancellationToken,
    /// Discovery mode of this start: without VIR, the persisted reconnect
    /// sends no fallback search.
    pub(crate) discovery: DiscoveryMode,
    /// Sends requests to the variant-detection listener.
    variant_detection: VariantDetectionSender,
    /// Callback for ECU connectivity changes and for ECU replies the transport
    /// does not pass on.
    connectivity_handler: Arc<dyn EcuConnectivityHandler>,
}

impl GatewaySession {
    pub(crate) fn new(
        transport_config: DoipTransportConfig,
        connection_tasks: Arc<ConnectionTasks>,
        cancel_token: CancellationToken,
        variant_detection: VariantDetectionSender,
        connectivity_handler: Arc<dyn EcuConnectivityHandler>,
        discovery: DiscoveryMode,
    ) -> Self {
        Self {
            connect_mutexes: Mutex::new(HashMap::new()),
            pending_announcements: Mutex::new(HashMap::new()),
            commit_tasks: Arc::new(ConnectionTasks::new()),
            transport_config,
            connection_tasks,
            cancel_token,
            discovery,
            variant_detection,
            connectivity_handler,
        }
    }

    /// A checkpoint of a connect attempt: `false` once the transport was
    /// stopped or restarted.
    pub(super) fn is_active(&self) -> bool {
        !self.cancel_token.is_cancelled()
    }

    /// The connect lock of the gateway `logical_address`, see [`connect`].
    fn mutex_for_gateway(&self, logical_address: u16) -> Arc<tokio::sync::Mutex<()>> {
        Arc::clone(
            lock_mutex(&self.connect_mutexes)
                .entry(logical_address)
                .or_default(),
        )
    }

    /// Waits for the connect lock of the gateway `logical_address`.
    pub(crate) async fn acquire_connect_guard(
        self: &Arc<Self>,
        logical_address: u16,
    ) -> GatewayConnectGuard {
        GatewayConnectGuard {
            session: Arc::clone(self),
            logical_address,
            _held: self.mutex_for_gateway(logical_address).lock_owned().await,
        }
    }

    /// Takes the connect lock of the gateway `logical_address` if no connect
    /// of it holds it.
    pub(crate) fn try_acquire_connect_guard(
        self: &Arc<Self>,
        logical_address: u16,
    ) -> Option<GatewayConnectGuard> {
        let held = self
            .mutex_for_gateway(logical_address)
            .try_lock_owned()
            .ok()?;
        Some(GatewayConnectGuard {
            session: Arc::clone(self),
            logical_address,
            _held: held,
        })
    }

    /// Newest announcement per gateway (by logical address) that is waiting
    /// for the gateway's connect lock. Entries are removed by the connect task.
    pub(crate) fn lock_pending_announcements(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<u16, DiscoveredGateway>> {
        lock_mutex(&self.pending_announcements)
    }
}
