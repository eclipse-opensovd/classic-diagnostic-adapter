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
    EcuAddresses, EcuConnectivityHandler, HashMap, HashMapExtensions, HashSet,
    VariantDetectionSender,
};
pub(crate) use connect::{ConnectFailure, ConnectOutcome, DirectRejection, PendingConnect};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use crate::{ConnectionTasks, DiscoveredGateway, DoipTransportConfig, config::DiscoveryMode};

/// Maps each gateway logical address to the logical addresses and the (lowercase)
/// names of the ECUs reached through it.
pub(crate) async fn gateway_ecu_maps<T: EcuAddresses>(
    ecus: &HashMap<String, RwLock<T>>,
) -> (HashMap<u16, Vec<u16>>, HashMap<u16, Vec<String>>) {
    let mut gateway_ecu_map: HashMap<u16, Vec<u16>> = HashMap::new();
    let mut gateway_ecu_name_map: HashMap<u16, Vec<String>> = HashMap::new();
    for ecu_lock in ecus.values() {
        let ecu = ecu_lock.read().await;
        gateway_ecu_map
            .entry(ecu.logical_gateway_address())
            .or_default()
            .push(ecu.logical_address());
        gateway_ecu_name_map
            .entry(ecu.logical_gateway_address())
            .or_default()
            .push(ecu.ecu_name().to_lowercase());
    }
    (gateway_ecu_map, gateway_ecu_name_map)
}

/// Gateway connect state of one transport start. Replaced on every start, so
/// work left over from an earlier start cannot change the current one.
pub(crate) struct GatewaySession {
    /// The connect lock of each gateway, see [`connect`].
    connect_locks: Mutex<HashMap<u16, Arc<tokio::sync::Mutex<()>>>>,
    /// Gateways with an announcement waiting for their connect lock, with the
    /// newest announcement: one task per gateway waits, see
    /// [`vir_vam::handle_announcement`](crate::vir_vam::handle_announcement).
    announced: Mutex<HashMap<u16, DiscoveredGateway>>,
    /// Gateways whose connect reported their ECUs connected and has not yet
    /// decided to keep them: a stop that aborts the connect in this window
    /// reports them disconnected again. Gateways whose connect did not get
    /// that far keep their ECU states (e.g. `AssumedOnline`).
    pub(crate) online_reports: Mutex<HashSet<u16>>,
    pub(crate) transport_config: DoipTransportConfig,
    pub(crate) connection_tasks: Arc<ConnectionTasks>,
    pub(crate) cancel_token: CancellationToken,
    /// Discovery mode of this start: without VIR, the persisted reconnect
    /// sends no fallback search.
    pub(crate) discovery: DiscoveryMode,
    variant_detection: VariantDetectionSender,
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
            connect_locks: Mutex::new(HashMap::new()),
            announced: Mutex::new(HashMap::new()),
            online_reports: Mutex::new(HashSet::default()),
            transport_config,
            connection_tasks,
            cancel_token,
            discovery,
            variant_detection,
            connectivity_handler,
        }
    }
}
