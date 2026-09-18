/*
 * SPDX-FileCopyrightText: 2025 Copyright (c) Contributors to the Eclipse Foundation
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

use std::{future::Future, sync::Arc, time::Duration};

use cda_interfaces::{
    DiagServiceError, DoipComParams, EcuAddresses, EcuConnectivityHandler, HashMap,
    HashMapExtensions, VariantDetectionRequest, VariantDetectionSender, dlt_ctx,
};
use doip_definitions::{
    header::PayloadType,
    payload::{DoipPayload, VehicleIdentificationRequest},
};
use tokio::sync::{Mutex, RwLock};

use crate::{
    ConnectionTasks, DiscoveredGateway, DoipGatewaySetupError, DoipGatewayState,
    DoipTransportConfig,
    connections::{GatewayState, handle_gateway_connection},
    socket::DoIPUdpSocket,
};

fn is_gateway(ecu: &impl EcuAddresses) -> bool {
    ecu.logical_gateway_address() == ecu.logical_address()
}

fn add_discovered_gateway(gateways: &mut Vec<DiscoveredGateway>, gateway: DiscoveredGateway) {
    if gateways
        .iter()
        .any(|known| known.logical_address == gateway.logical_address)
    {
        tracing::debug!(
            ecu_name = %gateway.ecu_name,
            logical_address = %format!("{:#06x}", gateway.logical_address),
            "Ignoring duplicate VAM"
        );
        return;
    }
    gateways.push(gateway);
}

pub(crate) async fn get_vehicle_identification<T, F>(
    socket: &mut DoIPUdpSocket,
    netmask: u32,
    gateway_port: u16,
    ecus: &Arc<HashMap<String, RwLock<T>>>,
    mut shutdown_signal: futures::future::Shared<F>,
) -> Result<Vec<DiscoveredGateway>, DiagServiceError>
where
    T: EcuAddresses,
    F: Future<Output = ()> + Send + 'static,
{
    // send VIR
    tracing::info!("Broadcasting VIR");
    let broadcast_ip = "255.255.255.255";
    socket
        .send(
            DoipPayload::VehicleIdentificationRequest(VehicleIdentificationRequest {}),
            format!("{broadcast_ip}:{gateway_port}")
                .parse()
                .map_err(|_| DiagServiceError::SendFailed("Invalid port".to_owned()))?,
        )
        .await
        .map_err(|e| DiagServiceError::SendFailed(format!("Failed to send VIR: {e:?}")))?;

    let mut gateways = Vec::new();

    let vam_timeout = Duration::from_secs(1); // not the actual timeout from the spec ...

    tokio::select! {
        // Use `biased` to prioritize shutdown signal over the VIR receive loop.
        // This ensures that if shutdown is already signaled when entering the
        // select, we exit immediately without starting unnecessary work.
        biased;
        () = &mut shutdown_signal => {
            tracing::info!("Shutdown signal received");
        },
        () = cda_interfaces::util::tokio_ext::sleep_for(vam_timeout) => {
            tracing::info!("Finished waiting for VIRs");
        },
        () = async { // loop until timeout is exceeded or shutdown signal is received
                loop {
                    tracing::info!("Waiting for VIRs...");
                    match socket.recv().await {
                        Some(Ok((doip_msg, source_addr))) => {
                            if let PayloadType::VehicleIdentificationRequest =
                                doip_msg.header.payload_type {
                                // skip our own VIR
                                tracing::info!("Skipping own VIR");
                                continue;
                            }
                            match handle_vam::<T>(ecus, doip_msg, source_addr, netmask).await {
                                Ok(Some(gateway)) => add_discovered_gateway(&mut gateways, gateway),
                                Ok(None) => { /* ignore non-matching VAMs */ }
                                Err(e) => tracing::error!(error = ?e, "Failed to handle VAM"),
                            }
                        }
                        Some(Err(e)) => {
                            tracing::warn!("Failed to receive VAMs: {e:?}");
                        },
                        None => {
                            tracing::warn!("Incomplete VAM due to connection closure/error");
                            break;
                        }
                    }
                }
            } => { /* nothing else to do once finished */ }
    }

    Ok(gateways)
}

#[allow(
    clippy::too_many_lines,
    reason = "Contains nested private functions that should remain in scope"
)]
pub(crate) async fn listen_for_vams<T, F>(
    transport_config: DoipTransportConfig,
    netmask: u32,
    state: DoipGatewayState<T>,
    connection_tasks: Arc<ConnectionTasks>,
    variant_detection: VariantDetectionSender,
    connectivity_handler: Arc<dyn EcuConnectivityHandler>,
    mut shutdown_signal: futures::future::Shared<F>,
) -> tokio::task::JoinHandle<()>
where
    T: EcuAddresses + DoipComParams,
    F: Future<Output = ()> + Send + 'static,
{
    #[derive(Debug)]
    struct DoipMessageContext {
        doip_msg: doip_definitions::message::DoipMessage,
        source_addr: std::net::SocketAddr,
        netmask: u32,
    }

    #[derive(Clone)]
    struct VamNotifications {
        variant_detection: VariantDetectionSender,
        connectivity_handler: Arc<dyn EcuConnectivityHandler>,
    }

    #[tracing::instrument(
        skip(
            state,
            connection_tasks,
            gateway_ecu_map,
            gateway_ecu_name_map,
            vam_notifications,
            transport_config
        ),
        fields(
            dlt_context = dlt_ctx!("DOIP")
        )
    )]
    async fn handle_doip_response<T: EcuAddresses + DoipComParams>(
        transport_config: &DoipTransportConfig,
        state: &DoipGatewayState<T>,
        connection_tasks: &Arc<ConnectionTasks>,
        doip_msg_ctx: DoipMessageContext,
        gateway_ecu_map: &HashMap<u16, Vec<u16>>,
        gateway_ecu_name_map: &HashMap<u16, Vec<String>>,
        vam_notifications: VamNotifications,
    ) {
        let DoipMessageContext {
            doip_msg,
            source_addr,
            netmask,
        } = doip_msg_ctx;
        match handle_vam::<T>(&state.ecus, doip_msg, source_addr, netmask).await {
            Ok(Some(doip_target)) => {
                tracing::debug!(
                    ecu_name = %doip_target.ecu_name,
                    logical_address = %format!("{:#06x}", doip_target.logical_address),
                    "VAM received"
                );
                if state
                    .logical_address_to_connection
                    .read()
                    .await
                    .get(&doip_target.logical_address)
                    .is_some()
                {
                    // sending variant detection, will update the ECU state
                    // (i.e. disconnected -> connected)
                    send_variant_detection(
                        gateway_ecu_name_map,
                        &vam_notifications.variant_detection,
                        doip_target.logical_address,
                    )
                    .await;
                } else {
                    tracing::info!(ecu_name = %doip_target.ecu_name, "New Gateway ECU detected");

                    match handle_gateway_connection::<T>(
                        doip_target,
                        transport_config,
                        &GatewayState {
                            doip_connections: Arc::clone(&state.doip_connections),
                            ecus: Arc::clone(&state.ecus),
                            gateway_ecu_map: gateway_ecu_map.clone(),
                            connection_tasks: Arc::clone(connection_tasks),
                        },
                        vam_notifications.connectivity_handler,
                    )
                    .await
                    {
                        Ok(logical_address) => {
                            state.logical_address_to_connection.write().await.insert(
                                logical_address,
                                state.doip_connections.read().await.len().saturating_sub(1),
                            );
                            send_variant_detection(
                                gateway_ecu_name_map,
                                &vam_notifications.variant_detection,
                                logical_address,
                            )
                            .await;
                        }
                        Err(e) => {
                            tracing::error!(
                                error = ?e,
                                "Failed to handle new Gateway connection"
                            );
                        }
                    }
                }
            }
            Ok(None) => { /* ignore non-matching VAMs */ }
            Err(e) => tracing::warn!(error = ?e, "Failed to handle VAM"),
        }
    }

    #[tracing::instrument(skip_all,
        fields(dlt_context = dlt_ctx!("DOIP"))
    )]
    async fn send_variant_detection(
        gateway_ecu_name_map: &HashMap<u16, Vec<String>>,
        variant_detection: &VariantDetectionSender,
        logical_address: u16,
    ) {
        if let Some(ecus) = gateway_ecu_name_map.get(&logical_address) {
            if let Err(e) = variant_detection
                .send(VariantDetectionRequest::new(ecus.clone()))
                .await
            {
                tracing::warn!(
                    error = ?e,
                    "Failed to send variant detection request"
                );
            } else {
                tracing::info!(
                    ecus = ?ecus,
                    "Variant detection request sent"
                );
            }
        }
    }

    // create mapping gateway_logical_address -> Vec<ecu_logical_address>
    let mut gateway_ecu_map: HashMap<u16, Vec<u16>> = HashMap::new();
    let mut gateway_ecu_name_map: HashMap<u16, Vec<String>> = HashMap::new();
    for ecu_lock in state.ecus.values() {
        let ecu = ecu_lock.read().await;
        let ecu_name = ecu.ecu_name();

        let addr = ecu.logical_address();
        let gateway_addr = ecu.logical_gateway_address();
        gateway_ecu_map.entry(gateway_addr).or_default().push(addr);
        gateway_ecu_name_map
            .entry(gateway_addr)
            .or_default()
            .push(ecu_name.to_lowercase());
    }

    tracing::info!("Listening for spontaneous VAMs");
    let notifications = VamNotifications {
        variant_detection,
        connectivity_handler,
    };

    cda_interfaces::spawn_named!(
        "vam-listen",
        Box::pin(async move {
            let broadcast_ip = "0.0.0.0";
            let broadcast_socket = if transport_config.tester_ip == broadcast_ip {
                Arc::clone(&state.socket)
            } else {
                match crate::create_udp_vir_socket(broadcast_ip, transport_config.port) {
                    Ok(sock) => Arc::new(Mutex::new(Some(sock))),
                    Err(e) => {
                        tracing::warn!(
                            broadcast_ip = %broadcast_ip,
                            tester_ip = %transport_config.tester_ip,
                            gateway_port = %transport_config.port,
                            error = ?e,
                            "Failed to bind broadcast socket, falling back to tester IP,\
                             this can lead to missed VAMs"
                        );
                        Arc::clone(&state.socket)
                    }
                }
            };

            loop {
                let mut socket_guard = broadcast_socket.lock().await;
                // `start()` binds `state.socket` before spawning this task, so
                // this is unreachable. Log and stop rather than panic.
                let Some(socket) = socket_guard.as_mut() else {
                    tracing::error!("Broadcast socket unexpectedly unbound; stopping vam listener");
                    break;
                };
                tokio::select! {
                    // Use `biased` to prioritize shutdown signal and cancel handling
                    // over processing the VAM
                    biased;
                    () = &mut shutdown_signal => {
                        break
                    },
                    response = socket.recv() => {
                        match response {
                            Some(Ok((doip_msg, source_addr))) => {
                                if let DoipPayload::VehicleAnnouncementMessage(_) = &doip_msg.payload {
                                    handle_doip_response(
                                        &transport_config,
                                        &state,
                                        &connection_tasks,
                                        DoipMessageContext {
                                            doip_msg,
                                            source_addr,
                                            netmask,
                                        },
                                        &gateway_ecu_map,
                                        &gateway_ecu_name_map,
                                        notifications.clone(),
                                    ).await;
                                }
                            }
                            Some(Err(error)) => tracing::warn!(?error, "Failed to receive VAM"),
                            None => {
                                tracing::warn!("VAM socket closed");
                                break;
                            }
                        }
                    },
                }
            }
        })
    )
}

#[tracing::instrument(skip_all,
    fields(dlt_context = dlt_ctx!("DOIP"))
)]
async fn handle_vam<T>(
    ecus: &Arc<HashMap<String, RwLock<T>>>,
    doip_msg: doip_definitions::message::DoipMessage,
    source_addr: std::net::SocketAddr,
    netmask: u32,
) -> Result<Option<DiscoveredGateway>, DoipGatewaySetupError>
where
    T: EcuAddresses,
{
    match source_addr {
        std::net::SocketAddr::V4(socket_addr_v4) => {
            if socket_addr_v4.ip().to_bits() & netmask != netmask {
                tracing::warn!(
                    source_ip = %source_addr.ip(),
                    subnet_mask = ?netmask,
                    "Ignoring VAM from outside tester subnet"
                );
                return Ok(None);
            }
        }
        std::net::SocketAddr::V6(_) => {
            // ipv6 is not expected nor supported
            return Ok(None);
        }
    }
    match doip_msg.payload {
        DoipPayload::VehicleAnnouncementMessage(vam) => {
            tracing::debug!("VAM received, parsing ...");
            let mut matched_ecu = None;
            for (name, ecu) in ecus.iter() {
                let ecu = ecu.read().await;
                if ecu.logical_address().to_be_bytes() == vam.logical_address {
                    if !is_gateway(&*ecu) {
                        tracing::warn!(
                            ecu_name = %name,
                            logical_address = %format!("{:#06x}", ecu.logical_address()),
                            gateway_address = %format!("{:#06x}", ecu.logical_gateway_address()),
                            "Ignoring VAM from non-gateway ECU"
                        );
                        return Ok(None);
                    }
                    matched_ecu = Some(name.to_owned());
                    break;
                }
            }
            if let Some(ecu) = matched_ecu {
                let logical_address = u16::from_be_bytes(vam.logical_address);
                tracing::debug!(
                    ecu_name = %ecu,
                    source_ip = %source_addr.ip(),
                    logical_address = %format!("{:#06x}", logical_address),
                    protocol_version = ?doip_msg.header.protocol_version,
                    "Matching ECU found"
                );
                Ok(Some(DiscoveredGateway {
                    ip: source_addr.ip().to_string(),
                    ecu_name: ecu.clone(),
                    logical_address,
                    doip_protocol_version: doip_msg.header.protocol_version,
                }))
            } else {
                tracing::warn!("VAM received but no matching ECU found");
                Err(DoipGatewaySetupError::UnknownECU {
                    logical_address: u16::from_be_bytes(vam.logical_address),
                    protocol_version: u8::from(doip_msg.header.protocol_version),
                })
            }
        }
        _ => Err(DoipGatewaySetupError::ResourceError(format!(
            "Expected VAM, got: {doip_msg:?}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use cda_interfaces::EcuAddresses;
    use doip_definitions::header::ProtocolVersion;

    use super::{add_discovered_gateway, is_gateway};
    use crate::DiscoveredGateway;

    struct TestEcu {
        logical_address: u16,
        gateway_address: u16,
    }

    impl EcuAddresses for TestEcu {
        fn tester_address(&self) -> u16 {
            0x0E80
        }

        fn logical_address(&self) -> u16 {
            self.logical_address
        }

        fn logical_gateway_address(&self) -> u16 {
            self.gateway_address
        }

        fn logical_functional_address(&self) -> u16 {
            0xE400
        }

        fn ecu_name(&self) -> String {
            "test".to_owned()
        }

        fn logical_address_eq<T: EcuAddresses>(&self, other: &T) -> bool {
            self.logical_address == other.logical_address()
        }
    }

    fn gateway(ecu_name: &str, logical_address: u16) -> DiscoveredGateway {
        DiscoveredGateway {
            ip: "127.0.0.1".to_owned(),
            ecu_name: ecu_name.to_owned(),
            logical_address,
            doip_protocol_version: ProtocolVersion::Iso13400_2012,
        }
    }

    #[test]
    fn duplicate_vams_create_only_one_gateway() {
        let mut gateways = Vec::new();

        add_discovered_gateway(&mut gateways, gateway("first", 0x110A));
        add_discovered_gateway(&mut gateways, gateway("duplicate", 0x110A));
        add_discovered_gateway(&mut gateways, gateway("other", 0x1163));

        assert_eq!(gateways.len(), 2);
        assert_eq!(
            gateways.first().map(|gateway| gateway.ecu_name.as_str()),
            Some("first")
        );
        assert_eq!(
            gateways.get(1).map(|gateway| gateway.ecu_name.as_str()),
            Some("other")
        );
    }

    #[test]
    fn ecu_with_own_gateway_address_is_a_gateway() {
        assert!(is_gateway(&TestEcu {
            logical_address: 0x110A,
            gateway_address: 0x110A,
        }));
    }

    #[test]
    fn ecu_behind_another_gateway_is_not_a_gateway() {
        assert!(!is_gateway(&TestEcu {
            logical_address: 0x1163,
            gateway_address: 0x110A,
        }));
    }
}
