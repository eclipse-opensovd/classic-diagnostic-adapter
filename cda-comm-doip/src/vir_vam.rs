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
    DiagServiceError, DoipComParams, DoipGatewaySetupError, EcuAddresses, EcuConnectivityHandler,
    HashMap, HashMapExtensions, dlt_ctx,
};
use doip_definitions::{
    header::PayloadType,
    payload::{DoipPayload, VehicleIdentificationRequest},
};
use tokio::sync::{Mutex, RwLock, mpsc};
use tokio_util::sync::CancellationToken;

use crate::{
    DiscoveredGateway, DoipGatewayState, DoipTransportConfig,
    connections::{GatewayState, handle_gateway_connection},
    socket::DoIPUdpSocket,
};
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
                                Ok(Some(gateway)) => gateways.push(gateway),
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
    variant_detection: mpsc::Sender<Vec<String>>,
    connectivity_handler: Arc<dyn EcuConnectivityHandler>,
    mut shutdown_signal: futures::future::Shared<F>,
    cancel_token: CancellationToken,
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

    #[tracing::instrument(
        skip(
            state,
            gateway_ecu_map,
            gateway_ecu_name_map,
            variant_detection,
            connectivity_handler,
            transport_config
        ),
        fields(
            dlt_context = dlt_ctx!("DOIP")
        )
    )]
    async fn handle_doip_response<T: EcuAddresses + DoipComParams>(
        transport_config: &DoipTransportConfig,
        state: &DoipGatewayState<T>,
        doip_msg_ctx: DoipMessageContext,
        gateway_ecu_map: &HashMap<u16, Vec<u16>>,
        gateway_ecu_name_map: &HashMap<u16, Vec<String>>,
        variant_detection: mpsc::Sender<Vec<String>>,
        connectivity_handler: Arc<dyn EcuConnectivityHandler>,
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
                        &variant_detection,
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
                            connection_tasks: Arc::clone(&state.connection_tasks),
                        },
                        connectivity_handler,
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
                                &variant_detection,
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
        variant_detection: &mpsc::Sender<Vec<String>>,
        logical_address: u16,
    ) {
        if let Some(ecus) = gateway_ecu_name_map.get(&logical_address) {
            if let Err(e) = variant_detection.send(ecus.clone()).await {
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

    cda_interfaces::spawn_named!(
        "vam-listen",
        Box::pin(async move {
            let broadcast_ip = "0.0.0.0";
            let broadcast_socket = if transport_config.tester_ip == broadcast_ip {
                Arc::clone(&state.socket)
            } else {
                match crate::create_udp_vir_socket(broadcast_ip, transport_config.port) {
                    Ok(sock) => Arc::new(Mutex::new(sock)),
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
                let mut socket = broadcast_socket.lock().await;
                tokio::select! {
                    // Use `biased` to prioritize shutdown signal and cancel handling
                    // over processing the VAM
                    biased;
                    () = &mut shutdown_signal => {
                        break
                    },
                    () = cancel_token.cancelled() => {
                        break
                    },
                    Some(Ok((doip_msg, source_addr))) = socket.recv() => {
                        if let DoipPayload::VehicleAnnouncementMessage(_) = &doip_msg.payload {
                            handle_doip_response(
                                &transport_config,
                                &state,
                                DoipMessageContext {
                                    doip_msg,
                                    source_addr,
                                    netmask,
                                },
                                &gateway_ecu_map,
                                &gateway_ecu_name_map,
                                variant_detection.clone(),
                                Arc::clone(&connectivity_handler),
                            ).await;
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
                if ecu.read().await.logical_address().to_be_bytes() == vam.logical_address {
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
