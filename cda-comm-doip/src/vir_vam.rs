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

use std::{future::Future, sync::Arc, time::Duration};

use cda_interfaces::{
    DiagServiceError, DoipComParamProvider, EcuAddressProvider, HashMap, HashMapExtensions, dlt_ctx,
};
use doip_definitions::{
    header::PayloadType,
    payload::{DoipPayload, VehicleIdentificationRequest},
};
use doip_sockets::udp::UdpSocket;
use tokio::sync::{Mutex, RwLock, mpsc};

use crate::{DoipDiagGateway, DoipTarget, connections::handle_gateway_connection};
pub(crate) async fn get_vehicle_identification<T, F>(
    socket: &mut UdpSocket,
    netmask: u32,
    gateway_port: u16,
    ecus: &Arc<HashMap<String, RwLock<T>>>,
    shutdown_signal: F,
) -> Result<Vec<DoipTarget>, DiagServiceError>
where
    T: EcuAddressProvider,
    F: Future<Output = ()> + Clone + Send + 'static,
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
    loop {
        tokio::select! {
            () = shutdown_signal.clone() => {
                break
            },
            res = tokio::time::timeout(vam_timeout, socket.recv()) => {
                match res {
                    Ok(Some(Ok((doip_msg, source_addr)))) => {
                        if let PayloadType::VehicleIdentificationRequest =
                            doip_msg.header.payload_type {
                            // skip our own VIR
                            continue;
                        }
                        match handle_vam::<T>(ecus, doip_msg, source_addr, netmask).await {
                            Ok(Some(gateway)) => gateways.push(gateway),
                            Ok(None) => { /* ignore non-matching VAMs */ }
                            Err(e) => tracing::error!(error = ?e, "Failed to handle VAM"),
                        }
                    }
                    Ok(Some(Err(e))) => return Err(DiagServiceError::UnexpectedResponse(Some(
                        format!("Failed to receive VAMs: {e:?}"))
                    )),
                    Ok(None) => return Err(DiagServiceError::ConnectionClosed(
                        "Incomplete VAM due to connection closure/error".to_owned()
                    )),
                    Err(_) => {
                        // no VAM received within timeout
                        break;
                    }
                }
            }
        }
    }
    Ok(gateways)
}

#[allow(clippy::too_many_lines)] // allowed due to nested functions
pub(crate) async fn listen_for_vams<T, F>(
    tester_ip: String,
    gateway_port: u16,
    netmask: u32,
    gateway: DoipDiagGateway<T>,
    variant_detection: mpsc::Sender<Vec<String>>,
    send_timeout: Duration,
    shutdown_signal: F,
) where
    T: EcuAddressProvider + DoipComParamProvider,
    F: Future<Output = ()> + Clone + Send + 'static,
{
    #[derive(Debug)]
    struct DoipMessageContext {
        doip_msg: doip_definitions::message::DoipMessage,
        source_addr: std::net::SocketAddr,
        netmask: u32,
    }

    #[tracing::instrument(skip(gateway, gateway_ecu_map, gateway_ecu_name_map, variant_detection),
        fields(
            dlt_context = dlt_ctx!("DOIP")
        )
    )]
    async fn handle_doip_response<T: EcuAddressProvider + DoipComParamProvider>(
        tester_ip: &str,
        gateway: &DoipDiagGateway<T>,
        send_timeout: Duration,
        doip_msg_ctx: DoipMessageContext,
        gateway_ecu_map: &HashMap<u16, Vec<u16>>,
        gateway_ecu_name_map: &HashMap<u16, Vec<String>>,
        variant_detection: mpsc::Sender<Vec<String>>,
    ) {
        let DoipMessageContext {
            doip_msg,
            source_addr,
            netmask,
        } = doip_msg_ctx;
        match handle_vam::<T>(&gateway.ecus, doip_msg, source_addr, netmask).await {
            Ok(Some(doip_target)) => {
                tracing::debug!(
                    ecu_name = %doip_target.ecu,
                    logical_address = %format!("{:#06x}", doip_target.logical_address),
                    "VAM received"
                );
                if gateway
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
                    tracing::info!(ecu_name = %doip_target.ecu, "New Gateway ECU detected");

                    match handle_gateway_connection::<T>(
                        tester_ip,
                        doip_target,
                        &gateway.doip_connections,
                        &gateway.ecus,
                        gateway_ecu_map,
                        send_timeout,
                    )
                    .await
                    {
                        Ok(logical_address) => {
                            gateway.logical_address_to_connection.write().await.insert(
                                logical_address,
                                gateway
                                    .doip_connections
                                    .read()
                                    .await
                                    .len()
                                    .saturating_sub(1),
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
                tracing::error!(
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
    for ecu_lock in gateway.ecus.values() {
        let ecu = ecu_lock.read().await;
        let ecu_name = ecu.ecu_name();

        let addr = ecu.logical_address();
        let gateway = ecu.logical_gateway_address();
        gateway_ecu_map.entry(gateway).or_default().push(addr);
        gateway_ecu_name_map
            .entry(gateway)
            .or_default()
            .push(ecu_name.to_lowercase());
    }

    tracing::info!("Listening for spontaneous VAMs");

    cda_interfaces::spawn_named!(
        "vam-listen",
        Box::pin(async move {
            let broadcast_ip = "0.0.0.0";
            let broadcast_socket = if tester_ip == broadcast_ip {
                Arc::clone(&gateway.socket)
            } else {
                match crate::create_socket(broadcast_ip, gateway_port) {
                    Ok(sock) => Arc::new(Mutex::new(sock)),
                    Err(e) => {
                        tracing::warn!(
                            broadcast_ip = %broadcast_ip,
                            tester_ip = %tester_ip,
                            gateway_port = %gateway_port,
                            error = ?e,
                            "Failed to bind broadcast socket, falling back to tester IP,\
                             this can lead to missed VAMs"
                        );
                        Arc::clone(&gateway.socket)
                    }
                }
            };

            loop {
                let mut socket = broadcast_socket.lock().await;
                let signal = shutdown_signal.clone();
                tokio::select! {
                    () = signal => {
                        break
                    },
                    Some(Ok((doip_msg, source_addr))) = socket.recv() => {
                        if let DoipPayload::VehicleAnnouncementMessage(_) = &doip_msg.payload {
                            handle_doip_response(
                                &tester_ip,
                                &gateway,
                                send_timeout,
                                DoipMessageContext { doip_msg, source_addr, netmask },
                                &gateway_ecu_map,
                                &gateway_ecu_name_map,
                                variant_detection.clone(),
                            ).await;
                        }
                    },
                }
            }
        })
    );
}

#[tracing::instrument(skip_all,
    fields(dlt_context = dlt_ctx!("DOIP"))
)]
async fn handle_vam<T>(
    ecus: &Arc<HashMap<String, RwLock<T>>>,
    doip_msg: doip_definitions::message::DoipMessage,
    source_addr: std::net::SocketAddr,
    netmask: u32,
) -> Result<Option<DoipTarget>, String>
where
    T: EcuAddressProvider,
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
                    "Matching ECU found"
                );
                Ok(Some(DoipTarget {
                    ip: source_addr.ip().to_string(),
                    ecu: ecu.clone(),
                    logical_address,
                }))
            } else {
                tracing::warn!("VAM received but no matching ECU found");
                Err(format!(
                    "No matching ECU found for VAM: {:02x?}",
                    vam.logical_address
                ))
            }
        }
        _ => Err(format!("Expected VAM, got: {doip_msg:?}")),
    }
}
