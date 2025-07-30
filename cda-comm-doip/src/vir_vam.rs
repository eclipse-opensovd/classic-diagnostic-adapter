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

use std::{sync::Arc, time::Duration};

use cda_interfaces::{DoipComParamProvider, EcuAddressProvider, TesterPresentControlMessage};
use doip_definitions::{
    header::PayloadType,
    payload::{DoipPayload, VehicleIdentificationRequest},
};
use doip_sockets::udp::UdpSocket;
use hashbrown::HashMap;
use tokio::sync::{RwLock, mpsc};

use crate::{DoipDiagGateway, DoipTarget, LOG_TARGET, connections::handle_gateway_connection};

pub(crate) async fn get_vehicle_identification<T, F>(
    socket: &mut UdpSocket,
    gateway_port: u16,
    ecus: &Arc<HashMap<String, RwLock<T>>>,
    shutdown_signal: F,
) -> Result<Vec<DoipTarget>, String>
where
    T: EcuAddressProvider,
    F: Future<Output = ()> + Clone + Send + 'static,
{
    // send VIR
    log::info!(target: LOG_TARGET, "Broadcasting VIR");
    let broadcast_ip = "255.255.255.255";
    socket
        .send(
            DoipPayload::VehicleIdentificationRequest(VehicleIdentificationRequest {}),
            format!("{broadcast_ip}:{gateway_port}")
                .parse()
                .map_err(|_| "Invalid port")?,
        )
        .await
        .map_err(|e| format!("Failed to send VIR: {e:?}"))?;

    let mut gateways = Vec::new();

    let vam_timeout = Duration::from_millis(1000); // not the actual timeout from the spec ...
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
                        match handle_vam::<T>(ecus, doip_msg, source_addr).await {
                            Ok(gateway) => gateways.push(gateway),
                            Err(e) => log::error!(
                                target: LOG_TARGET,
                                "Failed to handle VAM: {e:?}"
                            ),
                        }
                    }
                    Ok(Some(Err(e))) => return Err(format!("Failed to receive VAMs: {e:?}")),
                    Ok(None) => return Err("Gateway closed connection".to_owned()),
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

pub(crate) async fn listen_for_vams<T, F>(
    gateway: DoipDiagGateway<T>,
    variant_detection: mpsc::Sender<Vec<String>>,
    tester_present: mpsc::Sender<TesterPresentControlMessage>,
    shutdown_signal: F,
) where
    T: EcuAddressProvider + DoipComParamProvider,
    F: Future<Output = ()> + Clone + Send + 'static,
{
    #[tracing::instrument(skip(gateway, gateway_ecu_map, gateway_ecu_name_map, variant_detection))]
    async fn handle_doip_response<T: EcuAddressProvider + DoipComParamProvider>(
        gateway: &DoipDiagGateway<T>,
        doip_msg: doip_definitions::message::DoipMessage,
        source_addr: std::net::SocketAddr,
        gateway_ecu_map: &HashMap<u16, Vec<u16>>,
        gateway_ecu_name_map: &HashMap<u16, Vec<String>>,
        variant_detection: mpsc::Sender<Vec<String>>,
        tester_present: mpsc::Sender<TesterPresentControlMessage>,
    ) {
        match handle_vam::<T>(&gateway.ecus, doip_msg, source_addr).await {
            Ok(doip_target) => {
                log::debug!(target: LOG_TARGET, "VAM received from {} on logical address {:#06x}",
                    doip_target.ecu, doip_target.logical_address);
                if gateway
                    .logical_address_to_connection
                    .read()
                    .await
                    .get(&doip_target.logical_address)
                    .is_none()
                {
                    log::info!(target: LOG_TARGET, "New Gateway ECU detected: {}", doip_target.ecu);

                    match handle_gateway_connection::<T>(
                        doip_target,
                        &gateway.doip_connections,
                        &gateway.ecus,
                        gateway_ecu_map,
                        tester_present,
                    )
                    .await
                    {
                        Ok(logical_address) => {
                            // log::info!(target: LOG_TARGET, "New Gateway connection established");
                            gateway.logical_address_to_connection.write().await.insert(
                                logical_address,
                                gateway.doip_connections.read().await.len() - 1,
                            );
                            // log::info!(target: LOG_TARGET, "New Gateway connection stored");
                            if let Some(ecus) = gateway_ecu_name_map.get(&logical_address) {
                                if let Err(e) = variant_detection.send(ecus.clone()).await {
                                    log::error!(target: LOG_TARGET,
                                        "Failed to send variant detection request: {e:?}");
                                } else {
                                    log::info!(target: LOG_TARGET,
                                        "Variant detection request sent for ECUs: {ecus:?}");
                                }
                            }
                        }
                        Err(e) => {
                            log::error!(target: LOG_TARGET,
                                "Failed to handle new Gateway connection: {e:?}");
                        }
                    }
                }
            }
            Err(e) => log::warn!(target: LOG_TARGET, "Failed to handle VAM: {e:?}"),
        }
    }

    // create mapping gateway_logical_address -> Vec<ecu_logical_address>
    let mut gateway_ecu_map: HashMap<u16, Vec<u16>> = HashMap::new();
    let mut gateway_ecu_name_map: HashMap<u16, Vec<String>> = HashMap::new();
    for ecu_lock in gateway.ecus.values() {
        let ecu = ecu_lock.read().await;
        let addr = ecu.logical_address();
        let gateway = ecu.logical_gateway_address();
        gateway_ecu_map
            .entry(gateway)
            .or_insert_with(Vec::new)
            .push(addr);
        gateway_ecu_name_map
            .entry(gateway)
            .or_insert_with(Vec::new)
            .push(ecu.ecu_name().to_lowercase());
    }

    log::info!(target: LOG_TARGET, "Listening for spontaneous VAMs");

    cda_interfaces::spawn_named!(
        "vam-listen",
        Box::pin(async move {
            loop {
                let mut socket = gateway.socket.lock().await;
                let signal = shutdown_signal.clone();
                tokio::select! {
                    () = signal => {
                        break
                    },
                    Some(Ok((doip_msg, source_addr))) = socket.recv() => {
                        if let DoipPayload::VehicleAnnouncementMessage(_) = &doip_msg.payload {
                            handle_doip_response(
                                &gateway, doip_msg, source_addr,
                                &gateway_ecu_map, &gateway_ecu_name_map, variant_detection.clone(),
                                tester_present.clone(),
                            ).await;
                        }
                    }
                }
            }
        })
    );
}

async fn handle_vam<T>(
    ecus: &Arc<HashMap<String, RwLock<T>>>,
    doip_msg: doip_definitions::message::DoipMessage,
    source_addr: std::net::SocketAddr,
) -> Result<DoipTarget, String>
where
    T: EcuAddressProvider,
{
    match doip_msg.payload {
        DoipPayload::VehicleAnnouncementMessage(vam) => {
            log::debug!(target: LOG_TARGET, "VAM received, parsing ...");
            let mut matched_ecu = None;
            for (name, ecu) in ecus.iter() {
                if ecu.read().await.logical_address().to_be_bytes() == vam.logical_address {
                    matched_ecu = Some(name.to_owned());
                    break;
                }
            }
            if let Some(ecu) = matched_ecu {
                let logical_address = u16::from_be_bytes(vam.logical_address);
                log::debug!(
                    target: LOG_TARGET,
                    "Matching ECU found {} on {} logical address {:#06x}",
                    ecu,
                    source_addr.ip(),
                    logical_address
                );
                Ok(DoipTarget {
                    ip: source_addr.ip().to_string(),
                    ecu: ecu.clone(),
                    logical_address,
                })
            } else {
                log::warn!(target: LOG_TARGET, "VAM received but no matching ECU found");
                Err(format!(
                    "No matching ECU found for VAM: {:02x?}",
                    vam.logical_address
                ))
            }
        }
        _ => Err(format!("Expected VAM, got: {doip_msg:?}")),
    }
}
