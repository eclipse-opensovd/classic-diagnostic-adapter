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

use std::time::Duration;

use doip_definitions::{
    message::DoipMessage,
    payload::{ActivationCode, DoipPayload, RoutingActivationRequest, RoutingActivationResponse},
};

const ENABLED_SSL_CIPHERS: [&str; 4] = [
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES128-SHA256",
    "ECDHE-ECDSA-NULL-SHA",
    "TLS_FALLBACK_SCSV",
];

const ELIPTIC_CURVE_GROUPS: [&str; 8] = [
    "x25519",
    "secp256r1",
    "secp384r1",
    "x448",
    "secp521r1",
    "brainpoolP256r1",
    "brainpoolP384r1",
    "brainpoolP512r1",
];

pub(crate) trait ECUConnection {
    async fn send(&mut self, msg: DoipPayload) -> Result<(), String>
    where
        Self: std::borrow::Borrow<Self>;
    async fn read(&mut self) -> Option<Result<DoipMessage, doip_sockets::Error>>
    where
        Self: std::borrow::Borrow<Self>;
}

pub(crate) enum EcuConnectionVariant {
    Tls(doip_sockets::tcp::DoIpSslStream),
    Plain(doip_sockets::tcp::TcpStream),
}

pub(crate) struct EcuConnectionTarget {
    pub(crate) ecu_connection: EcuConnectionVariant,
    pub(crate) log_target: String,
}

impl ECUConnection for EcuConnectionVariant {
    async fn send(&mut self, msg: DoipPayload) -> Result<(), String> {
        match self {
            EcuConnectionVariant::Tls(conn) => conn.send(msg).await,
            EcuConnectionVariant::Plain(conn) => conn.send(msg).await,
        }
        .map_err(|e| format!("Failed to send message: {e:?}"))
    }

    async fn read(&mut self) -> Option<Result<DoipMessage, doip_sockets::Error>> {
        match self {
            EcuConnectionVariant::Tls(conn) => conn.read().await,
            EcuConnectionVariant::Plain(conn) => conn.read().await,
        }
    }
}

pub(crate) async fn establish_ecu_connection(
    gateway_ip: &str,
    routing_activation_request: RoutingActivationRequest,
    log_target: &str,
    connect_timeout: Duration,
    routing_activation_timeout: Duration,
) -> Result<EcuConnectionTarget, String> {
    let mut gateway_conn: EcuConnectionVariant = match tokio::time::timeout(
        connect_timeout,
        doip_sockets::tcp::TcpStream::connect(format!("{}:{}", gateway_ip, 13400)), // unencrypted
    )
    .await
    {
        Ok(Ok(stream)) => EcuConnectionVariant::Plain(stream),
        Ok(Err(e)) => return Err(format!("Connect failed: {e:?}")),
        Err(_) => return Err("Connect timed out after 10 seconds".to_owned()),
    };

    if let Err(e) = gateway_conn
        .send(DoipPayload::RoutingActivationRequest(
            routing_activation_request,
        ))
        .await
    {
        return Err(format!("Failed to send routing activation: {e:?}"));
    }

    match try_read_routing_activation_response(
        routing_activation_timeout,
        &mut gateway_conn,
        log_target,
    )
    .await
    {
        Ok(msg) => {
            match msg.activation_code {
                ActivationCode::SuccessfullyActivated => {
                    log::info!(target: &log_target, "Routing activated");
                    // Routing activated
                    Ok(EcuConnectionTarget {
                        ecu_connection: gateway_conn,
                        log_target: log_target.to_owned(),
                    })
                }
                ActivationCode::DeniedRequestEncryptedTLSConnection => {
                    log::info!(target: &log_target, "TLS connection requested");
                    let log_target = if log_target.ends_with("[TLS]") {
                        log_target.to_owned()
                    } else {
                        format!("{log_target} [TLS]")
                    };

                    establish_tls_ecu_connection(
                        gateway_ip,
                        routing_activation_request,
                        connect_timeout,
                        routing_activation_timeout,
                        &log_target,
                    )
                    .await
                    .map(|conn| EcuConnectionTarget {
                        ecu_connection: conn,
                        log_target,
                    })
                }
                _ => Err(format!(
                    "Failed to activate routing: {:?}",
                    msg.activation_code
                )),
            }
        }
        Err(e) => Err(format!("Failed to activate routing: {e:?}")),
    }
}

pub(crate) async fn establish_tls_ecu_connection(
    gateway_ip: &str,
    routing_activation_request: RoutingActivationRequest,
    connnect_timeout: Duration,
    routing_activation_timeout: Duration,
    log_target: &String,
) -> Result<EcuConnectionVariant, String> {
    let mut gateway_conn: EcuConnectionVariant = match tokio::time::timeout(
        connnect_timeout,
        doip_sockets::tcp::DoIpSslStream::connect_with_ciphers(
            format!("{}:{}", gateway_ip, 3496),
            &ENABLED_SSL_CIPHERS,
            Some(&ELIPTIC_CURVE_GROUPS),
        ), // ssl
    )
    .await
    {
        Ok(Ok(stream)) => EcuConnectionVariant::Tls(stream),
        Ok(Err(e)) => return Err(format!("Connect failed: {e:?}")),
        Err(_) => return Err("Connect timed out after 10 seconds".to_owned()),
    };

    if let Err(e) = gateway_conn
        .send(DoipPayload::RoutingActivationRequest(
            routing_activation_request,
        ))
        .await
    {
        return Err(format!("Failed to send routing activation: {e:?}"));
    }

    match try_read_routing_activation_response(
        routing_activation_timeout,
        &mut gateway_conn,
        log_target,
    )
    .await
    {
        Ok(msg) => {
            if msg.activation_code != ActivationCode::SuccessfullyActivated {
                return Err(format!(
                    "Failed to activate routing: {:?}",
                    msg.activation_code
                ));
            }
            log::info!(target: &log_target, "Routing activated");
            Ok(gateway_conn) // Routing activated
        }
        Err(e) => Err(format!("Failed to activate routing: {e:?}")),
    }
}

async fn try_read_routing_activation_response(
    timeout: std::time::Duration,
    reader: &mut impl ECUConnection,
    log_target: &str,
) -> Result<RoutingActivationResponse, String> {
    match tokio::time::timeout(timeout, reader.read()).await {
        Ok(Some(Ok(msg))) => match msg.payload {
            DoipPayload::RoutingActivationResponse(routing_activation_response) => {
                log::debug!(target: &log_target, "Received routing activation response from source {:02x?} with logical address {:02x?}", routing_activation_response.source_address, routing_activation_response.logical_address);
                Ok(routing_activation_response)
            }
            _ => Err(format!("Received non-routing activation response: {msg:?}")),
        },
        Ok(Some(Err(e))) => Err(format!("Error reading from gateway: {e:?}")),
        Ok(None) => Err("Gateway closed connection".to_owned()),
        Err(_) => Err("Timeout waiting for Routing Activation Response".to_owned()),
    }
}
