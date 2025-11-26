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

use cda_interfaces::DiagServiceError;
use doip_definitions::{
    message::DoipMessage,
    payload::{ActivationCode, DoipPayload, RoutingActivationRequest, RoutingActivationResponse},
};
use tokio::sync::Mutex;

use crate::ConnectionError;

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

pub(crate) trait ECUConnectionRead {
    async fn read(&mut self) -> Option<Result<DoipMessage, doip_sockets::Error>>
    where
        Self: std::borrow::Borrow<Self>;
}

pub(crate) trait ECUConnectionSend {
    async fn send(&mut self, msg: DoipPayload) -> Result<(), ConnectionError>
    where
        Self: std::borrow::Borrow<Self>;
}

enum EcuConnectionVariant {
    Tls(doip_sockets::tcp::DoIpSslStream),
    Plain(doip_sockets::tcp::TcpStream),
}

impl EcuConnectionVariant {
    async fn send(&mut self, msg: DoipPayload) -> Result<(), ConnectionError> {
        match self {
            EcuConnectionVariant::Tls(conn) => conn.send(msg).await,
            EcuConnectionVariant::Plain(conn) => conn.send(msg).await,
        }
        .map_err(|e| ConnectionError::SendFailed(format!("Failed to send message: {e:?}")))
    }
    async fn read(&mut self) -> Option<Result<DoipMessage, doip_sockets::Error>> {
        match self {
            EcuConnectionVariant::Tls(conn) => conn.read().await,
            EcuConnectionVariant::Plain(conn) => conn.read().await,
        }
    }
    fn into_split(self) -> (EcuConnectionReadVariant, EcuConnectionSendVariant) {
        match self {
            EcuConnectionVariant::Tls(conn) => {
                let (read, write) = conn.into_split();
                (
                    EcuConnectionReadVariant::Tls(read),
                    EcuConnectionSendVariant::Tls(write),
                )
            }
            EcuConnectionVariant::Plain(conn) => {
                let (read, write) = conn.into_split();
                (
                    EcuConnectionReadVariant::Plain(read),
                    EcuConnectionSendVariant::Plain(write),
                )
            }
        }
    }
}

pub(crate) enum EcuConnectionReadVariant {
    Tls(doip_sockets::tcp::TcpStreamReadHalf<tokio_openssl::SslStream<tokio::net::TcpStream>>),
    Plain(doip_sockets::tcp::TcpStreamReadHalf<tokio::net::TcpStream>),
}
pub(crate) enum EcuConnectionSendVariant {
    Tls(doip_sockets::tcp::TcpStreamWriteHalf<tokio_openssl::SslStream<tokio::net::TcpStream>>),
    Plain(doip_sockets::tcp::TcpStreamWriteHalf<tokio::net::TcpStream>),
}

pub(crate) struct EcuConnectionTarget {
    pub(crate) ecu_connection_rx: Mutex<EcuConnectionReadVariant>,
    pub(crate) ecu_connection_tx: Mutex<EcuConnectionSendVariant>,
    pub(crate) gateway_name: String,
    pub(crate) gateway_ip: String,
}

impl EcuConnectionTarget {
    pub(crate) async fn lock_send(&self) -> tokio::sync::MutexGuard<'_, EcuConnectionSendVariant> {
        self.ecu_connection_tx.lock().await
    }

    pub(crate) async fn lock_read(&self) -> tokio::sync::MutexGuard<'_, EcuConnectionReadVariant> {
        self.ecu_connection_rx.lock().await
    }

    pub(crate) async fn replace_connection(&self, new_target: EcuConnectionTarget) {
        let mut ecu_connection_rx = self.ecu_connection_rx.lock().await;
        let mut ecu_connection_tx = self.ecu_connection_tx.lock().await;
        *ecu_connection_rx = new_target.ecu_connection_rx.into_inner();
        *ecu_connection_tx = new_target.ecu_connection_tx.into_inner();
    }
}

impl ECUConnectionSend for EcuConnectionSendVariant {
    async fn send(&mut self, msg: DoipPayload) -> Result<(), ConnectionError> {
        match self {
            EcuConnectionSendVariant::Tls(conn) => conn.send(msg).await,
            EcuConnectionSendVariant::Plain(conn) => conn.send(msg).await,
        }
        .map_err(|e| ConnectionError::SendFailed(format!("Failed to send message: {e:?}")))
    }
}

impl ECUConnectionRead for EcuConnectionReadVariant {
    async fn read(&mut self) -> Option<Result<DoipMessage, doip_sockets::Error>> {
        match self {
            EcuConnectionReadVariant::Tls(conn) => conn.read().await,
            EcuConnectionReadVariant::Plain(conn) => conn.read().await,
        }
    }
}

#[tracing::instrument(
    skip(routing_activation_request),
    fields(
        gateway_ip,
        gateway_name,
        connect_timeout_ms = connect_timeout.as_millis(),
        routing_timeout_ms = routing_activation_timeout.as_millis()
    )
)]
pub(crate) async fn establish_ecu_connection(
    gateway_ip: &str,
    gateway_name: &str,
    routing_activation_request: RoutingActivationRequest,
    connect_timeout: Duration,
    routing_activation_timeout: Duration,
) -> Result<EcuConnectionTarget, ConnectionError> {
    let mut gateway_conn = match tokio::time::timeout(
        connect_timeout,
        doip_sockets::tcp::TcpStream::connect(format!("{}:{}", gateway_ip, 13400)), // unencrypted
    )
    .await
    {
        Ok(Ok(stream)) => EcuConnectionVariant::Plain(stream),
        Ok(Err(e)) => return Err(ConnectionError::ConnectionFailed(e.to_string())),
        Err(_) => {
            return Err(ConnectionError::Timeout(
                "Connect timed out after 10 seconds".to_owned(),
            ));
        }
    };

    if let Err(e) = gateway_conn
        .send(DoipPayload::RoutingActivationRequest(
            routing_activation_request,
        ))
        .await
    {
        return Err(ConnectionError::RoutingError(format!(
            "Failed to send routing activation: {e:?}"
        )));
    }

    match try_read_routing_activation_response(
        routing_activation_timeout,
        &mut gateway_conn,
        gateway_name,
        gateway_ip,
    )
    .await
    {
        Ok(msg) => {
            match msg.activation_code {
                ActivationCode::SuccessfullyActivated => {
                    tracing::info!("Routing activated");
                    let (read, write) = gateway_conn.into_split();
                    // Routing activated
                    Ok(EcuConnectionTarget {
                        ecu_connection_tx: Mutex::new(write),
                        ecu_connection_rx: Mutex::new(read),
                        gateway_name: gateway_name.to_owned(),
                        gateway_ip: gateway_ip.to_owned(),
                    })
                }
                ActivationCode::DeniedRequestEncryptedTLSConnection => {
                    tracing::info!("TLS connection requested");
                    let tls_gateway_name = if gateway_name.ends_with("[TLS]") {
                        gateway_name.to_owned()
                    } else {
                        format!("{gateway_name} [TLS]")
                    };

                    establish_tls_ecu_connection(
                        gateway_ip,
                        &tls_gateway_name,
                        routing_activation_request,
                        connect_timeout,
                        routing_activation_timeout,
                    )
                    .await
                }
                _ => Err(ConnectionError::RoutingError(format!(
                    "Failed to activate routing: {:?}",
                    msg.activation_code
                ))),
            }
        }
        Err(e) => Err(ConnectionError::RoutingError(format!(
            "Failed to activate routing: {e:?}"
        ))),
    }
}

#[tracing::instrument(
    skip(routing_activation_request),
    fields(
        gateway_ip,
        gateway_name,
        connect_timeout_ms = connnect_timeout.as_millis(),
        routing_timeout_ms = routing_activation_timeout.as_millis()
    )
)]
pub(crate) async fn establish_tls_ecu_connection(
    gateway_ip: &str,
    gateway_name: &str,
    routing_activation_request: RoutingActivationRequest,
    connnect_timeout: Duration,
    routing_activation_timeout: Duration,
) -> Result<EcuConnectionTarget, ConnectionError> {
    let mut gateway_conn = match tokio::time::timeout(
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
        Ok(Err(e)) => {
            return Err(ConnectionError::ConnectionFailed(format!(
                "Connect failed: {e:?}"
            )));
        }
        Err(_) => {
            return Err(ConnectionError::Timeout(
                "Connect timed out after 10 seconds".to_owned(),
            ));
        }
    };

    if let Err(e) = gateway_conn
        .send(DoipPayload::RoutingActivationRequest(
            routing_activation_request,
        ))
        .await
    {
        return Err(ConnectionError::RoutingError(format!(
            "Failed to send routing activation: {e:?}"
        )));
    }

    match try_read_routing_activation_response(
        routing_activation_timeout,
        &mut gateway_conn,
        gateway_name,
        gateway_ip,
    )
    .await
    {
        Ok(msg) => {
            if msg.activation_code != ActivationCode::SuccessfullyActivated {
                return Err(ConnectionError::RoutingError(format!(
                    "Failed to activate routing: {:?}",
                    msg.activation_code
                )));
            }
            tracing::info!("Routing activated");
            let (read, write) = gateway_conn.into_split();
            Ok(EcuConnectionTarget {
                ecu_connection_tx: Mutex::new(write),
                ecu_connection_rx: Mutex::new(read),
                gateway_name: gateway_name.to_owned(),
                gateway_ip: gateway_ip.to_owned(),
            }) // Routing activated
        }
        Err(e) => Err(ConnectionError::RoutingError(format!(
            "Failed to activate routing: {e:?}"
        ))),
    }
}

// Allow the underscore bindings because the variables
// are not used, but we want them in the tracing fields.
#[allow(clippy::used_underscore_binding)]
#[tracing::instrument(
    skip(reader),
    fields(
        gateway_name = %_gateway_name,
        gateway_ip   = %_gateway_ip,
        timeout_ms   = timeout.as_millis(),
    )
)]
async fn try_read_routing_activation_response(
    timeout: std::time::Duration,
    reader: &mut EcuConnectionVariant,
    _gateway_name: &str,
    _gateway_ip: &str,
) -> Result<RoutingActivationResponse, DiagServiceError> {
    match tokio::time::timeout(timeout, reader.read()).await {
        Ok(Some(Ok(msg))) => match msg.payload {
            DoipPayload::RoutingActivationResponse(routing_activation_response) => {
                tracing::debug!(
                    source_address = ?routing_activation_response.source_address,
                    logical_address = ?routing_activation_response.logical_address,
                    "Received routing activation response"
                );
                Ok(routing_activation_response)
            }
            _ => Err(DiagServiceError::UnexpectedResponse(Some(format!(
                "Received non-routing activation response: {msg:?}"
            )))),
        },
        Ok(Some(Err(e))) => Err(DiagServiceError::UnexpectedResponse(Some(format!(
            "Error reading from gateway: {e:?}"
        )))),
        Ok(None) => Err(DiagServiceError::ConnectionClosed),
        Err(_) => Err(DiagServiceError::Timeout),
    }
}
