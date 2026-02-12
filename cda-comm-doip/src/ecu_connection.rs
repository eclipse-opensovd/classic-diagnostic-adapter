/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

use std::{pin::Pin, time::Duration};

use cda_interfaces::{DiagServiceError, dlt_ctx};
use doip_definitions::{
    message::DoipMessage,
    payload::{ActivationCode, DoipPayload, RoutingActivationRequest, RoutingActivationResponse},
};
use openssl::ssl::{Ssl, SslContextBuilder, SslMethod, SslOptions, SslVerifyMode, SslVersion};
use tokio::{
    net::{TcpSocket, TcpStream},
    sync::Mutex,
};
use tokio_openssl::SslStream;

use crate::{
    ConnectionError,
    socket::{DoIPConnection, DoIPConnectionReadHalf, DoIPConnectionWriteHalf},
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

pub(crate) trait ECUConnectionRead {
    async fn read(&mut self) -> Option<Result<DoipMessage, ConnectionError>>
    where
        Self: std::borrow::Borrow<Self>;
}

pub(crate) trait ECUConnectionSend {
    async fn send(&mut self, msg: DoipPayload) -> Result<(), ConnectionError>
    where
        Self: std::borrow::Borrow<Self>;
}

enum EcuConnectionVariant {
    Tls(DoIPConnection<tokio_openssl::SslStream<TcpStream>>),
    Plain(DoIPConnection<TcpStream>),
}

impl EcuConnectionVariant {
    async fn send(&mut self, msg: DoipPayload) -> Result<(), ConnectionError> {
        match self {
            EcuConnectionVariant::Tls(conn) => conn.send(msg).await,
            EcuConnectionVariant::Plain(conn) => conn.send(msg).await,
        }
        .map_err(|e| ConnectionError::SendFailed(format!("Failed to send message: {e:?}")))
    }
    async fn read(&mut self) -> Option<Result<DoipMessage, ConnectionError>> {
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
    Tls(DoIPConnectionReadHalf<tokio_openssl::SslStream<tokio::net::TcpStream>>),
    Plain(DoIPConnectionReadHalf<tokio::net::TcpStream>),
}
pub(crate) enum EcuConnectionSendVariant {
    Tls(DoIPConnectionWriteHalf<tokio_openssl::SslStream<tokio::net::TcpStream>>),
    Plain(DoIPConnectionWriteHalf<tokio::net::TcpStream>),
}

pub(crate) struct EcuConnectionTarget {
    pub(crate) ecu_connection_rx: Mutex<Option<EcuConnectionReadVariant>>,
    pub(crate) ecu_connection_tx: Mutex<Option<EcuConnectionSendVariant>>,
    pub(crate) gateway_name: String,
    pub(crate) gateway_ip: String,
}

pub struct EcuConnectionSendGuard<'a> {
    guard: tokio::sync::MutexGuard<'a, Option<EcuConnectionSendVariant>>,
}

impl EcuConnectionSendGuard<'_> {
    pub(crate) fn get_sender(&mut self) -> &mut EcuConnectionSendVariant {
        self.guard.as_mut().expect("Sender should be Some")
    }
}

pub struct EcuConnectionReadGuard<'a> {
    guard: tokio::sync::MutexGuard<'a, Option<EcuConnectionReadVariant>>,
}

impl EcuConnectionReadGuard<'_> {
    pub(crate) fn get_reader(&mut self) -> &mut EcuConnectionReadVariant {
        self.guard.as_mut().expect("Reader should be Some")
    }
}

pub struct EcuConnectionGuard<'a> {
    read_guard: EcuConnectionReadGuard<'a>,
    send_guard: EcuConnectionSendGuard<'a>,
}

impl EcuConnectionTarget {
    pub(crate) async fn lock_send(&self) -> Result<EcuConnectionSendGuard<'_>, ConnectionError> {
        let guard = self.ecu_connection_tx.lock().await;
        match *guard {
            Some(_) => Ok(EcuConnectionSendGuard { guard }),
            None => Err(ConnectionError::Closed),
        }
    }

    pub(crate) async fn lock_read(&self) -> Result<EcuConnectionReadGuard<'_>, ConnectionError> {
        let guard = self.ecu_connection_rx.lock().await;
        match *guard {
            Some(_) => Ok(EcuConnectionReadGuard { guard }),
            None => Err(ConnectionError::Closed),
        }
    }

    pub(crate) async fn lock_connection(&self) -> EcuConnectionGuard<'_> {
        let ecu_connection_rx = self.ecu_connection_rx.lock().await;
        let ecu_connection_tx = self.ecu_connection_tx.lock().await;
        EcuConnectionGuard {
            read_guard: EcuConnectionReadGuard {
                guard: ecu_connection_rx,
            },
            send_guard: EcuConnectionSendGuard {
                guard: ecu_connection_tx,
            },
        }
    }

    pub(crate) fn reconnect(guard: &mut EcuConnectionGuard<'_>, new_target: EcuConnectionTarget) {
        *guard.read_guard.guard = new_target.ecu_connection_rx.into_inner();
        *guard.send_guard.guard = new_target.ecu_connection_tx.into_inner();
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
    async fn read(&mut self) -> Option<Result<DoipMessage, ConnectionError>> {
        match self {
            EcuConnectionReadVariant::Tls(conn) => conn.read().await,
            EcuConnectionReadVariant::Plain(conn) => conn.read().await,
        }
    }
}

async fn connect_to_gateway(
    tester_ip: &str,
    gateway_ip: &str,
    port: u16,
) -> Result<tokio::net::TcpStream, ConnectionError> {
    tracing::debug!("Connecting to gateway at {gateway_ip}:{port} from tester IP {tester_ip}");
    let target = format!("{gateway_ip}:{port}");
    // todo: the source port should be configurable
    let source_ip = format!("{tester_ip}:0");
    let local_addr = source_ip.parse().map_err(|e| {
        ConnectionError::ConnectionFailed(format!("Failed to parse source IP address: {e:?}"))
    })?;
    let socket = TcpSocket::new_v4().map_err(|e| {
        ConnectionError::ConnectionFailed(format!("Failed to create TCP socket: {e:?}"))
    })?;
    socket.bind(local_addr).map_err(|e| {
        ConnectionError::ConnectionFailed(format!("Failed to bind TCP socket: {e:?}"))
    })?;
    let target_addr = target.parse().map_err(|e| {
        ConnectionError::ConnectionFailed(format!("Failed to parse target IP address: {e:?}"))
    })?;
    let stream = socket.connect(target_addr).await.map_err(|e| {
        ConnectionError::ConnectionFailed(format!("Failed to connect to target: {e:?}"))
    })?;
    tracing::debug!("Successfully created Socket & tokio stream to gateway at {gateway_ip}:{port}");
    Ok(stream)
}

#[tracing::instrument(
    skip(routing_activation_request),
    fields(
        gateway_ip,
        gateway_name,
        connect_timeout_ms = connect_timeout.as_millis(),
        routing_timeout_ms = routing_activation_timeout.as_millis(),
        dlt_context = dlt_ctx!("DOIP"),
    )
)]
pub(crate) async fn establish_ecu_connection(
    tester_ip: &str,
    gateway_ip: &str,
    gateway_name: &str,
    routing_activation_request: RoutingActivationRequest,
    connect_timeout: Duration,
    routing_activation_timeout: Duration,
) -> Result<EcuConnectionTarget, ConnectionError> {
    let mut gateway_conn = match tokio::time::timeout(
        connect_timeout,
        connect_to_gateway(tester_ip, gateway_ip, 13400),
    )
    .await
    {
        Ok(Ok(stream)) => EcuConnectionVariant::Plain(DoIPConnection::new(stream)),
        Ok(Err(e)) => return Err(e),
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
                        ecu_connection_tx: Mutex::new(Some(write)),
                        ecu_connection_rx: Mutex::new(Some(read)),
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
                        tester_ip,
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
        routing_timeout_ms = routing_activation_timeout.as_millis(),
        dlt_context = dlt_ctx!("DOIP"),
    )
)]
pub(crate) async fn establish_tls_ecu_connection(
    tester_ip: &str,
    gateway_ip: &str,
    gateway_name: &str,
    routing_activation_request: RoutingActivationRequest,
    connnect_timeout: Duration,
    routing_activation_timeout: Duration,
) -> Result<EcuConnectionTarget, ConnectionError> {
    let mut gateway_conn = match tokio::time::timeout(
        connnect_timeout,
        connect_to_gateway(tester_ip, gateway_ip, 3496),
    )
    .await
    {
        Ok(Ok(stream)) => {
            // allow unsafe ciphers
            let mut builder = SslContextBuilder::new(SslMethod::tls_client()).map_err(|e| {
                ConnectionError::ConnectionFailed(format!(
                    "Failed to create SSL context builder: {e:?}"
                ))
            })?;

            builder
                .set_cipher_list(&ENABLED_SSL_CIPHERS.join(":"))
                .map_err(|e| {
                    ConnectionError::ConnectionFailed(format!("Failed to set cipher list: {e:?}"))
                })?;
            builder.set_verify(SslVerifyMode::NONE);
            // necessary for NULL encryption
            builder.set_security_level(0);
            builder
                .set_min_proto_version(Some(SslVersion::TLS1_2))
                .map_err(|e| {
                    ConnectionError::ConnectionFailed(format!(
                        "Failed to set minimum TLS version: {e:?}"
                    ))
                })?;
            builder
                .set_max_proto_version(Some(SslVersion::TLS1_3))
                .map_err(|e| {
                    ConnectionError::ConnectionFailed(format!(
                        "Failed to set maximum TLS version: {e:?}"
                    ))
                })?;

            builder
                .set_groups_list(&ELIPTIC_CURVE_GROUPS.join(":"))
                .map_err(|e| {
                    ConnectionError::ConnectionFailed(format!(
                        "Failed to set elliptic curve groups: {e:?}"
                    ))
                })?;

            let preset_options = builder.options();
            // this is the flag legacy_renegotiation in openssl client
            builder
                .set_options(preset_options.union(SslOptions::ALLOW_UNSAFE_LEGACY_RENEGOTIATION));

            let ctx = builder.build();
            let ssl = Ssl::new(&ctx).map_err(|e| {
                ConnectionError::ConnectionFailed(format!("Failed to create SSL context: {e:?}"))
            })?;

            let mut stream = SslStream::new(ssl, stream).map_err(|e| {
                ConnectionError::ConnectionFailed(format!("Failed to create SSL stream: {e:?}"))
            })?;
            // wait for the actual connection .
            Pin::new(&mut stream).connect().await.map_err(|e| {
                ConnectionError::ConnectionFailed(format!("Unable to Pin SSL connection: {e}"))
            })?;

            EcuConnectionVariant::Tls(DoIPConnection::new(stream))
        }
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
                ecu_connection_tx: Mutex::new(Some(write)),
                ecu_connection_rx: Mutex::new(Some(read)),
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
        dlt_context  = dlt_ctx!("DOIP"),
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
        Ok(None) => Err(DiagServiceError::ConnectionClosed(
            "Incomplete routing activation response due to connection closure or error".to_owned(),
        )),
        Err(_) => Err(DiagServiceError::Timeout),
    }
}
