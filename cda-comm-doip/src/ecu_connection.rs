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

use cda_interfaces::{DiagServiceError, dlt_ctx};
use doip_definitions::{
    message::DoipMessage,
    payload::{ActivationCode, DoipPayload, RoutingActivationResponse},
};
#[cfg(all(feature = "mbedtls", not(feature = "openssl")))]
use mbedtls_rs::{
    async_stream::TlsStream,
    ssl::{SslConfigBuilder, SslVerifyMode, TlsVersion},
};
#[cfg(feature = "openssl")]
use openssl::ssl::{Ssl, SslContextBuilder, SslMethod, SslOptions, SslVerifyMode, SslVersion};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpSocket, TcpStream},
    sync::Mutex,
};
#[cfg(feature = "openssl")]
use tokio_openssl::SslStream as TlsStream;

use crate::{
    ConnectionError, GatewayConnectionConfig, GatewayDoipConfig,
    socket::{DoIPConnection, DoIPConnectionReadHalf, DoIPConnectionWriteHalf, DoipSocketConfig},
};

/// This module contains the (currently) static TLS configuration for the CDA
///
/// In the future this should be configurable via configurationfile instead.
mod tlsconfig {
    #[cfg(all(feature = "mbedtls", not(feature = "openssl")))]
    use mbedtls_rs::ffi::{
        MBEDTLS_SSL_EMPTY_RENEGOTIATION_INFO, MBEDTLS_SSL_IANA_TLS_GROUP_BP256R1,
        MBEDTLS_SSL_IANA_TLS_GROUP_BP384R1, MBEDTLS_SSL_IANA_TLS_GROUP_BP512R1,
        MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1, MBEDTLS_SSL_IANA_TLS_GROUP_SECP384R1,
        MBEDTLS_SSL_IANA_TLS_GROUP_SECP521R1, MBEDTLS_SSL_IANA_TLS_GROUP_X448,
        MBEDTLS_SSL_IANA_TLS_GROUP_X25519, MBEDTLS_TLS_ECDHE_ECDSA_WITH_NULL_SHA,
        MBEDTLS_TLS1_3_SIG_ECDSA_SECP256R1_SHA256, MBEDTLS_TLS1_3_SIG_ECDSA_SECP384R1_SHA384,
        MBEDTLS_TLS1_3_SIG_ECDSA_SECP521R1_SHA512, MBEDTLS_TLS1_3_SIG_ECDSA_SHA1,
        MBEDTLS_TLS1_3_SIG_ED25519, MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA1,
        MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA256, MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA384,
        MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA512,
    };

    #[cfg(feature = "openssl")]
    pub const ENABLED_SSL_CIPHERS: [&str; 4] = [
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES128-SHA256",
        "ECDHE-ECDSA-NULL-SHA",
        "TLS_FALLBACK_SCSV",
    ];

    #[cfg(all(feature = "mbedtls", not(feature = "openssl")))]
    pub const MBEDTLS_SSL_CIPHERSUITES: [i32; 2] = [
        MBEDTLS_TLS_ECDHE_ECDSA_WITH_NULL_SHA as i32,
        MBEDTLS_SSL_EMPTY_RENEGOTIATION_INFO as i32,
    ];

    #[cfg(feature = "openssl")]
    pub const ELIPTIC_CURVE_GROUPS: [&str; 8] = [
        "x25519",
        "secp256r1",
        "secp384r1",
        "x448",
        "secp521r1",
        "brainpoolP256r1",
        "brainpoolP384r1",
        "brainpoolP512r1",
    ];

    #[cfg(all(feature = "mbedtls", not(feature = "openssl")))]
    pub const MBEDTLS_CURVE_GROUPS: [u16; 8] = [
        MBEDTLS_SSL_IANA_TLS_GROUP_X25519 as u16,
        MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1 as u16,
        MBEDTLS_SSL_IANA_TLS_GROUP_SECP384R1 as u16,
        MBEDTLS_SSL_IANA_TLS_GROUP_X448 as u16,
        MBEDTLS_SSL_IANA_TLS_GROUP_SECP521R1 as u16,
        MBEDTLS_SSL_IANA_TLS_GROUP_BP256R1 as u16,
        MBEDTLS_SSL_IANA_TLS_GROUP_BP384R1 as u16,
        MBEDTLS_SSL_IANA_TLS_GROUP_BP512R1 as u16,
    ];

    #[cfg(all(feature = "mbedtls", not(feature = "openssl")))]
    pub const MBEDTLS_SIGNATURE_ALGORITHMS: [u16; 9] = [
        MBEDTLS_TLS1_3_SIG_ECDSA_SECP521R1_SHA512 as u16,
        MBEDTLS_TLS1_3_SIG_ECDSA_SECP384R1_SHA384 as u16,
        MBEDTLS_TLS1_3_SIG_ECDSA_SECP256R1_SHA256 as u16,
        MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA512 as u16,
        MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA384 as u16,
        MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA256 as u16,
        MBEDTLS_TLS1_3_SIG_ECDSA_SHA1 as u16,
        MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA1 as u16,
        MBEDTLS_TLS1_3_SIG_ED25519 as u16,
    ];
}

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

enum EcuConnectionVariant<T: AsyncRead + AsyncWrite + Unpin = TcpStream> {
    #[cfg(any(feature = "openssl", feature = "mbedtls"))]
    Tls(DoIPConnection<TlsStream<TcpStream>>),
    Plain(DoIPConnection<T>),
}

impl<T: AsyncRead + AsyncWrite + Unpin> EcuConnectionVariant<T> {
    async fn send(&mut self, msg: DoipPayload) -> Result<(), ConnectionError> {
        match self {
            #[cfg(any(feature = "openssl", feature = "mbedtls"))]
            EcuConnectionVariant::Tls(conn) => conn.send(msg).await,
            EcuConnectionVariant::Plain(conn) => conn.send(msg).await,
        }
        .map_err(|e| ConnectionError::SendFailed(format!("Failed to send message: {e:?}")))
    }
    async fn read(&mut self) -> Option<Result<DoipMessage, ConnectionError>> {
        match self {
            #[cfg(any(feature = "openssl", feature = "mbedtls"))]
            EcuConnectionVariant::Tls(conn) => conn.read().await,
            EcuConnectionVariant::Plain(conn) => conn.read().await,
        }
    }
    fn into_split(self) -> (EcuConnectionReadVariant<T>, EcuConnectionSendVariant<T>) {
        match self {
            #[cfg(any(feature = "openssl", feature = "mbedtls"))]
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

pub(crate) enum EcuConnectionReadVariant<T: AsyncRead + Unpin = TcpStream> {
    #[cfg(any(feature = "openssl", feature = "mbedtls"))]
    Tls(DoIPConnectionReadHalf<TlsStream<TcpStream>>),
    Plain(DoIPConnectionReadHalf<T>),
}
pub(crate) enum EcuConnectionSendVariant<T: AsyncWrite + Unpin = TcpStream> {
    #[cfg(any(feature = "openssl", feature = "mbedtls"))]
    Tls(DoIPConnectionWriteHalf<TlsStream<TcpStream>>),
    Plain(DoIPConnectionWriteHalf<T>),
}

pub(crate) struct EcuConnectionTarget<
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static = TcpStream,
> {
    pub(crate) ecu_connection_rx: Mutex<Option<EcuConnectionReadVariant<T>>>,
    pub(crate) ecu_connection_tx: Mutex<Option<EcuConnectionSendVariant<T>>>,
    pub(crate) gateway_doip_config: GatewayDoipConfig,
}

pub struct EcuConnectionSendGuard<'a, T: AsyncWrite + Unpin = TcpStream> {
    guard: tokio::sync::MutexGuard<'a, Option<EcuConnectionSendVariant<T>>>,
}

impl<T: AsyncWrite + Unpin> EcuConnectionSendGuard<'_, T> {
    pub(crate) fn get_sender(&mut self) -> &mut EcuConnectionSendVariant<T> {
        self.guard.as_mut().expect("Sender should be Some")
    }
}

pub struct EcuConnectionReadGuard<'a, T: AsyncRead + Unpin = TcpStream> {
    guard: tokio::sync::MutexGuard<'a, Option<EcuConnectionReadVariant<T>>>,
}

impl<T: AsyncRead + Unpin> EcuConnectionReadGuard<'_, T> {
    pub(crate) fn get_reader(&mut self) -> &mut EcuConnectionReadVariant<T> {
        self.guard.as_mut().expect("Reader should be Some")
    }
}

pub struct EcuConnectionGuard<'a, T: AsyncRead + AsyncWrite + Unpin + Send + 'static = TcpStream> {
    read_guard: EcuConnectionReadGuard<'a, T>,
    send_guard: EcuConnectionSendGuard<'a, T>,
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> EcuConnectionTarget<T> {
    pub(crate) async fn lock_send(&self) -> Result<EcuConnectionSendGuard<'_, T>, ConnectionError> {
        let guard = self.ecu_connection_tx.lock().await;
        match *guard {
            Some(_) => Ok(EcuConnectionSendGuard { guard }),
            None => Err(ConnectionError::Closed),
        }
    }

    pub(crate) async fn lock_read(&self) -> Result<EcuConnectionReadGuard<'_, T>, ConnectionError> {
        let guard = self.ecu_connection_rx.lock().await;
        match *guard {
            Some(_) => Ok(EcuConnectionReadGuard { guard }),
            None => Err(ConnectionError::Closed),
        }
    }

    pub(crate) async fn lock_connection(&self) -> EcuConnectionGuard<'_, T> {
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

    pub(crate) fn reconnect(
        guard: &mut EcuConnectionGuard<'_, T>,
        new_target: EcuConnectionTarget<T>,
    ) {
        *guard.read_guard.guard = new_target.ecu_connection_rx.into_inner();
        *guard.send_guard.guard = new_target.ecu_connection_tx.into_inner();
    }
}

impl<T: AsyncWrite + Unpin> ECUConnectionSend for EcuConnectionSendVariant<T> {
    async fn send(&mut self, msg: DoipPayload) -> Result<(), ConnectionError> {
        match self {
            #[cfg(any(feature = "openssl", feature = "mbedtls"))]
            EcuConnectionSendVariant::Tls(conn) => conn.send(msg).await,
            EcuConnectionSendVariant::Plain(conn) => conn.send(msg).await,
        }
        .map_err(|e| ConnectionError::SendFailed(format!("Failed to send message: {e:?}")))
    }
}

impl<T: AsyncRead + Unpin> ECUConnectionRead for EcuConnectionReadVariant<T> {
    async fn read(&mut self) -> Option<Result<DoipMessage, ConnectionError>> {
        match self {
            #[cfg(any(feature = "openssl", feature = "mbedtls"))]
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

fn socket_config(config: &GatewayConnectionConfig) -> DoipSocketConfig {
    DoipSocketConfig {
        protocol_version: config.doip.protocol_version,
        send_diagnostic_message_ack: config.doip.transport.send_diagnostic_message_ack,
    }
}

#[tracing::instrument(
    skip_all,
    fields(
        tester_ip = config.doip.transport.tester_ip.clone(),
        port = config.doip.transport.port,
        gateway_ip = config.doip.gateway_ip.clone(),
        gateway_name = config.doip.name.clone(),
        connect_timeout_ms = config.ecu_timeouts.connection.as_millis(),
        routing_timeout_ms = config.ecu_timeouts.routing_activation.as_millis(),
        dlt_context = dlt_ctx!("DOIP"),
    )
)]
pub(crate) async fn establish_ecu_connection(
    config: &GatewayConnectionConfig,
) -> Result<EcuConnectionTarget, ConnectionError> {
    let mut gateway_conn = match tokio::time::timeout(
        config.ecu_timeouts.connection,
        connect_to_gateway(
            &config.doip.transport.tester_ip,
            &config.doip.gateway_ip,
            config.doip.transport.port,
        ),
    )
    .await
    {
        Ok(Ok(stream)) => {
            EcuConnectionVariant::Plain(DoIPConnection::new(stream, socket_config(config)))
        }
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(ConnectionError::Timeout(
                "Connect timed out after 10 seconds".to_owned(),
            ));
        }
    };

    if let Err(e) = gateway_conn
        .send(DoipPayload::RoutingActivationRequest(
            config.routing_activation_request,
        ))
        .await
    {
        return Err(ConnectionError::RoutingError(format!(
            "Failed to send routing activation: {e:?}"
        )));
    }

    match try_read_routing_activation_response(
        config.ecu_timeouts.routing_activation,
        &mut gateway_conn,
        &config.doip.name,
        &config.doip.gateway_ip,
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
                        gateway_doip_config: config.doip.clone(),
                    })
                }
                ActivationCode::DeniedRequestEncryptedTLSConnection => {
                    tracing::info!("TLS connection requested");
                    let tls_gateway_name = if config.doip.name.ends_with("[TLS]") {
                        config.doip.name.clone()
                    } else {
                        format!("{} [TLS]", config.doip.name)
                    };

                    let mut tls_config = config.clone();
                    tls_config.doip.name = tls_gateway_name;
                    establish_tls_ecu_connection(&tls_config).await
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
    skip_all,
    fields(
        tester_ip = config.doip.transport.tester_ip.clone(),
        port = config.doip.transport.tls_port,
        gateway_ip = config.doip.gateway_ip.clone(),
        gateway_name = config.doip.name.clone(),
        connect_timeout_ms = config.ecu_timeouts.connection.as_millis(),
        routing_timeout_ms = config.ecu_timeouts.routing_activation.as_millis(),
        dlt_context = dlt_ctx!("DOIP"),
    )
)]
pub(crate) async fn establish_tls_ecu_connection(
    config: &GatewayConnectionConfig,
) -> Result<EcuConnectionTarget, ConnectionError> {
    let mut gateway_conn = match tokio::time::timeout(
        config.ecu_timeouts.connection,
        connect_to_gateway(
            &config.doip.transport.tester_ip,
            &config.doip.gateway_ip,
            config.doip.transport.tls_port,
        ),
    )
    .await
    {
        Ok(Ok(stream)) => create_tls_stream(stream, socket_config(config)).await?,
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
            config.routing_activation_request,
        ))
        .await
    {
        return Err(ConnectionError::RoutingError(format!(
            "Failed to send routing activation: {e:?}"
        )));
    }

    match try_read_routing_activation_response(
        config.ecu_timeouts.routing_activation,
        &mut gateway_conn,
        &config.doip.name,
        &config.doip.gateway_ip,
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
                gateway_doip_config: config.doip.clone(),
            }) // Routing activated
        }
        Err(e) => Err(ConnectionError::RoutingError(format!(
            "Failed to activate routing: {e:?}"
        ))),
    }
}

#[cfg(all(feature = "mbedtls", not(feature = "openssl")))]
async fn create_tls_stream(
    stream: tokio::net::TcpStream,
    socket_config: DoipSocketConfig,
) -> Result<EcuConnectionVariant, ConnectionError> {
    let config = SslConfigBuilder::new_client()
        .map_err(|e| {
            ConnectionError::ConnectionFailed(format!("Failed to create SSL config: {e:?}"))
        })?
        .max_tls_version(TlsVersion::Tls12)
        .min_tls_version(TlsVersion::Tls12)
        .verify_mode(SslVerifyMode::None)
        .ciphersuites(tlsconfig::MBEDTLS_SSL_CIPHERSUITES.as_slice())
        .groups(tlsconfig::MBEDTLS_CURVE_GROUPS.as_slice())
        .sig_algs(tlsconfig::MBEDTLS_SIGNATURE_ALGORITHMS.as_slice())
        .build();

    let ssl = TlsStream::connect(config, stream, None)
        .await
        .map_err(|e| {
            ConnectionError::ConnectionFailed(format!("Failed to create SSL stream: {e:?}"))
        })?;
    Ok(EcuConnectionVariant::Tls(DoIPConnection::new(
        ssl,
        socket_config,
    )))
}

#[cfg(feature = "openssl")]
async fn create_tls_stream(
    stream: tokio::net::TcpStream,
    socket_config: DoipSocketConfig,
) -> Result<EcuConnectionVariant, ConnectionError> {
    // allow unsafe ciphers
    let mut builder = SslContextBuilder::new(SslMethod::tls_client()).map_err(|e| {
        ConnectionError::ConnectionFailed(format!("Failed to create SSL context builder: {e:?}"))
    })?;

    builder
        .set_cipher_list(&tlsconfig::ENABLED_SSL_CIPHERS.join(":"))
        .map_err(|e| {
            ConnectionError::ConnectionFailed(format!("Failed to set cipher list: {e:?}"))
        })?;
    builder.set_verify(SslVerifyMode::NONE);
    // necessary for NULL encryption
    builder.set_security_level(0);
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .map_err(|e| {
            ConnectionError::ConnectionFailed(format!("Failed to set minimum TLS version: {e:?}"))
        })?;
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|e| {
            ConnectionError::ConnectionFailed(format!("Failed to set maximum TLS version: {e:?}"))
        })?;

    builder
        .set_groups_list(&tlsconfig::ELIPTIC_CURVE_GROUPS.join(":"))
        .map_err(|e| {
            ConnectionError::ConnectionFailed(format!("Failed to set elliptic curve groups: {e:?}"))
        })?;

    let preset_options = builder.options();
    // this is the flag legacy_renegotiation in openssl client
    builder.set_options(preset_options.union(SslOptions::ALLOW_UNSAFE_LEGACY_RENEGOTIATION));

    let ctx = builder.build();
    let ssl = Ssl::new(&ctx).map_err(|e| {
        ConnectionError::ConnectionFailed(format!("Failed to create SSL context: {e:?}"))
    })?;

    let mut stream = TlsStream::new(ssl, stream).map_err(|e| {
        ConnectionError::ConnectionFailed(format!("Failed to create SSL stream: {e:?}"))
    })?;
    // wait for the actual connection .
    std::pin::Pin::new(&mut stream)
        .connect()
        .await
        .map_err(|e| {
            ConnectionError::ConnectionFailed(format!("Unable to Pin SSL connection: {e}"))
        })?;

    Ok(EcuConnectionVariant::Tls(DoIPConnection::new(
        stream,
        socket_config,
    )))
}

// Allow building CDA without TLS support
#[cfg(all(not(feature = "openssl"), not(feature = "mbedtls")))]
#[allow(
    clippy::unused_async,
    reason = "async matches the signature of the TLS-enabled variant"
)]
async fn create_tls_stream(
    _stream: tokio::net::TcpStream,
    _socket_config: DoipSocketConfig,
) -> Result<EcuConnectionVariant, ConnectionError> {
    Err(ConnectionError::ConnectionFailed(
        "CDA built without TLS support.".to_owned(),
    ))
}

#[allow(
    clippy::used_underscore_binding,
    reason = "Variables are unused in the function but required as named tracing fields"
)]
#[tracing::instrument(
    skip(reader),
    fields(
        gateway_name = %_gateway_name,
        gateway_ip   = %_gateway_ip,
        timeout_ms   = timeout.as_millis(),
        dlt_context  = dlt_ctx!("DOIP"),
    )
)]
async fn try_read_routing_activation_response<T: AsyncRead + AsyncWrite + Unpin>(
    timeout: std::time::Duration,
    reader: &mut EcuConnectionVariant<T>,
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
