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

// The `can` feature alone relies on Linux SocketCAN ISO-TP sockets
// (tokio-socketcan-isotp). Off Linux it is only usable together with a
// platform-independent transport: `can-socketcand`
// (`socketcand:<host>:<port>:<bus>`). Fail early with an actionable message
// instead of letting socket creation fail at runtime with a cryptic error.
#[cfg(all(
    feature = "can",
    not(target_os = "linux"),
    not(feature = "can-socketcand")
))]
compile_error!(
    "The `can` feature requires Linux (SocketCAN/ISO-TP). On other platforms enable \
     `can-socketcand` to reach a CAN bus over a socketcand daemon."
);

pub mod config;
pub mod multi_transport;

// Re-export types that are always available
pub use multi_transport::{MultiTransportGateway, TransportType};

// The CAN transport itself is compiled only with the `can` feature; the
// single gate here lets everything inside `gateway` assume the feature is
// enabled.
#[cfg(feature = "can")]
mod gateway;
#[cfg(feature = "can")]
pub use gateway::{CanDiagGateway, error};

/// Stub `CanDiagGateway` when the `can` feature is disabled.
///
/// This type exists only to satisfy the `Option<CanDiagGateway>` field in
/// [`MultiTransportGateway`]. It has no constructor, so a value of this type
/// can never exist in a non-`can` build: the `EcuGateway` impl below is only
/// needed for type-checking and is statically unreachable.
#[cfg(not(feature = "can"))]
#[derive(Clone)]
pub struct CanDiagGateway {
    _unconstructable: std::convert::Infallible,
}

#[cfg(not(feature = "can"))]
impl cda_interfaces::EcuGateway for CanDiagGateway {
    async fn shutdown(&mut self) {}

    async fn get_gateway_network_address(&self, _logical_address: u16) -> Option<String> {
        None
    }

    async fn send(
        &self,
        _transmission_params: cda_interfaces::TransmissionParameters,
        _message: cda_interfaces::ServicePayload,
        _response_sender: tokio::sync::mpsc::Sender<
            Result<Option<cda_interfaces::UdsResponse>, cda_interfaces::DiagServiceError>,
        >,
        _expect_uds_reply: bool,
    ) -> Result<(), cda_interfaces::DiagServiceError> {
        Err(cda_interfaces::DiagServiceError::EcuOffline(
            "CAN support is not enabled. Compile with the `can` feature.".to_owned(),
        ))
    }

    async fn ecu_online<E: cda_interfaces::EcuAddresses>(
        &self,
        _ecu_name: &str,
        _ecu_db: &tokio::sync::RwLock<E>,
    ) -> Result<(), cda_interfaces::DiagServiceError> {
        Err(cda_interfaces::DiagServiceError::EcuOffline(
            "CAN support is not enabled. Compile with the `can` feature.".to_owned(),
        ))
    }

    async fn send_functional(
        &self,
        _transmission_params: cda_interfaces::TransmissionParameters,
        _message: cda_interfaces::ServicePayload,
        expected_ecu_logical_addrs: cda_interfaces::HashMap<u16, String>,
        _timeout: std::time::Duration,
        _expect_positive_response: bool,
    ) -> Result<
        cda_interfaces::HashMap<
            String,
            Result<cda_interfaces::UdsResponse, cda_interfaces::DiagServiceError>,
        >,
        cda_interfaces::DiagServiceError,
    > {
        Ok(expected_ecu_logical_addrs
            .into_values()
            .map(|name| {
                (
                    name,
                    Err(cda_interfaces::DiagServiceError::EcuOffline(
                        "CAN support is not enabled. Compile with the `can` feature.".to_owned(),
                    )),
                )
            })
            .collect())
    }
}
