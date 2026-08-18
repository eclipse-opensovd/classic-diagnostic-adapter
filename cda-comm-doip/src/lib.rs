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

//! `DoIP` (Diagnostics over IP) transport for the Classic Diagnostic Adapter.
//!
//! The actual transport implementation - socket creation, gateway state,
//! connection handling and everything that depends on `doip-definitions` /
//! `doip-codec` / `socket2` / `futures` / `tokio-util` - is compiled only with
//! the `doip` feature. Without it this crate exposes only the config and error
//! types plus uninhabited stubs of [`DoipDiagGateway`], [`socket::DoIPUdpSocket`],
//! and [`create_udp_vir_socket`], so downstream crates (`cda-main`, `cda-sovd`,
//! `integration-tests`) compile unchanged and CDA can ship as a CAN-only
//! binary without pulling in the `DoIP` dependency tree.

pub mod config;
pub mod error;
pub use error::{ConnectionError, DoipGatewaySetupError};

// The DoIP transport itself and every module that pulls in `doip-definitions`
// / `doip-codec` / `socket2` / `futures` / `tokio-util` is compiled only with
// the `doip` feature.
#[cfg(feature = "doip")]
pub mod socket;
#[cfg(feature = "doip")]
mod connection_receiver;
#[cfg(feature = "doip")]
mod connection_sender;
#[cfg(feature = "doip")]
mod connections;
#[cfg(feature = "doip")]
mod ecu_connection;
#[cfg(feature = "doip")]
mod vir_vam;
#[cfg(feature = "doip")]
mod gateway;

#[cfg(feature = "doip")]
pub use gateway::{DoipDiagGateway, create_udp_vir_socket};


#[cfg(feature = "doip")]
pub(crate) use gateway::{
    DiagnosticResponse, DiscoveredGateway, DoipConnection, DoipEcu, DoipGatewayState,
    DoipTransportConfig, EcuTimeouts, GatewayConnectionConfig, GatewayDoipConfig, GatewaySetup,
};


#[cfg(not(feature = "doip"))]
mod stub;
#[cfg(not(feature = "doip"))]
pub use stub::{DoipDiagGateway, create_udp_vir_socket};


#[cfg(not(feature = "doip"))]
pub mod socket {

    /// No value of this type can ever be constructed, so any function that
    /// would receive one is statically unreachable in a non-`doip` build.
    pub struct DoIPUdpSocket {
        _unconstructable: std::convert::Infallible,
    }
}
