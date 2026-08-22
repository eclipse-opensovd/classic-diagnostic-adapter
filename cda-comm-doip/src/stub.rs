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

//! Uninhabited stub types compiled when the `doip` feature is disabled.
//!
//! These stubs exist purely to satisfy generic bounds and public function
//! signatures elsewhere in the workspace so the whole tree keeps compiling
//! without the `DoIP` transport and its dependency subtree

use std::{convert::Infallible, marker::PhantomData, sync::Arc, time::Duration};

use async_trait::async_trait;
use cda_interfaces::{
    DiagServiceError, DoipComParams, EcuAddresses, FunctionalTransport, HashMap, NetworkTopology,
    PhysicalTransport, ReusableTransportResource, RouteStatus, ServicePayload, Shutdown,
    TransmissionParameters, TransportProbe, TransportResponse,
};
use tokio::sync::{Mutex, RwLock, mpsc};

use crate::{DoipGatewaySetupError, socket::DoIPUdpSocket};

pub struct DoipDiagGateway<T> {
    never: Infallible,
    _phantom: PhantomData<fn() -> T>,
}

impl<T> Clone for DoipDiagGateway<T> {
    fn clone(&self) -> Self {
        match self.never {}
    }
}

impl<T: EcuAddresses + DoipComParams> PhysicalTransport for DoipDiagGateway<T> {
    async fn send(
        &self,
        _transmission_params: TransmissionParameters,
        _message: ServicePayload,
        _response_sender: mpsc::Sender<Result<Option<TransportResponse>, DiagServiceError>>,
        _expect_uds_reply: bool,
    ) -> Result<tokio::task::JoinHandle<()>, DiagServiceError> {
        Err(DiagServiceError::EcuOffline(
            "DoIP support is not enabled. Compile with the `doip` feature.".to_owned(),
        ))
    }

    async fn ecu_online<E: EcuAddresses>(
        &self,
        _ecu_name: &str,
        _ecu_db: &RwLock<E>,
    ) -> Result<(), DiagServiceError> {
        Err(DiagServiceError::EcuOffline(
            "DoIP support is not enabled. Compile with the `doip` feature.".to_owned(),
        ))
    }
}

impl<T: EcuAddresses + DoipComParams> FunctionalTransport for DoipDiagGateway<T> {
    async fn send_functional(
        &self,
        _transmission_params: TransmissionParameters,
        _message: ServicePayload,
        _expected_ecu_logical_addrs: HashMap<u16, String>,
        _timeout: Duration,
        _expect_positive_response: bool,
    ) -> Result<HashMap<String, Result<ServicePayload, DiagServiceError>>, DiagServiceError> {
        Err(DiagServiceError::RequestNotSupported(
            "DoIP functional addressing is not available because DoIP support is disabled."
                .to_owned(),
        ))
    }
}

impl<T: EcuAddresses + DoipComParams> NetworkTopology for DoipDiagGateway<T> {
    async fn get_gateway_network_address(&self, _logical_address: u16) -> Option<String> {
        None
    }
}

impl<T: EcuAddresses + DoipComParams> TransportProbe for DoipDiagGateway<T> {
    async fn route_status(&self, _ecu_name: &str) -> RouteStatus {
        RouteStatus::NotConfigured
    }

    async fn probe_ecu(&self, _ecu_name: &str) -> bool {
        false
    }
}

impl<T: EcuAddresses + DoipComParams> ReusableTransportResource for DoipDiagGateway<T> {
    type TransportResource = DoIPUdpSocket;

    fn reusable_transport_resource(&self) -> Option<Arc<Mutex<Self::TransportResource>>> {
        None
    }
}

#[async_trait]
impl<T: EcuAddresses + DoipComParams> Shutdown for DoipDiagGateway<T> {
    async fn shutdown(&self) {}
}

pub fn create_udp_vir_socket(
    _tester_ip: &str,
    _gateway_port: u16,
) -> Result<DoIPUdpSocket, DoipGatewaySetupError> {
    Err(DoipGatewaySetupError::InvalidConfiguration(
        "DoIP support is not enabled. Compile with the `doip` feature.".to_owned(),
    ))
}
