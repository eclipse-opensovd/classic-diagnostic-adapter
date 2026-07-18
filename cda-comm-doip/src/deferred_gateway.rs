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

//! Deferred gateway implementation for `DoIP` communication.
//!
//! [`DeferredGateway`] wraps a shared slot that holds an optional [`DoipDiagGateway`].
//! When the slot is `None`, the gateway is "disabled" and all `EcuGateway` methods
//! return [`DiagServiceError::EcuOffline`]. When the slot is `Some`, calls are delegated
//! to the inner gateway.
//!
//! This design allows the real `UdsManager` to be constructed at startup with a
//! `DeferredGateway` in an inactive state. The [`DoipCommHandle`](super::comm_handle::DoipCommHandle)
//! can then "enable" communication by building the real gateway into the shared slot, or "disable"
//! by taking and shutting down the inner gateway.

use std::{sync::Arc, time::Duration};

use cda_interfaces::{
    DiagServiceError, DoipComParams, EcuAddresses, EcuGateway, EcuGatewaySockets, HashMap,
    ServicePayload, TransmissionParameters, UdsResponse,
};
use tokio::sync::{Mutex, RwLock, mpsc};

use crate::{DoipDiagGateway, socket::DoIPUdpSocket};

/// A deferred `DoIP` gateway that can be in a disabled (empty) or active (populated) state.
///
/// The gateway is backed by a shared `Arc<RwLock<Option<DoipDiagGateway<T>>>>` that is
/// owned by the [`DoipCommHandle`](crate::comm_handle::DoipCommHandle). When the handle
/// enables communication, it builds the real gateway into the slot; when it disables,
/// it takes and shuts down the inner gateway.
///
/// This allows the real `UdsManager` to be constructed at startup with a `DeferredGateway`
/// that initially returns `EcuOffline` for all diagnostic requests. Once the handle
/// enables communication, the same `UdsManager` automatically starts working because
/// it delegates to the inner gateway via the shared slot.
pub struct DeferredGateway<T: EcuAddresses + DoipComParams> {
    /// Shared slot holding the optional inner gateway.
    /// When `None`, the gateway is disabled.
    slot: Arc<RwLock<Option<DoipDiagGateway<T>>>>,
    /// The reserved UDP socket, created at startup and retained even when disabled.
    /// This ensures the port remains bound and no other process can take it.
    socket: Arc<Mutex<DoIPUdpSocket>>,
}

impl<T: EcuAddresses + DoipComParams> Clone for DeferredGateway<T> {
    fn clone(&self) -> Self {
        Self {
            slot: Arc::clone(&self.slot),
            socket: Arc::clone(&self.socket),
        }
    }
}

impl<T: EcuAddresses + DoipComParams> DeferredGateway<T> {
    /// Creates a new `DeferredGateway` with an empty slot and the given reserved socket.
    ///
    /// The gateway starts in the "disabled" state (slot is `None`). Callers must
    /// use the [`DoipCommHandle`](crate::comm_handle::DoipCommHandle) to enable
    /// communication and populate the slot.
    #[must_use]
    pub fn new(
        slot: Arc<RwLock<Option<DoipDiagGateway<T>>>>,
        socket: Arc<Mutex<DoIPUdpSocket>>,
    ) -> Self {
        Self { slot, socket }
    }

    /// Returns a reference to the shared slot.
    ///
    /// This is used by the [`DoipCommHandle`](crate::comm_handle::DoipCommHandle) to populate or clear the gateway.
    #[must_use]
    pub fn slot(&self) -> &Arc<RwLock<Option<DoipDiagGateway<T>>>> {
        &self.slot
    }
}

impl<T: EcuAddresses + DoipComParams> EcuGateway for DeferredGateway<T> {
    async fn get_gateway_network_address(&self, logical_address: u16) -> Option<String> {
        let guard = self.slot.read().await;
        match guard.as_ref() {
            Some(gateway) => gateway.get_gateway_network_address(logical_address).await,
            None => None,
        }
    }

    async fn send(
        &self,
        transmission_params: TransmissionParameters,
        message: ServicePayload,
        response_sender: mpsc::Sender<Result<Option<UdsResponse>, DiagServiceError>>,
        expect_uds_reply: bool,
    ) -> Result<(), DiagServiceError> {
        let guard = self.slot.read().await;
        match guard.as_ref() {
            Some(gateway) => {
                gateway
                    .send(
                        transmission_params,
                        message,
                        response_sender,
                        expect_uds_reply,
                    )
                    .await
            }
            None => Err(DiagServiceError::RequestNotSupported(
                "DoIP communication disabled".to_owned(),
            )),
        }
    }

    async fn ecu_online<E: EcuAddresses>(
        &self,
        ecu_name: &str,
        ecu_db: &RwLock<E>,
    ) -> Result<(), DiagServiceError> {
        let guard = self.slot.read().await;
        match guard.as_ref() {
            Some(gateway) => gateway.ecu_online(ecu_name, ecu_db).await,
            None => Err(DiagServiceError::RequestNotSupported(format!(
                "DoIP communication disabled for {ecu_name}"
            ))),
        }
    }

    async fn send_functional(
        &self,
        transmission_params: TransmissionParameters,
        message: ServicePayload,
        expected_ecu_logical_addrs: HashMap<u16, String>,
        timeout: Duration,
        expect_positive_response: bool,
    ) -> Result<HashMap<String, Result<UdsResponse, DiagServiceError>>, DiagServiceError> {
        let guard = self.slot.read().await;
        match guard.as_ref() {
            Some(gateway) => {
                gateway
                    .send_functional(
                        transmission_params,
                        message,
                        expected_ecu_logical_addrs,
                        timeout,
                        expect_positive_response,
                    )
                    .await
            }
            None => Err(DiagServiceError::RequestNotSupported(
                "DoIP communication disabled".to_owned(),
            )),
        }
    }
}

impl<T: EcuAddresses + DoipComParams> EcuGatewaySockets for DeferredGateway<T> {
    type Socket = DoIPUdpSocket;

    fn upd_socket(&self) -> Arc<Mutex<Self::Socket>> {
        Arc::clone(&self.socket)
    }
}

#[async_trait::async_trait]
impl<T: EcuAddresses + DoipComParams> cda_interfaces::Shutdown for DeferredGateway<T> {
    async fn shutdown(&mut self) {
        let mut guard = self.slot.write().await;
        if let Some(mut gateway) = guard.take() {
            cda_interfaces::Shutdown::shutdown(&mut gateway).await;
        }
    }
}
