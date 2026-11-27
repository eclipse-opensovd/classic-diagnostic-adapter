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

//! Diagnostic transport router that can route UDS messages over `DoIP`, CAN or
//! K-Line.
//!
//! This module provides `DiagnosticTransportRouter` which implements the `EcuGateway`
//! trait and can route messages to ECUs over multiple transports (`DoIP`, CAN
//! and/or K-Line).
//!
//! # Routing Strategy
//!
//! 1. An explicit per-ECU **transport override** from the config is a hard
//!    pin: the ECU always uses that transport.
//! 2. Without a pin, the ECU is bound to the transport it is **first
//!    detected** on. `DoIP` is preferred when both transports know the ECU at
//!    that moment; a CAN-mapped ECU that never appeared over `DoIP` is probed
//!    on demand.
//! 3. The binding is **sticky**: `ecu_online` and all subsequent sends use
//!    the bound transport. There is no automatic failover - if the bound
//!    transport loses the ECU it is reported offline until that same
//!    transport detects it again.
//!
//! # Usage
//!
//! ```ignore
//! use cda_interfaces::HashMap;
//! let overrides = HashMap::default(); // or populate from config
//! let gateway = DiagnosticTransportRouter::new(overrides)
//!     .with_doip(doip_gateway)
//!     .with_can(can_gateway);
//! ```

use std::{pin::Pin, sync::Arc};

use async_trait::async_trait;
pub use cda_interfaces::TransportType;
use cda_interfaces::{
    DiagServiceError, EcuAddresses, EcuGateway, FunctionalTransport, HashMap, NetworkTopology,
    PhysicalTransport, RouteStatus, ServicePayload, Shutdown, TransmissionParameters,
    TransportProbe, TransportResponse,
    communication_control::{
        DoipEndpoint, TransportControl, TransportState, TransportStateTracker,
        error::CommControlError,
    },
};
use tokio::sync::{Mutex, RwLock, mpsc};

/// Uninhabited default for the router's third transport type parameter; a
/// router left with it never holds a third gateway.
#[derive(Clone)]
pub enum DisabledGateway {}

impl PhysicalTransport for DisabledGateway {
    fn send(
        &self,
        _transmission_params: TransmissionParameters,
        _message: ServicePayload,
        _response_sender: mpsc::Sender<Result<Option<TransportResponse>, DiagServiceError>>,
        _expect_uds_reply: bool,
    ) -> impl Future<Output = Result<tokio::task::JoinHandle<()>, DiagServiceError>> + Send {
        std::future::ready(Err(DiagServiceError::EcuOffline(
            "No gateway is configured for this transport".to_owned(),
        )))
    }

    fn ecu_online<E: EcuAddresses>(
        &self,
        _ecu_name: &str,
        _ecu_db: &RwLock<E>,
    ) -> impl Future<Output = Result<(), DiagServiceError>> + Send {
        std::future::ready(Err(DiagServiceError::EcuOffline(
            "No gateway is configured for this transport".to_owned(),
        )))
    }
}

impl FunctionalTransport for DisabledGateway {
    fn send_functional(
        &self,
        _transmission_params: TransmissionParameters,
        _message: ServicePayload,
        _expected_ecu_logical_addrs: HashMap<u16, String>,
        _timeout: std::time::Duration,
        _expect_positive_response: bool,
    ) -> impl Future<
        Output = Result<
            HashMap<String, Result<ServicePayload, DiagServiceError>>,
            DiagServiceError,
        >,
    > + Send {
        std::future::ready(Err(DiagServiceError::EcuOffline(
            "No gateway is configured for this transport".to_owned(),
        )))
    }
}

impl NetworkTopology for DisabledGateway {
    fn get_gateway_network_address(
        &self,
        _logical_address: u16,
    ) -> impl Future<Output = Option<String>> + Send {
        std::future::ready(None)
    }
}

impl TransportProbe for DisabledGateway {
    fn route_status(&self, _ecu_name: &str) -> impl Future<Output = RouteStatus> + Send {
        std::future::ready(RouteStatus::NotConfigured)
    }

    fn probe_ecu(&self, _ecu_name: &str) -> impl Future<Output = bool> + Send {
        std::future::ready(false)
    }
}

#[async_trait]
impl Shutdown for DisabledGateway {
    async fn shutdown(&self) {
        match *self {}
    }
}

#[async_trait]
impl TransportControl for DisabledGateway {
    async fn enable(&self) -> Result<(), CommControlError> {
        match *self {}
    }

    async fn disable(&self) -> Result<(), CommControlError> {
        match *self {}
    }

    async fn state(&self) -> TransportState {
        match *self {}
    }
}

/// A router that can route diagnostic messages over multiple transports.
///
/// This router wraps `DoIP`, CAN and K-Line gateways. Each ECU is either pinned
/// to a transport via config override or bound to the transport it was first
/// detected on (`DoIP` preferred); see the module docs for the full strategy.
#[doc(alias = "MultiTransportGateway")]
pub struct DiagnosticTransportRouter<
    D: EcuGateway + TransportProbe,
    C: EcuGateway + TransportProbe,
    K: EcuGateway + TransportProbe = DisabledGateway,
> {
    /// Optional `DoIP` gateway
    doip_gateway: Option<D>,
    /// Optional CAN gateway
    can_gateway: Option<C>,
    kline_gateway: Option<K>,
    /// Per-ECU transport overrides (ECU name lowercase -> transport).
    /// ECUs not in this map are bound at first detection.
    transport_overrides: Arc<HashMap<String, TransportType>>,
    /// Transport each un-pinned ECU was first detected on (lowercase name ->
    /// transport). Entries are written once per transport cycle and cleared by
    /// [`TransportControl::disable`], so
    /// a diagnostic session can never silently switch transports.
    ecu_bindings: Arc<RwLock<HashMap<String, TransportType>>>,
    /// Authoritative router lifecycle state.
    transport_state: Arc<TransportStateTracker>,
    /// Serializes a complete lifecycle operation (status check, gateway
    /// fan-out, final transition) against concurrent enable/disable callers.
    operation_lock: Arc<Mutex<()>>,
}

impl<D: EcuGateway + TransportProbe, C: EcuGateway + TransportProbe, K: EcuGateway + TransportProbe>
    DiagnosticTransportRouter<D, C, K>
{
    /// Creates a new diagnostic transport router with the given per-ECU transport overrides.
    #[must_use]
    pub fn new(transport_overrides: HashMap<String, TransportType>) -> Self {
        let tracker = TransportStateTracker::new(TransportState::Disabled);
        Self {
            doip_gateway: None,
            can_gateway: None,
            kline_gateway: None,
            transport_overrides: Arc::new(transport_overrides),
            ecu_bindings: Arc::new(RwLock::new(HashMap::default())),
            transport_state: Arc::new(tracker),
            operation_lock: Arc::new(Mutex::new(())),
        }
    }

    /// Adds a `DoIP` gateway to this diagnostic transport router.
    #[must_use]
    pub fn with_doip(mut self, gateway: D) -> Self {
        self.doip_gateway = Some(gateway);
        self
    }

    /// Adds a CAN gateway to this diagnostic transport router.
    #[must_use]
    pub fn with_can(mut self, gateway: C) -> Self {
        self.can_gateway = Some(gateway);
        self
    }

    /// Adds a K-Line gateway to this diagnostic transport router.
    #[must_use]
    pub fn with_kline(mut self, gateway: K) -> Self {
        self.kline_gateway = Some(gateway);
        self
    }

    /// Binds the ECU to a transport, sticky: if another task bound it first,
    /// the earlier binding wins and is returned.
    async fn bind(&self, ecu_name: &str, transport: TransportType) -> TransportType {
        let bound = *self
            .ecu_bindings
            .write()
            .await
            .entry(ecu_name.to_owned())
            .or_insert(transport);
        tracing::debug!(
            ecu = %ecu_name,
            transport = ?bound,
            "ECU bound to transport (first detection)"
        );
        bound
    }

    /// The CAN gateway's network address for the ECU, behind the `can://`
    /// scheme (see `get_ecu_network_address`).
    async fn can_ecu_network_address(&self, ecu_name: &str) -> Option<String> {
        match self.can_gateway {
            Some(ref can) => can
                .get_ecu_network_address(ecu_name)
                .await
                .map(|addr| format!("can://{addr}")),
            None => None,
        }
    }

    async fn kline_ecu_network_address(&self, ecu_name: &str) -> Option<String> {
        match self.kline_gateway {
            Some(ref kline) => kline
                .get_ecu_network_address(ecu_name)
                .await
                .map(|addr| format!("kline://{addr}")),
            None => None,
        }
    }

    async fn can_or_kline_ecu_network_address(&self, ecu_name: &str) -> Option<String> {
        match self.can_ecu_network_address(ecu_name).await {
            Some(addr) => Some(addr),
            None => self.kline_ecu_network_address(ecu_name).await,
        }
    }

    async fn kline_gateway_network_address(&self, logical_address: u16) -> Option<String> {
        match self.kline_gateway {
            Some(ref kline) => kline
                .get_gateway_network_address(logical_address)
                .await
                .map(|addr| format!("kline://{addr}")),
            None => None,
        }
    }

    async fn try_bind_kline(&self, ecu_name: &str) -> Option<TransportType> {
        match self.kline_gateway {
            Some(ref kline) => {
                self.try_bind_transport(ecu_name, kline, TransportType::KLine)
                    .await
            }
            None => None,
        }
    }

    async fn send_kline(
        &self,
        transmission_params: TransmissionParameters,
        message: ServicePayload,
        response_sender: mpsc::Sender<Result<Option<TransportResponse>, DiagServiceError>>,
        expect_uds_reply: bool,
    ) -> Result<tokio::task::JoinHandle<()>, DiagServiceError> {
        let kline = self
            .kline_gateway
            .as_ref()
            .ok_or_else(|| DiagServiceError::EcuOffline(transmission_params.ecu_name.clone()))?;
        kline
            .send(
                transmission_params,
                message,
                response_sender,
                expect_uds_reply,
            )
            .await
    }

    async fn kline_ecu_online<E: EcuAddresses>(
        &self,
        ecu_name: &str,
        ecu_db: &RwLock<E>,
    ) -> Result<(), DiagServiceError> {
        match self.kline_gateway {
            Some(ref kline) => kline.ecu_online(ecu_name, ecu_db).await,
            None => Err(DiagServiceError::EcuOffline(ecu_name.to_owned())),
        }
    }

    fn ensure_not_pinned_to_kline(&self, ecu_name: &str) -> Result<(), DiagServiceError> {
        if self.transport_overrides.get(&ecu_name.to_lowercase()) == Some(&TransportType::KLine) {
            Err(DiagServiceError::RequestNotSupported(format!(
                "ECU {ecu_name} is configured for K-Line, direct DoIP connection is not possible"
            )))
        } else {
            Ok(())
        }
    }

    /// Returns the network address for an ECU given its bound transport type.
    async fn network_address_for_transport(
        &self,
        ecu_name: &str,
        transport: TransportType,
    ) -> Option<String> {
        match transport {
            TransportType::DoIP => match self.doip_gateway {
                Some(ref doip) => doip.get_ecu_network_address(ecu_name).await,
                None => None,
            },
            TransportType::Can => self.can_ecu_network_address(ecu_name).await,
            TransportType::KLine => self.kline_ecu_network_address(ecu_name).await,
        }
    }

    /// Tries to detect and bind an ECU on a single transport.
    async fn try_bind_transport(
        &self,
        ecu_name: &str,
        gateway: &(impl EcuGateway + TransportProbe),
        transport: TransportType,
    ) -> Option<TransportType> {
        match gateway.route_status(ecu_name).await {
            RouteStatus::Ready => Some(self.bind(ecu_name, transport).await),
            RouteStatus::ProbeRequired => {
                if gateway.probe_ecu(ecu_name).await {
                    Some(self.bind(ecu_name, transport).await)
                } else {
                    None
                }
            }
            RouteStatus::NotConfigured | RouteStatus::Unavailable => None,
        }
    }

    /// Resolves the transport for an ECU using the unified detection logic.
    ///
    /// 1. Check for explicit override
    /// 2. Check for existing binding
    /// 3. First-detection: check transports in priority order (`DoIP` first, then CAN)
    ///    - Ready: bind and return
    ///    - `ProbeRequired`: probe, then bind and return if successful
    ///    - NotConfigured/Unavailable: continue to next transport
    async fn resolve_transport(&self, ecu_name: &str) -> Result<TransportType, DiagServiceError> {
        let ecu_name_lower = ecu_name.to_lowercase();

        // 1. Check override
        if let Some(&pinned) = self.transport_overrides.get(&ecu_name_lower) {
            return Ok(pinned);
        }

        // 2. Check existing binding
        if let Some(&bound) = self.ecu_bindings.read().await.get(&ecu_name_lower) {
            return Ok(bound);
        }

        // 3. First-detection: check transports in priority order (DoIP first)
        if let Some(ref doip) = self.doip_gateway
            && let Some(transport) = self
                .try_bind_transport(&ecu_name_lower, doip, TransportType::DoIP)
                .await
        {
            return Ok(transport);
        }

        if let Some(ref can) = self.can_gateway
            && let Some(transport) = self
                .try_bind_transport(&ecu_name_lower, can, TransportType::Can)
                .await
        {
            return Ok(transport);
        }

        self.try_bind_kline(&ecu_name_lower)
            .await
            .ok_or_else(|| DiagServiceError::EcuOffline(ecu_name.to_owned()))
    }

    /// Router-level send gate, rejecting datapath traffic while communication is
    /// inhibited.
    async fn ensure_communication_active(&self) -> Result<(), DiagServiceError> {
        if self.transport_state.active().await {
            Ok(())
        } else {
            Err(DiagServiceError::CommunicationDisabled(
                "Diagnostic communication disabled".to_owned(),
            ))
        }
    }
}

impl<D: EcuGateway + TransportProbe, C: EcuGateway + TransportProbe, K: EcuGateway + TransportProbe>
    PhysicalTransport for DiagnosticTransportRouter<D, C, K>
{
    #[tracing::instrument(skip_all, fields(
        ecu = %transmission_params.ecu_name,
        gateway_addr = transmission_params.gateway_address
    ))]
    async fn send(
        &self,
        transmission_params: TransmissionParameters,
        message: ServicePayload,
        response_sender: mpsc::Sender<Result<Option<TransportResponse>, DiagServiceError>>,
        expect_uds_reply: bool,
    ) -> Result<tokio::task::JoinHandle<()>, DiagServiceError> {
        self.ensure_communication_active().await?;
        let ecu_name = transmission_params.ecu_name.to_lowercase();
        let transport = self.resolve_transport(&ecu_name).await?;

        match transport {
            TransportType::DoIP => {
                let doip = self.doip_gateway.as_ref().ok_or_else(|| {
                    DiagServiceError::EcuOffline(transmission_params.ecu_name.clone())
                })?;
                doip.send(
                    transmission_params,
                    message,
                    response_sender,
                    expect_uds_reply,
                )
                .await
            }
            TransportType::Can => {
                let can = self.can_gateway.as_ref().ok_or_else(|| {
                    DiagServiceError::EcuOffline(transmission_params.ecu_name.clone())
                })?;
                can.send(
                    transmission_params,
                    message,
                    response_sender,
                    expect_uds_reply,
                )
                .await
            }
            TransportType::KLine => {
                self.send_kline(
                    transmission_params,
                    message,
                    response_sender,
                    expect_uds_reply,
                )
                .await
            }
        }
    }

    async fn ecu_online<E: EcuAddresses>(
        &self,
        ecu_name: &str,
        ecu_db: &RwLock<E>,
    ) -> Result<(), DiagServiceError> {
        // resolve_transport handles: overrides -> existing bindings -> first detection
        self.ensure_communication_active().await?;
        let transport = self.resolve_transport(ecu_name).await?;

        // Online check on the resolved transport only (no failover)
        match transport {
            TransportType::DoIP => match self.doip_gateway {
                Some(ref doip) => doip.ecu_online(ecu_name, ecu_db).await,
                None => Err(DiagServiceError::EcuOffline(ecu_name.to_owned())),
            },
            TransportType::Can => match self.can_gateway {
                Some(ref can) => can.ecu_online(ecu_name, ecu_db).await,
                None => Err(DiagServiceError::EcuOffline(ecu_name.to_owned())),
            },
            TransportType::KLine => self.kline_ecu_online(ecu_name, ecu_db).await,
        }
    }
}

impl<D: EcuGateway + TransportProbe, C: EcuGateway + TransportProbe, K: EcuGateway + TransportProbe>
    FunctionalTransport for DiagnosticTransportRouter<D, C, K>
{
    async fn send_functional(
        &self,
        transmission_params: TransmissionParameters,
        message: ServicePayload,
        expected_ecu_logical_addrs: HashMap<u16, String>,
        timeout: std::time::Duration,
        expect_positive_response: bool,
    ) -> Result<HashMap<String, Result<ServicePayload, DiagServiceError>>, DiagServiceError> {
        self.ensure_communication_active().await?;
        if let Some(ref doip) = self.doip_gateway {
            return doip
                .send_functional(
                    transmission_params,
                    message,
                    expected_ecu_logical_addrs,
                    timeout,
                    expect_positive_response,
                )
                .await;
        }

        if self.can_gateway.is_some() || self.kline_gateway.is_some() {
            Err(DiagServiceError::RequestNotSupported(
                "Neither the CAN nor the K-Line transport supports functional communication"
                    .to_owned(),
            ))
        } else {
            Err(DiagServiceError::EcuOffline(
                "No transport configured for functional request".to_owned(),
            ))
        }
    }
}

impl<D: EcuGateway + TransportProbe, C: EcuGateway + TransportProbe, K: EcuGateway + TransportProbe>
    NetworkTopology for DiagnosticTransportRouter<D, C, K>
{
    async fn get_gateway_network_address(&self, logical_address: u16) -> Option<String> {
        // DoIP addresses are returned verbatim (bare IP) to keep the SOVD
        // network-structure API compatible with pre-multi-transport releases.
        if let Some(ref doip) = self.doip_gateway
            && let Some(addr) = doip.get_gateway_network_address(logical_address).await
        {
            return Some(addr);
        }

        if let Some(ref can) = self.can_gateway
            && let Some(addr) = can.get_gateway_network_address(logical_address).await
        {
            return Some(format!("can://{addr}"));
        }

        self.kline_gateway_network_address(logical_address).await
    }

    async fn get_ecu_network_address(&self, ecu_name: &str) -> Option<String> {
        // Answer for the transport the ECU is pinned or bound to, so the
        // reported address always agrees with where send() routes (an ECU
        // can be known to both transports, e.g. a CAN mapping alongside its
        // DoIP identity). Same scheme convention as the address-based
        // lookup: DoIP addresses verbatim (the default impl yields None
        // today), CAN addresses behind a can:// scheme.
        let ecu_name = ecu_name.to_lowercase();

        // Check override or existing binding first
        if let Some(&pinned) = self.transport_overrides.get(&ecu_name) {
            return self.network_address_for_transport(&ecu_name, pinned).await;
        }

        if let Some(&bound) = self.ecu_bindings.read().await.get(&ecu_name) {
            return self.network_address_for_transport(&ecu_name, bound).await;
        }

        // No binding yet - try DoIP first, then CAN, then K-Line
        if let Some(ref doip) = self.doip_gateway
            && let Some(addr) = doip.get_ecu_network_address(&ecu_name).await
        {
            return Some(addr);
        }
        self.can_or_kline_ecu_network_address(&ecu_name).await
    }
}

#[async_trait]
impl<D: EcuGateway + TransportProbe, C: EcuGateway + TransportProbe, K: EcuGateway + TransportProbe>
    Shutdown for DiagnosticTransportRouter<D, C, K>
{
    async fn shutdown(&self) {
        if let Some(ref doip) = self.doip_gateway {
            doip.shutdown().await;
        }
        if let Some(ref can) = self.can_gateway {
            can.shutdown().await;
        }
        if let Some(ref kline) = self.kline_gateway {
            kline.shutdown().await;
        }
    }
}

impl<D: EcuGateway + TransportProbe, C: EcuGateway + TransportProbe, K: EcuGateway + TransportProbe>
    Clone for DiagnosticTransportRouter<D, C, K>
{
    fn clone(&self) -> Self {
        Self {
            doip_gateway: self.doip_gateway.clone(),
            can_gateway: self.can_gateway.clone(),
            kline_gateway: self.kline_gateway.clone(),
            transport_overrides: Arc::clone(&self.transport_overrides),
            ecu_bindings: Arc::clone(&self.ecu_bindings),
            transport_state: Arc::clone(&self.transport_state),
            operation_lock: Arc::clone(&self.operation_lock),
        }
    }
}

impl<
    D: EcuGateway + FunctionalTransport + TransportProbe + TransportControl,
    C: EcuGateway + TransportProbe + TransportControl,
    K: EcuGateway + TransportProbe + TransportControl,
> DiagnosticTransportRouter<D, C, K>
{
    /// Shared body for [`TransportControl::enable`] and [`TransportControl::disable`].
    ///
    /// * `in_progress`   - state to enter before fanning out to gateways.
    /// * `gateway_op`    - the [`TransportControl`] method to call on each gateway.
    /// * `success_state` - state to enter when all gateways succeed.
    async fn run_lifecycle_operation<F>(
        &self,
        in_progress: TransportState,
        gateway_op: F,
        target_state: TransportState,
    ) -> Result<(), CommControlError>
    where
        F: for<'a> Fn(
            &'a dyn TransportControl,
        )
            -> Pin<Box<dyn Future<Output = Result<(), CommControlError>> + Send + 'a>>,
    {
        let _lifecycle = self.operation_lock.lock().await;
        // After acquiring the guard, so concurrent callers observe the operation
        // completed by whoever acquired it first.
        if self.transport_state.state().await == target_state {
            return Ok(());
        }

        self.transport_state.transition(in_progress).await;

        let mut errors = Vec::new();
        let mut doip_succeeded = false;
        let mut can_succeeded = false;
        if let Some(doip) = &self.doip_gateway {
            let gateway = doip as &dyn TransportControl;
            if let Err(e) = gateway_op(gateway).await {
                errors.push(e.to_string());
            } else {
                doip_succeeded = true;
            }
        }
        if let Some(can) = &self.can_gateway {
            let gateway = can as &dyn TransportControl;
            if let Err(e) = gateway_op(gateway).await {
                errors.push(e.to_string());
            } else {
                can_succeeded = true;
            }
        }
        let kline_succeeded = self.kline_lifecycle_op(&gateway_op, &mut errors).await;

        if errors.is_empty() {
            self.transport_state.transition(target_state).await;
            Ok(())
        } else {
            if target_state == TransportState::Enabled {
                // An incomplete enable must not leave a gateway's background work
                // running while the router rejects all diagnostic traffic.
                if doip_succeeded
                    && let Some(doip) = &self.doip_gateway
                    && let Err(error) = doip.disable().await
                {
                    tracing::error!(error = %error, "Failed to roll back partially enabled DoIP gateway");
                    doip.shutdown().await;
                }
                if can_succeeded
                    && let Some(can) = &self.can_gateway
                    && let Err(error) = can.disable().await
                {
                    tracing::error!(error = %error, "Failed to roll back partially enabled CAN gateway");
                    can.shutdown().await;
                }
                self.roll_back_kline(kline_succeeded).await;
            }
            self.transport_state
                .transition(TransportState::Failed)
                .await;
            Err(CommControlError::InitFailedMultipleComponents(errors))
        }
    }

    async fn kline_lifecycle_op<F>(&self, gateway_op: &F, errors: &mut Vec<String>) -> bool
    where
        F: for<'a> Fn(
            &'a dyn TransportControl,
        )
            -> Pin<Box<dyn Future<Output = Result<(), CommControlError>> + Send + 'a>>,
    {
        let Some(kline) = &self.kline_gateway else {
            return false;
        };
        if let Err(e) = gateway_op(kline as &dyn TransportControl).await {
            errors.push(e.to_string());
            false
        } else {
            true
        }
    }

    async fn roll_back_kline(&self, enabled: bool) {
        if enabled
            && let Some(kline) = &self.kline_gateway
            && let Err(error) = kline.disable().await
        {
            tracing::error!(error = %error, "Failed to roll back partially enabled K-Line gateway");
            kline.shutdown().await;
        }
    }
}

/// Delegates the communication lifecycle to every configured gateway.
///
/// `enable`/`disable` fan out to the `DoIP` and CAN gateways. The router owns
/// its own [`TransportStateTracker`], which is the one external consumers
/// observe. The data-path gate
/// ([`ensure_communication_active`](DiagnosticTransportRouter::ensure_communication_active))
/// checks only the router-level status.
#[async_trait]
impl<
    D: EcuGateway + FunctionalTransport + TransportProbe + TransportControl,
    C: EcuGateway + TransportProbe + TransportControl,
    K: EcuGateway + TransportProbe + TransportControl,
> TransportControl for DiagnosticTransportRouter<D, C, K>
{
    async fn enable(&self) -> Result<(), CommControlError> {
        self.run_lifecycle_operation(
            TransportState::Enabling,
            |g| Box::pin(g.enable()),
            TransportState::Enabled,
        )
        .await
    }

    async fn disable(&self) -> Result<(), CommControlError> {
        self.run_lifecycle_operation(
            TransportState::Disabling,
            |g| Box::pin(g.disable()),
            TransportState::Disabled,
        )
        .await?;
        // Bindings are observed, not derived: only re-detection can rebuild
        // them, so clearing is their counterpart to swapping derived data on an update.
        // The router outlives every update to keep
        // the transports stable, and an update always disables first, so this
        // is what stops a stale binding from routing a re-added ECU.
        self.ecu_bindings.write().await.clear();
        Ok(())
    }

    async fn state(&self) -> TransportState {
        self.transport_state.state().await
    }

    async fn connect_ecu_direct(
        &self,
        ecu_name: &str,
        endpoint: DoipEndpoint,
    ) -> Result<(), DiagServiceError> {
        if self.transport_overrides.get(&ecu_name.to_lowercase()) == Some(&TransportType::Can) {
            return Err(DiagServiceError::RequestNotSupported(format!(
                "ECU {ecu_name} is configured for CAN, direct DoIP connection is not possible"
            )));
        }
        self.ensure_not_pinned_to_kline(ecu_name)?;
        let Some(ref doip) = self.doip_gateway else {
            return Err(DiagServiceError::RequestNotSupported(
                "DoIP is not enabled".to_owned(),
            ));
        };
        doip.connect_ecu_direct(ecu_name, endpoint).await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    use cda_interfaces::{
        EcuAddresses, RouteStatus, communication_control::DoipEndpoint, uds::TransportResponse,
    };

    use super::*;

    #[test]
    fn test_transport_type_debug() {
        assert_eq!(format!("{:?}", TransportType::DoIP), "DoIP");
        assert_eq!(format!("{:?}", TransportType::Can), "Can");
        assert_eq!(format!("{:?}", TransportType::KLine), "KLine");
    }

    /// A gateway with configurable outcomes and observable call counts, so a
    /// test can tell "never called" from "called and failed".
    #[derive(Clone)]
    struct FakeGateway {
        enable_fails: bool,
        disable_fails: bool,
        route: RouteStatus,
        address: Option<String>,
        send_calls: Arc<AtomicUsize>,
        online_calls: Arc<AtomicUsize>,
        enable_calls: Arc<AtomicUsize>,
        disable_calls: Arc<AtomicUsize>,
        shutdown_calls: Arc<AtomicUsize>,
        state: Arc<RwLock<TransportState>>,
    }

    impl FakeGateway {
        fn new(enable_fails: bool) -> Self {
            Self {
                enable_fails,
                disable_fails: false,
                route: RouteStatus::NotConfigured,
                address: None,
                send_calls: Arc::new(AtomicUsize::new(0)),
                online_calls: Arc::new(AtomicUsize::new(0)),
                enable_calls: Arc::new(AtomicUsize::new(0)),
                disable_calls: Arc::new(AtomicUsize::new(0)),
                shutdown_calls: Arc::new(AtomicUsize::new(0)),
                state: Arc::new(RwLock::new(TransportState::Disabled)),
            }
        }

        fn with_failing_disable(mut self) -> Self {
            self.disable_fails = true;
            self
        }

        fn with_route(mut self, route: RouteStatus) -> Self {
            self.route = route;
            self
        }

        fn with_address(mut self, address: &str) -> Self {
            self.address = Some(address.to_owned());
            self
        }
    }

    #[async_trait]
    impl Shutdown for FakeGateway {
        async fn shutdown(&self) {
            self.shutdown_calls.fetch_add(1, Ordering::Relaxed);
            *self.state.write().await = TransportState::Disabled;
        }
    }

    impl cda_interfaces::PhysicalTransport for FakeGateway {
        fn send(
            &self,
            _transmission_params: TransmissionParameters,
            _message: ServicePayload,
            _response_sender: mpsc::Sender<Result<Option<TransportResponse>, DiagServiceError>>,
            _expect_uds_reply: bool,
        ) -> impl Future<Output = Result<tokio::task::JoinHandle<()>, DiagServiceError>> {
            self.send_calls.fetch_add(1, Ordering::Relaxed);
            std::future::ready(Err(DiagServiceError::RequestNotSupported(
                "fake gateway".to_owned(),
            )))
        }

        fn ecu_online<T: EcuAddresses>(
            &self,
            ecu_name: &str,
            _ecu_db: &RwLock<T>,
        ) -> impl Future<Output = Result<(), DiagServiceError>> {
            self.online_calls.fetch_add(1, Ordering::Relaxed);
            std::future::ready(Err(DiagServiceError::EcuOffline(ecu_name.to_owned())))
        }
    }

    impl FunctionalTransport for FakeGateway {
        fn send_functional(
            &self,
            _transmission_params: TransmissionParameters,
            _message: ServicePayload,
            _expected_ecu_logical_addrs: HashMap<u16, String>,
            _timeout: Duration,
            _expect_positive_response: bool,
        ) -> impl Future<
            Output = Result<
                HashMap<String, Result<ServicePayload, DiagServiceError>>,
                DiagServiceError,
            >,
        > {
            std::future::ready(Ok(HashMap::default()))
        }
    }

    impl cda_interfaces::NetworkTopology for FakeGateway {
        fn get_gateway_network_address(
            &self,
            _logical_address: u16,
        ) -> impl Future<Output = Option<String>> {
            std::future::ready(self.address.clone())
        }

        fn get_ecu_network_address(&self, _ecu_name: &str) -> impl Future<Output = Option<String>> {
            std::future::ready(self.address.clone())
        }
    }

    impl TransportProbe for FakeGateway {
        fn route_status(&self, _ecu_name: &str) -> impl Future<Output = RouteStatus> {
            std::future::ready(self.route)
        }

        fn probe_ecu(&self, _ecu_name: &str) -> impl Future<Output = bool> {
            std::future::ready(false)
        }
    }

    #[async_trait]
    impl TransportControl for FakeGateway {
        async fn enable(&self) -> Result<(), CommControlError> {
            self.enable_calls.fetch_add(1, Ordering::Relaxed);
            if self.enable_fails {
                return Err(CommControlError::InitFailed(
                    "fake enable failure".to_owned(),
                ));
            }
            *self.state.write().await = TransportState::Enabled;
            Ok(())
        }

        async fn disable(&self) -> Result<(), CommControlError> {
            self.disable_calls.fetch_add(1, Ordering::Relaxed);
            if self.disable_fails {
                return Err(CommControlError::InitFailed(
                    "fake disable failure".to_owned(),
                ));
            }
            *self.state.write().await = TransportState::Disabled;
            Ok(())
        }

        async fn state(&self) -> TransportState {
            *self.state.read().await
        }

        async fn connect_ecu_direct(
            &self,
            _ecu_name: &str,
            _endpoint: DoipEndpoint,
        ) -> Result<(), DiagServiceError> {
            Ok(())
        }
    }

    fn test_endpoint() -> DoipEndpoint {
        DoipEndpoint {
            address: "10.0.0.5".parse().unwrap(),
            protocol_version: 0x02,
        }
    }

    #[tokio::test]
    async fn direct_connect_is_delegated_to_the_doip_gateway() {
        let router = DiagnosticTransportRouter::<FakeGateway, FakeGateway>::new(HashMap::default())
            .with_doip(FakeGateway::new(false))
            .with_can(FakeGateway::new(false));

        assert_eq!(
            router.connect_ecu_direct("ecu_a", test_endpoint()).await,
            Ok(())
        );
    }

    #[tokio::test]
    async fn direct_connect_is_unsupported_without_a_doip_gateway() {
        let router = DiagnosticTransportRouter::<FakeGateway, FakeGateway>::new(HashMap::default())
            .with_can(FakeGateway::new(false));

        assert!(matches!(
            router.connect_ecu_direct("ecu_a", test_endpoint()).await,
            Err(DiagServiceError::RequestNotSupported(_))
        ));
    }

    #[tokio::test]
    async fn direct_connect_is_unsupported_for_can_pinned_ecus() {
        let router = DiagnosticTransportRouter::<FakeGateway, FakeGateway>::new(
            HashMap::from_iter([("ecu_a".to_owned(), TransportType::Can)]),
        )
        .with_doip(FakeGateway::new(false))
        .with_can(FakeGateway::new(false));

        assert!(matches!(
            router.connect_ecu_direct("ECU_A", test_endpoint()).await,
            Err(DiagServiceError::RequestNotSupported(_))
        ));
    }

    #[tokio::test]
    async fn direct_connect_is_unsupported_for_kline_pinned_ecus() {
        let router = DiagnosticTransportRouter::<FakeGateway, FakeGateway>::new(
            HashMap::from_iter([("ecu_a".to_owned(), TransportType::KLine)]),
        )
        .with_doip(FakeGateway::new(false))
        .with_can(FakeGateway::new(false));

        assert!(matches!(
            router.connect_ecu_direct("ECU_A", test_endpoint()).await,
            Err(DiagServiceError::RequestNotSupported(_))
        ));
    }

    /// A runtime update disables the transport before replacing the ECU data.
    /// This router is never rebuilt, so a binding left over from the previous
    /// ECU set would decide the transport for a re-added ECU without ever
    /// re-detecting it.
    #[tokio::test]
    async fn disable_clears_transport_bindings_so_the_next_cycle_re_detects() {
        let router = DiagnosticTransportRouter::<FakeGateway, FakeGateway>::new(HashMap::default())
            .with_doip(FakeGateway::new(false))
            .with_can(FakeGateway::new(false));
        router.enable().await.unwrap();
        router.bind("ecu_a", TransportType::Can).await;
        assert_eq!(
            router.ecu_bindings.read().await.get("ecu_a"),
            Some(&TransportType::Can),
            "precondition: the ECU is bound to CAN"
        );

        router.disable().await.unwrap();

        assert!(
            router.ecu_bindings.read().await.is_empty(),
            "a disabled transport must not carry bindings into the next ECU set"
        );
    }

    /// When one gateway's `enable()` fails partway through the fan-out, the
    /// router must roll back the gateway that already succeeded rather than
    /// leave it live underneath a router that reports the operation failed.
    #[tokio::test]
    async fn failed_enable_rolls_back_the_gateway_that_already_succeeded() {
        let doip = FakeGateway::new(false);
        let can = FakeGateway::new(true);
        let router = DiagnosticTransportRouter::<FakeGateway, FakeGateway>::new(HashMap::default())
            .with_doip(doip.clone())
            .with_can(can.clone());

        let result = router.enable().await;

        assert!(matches!(
            result,
            Err(CommControlError::InitFailedMultipleComponents(_))
        ));
        assert_eq!(
            doip.enable_calls.load(Ordering::Relaxed),
            1,
            "the DoIP gateway must have been asked to enable"
        );
        assert_eq!(
            doip.disable_calls.load(Ordering::Relaxed),
            1,
            "the DoIP gateway succeeded, so it must be rolled back once CAN fails"
        );
        assert_eq!(can.enable_calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            can.disable_calls.load(Ordering::Relaxed),
            0,
            "CAN never succeeded, so there is nothing on it to roll back"
        );
        assert_eq!(
            router.state().await,
            TransportState::Failed,
            "the router itself must report the overall operation as failed"
        );
    }

    /// Rolling back the gateway that already enabled can itself fail. The
    /// router must then fall back to the shutdown path, so no background work
    /// outlives a router that reports the enable as failed.
    #[tokio::test]
    async fn failed_rollback_falls_back_to_the_gateway_shutdown_path() {
        let doip = FakeGateway::new(false).with_failing_disable();
        let can = FakeGateway::new(true);
        let router = DiagnosticTransportRouter::<FakeGateway, FakeGateway>::new(HashMap::default())
            .with_doip(doip.clone())
            .with_can(can.clone());

        assert!(router.enable().await.is_err());

        assert_eq!(
            doip.disable_calls.load(Ordering::Relaxed),
            1,
            "the DoIP gateway succeeded, so the rollback must have tried to disable it"
        );
        assert_eq!(
            doip.shutdown_calls.load(Ordering::Relaxed),
            1,
            "a rollback that fails must still terminate the gateway's background work"
        );
        assert_eq!(
            can.shutdown_calls.load(Ordering::Relaxed),
            0,
            "CAN never enabled, so there is nothing on it to shut down"
        );
        assert_eq!(doip.state().await, TransportState::Disabled);
        assert_eq!(router.state().await, TransportState::Failed);
    }

    /// A gateway that never succeeded must not be rolled back, and a fully
    /// successful enable must roll back nothing.
    #[tokio::test]
    async fn successful_enable_rolls_back_nothing() {
        let doip = FakeGateway::new(false);
        let can = FakeGateway::new(false);
        let router = DiagnosticTransportRouter::<FakeGateway, FakeGateway>::new(HashMap::default())
            .with_doip(doip.clone())
            .with_can(can.clone());

        assert_eq!(router.enable().await, Ok(()));

        assert_eq!(doip.disable_calls.load(Ordering::Relaxed), 0);
        assert_eq!(can.disable_calls.load(Ordering::Relaxed), 0);
        assert_eq!(router.state().await, TransportState::Enabled);
    }

    fn kline_test_params(ecu_name: &str) -> TransmissionParameters {
        TransmissionParameters {
            gateway_address: 0x0010,
            timeout_ack: Duration::from_millis(100),
            ecu_name: ecu_name.to_owned(),
            repeat_request_count_transmission: 0,
        }
    }

    async fn send_to<K: EcuGateway + TransportProbe>(
        router: &DiagnosticTransportRouter<FakeGateway, FakeGateway, K>,
        ecu_name: &str,
    ) -> Result<tokio::task::JoinHandle<()>, DiagServiceError> {
        let (response_sender, _response_receiver) = mpsc::channel(1);
        router
            .send(
                kline_test_params(ecu_name),
                ServicePayload {
                    data: vec![0x3E, 0x00],
                    source_address: 0x00F1,
                    target_address: 0x0010,
                    new_session: None,
                    new_security: None,
                },
                response_sender,
                true,
            )
            .await
    }

    #[tokio::test]
    async fn an_ecu_only_the_kline_gateway_knows_binds_to_kline() {
        let doip = FakeGateway::new(false);
        let can = FakeGateway::new(false);
        let kline = FakeGateway::new(false).with_route(RouteStatus::Ready);
        let router = DiagnosticTransportRouter::new(HashMap::default())
            .with_doip(doip.clone())
            .with_can(can.clone())
            .with_kline(kline.clone());
        router.enable().await.unwrap();

        assert!(send_to(&router, "ECU_K").await.is_err());

        assert_eq!(kline.send_calls.load(Ordering::Relaxed), 1);
        assert_eq!(doip.send_calls.load(Ordering::Relaxed), 0);
        assert_eq!(can.send_calls.load(Ordering::Relaxed), 0);
        assert_eq!(
            router.ecu_bindings.read().await.get("ecu_k"),
            Some(&TransportType::KLine)
        );
    }

    #[tokio::test]
    async fn doip_and_can_take_precedence_over_kline_at_first_detection() {
        let can = FakeGateway::new(false).with_route(RouteStatus::Ready);
        let kline = FakeGateway::new(false).with_route(RouteStatus::Ready);
        let router = DiagnosticTransportRouter::new(HashMap::default())
            .with_doip(FakeGateway::new(false))
            .with_can(can.clone())
            .with_kline(kline.clone());
        router.enable().await.unwrap();

        assert!(send_to(&router, "ECU_K").await.is_err());

        assert_eq!(can.send_calls.load(Ordering::Relaxed), 1);
        assert_eq!(kline.send_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn a_kline_pin_routes_to_the_kline_gateway_without_detection() {
        let kline = FakeGateway::new(false);
        let router = DiagnosticTransportRouter::new(HashMap::from_iter([(
            "ecu_k".to_owned(),
            TransportType::KLine,
        )]))
        .with_doip(FakeGateway::new(false).with_route(RouteStatus::Ready))
        .with_can(FakeGateway::new(false))
        .with_kline(kline.clone());
        router.enable().await.unwrap();

        assert!(send_to(&router, "ECU_K").await.is_err());

        assert_eq!(kline.send_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn a_kline_pin_without_a_kline_gateway_is_offline() {
        let router = DiagnosticTransportRouter::<FakeGateway, FakeGateway>::new(
            HashMap::from_iter([("ecu_k".to_owned(), TransportType::KLine)]),
        )
        .with_doip(FakeGateway::new(false))
        .with_can(FakeGateway::new(false));
        router.enable().await.unwrap();

        assert!(matches!(
            send_to(&router, "ECU_K").await,
            Err(DiagServiceError::EcuOffline(_))
        ));
    }

    #[tokio::test]
    async fn failed_enable_rolls_back_an_enabled_kline_gateway() {
        let can = FakeGateway::new(true);
        let kline = FakeGateway::new(false);
        let router = DiagnosticTransportRouter::new(HashMap::default())
            .with_doip(FakeGateway::new(false))
            .with_can(can)
            .with_kline(kline.clone());

        assert!(router.enable().await.is_err());

        assert_eq!(kline.enable_calls.load(Ordering::Relaxed), 1);
        assert_eq!(kline.disable_calls.load(Ordering::Relaxed), 1);
        assert_eq!(kline.state().await, TransportState::Disabled);
    }

    struct FakeEcu;

    impl EcuAddresses for FakeEcu {
        fn tester_address(&self) -> u16 {
            0x0E80
        }

        fn logical_address(&self) -> u16 {
            0x0010
        }

        fn logical_gateway_address(&self) -> u16 {
            0x0010
        }

        fn logical_functional_address(&self) -> u16 {
            0xE400
        }

        fn ecu_name(&self) -> String {
            "ecu_k".to_owned()
        }

        fn logical_address_eq<T: EcuAddresses>(&self, other: &T) -> bool {
            self.logical_address() == other.logical_address()
        }
    }

    fn kline_pinned() -> HashMap<String, TransportType> {
        HashMap::from_iter([("ecu_k".to_owned(), TransportType::KLine)])
    }

    #[tokio::test]
    async fn kline_addresses_carry_the_kline_scheme() {
        let router = DiagnosticTransportRouter::new(kline_pinned())
            .with_doip(FakeGateway::new(false))
            .with_can(FakeGateway::new(false))
            .with_kline(FakeGateway::new(false).with_address("COM3:16"));

        assert_eq!(
            router.get_ecu_network_address("ECU_K").await,
            Some("kline://COM3:16".to_owned())
        );
        assert_eq!(
            router.get_ecu_network_address("unbound").await,
            Some("kline://COM3:16".to_owned())
        );
        assert_eq!(
            router.get_gateway_network_address(0x0010).await,
            Some("kline://COM3:16".to_owned())
        );
    }

    #[tokio::test]
    async fn a_kline_pin_without_a_kline_gateway_has_no_address_and_is_offline() {
        let router = DiagnosticTransportRouter::<FakeGateway, FakeGateway>::new(kline_pinned())
            .with_doip(FakeGateway::new(false))
            .with_can(FakeGateway::new(false));
        router.enable().await.unwrap();

        assert_eq!(router.get_ecu_network_address("ECU_K").await, None);
        assert_eq!(router.get_gateway_network_address(0x0010).await, None);
        assert!(matches!(
            router.ecu_online("ECU_K", &RwLock::new(FakeEcu)).await,
            Err(DiagServiceError::EcuOffline(_))
        ));
    }

    #[tokio::test]
    async fn ecu_online_of_a_kline_pin_asks_the_kline_gateway() {
        let doip = FakeGateway::new(false);
        let kline = FakeGateway::new(false);
        let router = DiagnosticTransportRouter::new(kline_pinned())
            .with_doip(doip.clone())
            .with_can(FakeGateway::new(false))
            .with_kline(kline.clone());
        router.enable().await.unwrap();

        assert!(
            router
                .ecu_online("ECU_K", &RwLock::new(FakeEcu))
                .await
                .is_err()
        );

        assert_eq!(kline.online_calls.load(Ordering::Relaxed), 1);
        assert_eq!(doip.online_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn functional_requests_are_unsupported_with_only_a_kline_gateway() {
        let router = DiagnosticTransportRouter::<FakeGateway, FakeGateway, FakeGateway>::new(
            HashMap::default(),
        )
        .with_kline(FakeGateway::new(false));
        router.enable().await.unwrap();

        assert!(matches!(
            router
                .send_functional(
                    kline_test_params("ECU_K"),
                    ServicePayload {
                        data: vec![0x3E, 0x00],
                        source_address: 0x00F1,
                        target_address: 0x0010,
                        new_session: None,
                        new_security: None,
                    },
                    HashMap::default(),
                    Duration::from_millis(100),
                    true,
                )
                .await,
            Err(DiagServiceError::RequestNotSupported(_))
        ));
    }

    #[tokio::test]
    async fn a_failed_kline_rollback_falls_back_to_the_gateway_shutdown_path() {
        let kline = FakeGateway::new(false).with_failing_disable();
        let router = DiagnosticTransportRouter::new(HashMap::default())
            .with_doip(FakeGateway::new(false))
            .with_can(FakeGateway::new(true))
            .with_kline(kline.clone());

        assert!(router.enable().await.is_err());

        assert_eq!(kline.disable_calls.load(Ordering::Relaxed), 1);
        assert_eq!(kline.shutdown_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn an_ecu_no_gateway_knows_stays_offline_with_a_kline_gateway() {
        let router = DiagnosticTransportRouter::new(HashMap::default())
            .with_doip(FakeGateway::new(false))
            .with_can(FakeGateway::new(false))
            .with_kline(FakeGateway::new(false));
        router.enable().await.unwrap();

        assert!(matches!(
            send_to(&router, "ECU_X").await,
            Err(DiagServiceError::EcuOffline(_))
        ));
        assert_eq!(router.get_gateway_network_address(0x0010).await, None);
    }

    #[tokio::test]
    async fn an_ecu_no_gateway_knows_stays_offline_without_a_kline_gateway() {
        let router = DiagnosticTransportRouter::<FakeGateway, FakeGateway>::new(HashMap::default())
            .with_doip(FakeGateway::new(false))
            .with_can(FakeGateway::new(false));
        router.enable().await.unwrap();

        assert!(matches!(
            send_to(&router, "ECU_X").await,
            Err(DiagServiceError::EcuOffline(_))
        ));
    }

    #[tokio::test]
    async fn an_unbound_ecu_takes_the_can_address_before_the_kline_one() {
        let router = DiagnosticTransportRouter::new(HashMap::default())
            .with_doip(FakeGateway::new(false))
            .with_can(FakeGateway::new(false).with_address("vcan0:0x7E0"))
            .with_kline(FakeGateway::new(false).with_address("COM3:16"));

        assert_eq!(
            router.get_ecu_network_address("unbound").await,
            Some("can://vcan0:0x7E0".to_owned())
        );
    }

    #[tokio::test]
    async fn a_failing_kline_enable_fails_the_router_and_rolls_back_the_others() {
        let doip = FakeGateway::new(false);
        let router = DiagnosticTransportRouter::new(HashMap::default())
            .with_doip(doip.clone())
            .with_can(FakeGateway::new(false))
            .with_kline(FakeGateway::new(true));

        assert!(router.enable().await.is_err());

        assert_eq!(doip.disable_calls.load(Ordering::Relaxed), 1);
        assert_eq!(router.state().await, TransportState::Failed);
    }

    #[tokio::test]
    async fn shutdown_reaches_the_kline_gateway() {
        let kline = FakeGateway::new(false);
        let router = DiagnosticTransportRouter::new(HashMap::default())
            .with_doip(FakeGateway::new(false))
            .with_can(FakeGateway::new(false))
            .with_kline(kline.clone());

        router.shutdown().await;

        assert_eq!(kline.shutdown_calls.load(Ordering::Relaxed), 1);
    }
}
