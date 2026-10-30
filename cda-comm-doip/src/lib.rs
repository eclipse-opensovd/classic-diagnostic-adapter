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

use std::{
    net::IpAddr,
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use cda_interfaces::{
    DiagServiceError, DoipComParams, EcuAddresses, EcuConnectivityHandler, FunctionalTransport,
    HashMap, HashMapExtensions, NetworkTopology, PhysicalTransport, RouteStatus, ServicePayload,
    TransmissionParameters, TransportProbe, TransportResponse, VariantDetectionSender,
    communication_control::{
        DoipEndpoint, GatewayLifecycle, TransportControl, TransportState, error::CommControlError,
    },
    dlt_ctx, pending_nrc_from_raw,
    topology::{DiscoveryStrategy, KnownGateway, TopologyRuntime, is_physical_gateway},
    uds_response_from_raw,
    util::{self, tokio_ext},
};
use doip_definitions::{
    header::ProtocolVersion,
    payload::{
        DiagnosticMessage, DiagnosticMessageNack, DoipPayload, GenericNack,
        RoutingActivationRequest,
    },
};
use futures::FutureExt;
use tokio::{
    sync::{Mutex, RwLock, broadcast, mpsc},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

pub mod config;
pub mod error;
pub use error::{ConnectionError, DoipGatewaySetupError};
mod connection_receiver;
mod connection_sender;
mod connections;
mod ecu_connection;
mod gateway_session;
mod reconnect;
pub mod socket;
mod vir_vam;

#[cfg(test)]
pub(crate) mod test_helpers;

use crate::{
    config::DoipConfig,
    connections::{ConnectControl, EcuError},
    gateway_session::{ConnectFailure, ConnectOutcome, DirectRejection, GatewaySession},
    socket::DoIPUdpSocket,
};

/// Timeout when suppressPosRspMsgIndicationBit is set.
/// ECUs that reject a request usually respond quickly with an NRC and
/// this timeout window should be able to capture those while
/// not blocking for the full diagnostic timeout.
///
/// This constant is intentionally separate from `timeout_default` so it can be promoted to a
/// configuration entry, or a `ComParam` in a future iteration without changing the
/// surrounding logic.
const SUPPRESS_POSITIVE_RESPONSE_TIMEOUT: Duration = Duration::from_millis(500);

/// Finishes a started discovery (not as a full VIR discovery) when dropped, unless
/// finished explicitly. Moved into the task that ends the discovery, so a task
/// that is aborted (`stop`) still settles it.
struct DiscoveryGuard {
    topology: Arc<TopologyRuntime>,
    generation: u64,
    armed: bool,
}

impl DiscoveryGuard {
    fn begin(topology: &Arc<TopologyRuntime>) -> Self {
        Self {
            topology: Arc::clone(topology),
            generation: topology.begin_discovery(),
            armed: true,
        }
    }

    fn finish(mut self, full_vir_discovery: bool) {
        self.armed = false;
        self.topology
            .finish_discovery(self.generation, full_vir_discovery);
    }
}

impl Drop for DiscoveryGuard {
    fn drop(&mut self) {
        if self.armed {
            self.topology.finish_discovery(self.generation, false);
        }
    }
}

/// Events received on a `DoIP` connection.
///
/// `Msg` carries the raw UDS payload and its `DoIP` logical addresses. All other
/// variants are ISO 13400-2 protocol-level events that must be handled before
/// any UDS data is forwarded to the caller.
#[derive(Debug, Clone)]
enum DiagnosticResponse {
    /// A UDS payload received from an ECU, carried verbatim before classification.
    Msg {
        source_address: u16,
        target_address: u16,
        data: Vec<u8>,
    },
    /// An acknowledgment of a previously sent UDS payload, carrying the original
    /// request's logical address and data.
    Ack((u16, Vec<u8>)),
    /// A negative acknowledgment of a previously sent UDS payload, including
    /// the original Nack message struct.
    Nack(DiagnosticMessageNack),
    /// A response to a `DoIP` alive-check request, indicating that the ECU is reachable.
    AliveCheckResponse,
    /// `TesterPresent` NRC - intercepted at the decoding layer so the receiver
    /// can log it, report it as a reply of the ECU with its source address, and
    /// drop it without routing it to a per-ECU channel.
    TesterPresentNRC { source_address: u16, nrc: u8 },
    /// Generic `DoIP` negative acknowledgment, carrying the `GenericNack` struct with the NACK code.
    GenericNack(GenericNack), // todo #22 -> we need the address of the ECU that sent the nack
}

impl DiagnosticResponse {
    fn matches_request(&self, request: &[u8]) -> bool {
        let Some(sid) = request.first() else {
            return false;
        };

        match self {
            Self::Ack((_, previous)) => request.starts_with(previous),
            // Positive and negative echoes both belong to the request: a
            // final NRC can overtake the ACK, and ignoring it here consumes
            // it from the receiver - the later response read then times out
            // although the ECU answered.
            Self::Msg { data, .. } => util::uds_response_matches_request_sid(*sid, data),
            _ => false,
        }
    }
}

pub(crate) struct DoipGatewayState<T: EcuAddresses + DoipComParams> {
    pub(crate) doip_connections: Arc<RwLock<Vec<Arc<DoipConnection>>>>,
    pub(crate) logical_address_to_connection: Arc<RwLock<HashMap<u16, usize>>>,
    pub(crate) ecus: Arc<HashMap<String, RwLock<T>>>,
    /// `None` until the first successful `start()` binds it. No UDP socket is
    /// created at construction time, only when an authorized activation runs.
    pub(crate) socket: Arc<Mutex<Option<DoIPUdpSocket>>>,
    pub(crate) netmask: u32,
    /// Discovery plan and connected gateways, shared with topology persistence.
    pub(crate) topology: Arc<TopologyRuntime>,
    /// Connect state of the current transport start, `None` while stopped.
    /// Every function that works on a session clones it once and does not read
    /// this again, so work of an earlier start cannot change the current one.
    pub(crate) session: Arc<RwLock<Option<Arc<GatewaySession>>>>,
}

impl<T: EcuAddresses + DoipComParams> DoipGatewayState<T> {
    /// Whether the gateway `logical_address` has a connection.
    pub(crate) async fn has_connection(&self, logical_address: u16) -> bool {
        self.logical_address_to_connection
            .read()
            .await
            .contains_key(&logical_address)
    }

    /// Address that the connection of the given gateway was made to.
    pub(crate) async fn connection_ip(&self, logical_address: u16) -> Option<String> {
        self.doip_connections
            .read()
            .await
            .iter()
            .find(|connection| connection.ecus.contains_key(&logical_address))
            .map(|connection| connection.ip.clone())
    }
}

/// Owns all connection tasks for one enabled lifecycle so they stop together.
/// `None` once shut down: a task pushed afterwards is aborted right away.
/// A std mutex, so a task is registered in the same synchronous step that spawns it.
pub(crate) struct ConnectionTasks(StdMutex<Option<Vec<JoinHandle<()>>>>);

impl ConnectionTasks {
    fn new() -> Self {
        Self(StdMutex::new(Some(Vec::new())))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Vec<JoinHandle<()>>>> {
        util::std_ext::lock_mutex(&self.0)
    }

    /// Registers `task`, dropping the handles of finished tasks so the list
    /// does not grow with every reconnect.
    pub(crate) fn push(&self, task: JoinHandle<()>) {
        match self.lock().as_mut() {
            Some(tasks) => {
                tasks.retain(|task| !task.is_finished());
                tasks.push(task);
            }
            // E.g. a VAM or fallback connect racing with the transport stop.
            None => task.abort(),
        }
    }

    async fn shutdown(&self) {
        let mut tasks = self.lock().take().unwrap_or_default();
        for task in &tasks {
            task.abort();
        }
        for task in tasks.drain(..) {
            if let Err(error) = task.await
                && error.is_panic()
            {
                tracing::error!(%error, "DoIP connection task panicked during shutdown");
            }
        }
    }
}

/// Spawns `task` and registers it in one synchronous step, so a caller that
/// is dropped right afterwards cannot leave a task that `shutdown` misses.
fn spawn_connection_task(
    connection_tasks: &Arc<ConnectionTasks>,
    name: &str,
    task: impl Future<Output = ()> + Send + 'static,
) {
    connection_tasks.push(cda_interfaces::spawn_named!(name, task));
}

impl Drop for ConnectionTasks {
    fn drop(&mut self) {
        // Best effort cleanup, we cannot await the tasks in
        // here. A user should call 'shutdown' instead of relying on this.
        for task in self.lock().take().unwrap_or_default() {
            tracing::warn!("DoIP connection tasks dropped without `shutdown`, aborting tasks");
            task.abort();
        }
    }
}

impl<T: EcuAddresses + DoipComParams> Clone for DoipGatewayState<T> {
    fn clone(&self) -> Self {
        Self {
            doip_connections: Arc::clone(&self.doip_connections),
            logical_address_to_connection: Arc::clone(&self.logical_address_to_connection),
            ecus: Arc::clone(&self.ecus),
            socket: Arc::clone(&self.socket),
            netmask: self.netmask,
            topology: Arc::clone(&self.topology),
            session: Arc::clone(&self.session),
        }
    }
}

/// [[ dimpl~deferred-doip-transport, Deferred diagnostic transport activation, dimpl ]]
pub struct DoipDiagGateway<T: EcuAddresses + DoipComParams> {
    state: DoipGatewayState<T>,
    config: DoipConfig,
    variant_detection: VariantDetectionSender,
    connectivity_handler: Arc<dyn EcuConnectivityHandler>,
    lifecycle: Arc<GatewayLifecycle<DoipGatewayOperation>>,
}

/// Background work owned by the currently enabled lifecycle.
#[derive(Default)]
struct DoipGatewayOperation {
    cancel: Option<CancellationToken>,
    vam_listener: Option<JoinHandle<()>>,
    connection_tasks: Option<Arc<ConnectionTasks>>,
}

impl Drop for DoipGatewayOperation {
    fn drop(&mut self) {
        if self.cancel.is_some() || self.vam_listener.is_some() || self.connection_tasks.is_some() {
            tracing::warn!("DoIP gateway operation dropped without `shutdown`, aborting tasks");
        }
        self.take_and_abort();
    }
}

impl DoipGatewayOperation {
    fn take_and_abort(&mut self) -> (Option<JoinHandle<()>>, Option<Arc<ConnectionTasks>>) {
        if let Some(cancel) = self.cancel.take() {
            cancel.cancel();
        }
        let listener = self.vam_listener.take();
        if let Some(listener) = &listener {
            listener.abort();
        }
        (listener, self.connection_tasks.take())
    }

    async fn shutdown(&mut self) {
        let (listener, connection_tasks) = self.take_and_abort();
        if let Some(listener) = listener
            && let Err(error) = listener.await
            && !error.is_cancelled()
        {
            tracing::error!(%error, "DoIP VAM listener failed during shutdown");
        }
        if let Some(connection_tasks) = connection_tasks {
            connection_tasks.shutdown().await;
        }
    }
}

/// A gateway discovered on the network during `DoIP` vehicle discovery.
///
/// Contains the IP address, ECU name, and logical address obtained from a
/// `VehicleIdentificationResponse` or `EntityStatusResponse` message.
#[derive(Debug, Clone)]
pub(crate) struct DiscoveredGateway {
    pub(crate) ip: String,
    pub(crate) ecu_name: String,
    pub(crate) logical_address: u16,
    pub(crate) doip_protocol_version: ProtocolVersion,
}

impl From<&DiscoveredGateway> for KnownGateway {
    fn from(gateway: &DiscoveredGateway) -> Self {
        Self {
            name: gateway.ecu_name.clone(),
            logical_address: gateway.logical_address,
            network_address: Some(gateway.ip.clone()),
            doip_protocol_version: Some(u8::from(gateway.doip_protocol_version)),
        }
    }
}

/// Transport-level settings shared across all `DoIP` gateway connections.
/// Built once from `DoipConfig` in `DoipDiagGateway::new`; cloned into each
/// `GatewayDoipConfig` when a specific gateway is discovered.
#[derive(Clone)]
pub(crate) struct DoipTransportConfig {
    /// IP address of the diagnostic tester interface.
    pub(crate) tester_ip: String,
    /// TCP port for `DoIP` communication.
    pub(crate) port: u16,
    /// TCP port for `DoIP` over TLS communication.
    pub(crate) tls_port: u16,
    /// Whether to send a `DiagnosticMessageAck` upon receiving a `DiagnosticMessage`.
    pub(crate) send_diagnostic_message_ack: bool,
    /// Timeout for sending a single `DoIP` message.
    pub(crate) send_timeout: Duration,
    /// Interval between alive-check requests on idle connections (0 = disabled).
    pub(crate) alive_check_interval: Duration,
}

/// Per-gateway configuration combining the discovered gateway identity with the
/// shared transport settings.  Only constructed inside `handle_gateway_connection`
/// once a real `ip` and `name` are known - never holds placeholder values.
#[derive(Clone)]
pub(crate) struct GatewayDoipConfig {
    /// IP address of the gateway ECU.
    pub(crate) gateway_ip: String,
    /// Name of the gateway ECU.
    pub(crate) name: String,
    /// UDS address of the tester.
    pub(crate) tester_address: [u8; 2],
    /// The `DoIp` protocol version to use for this gateway connection.
    /// Set from the protocol version field in the VAM.
    pub(crate) protocol_version: ProtocolVersion,
    /// Shared transport-level settings (tester IP, ports, socket config, timeouts).
    pub(crate) transport: DoipTransportConfig,
}

/// ECU-lifecycle timeouts sourced from `EcuAddresses` / `DoipComParams` during gateway setup.
#[derive(Clone, Copy)]
pub(crate) struct EcuTimeouts {
    pub(crate) routing_activation: Duration,
    pub(crate) retry_delay: Duration,
    pub(crate) connection: Duration,
    pub(crate) max_retry_attempts: u32,
}

/// Parameters needed to (re-)establish a TCP connection to one `DoIP` gateway.
/// Cloned into the reconnect task and passed to `ecu_connection` functions;
/// does **not** carry one-time setup data such as the ECU list or variant-detection channel.
#[derive(Clone)]
pub(crate) struct GatewayConnectionConfig {
    pub(crate) doip: GatewayDoipConfig,
    pub(crate) routing_activation_request: RoutingActivationRequest,
    pub(crate) ecu_timeouts: EcuTimeouts,
}

/// One-shot setup bundle consumed by `connection_handler` when bringing up a new gateway.
/// Carries `GatewayConnectionConfig` plus the ECU list needed during initial channel creation,
/// the `ConnectivityHandler` for propagating connection events, and the [`EcuActivityReporter`] for
/// the frames the receiver task does not route to an ECU.
#[derive(Clone)]
pub(crate) struct GatewaySetup {
    pub(crate) connection: GatewayConnectionConfig,
    pub(crate) ecus: Vec<u16>,
    pub(crate) ecu_names: Vec<String>,
    pub(crate) connectivity_handler: Arc<dyn EcuConnectivityHandler>,
    pub(crate) activity_reporter: EcuActivityReporter,
}

/// Reports UDS frames that the transport receives but does not pass on as the
/// answer to a request, so that they still count as replies of the ECU.
///
/// The reported replies are used to update `last_seen` of the affected ECUs.
#[derive(Clone)]
pub(crate) struct EcuActivityReporter {
    /// Handler notified about the reported replies.
    connectivity_handler: Arc<dyn EcuConnectivityHandler>,
    /// Names of the ECUs behind one gateway, by logical address.
    ecu_names_by_address: Arc<HashMap<u16, Vec<String>>>,
}

impl EcuActivityReporter {
    pub(crate) fn new(
        connectivity_handler: Arc<dyn EcuConnectivityHandler>,
        ecu_names_by_address: HashMap<u16, Vec<String>>,
    ) -> Self {
        Self {
            connectivity_handler,
            ecu_names_by_address: Arc::new(ecu_names_by_address),
        }
    }

    /// Reports a frame as a reply of `ecu_name`.
    pub(crate) async fn report_activity_for_ecu_name(&self, ecu_name: &str) {
        self.connectivity_handler.on_ecu_replied(ecu_name).await;
    }

    /// Reports a frame from `source_address` as a reply of the ECUs with that
    /// logical address.
    pub(crate) async fn report_activity_for_address(&self, source_address: u16) {
        let Some(ecu_names) = self.ecu_names_by_address.get(&source_address) else {
            return;
        };
        for ecu_name in ecu_names {
            self.connectivity_handler.on_ecu_replied(ecu_name).await;
        }
    }
}

struct DoipEcu {
    sender: mpsc::Sender<DoipPayload>,
    receiver: broadcast::Receiver<Result<DiagnosticResponse, EcuError>>,
}

struct DoipConnection {
    ecus: HashMap<u16, Arc<Mutex<DoipEcu>>>,
    ip: String,
    activity: EcuActivityReporter,
}

impl<T: EcuAddresses + DoipComParams> DoipDiagGateway<T> {
    /// Create a new `DoipDiagGateway` instance.
    ///
    /// Purely in-memory. No UDP socket is created or bound, no packet is sent
    /// and no task is started, so this is safe to call in any `init_mode`.
    ///
    /// # Errors
    /// Returns `String` if initialization fails, e.g. when the configured
    /// tester address/subnet cannot be parsed into a netmask.
    #[tracing::instrument(
        skip(doip_config, ecus, variant_detection, connectivity_handler),
        fields(
            tester_ip = doip_config.tester_address,
            gateway_port = doip_config.gateway_port,
            ecu_count = ecus.len(),
            dlt_context = dlt_ctx!("DOIP")
        )
    )]
    pub async fn new(
        doip_config: &DoipConfig,
        ecus: Arc<HashMap<String, RwLock<T>>>,
        variant_detection: VariantDetectionSender,
        connectivity_handler: Arc<dyn EcuConnectivityHandler>,
    ) -> Result<Self, DoipGatewaySetupError> {
        Ok(Self {
            state: DoipGatewayState {
                doip_connections: Arc::new(RwLock::new(Vec::new())),
                logical_address_to_connection: Arc::new(RwLock::new(HashMap::new())),
                ecus,
                socket: Arc::new(Mutex::new(None)),
                netmask: create_netmask(&doip_config.tester_address, &doip_config.tester_subnet)?,
                topology: TopologyRuntime::new(DiscoveryStrategy::Vir),
                session: Arc::new(RwLock::new(None)),
            },
            config: doip_config.clone(),
            variant_detection,
            connectivity_handler,
            lifecycle: Arc::new(GatewayLifecycle::new(TransportState::Disabled)),
        })
    }

    fn transport_config(&self) -> DoipTransportConfig {
        let config = &self.config;
        DoipTransportConfig {
            tester_ip: config.tester_address.clone(),
            port: config.gateway_port,
            tls_port: config.tls_port,
            send_diagnostic_message_ack: config.send_diagnostic_message_ack,
            send_timeout: Duration::from_millis(config.send_timeout_ms),
            alive_check_interval: Duration::from_secs(config.alive_check_interval_secs),
        }
    }

    /// Shares `topology` with this gateway: its plan selects the discovery on the
    /// next start, and connected gateways and the end of the initial discovery are
    /// reported to it.
    #[must_use]
    pub fn with_topology_runtime(mut self, topology: Arc<TopologyRuntime>) -> Self {
        self.state.topology = topology;
        self
    }

    async fn start(
        &self,
        operation: &mut DoipGatewayOperation,
    ) -> Result<(), DoipGatewaySetupError> {
        let mut socket_guard = self.state.socket.lock().await;
        if operation.cancel.is_some()
            || operation.vam_listener.is_some()
            || operation.connection_tasks.is_some()
            || socket_guard.is_some()
        {
            return Err(DoipGatewaySetupError::InvalidState(
                "DoIP communication is already running".to_string(),
            ));
        }

        let config = &self.config;
        // Checked here and not at startup, so that communication can be enabled
        // later (e.g. on demand) while the network interface is not up yet.
        config
            .check_tester_address_available()
            .map_err(|error| DoipGatewaySetupError::InvalidConfiguration(error.to_string()))?;

        let transport_config = self.transport_config();
        let mask = self.state.netmask;
        let cancel = CancellationToken::new();
        let shutdown = cancel.child_token().cancelled_owned().shared();
        let connection_tasks = Arc::new(ConnectionTasks::new());
        operation.cancel = Some(cancel.clone());
        operation.connection_tasks = Some(Arc::clone(&connection_tasks));

        // Finishes the discovery on every early return, so a failed start does
        // not leave it running.
        let discovery = DiscoveryGuard::begin(&self.state.topology);

        // Set before anything connects, so every connect and the VAM listener of
        // this start work on the same session. Also with discovery disabled: a
        // direct connect registers in it.
        let session = Arc::new(GatewaySession::new(
            transport_config,
            Arc::clone(&connection_tasks),
            cancel.clone(),
            self.variant_detection.clone(),
            Arc::clone(&self.connectivity_handler),
            config.discovery,
        ));
        *self.state.session.write().await = Some(Arc::clone(&session));

        if !config.discovery.listens_for_vams() {
            tracing::info!(
                "DoIP discovery is disabled, no VIR is sent, VAMs are ignored and persisted \
                 gateways are not reconnected. ECUs have to be connected directly."
            );
            discovery.finish(false);
            return Ok(());
        }

        let discovery_strategy = self.state.topology.discovery_strategy();
        // Bound only if used: by the VAM listener started below, or by the
        // startup VIR broadcast. A reconnect searches from a socket of its own.
        let listens_for_vams = self.state.topology.listens_for_vams();
        let needs_socket = listens_for_vams
            || (matches!(discovery_strategy, DiscoveryStrategy::Vir)
                && config.discovery.sends_vir());
        if needs_socket {
            *socket_guard = Some(create_udp_vir_socket(
                &config.tester_address,
                config.gateway_port,
            )?);
        }
        match discovery_strategy {
            DiscoveryStrategy::Vir if !config.discovery.sends_vir() => {
                drop(socket_guard);
                tracing::info!("DoIP discovery is VAM only, not broadcasting a VIR");
                discovery.finish(false);
            }
            DiscoveryStrategy::Vir => {
                let socket = socket_guard.as_mut().ok_or_else(|| {
                    DoipGatewaySetupError::ResourceError("Discovery socket is not bound".to_owned())
                })?;
                let gateways = vir_vam::get_vehicle_identification::<T, _>(
                    socket,
                    mask,
                    config.gateway_port,
                    &self.state.ecus,
                    shutdown.clone(),
                )
                .await
                .map_err(|error| DoipGatewaySetupError::ResourceError(error.to_string()))?;
                drop(socket_guard);

                // No VIR fallback: the gateways were just announced.
                let connects = self.state.start_connects(&session, gateways);
                let state = self.state.clone();
                let task_session = Arc::clone(&session);
                // The connect task finishes the discovery, or its guard does if it is aborted.
                spawn_connection_task(&connection_tasks, "doip-initial-discovery", async move {
                    Self::finish_initial_discovery(&state, &task_session, discovery, connects)
                        .await;
                });
            }
            DiscoveryStrategy::Persisted { known, search } => {
                drop(socket_guard);
                let db_gateways = self.db_gateways().await;
                let plan = reconnect::plan_reconnect(&known, &search, &db_gateways, mask);
                tracing::info!(
                    unicast = plan.unicast.len(),
                    vir = plan.vir_for.len(),
                    discovery = ?config.discovery,
                    "Reconnecting to persisted gateways without a full VIR discovery"
                );
                let connects = self.state.start_connects(&session, plan.unicast);
                let state = self.state.clone();
                let task_session = Arc::clone(&session);
                spawn_connection_task(&connection_tasks, "doip-initial-reconnect", async move {
                    Self::finish_reconnect(
                        &state,
                        &task_session,
                        discovery,
                        connects,
                        plan.vir_for,
                        plan.unusable,
                    )
                    .await;
                });
            }
        }

        self.finish_start(operation, listens_for_vams, mask, &session, shutdown)
            .await
    }

    /// Starts the spontaneous VAM listener, unless `vam_handling_mode` disables it.
    async fn finish_start<F>(
        &self,
        operation: &mut DoipGatewayOperation,
        listens_for_vams: bool,
        mask: u32,
        session: &Arc<GatewaySession>,
        shutdown: futures::future::Shared<F>,
    ) -> Result<(), DoipGatewaySetupError>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        if listens_for_vams {
            let listener = vir_vam::listen_for_vams(
                session.transport_config.clone(),
                mask,
                self.state.clone(),
                Arc::clone(session),
                self.variant_detection.clone(),
                shutdown,
            )
            .await;
            operation.vam_listener = Some(listener);
        } else {
            tracing::info!("Spontaneous VAM listener not started (vam_handling_mode)");
        }
        Ok(())
    }

    /// Names of the database ECUs that are their own gateway, keyed by logical
    /// address (several for duplicate ECUs).
    async fn db_gateways(&self) -> HashMap<u16, Vec<String>> {
        let mut by_address: HashMap<u16, Vec<String>> = HashMap::new();
        for (name, ecu) in self.state.ecus.iter() {
            let ecu = ecu.read().await;
            if is_physical_gateway(ecu.logical_address(), ecu.logical_gateway_address()) {
                by_address
                    .entry(ecu.logical_address())
                    .or_default()
                    .push(name.clone());
            }
        }
        by_address
    }

    /// Completes the startup VIR discovery: the connects of the announced
    /// gateways were started by `start`. A gateway whose connect ends
    /// Connected is recorded at the address it announced, also if a direct
    /// connect in flight connected it (a direct connect itself is not
    /// recorded). Then the discovery is marked complete, unless the session was
    /// cancelled meanwhile: a start that was stopped did not search everything.
    async fn finish_initial_discovery(
        state: &DoipGatewayState<T>,
        session: &GatewaySession,
        discovery: DiscoveryGuard,
        connects: Vec<(DiscoveredGateway, gateway_session::PendingConnect)>,
    ) {
        for (gateway, connect) in connects {
            // A cancelled session must not write the shared topology.
            // A discovery connect recorded the gateway itself already.
            if connect.wait().await == ConnectOutcome::Connected
                && !session.cancel_token.is_cancelled()
                && !state.topology.is_connected(gateway.logical_address)
            {
                state
                    .topology
                    .record_connected(KnownGateway::from(&gateway));
            }
        }
        discovery.finish(!session.cancel_token.is_cancelled());
    }

    /// Completes a reconnect to persisted gateways: the direct connects were
    /// started by `start`. Gateways that could not be reached at their persisted
    /// address (and gateways that must be searched) are searched by one
    /// VIR search for all of them, instead of one per gateway; the ECUs of
    /// gateways still not found are reported disconnected. Then the discovery is
    /// marked complete. Without VIR (`doip.discovery = VamOnly`) nothing is
    /// searched: the gateways that failed their direct connect and the persisted
    /// gateways without a usable address (`unusable`) are reported unreachable,
    /// unless they are connected by then. A connect of one in flight (e.g. by
    /// its announcement) is waited for first.
    /// [[ dimpl~doip-persisted-reconnect, Reconnect to persisted gateways with VIR fallback, dimpl ]]
    /// [[ dimpl~doip-reconnect-discovery-mode, The persisted reconnect follows doip.discovery, dimpl ]]
    async fn finish_reconnect(
        state: &DoipGatewayState<T>,
        session: &Arc<GatewaySession>,
        discovery: DiscoveryGuard,
        connects: Vec<(DiscoveredGateway, gateway_session::PendingConnect)>,
        vir_for: cda_interfaces::HashSet<u16>,
        unusable: cda_interfaces::HashSet<u16>,
    ) {
        let attempted: cda_interfaces::HashSet<u16> = connects
            .iter()
            .map(|(gateway, _)| gateway.logical_address)
            .collect();
        let connected = connected_gateways(connects).await;
        let mut candidates: cda_interfaces::HashSet<u16> =
            attempted.difference(&connected).copied().collect();
        if session.discovery.sends_vir() {
            candidates.extend(vir_for);
            if !candidates.is_empty() {
                let found = Self::search_gateways(state, session, &candidates).await;
                let connected = connected_gateways(state.start_connects(session, found)).await;
                candidates.retain(|address| !connected.contains(address));
            }
        } else {
            candidates.extend(unusable);
        }
        // An announcement may have connected a gateway meanwhile; it is not reported.
        let mut unreachable = cda_interfaces::HashSet::default();
        for logical_address in candidates {
            if !state
                .is_connected_after_in_flight(session, logical_address)
                .await
            {
                unreachable.insert(logical_address);
            }
        }
        state.report_unreachable(session, unreachable).await;
        discovery.finish(false);
    }

    /// The gateways in `wanted` announced in answer to one VIR, sent from an
    /// ephemeral socket (see [`reconnect::fallback_identification`]). A failure
    /// is logged and finds nothing; a cancelled session searches nothing.
    async fn search_gateways(
        state: &DoipGatewayState<T>,
        session: &GatewaySession,
        wanted: &cda_interfaces::HashSet<u16>,
    ) -> Vec<DiscoveredGateway> {
        if session.cancel_token.is_cancelled() {
            return Vec::new();
        }
        tracing::info!(
            gateways = ?wanted,
            "Searching gateways not reachable at their persisted address by VIR"
        );
        let shutdown = session
            .cancel_token
            .child_token()
            .cancelled_owned()
            .shared();
        reconnect::fallback_identification(
            &session.transport_config.tester_ip,
            session.transport_config.port,
            state.netmask,
            &state.ecus,
            wanted,
            shutdown,
        )
        .await
        .unwrap_or_else(|error| {
            tracing::warn!(%error, "Fallback vehicle identification failed");
            Vec::new()
        })
    }

    async fn stop(&self, operation: &mut DoipGatewayOperation) {
        // Before the tasks are shut down, so no VAM or fallback connect starts after.
        // The session is dropped, not reused: the next start creates its own.
        let session = self.state.session.write().await.take();
        if let Some(session) = &session {
            session.cancel_token.cancel();
        }
        operation.shutdown().await;
        // The connects in flight are aborted now. Undo the report of those that
        // already reported their ECUs connected, like a connect that sees the
        // cancel. The others did not change the ECU states, so an `AssumedOnline`
        // ECU stays assumed online.
        // [[ dimpl~doip-stop-reverts-aborted-connects, A stop reports the ECUs of a connect it aborted after their connected report disconnected again, dimpl ]]
        if let Some(addresses) = session
            .map(|session| session.take_online_reports())
            .filter(|addresses| !addresses.is_empty())
        {
            let (_, gateway_ecu_name_map) =
                gateway_session::gateway_ecu_maps(&self.state.ecus).await;
            for ecu_names in addresses
                .iter()
                .filter_map(|address| gateway_ecu_name_map.get(address))
            {
                self.connectivity_handler
                    .on_gateway_disconnected(ecu_names)
                    .await;
            }
        }
        self.state.socket.lock().await.take();
        self.state.doip_connections.write().await.clear();
        self.state
            .logical_address_to_connection
            .write()
            .await
            .clear();
    }

    async fn get_doip_connection(
        &self,
        logical_address: u16,
    ) -> Result<Arc<DoipConnection>, DiagServiceError> {
        let conn_idx = *self
            .state
            .logical_address_to_connection
            .read()
            .await
            .get(&logical_address)
            .ok_or_else(|| DiagServiceError::EcuOffline(format!("[{logical_address}]")))?;

        let lock = self.state.doip_connections.read().await;
        let conn = lock
            .get(conn_idx)
            .ok_or(DiagServiceError::ConnectionClosed(format!(
                "Connection entry for address {logical_address} found, but it was already closed"
            )))?;

        Ok(Arc::clone(conn))
    }

    async fn get_ecu_mtx(
        &self,
        doip_conn: &DoipConnection,
        message: &ServicePayload,
        transmission_params: &TransmissionParameters,
    ) -> Result<Arc<Mutex<DoipEcu>>, DiagServiceError> {
        // first try looking up with the target address.
        if let Some(ecu) = doip_conn.ecus.get(&message.target_address) {
            return Ok(Arc::clone(ecu));
        }

        // if we cannot find the target address,
        // the request might be sent on the functional address
        // in that case, lookup the ecu name and check if the functional address
        // matches the given address.
        // this will be the case for tester present.
        if let Some(ecu) = self
            .state
            .ecus
            .get(&transmission_params.ecu_name.to_lowercase())
            && ecu.read().await.logical_functional_address() == message.target_address
            && let Some(gateway_ecu) = doip_conn.ecus.get(&transmission_params.gateway_address)
        {
            return Ok(Arc::clone(gateway_ecu));
        }

        Err(DiagServiceError::EcuOffline(
            transmission_params.ecu_name.clone(),
        ))
    }
}

impl<T: EcuAddresses + DoipComParams> PhysicalTransport for DoipDiagGateway<T> {
    #[tracing::instrument(skip_all,
        fields(dlt_context = dlt_ctx!("DOIP"))
    )]

    async fn send(
        &self,
        transmission_params: TransmissionParameters,
        message: ServicePayload,
        response_sender: mpsc::Sender<Result<Option<TransportResponse>, DiagServiceError>>,
        expect_uds_reply: bool,
    ) -> Result<tokio::task::JoinHandle<()>, DiagServiceError> {
        let start = Instant::now();

        let doip_conn = self
            .get_doip_connection(transmission_params.gateway_address)
            .await?;
        let ecu_mtx = self
            .get_ecu_mtx(&doip_conn, &message, &transmission_params)
            .await?;

        let doip_message = DiagnosticMessage {
            source_address: message.source_address.to_be_bytes(),
            target_address: message.target_address.to_be_bytes(),
            message: message.data,
        };
        let activity = doip_conn.activity.clone();

        let handle = cda_interfaces::spawn_named!(
            &format!("ecu-data-receive-{}", transmission_params.ecu_name),
            {
                async move {
                    let mut ecu = ecu_mtx.lock().await;
                    let lock_acquired = start.elapsed();
                    tracing::debug!(
                        ecu_name = %transmission_params.ecu_name,
                        locked_after = ?lock_acquired,
                        message_data = %util::tracing::print_hex(&doip_message.message, 8),
                        "Sending Message to ECU"
                    );

                    // Clear any pending messages
                    tokio_ext::clear_pending_messages(&mut ecu.receiver);
                    let receiver_flushed = start.elapsed().saturating_sub(lock_acquired);

                    let mut resend_counter = 0;
                    if let Err(e) = send_with_retries(
                        &doip_message,
                        &ecu.sender,
                        &mut resend_counter,
                        transmission_params.repeat_request_count_transmission,
                    )
                    .await
                    {
                        // failed to send the message after exhausting retries.
                        // informing receiver and giving up.
                        try_send_transport_response(&response_sender, Err(e)).await;
                        return;
                    }

                    let received_event = match wait_for_ack_or_response_until_timeout(
                        &mut ecu.receiver,
                        &transmission_params.ecu_name,
                        &doip_message,
                        transmission_params.timeout_ack,
                        &activity,
                    )
                    .await
                    {
                        Ok(first) => first,
                        Err(e) => {
                            try_send_transport_response(&response_sender, Err(e)).await;
                            return;
                        }
                    };

                    let send_and_ackd_after = start
                        .elapsed()
                        .saturating_sub(lock_acquired)
                        .saturating_sub(receiver_flushed);

                    if !expect_uds_reply {
                        try_send_transport_response(&response_sender, Ok(None)).await;
                    }

                    // Read ECU responses as long as the sender is open.
                    // We might get multiple responses for a single request,
                    // e.g. when the ECU is busy and sends NRC 0x78.
                    read_ecu_responses(
                        &mut ecu.receiver,
                        &transmission_params.ecu_name,
                        &response_sender,
                        received_event,
                    )
                    .await;

                    let rx_done = start
                        .elapsed()
                        .saturating_sub(lock_acquired)
                        .saturating_sub(send_and_ackd_after)
                        .saturating_sub(receiver_flushed);
                    tracing::debug!(
                        ecu_name = %transmission_params.ecu_name,
                        total_duration = ?start.elapsed(),
                        lock_duration = ?lock_acquired,
                        flush_duration = ?receiver_flushed,
                        send_ack_duration = ?send_and_ackd_after,
                        response_duration = ?rx_done,
                        "Handled DOIP request timing breakdown"
                    );
                }
            }
        );

        Ok(handle)
    }

    async fn ecu_online<E: EcuAddresses>(
        &self,
        ecu_name: &str,
        ecu_db: &RwLock<E>,
    ) -> Result<(), DiagServiceError> {
        let ecu_lock = ecu_db.read().await;

        let doip_conn = self
            .get_doip_connection(ecu_lock.logical_gateway_address())
            .await?;
        doip_conn
            .ecus
            .get(&ecu_lock.logical_address())
            .ok_or_else(|| DiagServiceError::EcuOffline(ecu_name.to_owned()))?;
        Ok(())
    }
}

impl<T: EcuAddresses + DoipComParams> FunctionalTransport for DoipDiagGateway<T> {
    async fn send_functional(
        &self,
        transmission_params: TransmissionParameters,
        message: ServicePayload,
        expected_ecu_logical_addrs: HashMap<u16, String>,
        timeout: Duration,
        expect_positive_response: bool,
    ) -> Result<HashMap<String, Result<ServicePayload, DiagServiceError>>, DiagServiceError> {
        let doip_conn = self
            .get_doip_connection(transmission_params.gateway_address)
            .await?;

        // Get the gateway ECU for sending the functional request
        let gateway_ecu = doip_conn
            .ecus
            .get(&transmission_params.gateway_address)
            .ok_or_else(|| DiagServiceError::EcuOffline("Gateway ECU not found".to_string()))?;

        let doip_message = DiagnosticMessage {
            source_address: message.source_address.to_be_bytes(),
            target_address: message.target_address.to_be_bytes(),
            message: message.data,
        };

        let mut result_map = HashMap::new();
        let expected_count = expected_ecu_logical_addrs.len();

        tracing::debug!(
            gateway_address = %transmission_params.gateway_address,
            expected_ecus = expected_count,
            message_data = %util::tracing::print_hex(&doip_message.message, 8),
            "Sending functional request to gateway"
        );

        // Send the functional request once
        let mut ecu = gateway_ecu.lock().await;
        let mut ecu_mtxs = expected_ecu_logical_addrs
            .iter()
            .filter_map(|(addr, name)| {
                if *addr == transmission_params.gateway_address {
                    None
                } else {
                    doip_conn
                        .ecus
                        .get(addr)
                        .cloned()
                        .map(|ecu| (name.clone(), ecu))
                }
            })
            .collect::<Vec<_>>();

        // Clear any pending messages
        tokio_ext::clear_pending_messages(&mut ecu.receiver);

        let mut resend_counter = 0;
        send_with_retries(
            &doip_message,
            &ecu.sender,
            &mut resend_counter,
            transmission_params.repeat_request_count_transmission,
        )
        .await?;

        drop(ecu); // release lock before waiting for responses
        ecu_mtxs.push((
            transmission_params.ecu_name.to_lowercase(),
            Arc::clone(gateway_ecu),
        ));

        // Use a short window to capture any negative responses instead of the full timeout,
        // as NRCs are usually sent immediately by the ECUs.
        let response_timeout = if expect_positive_response {
            timeout
        } else {
            SUPPRESS_POSITIVE_RESPONSE_TIMEOUT
        };

        let received_responses: Arc<Mutex<HashMap<String, Result<DiagnosticMessage, EcuError>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let mut futures = Vec::new();
        for (name, ecu) in ecu_mtxs.drain(..) {
            let received_responses = Arc::clone(&received_responses);
            let fut = async move {
                let mut lock = ecu.lock().await;
                if let Some(response) = wait_for_ecu_response(&mut lock, response_timeout).await {
                    received_responses.lock().await.insert(name, response);
                }
            };
            futures.push(fut);
        }

        futures::future::join_all(futures).await;

        for (ecu_name, msg) in received_responses.lock().await.drain() {
            if !result_map.contains_key(&ecu_name) {
                match msg {
                    Ok(msg) => {
                        let source_addr = u16::from_be_bytes(msg.source_address);

                        let uds_response = ServicePayload {
                            data: msg.message,
                            source_address: source_addr,
                            target_address: u16::from_be_bytes(msg.target_address),
                            new_session: None,
                            new_security: None,
                        };

                        result_map.insert(ecu_name.clone(), Ok(uds_response));

                        tracing::debug!(
                            ecu_name = %ecu_name,
                            source_addr = source_addr,
                            "Received functional response"
                        );
                    }
                    Err(e) => {
                        tracing::debug!(
                            ecu_name = %ecu_name,
                            "Error receiving functional response: {e}"
                        );
                        result_map.insert(ecu_name.clone(), Err(e.into()));
                    }
                }
            }
        }

        // For ECUs that did not respond:
        // Insert a TimeoutError for ECUs that did not response, if
        // a positive response is expected. (suppress bit is not set)
        for (logical_addr, ecu_name) in &expected_ecu_logical_addrs {
            if !result_map.contains_key(ecu_name) && expect_positive_response {
                result_map.insert(ecu_name.clone(), Err(DiagServiceError::Timeout));
                tracing::debug!(
                    ecu_name = %ecu_name,
                    logical_addr = logical_addr,
                    "ECU did not respond to functional request"
                );
            }
        }

        Ok(result_map)
    }
}

impl<T: EcuAddresses + DoipComParams> NetworkTopology for DoipDiagGateway<T> {
    async fn get_gateway_network_address(&self, logical_address: u16) -> Option<String> {
        self.state.connection_ip(logical_address).await
    }
}

/// Time a direct connect may take on top of the connect and routing activation
/// timeouts of the ECU. Covers the TLS handshake, which has no timeout of its own.
const DIRECT_CONNECT_HEADROOM: Duration = Duration::from_secs(5);

impl<T: EcuAddresses + DoipComParams> DoipDiagGateway<T> {
    /// Connects `ecu_name` to `address` without VIR/VAM discovery, then continues
    /// like a discovered gateway: routing activation, TLS upgrade, ECU identification.
    ///
    /// The connect runs in a task of the current session, so that it is not left
    /// half done when the caller gives up (client disconnect, HTTP timeout).
    /// Disabling communication cancels it, without waiting for it.
    async fn connect_direct(
        &self,
        ecu_name: &str,
        address: IpAddr,
        protocol_version: u8,
    ) -> Result<(), DiagServiceError> {
        let ecu_name = ecu_name.to_lowercase();
        let protocol_version = ProtocolVersion::try_from(&protocol_version).map_err(|_| {
            DiagServiceError::InvalidRequest(format!(
                "Unsupported DoIP protocol version {protocol_version:#04x}"
            ))
        })?;
        let ecu_lock = self
            .state
            .ecus
            .get(&ecu_name)
            .ok_or_else(|| DiagServiceError::NotFound(format!("ECU {ecu_name} not found")))?;
        let (logical_address, is_gateway) = {
            let ecu = ecu_lock.read().await;
            (ecu.logical_address(), vir_vam::is_gateway(&*ecu))
        };
        if !is_gateway {
            return Err(DiagServiceError::InvalidRequest(format!(
                "ECU '{ecu_name}' is not a gateway, only gateway ECUs can be connected directly"
            )));
        }

        let Some(session) = self
            .state
            .session
            .read()
            .await
            .clone()
            .filter(|session| !session.cancel_token.is_cancelled())
        else {
            return Err(DiagServiceError::CommunicationDisabled(
                "DoIP communication is not enabled".to_owned(),
            ));
        };
        let control = ConnectControl {
            cancel: session.cancel_token.clone(),
            headroom: DIRECT_CONNECT_HEADROOM,
        };
        let gateway = DiscoveredGateway {
            ip: address.to_string(),
            ecu_name: ecu_name.clone(),
            logical_address,
            doip_protocol_version: protocol_version,
        };
        let receiver = match self
            .state
            .start_direct_connect(&session, gateway, control)
            .await
        {
            Ok(receiver) => receiver,
            Err(DirectRejection::Connecting) => {
                return Err(DiagServiceError::Conflict(format!(
                    "ECU '{ecu_name}' is currently being connected"
                )));
            }
            Err(DirectRejection::Connected) => {
                let connected_ip = self
                    .get_gateway_network_address(logical_address)
                    .await
                    .unwrap_or_else(|| "an unknown address".to_owned());
                return Err(DiagServiceError::Conflict(format!(
                    "ECU '{ecu_name}' is already connected on {connected_ip}"
                )));
            }
        };
        tracing::info!(
            ecu_name = %ecu_name,
            %address,
            ?protocol_version,
            "Connecting ECU directly"
        );
        let disabled = || {
            DiagServiceError::CommunicationDisabled(
                "DoIP communication was disabled while connecting".to_owned(),
            )
        };
        match receiver.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(ConnectFailure::Error(error))) => {
                tracing::warn!(ecu_name = %ecu_name, %address, %error, "Direct connection failed");
                Err(error.into())
            }
            Ok(Err(ConnectFailure::Cancelled)) => {
                tracing::warn!(
                    ecu_name = %ecu_name,
                    %address,
                    error = "DoIP communication was disabled while connecting",
                    "Direct connection failed"
                );
                Err(disabled())
            }
            // The task ended without a result: aborted by the transport stop.
            Err(_) if session.cancel_token.is_cancelled() => Err(disabled()),
            Err(_) => {
                tracing::error!(ecu_name = %ecu_name, "Direct connect task failed");
                Err(DiagServiceError::ResourceError(format!(
                    "Connecting ECU '{ecu_name}' failed unexpectedly"
                )))
            }
        }
    }
}

impl<T: EcuAddresses + DoipComParams> TransportProbe for DoipDiagGateway<T> {
    async fn route_status(&self, ecu_name: &str) -> RouteStatus {
        let ecu_name = ecu_name.to_lowercase();
        let Some(ecu_lock) = self.state.ecus.get(&ecu_name) else {
            return RouteStatus::NotConfigured;
        };
        // Check if the gateway connection for this ECU is established
        let gateway_addr = ecu_lock.read().await.logical_gateway_address();
        if self.get_doip_connection(gateway_addr).await.is_ok() {
            RouteStatus::Ready
        } else {
            // DoIP addressing is gateway-scoped, so there is
            // no per-ECU probe to offer. Reconnecting is this transport's job
            // (VAM listener, connection-reset task), not the router's.
            RouteStatus::Unavailable
        }
    }

    fn probe_ecu(&self, _ecu_name: &str) -> impl Future<Output = bool> {
        std::future::ready(false)
    }
}
/// Waits for the `DoIP` diagnostic-message acknowledgement from the gateway,
/// with a deadline of `timeout`.
#[allow(
    clippy::needless_continue,
    reason = "Explicit continue improves readability of wait logic"
)]
async fn wait_for_ack_or_response_until_timeout(
    receiver: &mut broadcast::Receiver<Result<DiagnosticResponse, EcuError>>,
    ecu_name: &str,
    sent_message: &DiagnosticMessage,
    timeout: Duration,
    activity: &EcuActivityReporter,
) -> Result<Option<DiagnosticResponse>, DiagServiceError> {
    async fn wait_for_ack_or_response(
        receiver: &mut broadcast::Receiver<Result<DiagnosticResponse, EcuError>>,
        ecu_name: &str,
        sent_message: &DiagnosticMessage,
        activity: &EcuActivityReporter,
    ) -> Result<Option<DiagnosticResponse>, DiagServiceError> {
        loop {
            let response = match receiver.recv().await {
                Ok(Ok(response)) => response,
                Ok(Err(e)) => {
                    tracing::error!(
                        ecu_name = %ecu_name,
                        error = %e,
                        "Error while waiting for ACK/NACK"
                    );

                    return Err(DiagServiceError::NoResponse(format!(
                        "Error while waiting for ACK/NACK, {e}"
                    )));
                }
                Err(_) => {
                    tracing::error!(
                        ecu_name = %ecu_name,
                        "ECU receiver unexpectedly closed while waiting for ACK/NACK"
                    );

                    return Err(DiagServiceError::NoResponse(
                        "ECU receiver unexpectedly closed".to_owned(),
                    ));
                }
            };

            match &response {
                DiagnosticResponse::Nack(nack) => {
                    tracing::warn!(
                        ecu_name = %ecu_name,
                        nack_code = ?nack.nack_code,
                        "Received NACK"
                    );
                    return Err(DiagServiceError::Nack(u8::from(nack.nack_code)));
                }
                DiagnosticResponse::GenericNack(nack) => {
                    tracing::warn!(
                        ecu_name = %ecu_name,
                        nack_code = ?nack.nack_code,
                        "Received generic NACK"
                    );
                    return Err(DiagServiceError::Nack(u8::from(nack.nack_code)));
                }
                _ => {}
            }

            if !response.matches_request(&sent_message.message) {
                if let DiagnosticResponse::Ack((_, previous)) = &response {
                    tracing::warn!(
                        ecu_name = %ecu_name,
                        previous = %util::tracing::print_hex(previous, 8),
                        sent = %util::tracing::print_hex(&sent_message.message, 8),
                        "ACK previous message does not match sent message"
                    );
                } else {
                    tracing::debug!(
                        ecu_name = %ecu_name,
                        ?response,
                        "Received response does not match sent message. Ignoring."
                    );
                    // Not the answer to this request, but still a reply of the ECU:
                    // the channel of the request's ECU only carries its frames.
                    if matches!(response, DiagnosticResponse::Msg { .. }) {
                        activity
                            .report_activity_for_ecu_name(&ecu_name.to_lowercase())
                            .await;
                    }
                }

                continue;
            }

            return match response {
                DiagnosticResponse::Ack((_, _)) => {
                    tracing::debug!(ecu_name = %ecu_name, "Received ACK");
                    Ok(None)
                }
                response => {
                    tracing::debug!(
                        ecu_name = %ecu_name,
                        "Received diagnostic response before ACK, treating as implicit ACK"
                    );
                    Ok(Some(response))
                }
            };
        }
    }

    if let Ok(result) = tokio::time::timeout(
        timeout,
        wait_for_ack_or_response(receiver, ecu_name, sent_message, activity),
    )
    .await
    {
        result
    } else {
        tracing::warn!(
            ecu_name = %ecu_name,
            timeout = ?timeout,
            "Timeout waiting for ACK/NACK from ECU"
        );
        Err(DiagServiceError::Timeout)
    }
}

/// Reads ECU responses from `receiver` and forwards them through
/// `response_sender` until either the sender is closed (caller no longer
/// interested) or the receiver is closed (connection dropped).
///
/// `received_message` carries an already-received response from the implicit-ACK path
/// (where the ECU skipped the ACK and sent the diagnostic reply directly).
/// Pass `None` after a normal explicit ACK.
async fn read_ecu_responses(
    receiver: &mut broadcast::Receiver<Result<DiagnosticResponse, EcuError>>,
    ecu_name: &str,
    response_sender: &mpsc::Sender<Result<Option<TransportResponse>, DiagServiceError>>,
    received_event: Option<DiagnosticResponse>,
) {
    if let Some(event) = received_event
        && !try_send_transport_response(response_sender, diagnostic_response_to_transport(event))
            .await
    {
        return;
    }
    loop {
        tokio::select! {
            // Using biased saves a bit of CPU time because tokio does not
            // have to generate a random number to select the branch.
            // Prioritizing the ECU receiver over the closed handler is fine
            // because it is unlikely that both fire at the exact same time.
            biased;
            res = receiver.recv() => {
                if let Ok(res) = res {
                    match res {
                        Ok(event) => {
                            if !try_send_transport_response(
                                response_sender,
                                diagnostic_response_to_transport(event),
                            )
                            .await
                            {
                                break;
                            }
                        }
                        Err(e) => {
                            tracing::error!(
                                ecu_name = %ecu_name,
                                error = %e,
                                "Error while waiting for response message"
                            );
                            if !try_send_transport_response(
                                response_sender,
                                Err(DiagServiceError::NoResponse(format!(
                                    "Error while waiting for message, {e}"
                                ))),
                            )
                            .await
                            {
                                break;
                            }
                        }
                    }
                } else {
                    tracing::error!(
                        ecu_name = %ecu_name,
                        "ECU receiver unexpectedly closed while waiting for response"
                    );
                    try_send_transport_response(
                        response_sender,
                        Err(DiagServiceError::NoResponse(
                            "ECU receiver unexpectedly closed".to_owned(),
                        )),
                    )
                    .await;
                    break;
                }
            }
            () = response_sender.closed() => {
                tracing::debug!(
                    ecu_name = %ecu_name,
                    "Response sender closed, aborting loop"
                );
                break;
            }
        }
    }
}

/// Converts a [`DiagnosticResponse::Msg`] to a [`TransportResponse`] result for the
/// caller channel.
///
/// Pending NRCs are classified via [`pending_nrc_from_raw`]; all other frames
/// are classified as final via [`uds_response_from_raw`].
///
/// `TesterPresentNRC` is absorbed by [`connection_receiver`] before it is
/// broadcast to any per-ECU channel -- it never reaches this function.
/// All other [`DiagnosticResponse`] variants (Ack, Nack, etc.) must be
/// handled before calling this function.
fn diagnostic_response_to_transport(
    event: DiagnosticResponse,
) -> Result<Option<TransportResponse>, DiagServiceError> {
    match event {
        DiagnosticResponse::Msg {
            data,
            source_address,
            target_address,
        } => {
            if let Some(pending) = pending_nrc_from_raw(&data, source_address) {
                Ok(Some(TransportResponse::Pending(pending)))
            } else {
                Ok(Some(TransportResponse::UdsResponse(uds_response_from_raw(
                    data,
                    source_address,
                    target_address,
                ))))
            }
        }
        _ => Err(DiagServiceError::BadPayload(
            "Unexpected DoIP event type in UDS response stream".to_owned(),
        )),
    }
}

#[allow(
    clippy::needless_continue,
    reason = "Explicit continue improves readability of complex loop logic"
)]
async fn wait_for_ecu_response(
    ecu: &mut DoipEcu,
    timeout: Duration,
) -> Option<Result<DiagnosticMessage, EcuError>> {
    tokio::time::timeout(timeout, async {
        loop {
            match ecu.receiver.recv().await {
                Ok(Ok(DiagnosticResponse::Msg {
                    source_address,
                    target_address,
                    data,
                })) => {
                    return Some(Ok(DiagnosticMessage {
                        source_address: source_address.to_be_bytes(),
                        target_address: target_address.to_be_bytes(),
                        message: data,
                    }));
                }
                Ok(Ok(_ignore)) => {
                    // Ignore other event types
                    continue;
                }
                Ok(Err(e)) => {
                    return Some(Err(e));
                }
                Err(_) => {
                    // Receiver closed
                    return None;
                }
            }
        }
    })
    .await
    .unwrap_or_default()
}

/// Waits for `connects` and returns the gateways that ended connected.
async fn connected_gateways(
    connects: Vec<(DiscoveredGateway, gateway_session::PendingConnect)>,
) -> cda_interfaces::HashSet<u16> {
    let mut connected = cda_interfaces::HashSet::default();
    for (gateway, connect) in connects {
        if connect.wait().await == ConnectOutcome::Connected {
            connected.insert(gateway.logical_address);
        }
    }
    connected
}

fn create_netmask(tester_ip: &str, tester_subnet: &str) -> Result<u32, DoipGatewaySetupError> {
    let ip = tester_ip.parse::<std::net::Ipv4Addr>().map_err(|e| {
        DoipGatewaySetupError::InvalidAddress(format!(
            "DoipGateway: Failed to parse tester IP address: {e:?}"
        ))
    })?;
    let subnet = tester_subnet.parse::<std::net::Ipv4Addr>().map_err(|e| {
        DoipGatewaySetupError::InvalidAddress(format!(
            "DoipGateway: Failed to parse tester subnet mask: {e:?}"
        ))
    })?;

    Ok(ip.to_bits() & subnet.to_bits())
}

/// Creates a UDP socket for `DoIP` communication.
///
/// # Errors
/// Returns errors when:
/// * The provided `tester_ip` and `gateway_port` cannot be parsed into a valid `SocketAddr`,
///   resulting in a `DoipGatewaySetupError::InvalidAddress`.
/// * The underlying system call to create a new socket fails,
///   resulting in a `DoipGatewaySetupError::SocketCreationFailed`.
/// * Setting the `SO_REUSEADDR` socket option fails,
///   resulting in a `DoipGatewaySetupError::InvalidAddress`.
/// * On Unix-like systems, setting the `SO_REUSEPORT` socket option fails,
///   resulting in a `DoipGatewaySetupError::PortBindFailed`.
/// * Setting the `SO_BROADCAST` socket option fails,
///   resulting in a `DoipGatewaySetupError::SocketCreationFailed`.
/// * Binding the socket to the specified `tester_ip` and `gateway_port` fails,
///   resulting in a `DoipGatewaySetupError::SocketCreationFailed`.
/// * The `DoIPUdpSocket` constructor fails to create the DoIP-specific socket from the standard UDP socket,
///   resulting in a `DoipGatewaySetupError::SocketCreationFailed`.
pub fn create_udp_vir_socket(
    tester_ip: &str,
    gateway_port: u16,
) -> Result<DoIPUdpSocket, DoipGatewaySetupError> {
    let tester_ip = match tester_ip {
        "127.0.0.1" => "0.0.0.0",
        _ => tester_ip,
    };
    let broadcast_addr: std::net::SocketAddr =
        format!("{tester_ip}:{gateway_port}").parse().map_err(|e| {
            DoipGatewaySetupError::InvalidAddress(format!(
                "DoipGateway: Failed to create broadcast addr: {e:?}"
            ))
        })?;

    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .map_err(|e| {
        DoipGatewaySetupError::SocketCreationFailed(format!(
            "DoipGateway: Failed to create socket: {e:?}"
        ))
    })?;

    socket.set_reuse_address(true).map_err(|e| {
        DoipGatewaySetupError::InvalidAddress(format!(
            "DoipGateway: Failed to set reuse address: {e:?}"
        ))
    })?;
    #[cfg(target_family = "unix")]
    socket.set_reuse_port(true).map_err(|e| {
        DoipGatewaySetupError::PortBindFailed(format!(
            "DoipGateway: Failed to set reuse port: {e:?}"
        ))
    })?;
    socket.set_broadcast(true).map_err(|e| {
        DoipGatewaySetupError::SocketCreationFailed(format!(
            "DoipGateway: Failed to set broadcast flag on socket: {e:?}"
        ))
    })?;
    socket.set_nonblocking(true).map_err(|e| {
        DoipGatewaySetupError::InvalidConfiguration(format!(
            "DoipGateway: Failed to set non-blocking mode: {e:?}"
        ))
    })?;

    socket.bind(&broadcast_addr.into()).map_err(|e| {
        DoipGatewaySetupError::SocketCreationFailed(format!(
            "DoipGateway: Failed to bind socket, ip {tester_ip}, port {gateway_port}: {e:?}"
        ))
    })?;

    let std_sock: std::net::UdpSocket = socket.into();
    DoIPUdpSocket::new(std_sock, ProtocolVersion::DefaultValue).map_err(|e| {
        DoipGatewaySetupError::SocketCreationFailed(format!(
            "DoipGateway: Failed to create DoIP socket from std socket: {e:?}"
        ))
    })
}

impl<T: EcuAddresses + DoipComParams> Clone for DoipDiagGateway<T> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            config: self.config.clone(),
            variant_detection: self.variant_detection.clone(),
            connectivity_handler: Arc::clone(&self.connectivity_handler),
            lifecycle: Arc::clone(&self.lifecycle),
        }
    }
}

#[async_trait]
impl<T: EcuAddresses + DoipComParams> cda_interfaces::Shutdown for DoipDiagGateway<T> {
    async fn shutdown(&self) {
        if let Err(error) = self.disable().await {
            tracing::error!(%error, "Failed to disable DoIP communication during shutdown");
        }
    }
}

#[async_trait]
impl<T: EcuAddresses + DoipComParams> TransportControl for DoipDiagGateway<T> {
    async fn enable(&self) -> Result<(), CommControlError> {
        let mut operation = self.lifecycle.operation.lock().await;
        if self.lifecycle.coordinator.active().await {
            return Ok(());
        }
        // Clean up any residual resources, usually should be a no-op
        self.stop(&mut operation).await;
        self.lifecycle
            .coordinator
            .transition(TransportState::Enabling)
            .await;
        match self.start(&mut operation).await {
            Ok(()) => {
                self.lifecycle
                    .coordinator
                    .transition(TransportState::Enabled)
                    .await;
                Ok(())
            }
            Err(error) => {
                self.stop(&mut operation).await;
                self.lifecycle
                    .coordinator
                    .transition(TransportState::Failed)
                    .await;
                Err(CommControlError::InitFailed(error.to_string()))
            }
        }
    }

    async fn disable(&self) -> Result<(), CommControlError> {
        let mut operation = self.lifecycle.operation.lock().await;
        self.lifecycle
            .coordinator
            .transition(TransportState::Disabling)
            .await;
        self.stop(&mut operation).await;
        self.lifecycle
            .coordinator
            .transition(TransportState::Disabled)
            .await;
        Ok(())
    }

    async fn state(&self) -> TransportState {
        self.lifecycle.coordinator.state().await
    }

    async fn connect_ecu_direct(
        &self,
        ecu_name: &str,
        endpoint: DoipEndpoint,
    ) -> Result<(), DiagServiceError> {
        self.connect_direct(ecu_name, endpoint.address, endpoint.protocol_version)
            .await
    }
}

async fn send_with_retries(
    msg: &DiagnosticMessage,
    sender: &mpsc::Sender<DoipPayload>,
    resend_counter: &mut u32,
    max_retries: u32,
) -> Result<(), DiagServiceError> {
    while let Err(e) = sender
        .send(DoipPayload::DiagnosticMessage(msg.clone()))
        .await
    {
        *resend_counter = resend_counter.saturating_add(1);
        if *resend_counter > max_retries {
            return Err(DiagServiceError::SendFailed(format!(
                "Failed to send message after {max_retries} attempts: {e:?}",
            )));
        }
    }
    Ok(())
}

#[tracing::instrument(skip_all,
    fields(dlt_context = dlt_ctx!("DOIP"))
)]
async fn try_send_transport_response(
    response_sender: &mpsc::Sender<Result<Option<TransportResponse>, DiagServiceError>>,
    response: Result<Option<TransportResponse>, DiagServiceError>,
) -> bool {
    if let Err(err) = response_sender.send(response).await {
        tracing::error!(error = %err, "Failed to send response");
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use std::{net::UdpSocket, sync::Arc, time::Duration};

    use cda_interfaces::{
        DiagServiceError, HashMap, HashMapExtensions, PendingNrc, PhysicalTransport,
        ServicePayload, TransmissionParameters, TransportResponse, UDS_ID_RESPONSE_BITMASK,
        VariantDetectionSender,
        communication_control::{DoipEndpoint, GatewayLifecycle, TransportControl, TransportState},
        nrc, service_ids,
    };
    use doip_definitions::{
        header::ProtocolVersion,
        payload::{DiagnosticMessage, DoipPayload},
    };
    use tokio::sync::{Mutex, RwLock, broadcast, mpsc};
    use tokio_util::sync::CancellationToken;

    use crate::{
        ConnectionTasks, DiagnosticResponse, DoIPUdpSocket, DoipConfig, DoipConnection,
        DoipDiagGateway, DoipEcu, DoipGatewayState,
        config::DiscoveryMode,
        gateway_session::{ConnectOutcome, GatewaySession, PendingConnect},
        read_ecu_responses, spawn_connection_task,
        test_helpers::{
            FakeGateway, OrderRecorder, RecordingConnectivityHandler, TestEcu, activity_reporter,
            connect_control, discovered, discovered_at, gateway_with_gateways, no_activity,
            session_for, session_with, session_with_discovery, wait_until,
        },
        wait_for_ack_or_response_until_timeout,
    };

    const ECU_ADDR: u16 = 0x0E80;
    const GATEWAY_ADDR: u16 = 0x1234;
    const TESTER_ADDR: u16 = 0x0E00;
    const PAYLOAD: [u8; 2] = [0xF1, 0x90];
    const REQUEST_DATA: [u8; 3] = [service_ids::READ_DATA_BY_IDENTIFIER, PAYLOAD[0], PAYLOAD[1]];
    const RESPONSE_DATA: [u8; 4] = [
        service_ids::READ_DATA_BY_IDENTIFIER | UDS_ID_RESPONSE_BITMASK,
        PAYLOAD[0],
        PAYLOAD[1],
        0x01,
    ];

    /// Builds a minimal `DoipDiagGateway` whose single ECU is backed by the
    /// caller-supplied broadcast receiver and mpsc sender.
    ///
    /// The mpsc `_doip_payload_rx` must be kept alive by the caller for the
    /// duration of the test; `send_with_retries` writes into it and will error
    /// if the receiver is dropped before it gets a chance to send.
    fn make_gateway(
        broadcast_rx: broadcast::Receiver<Result<DiagnosticResponse, crate::connections::EcuError>>,
        doip_payload_tx: mpsc::Sender<DoipPayload>,
    ) -> DoipDiagGateway<TestEcu> {
        let ecu = Arc::new(Mutex::new(DoipEcu {
            sender: doip_payload_tx,
            receiver: broadcast_rx,
        }));

        let mut ecus = HashMap::new();
        ecus.insert(ECU_ADDR, ecu);
        let conn = Arc::new(DoipConnection {
            ecus,
            ip: "127.0.0.1".to_owned(),
            activity: no_activity(),
        });

        // DoIPUdpSocket is never touched during send()
        let std_sock = UdpSocket::bind("127.0.0.1:0").expect("bind test socket");
        std_sock
            .set_nonblocking(true)
            .expect("set nonblocking for test socket");
        let udp_socket = DoIPUdpSocket::new(std_sock, ProtocolVersion::Iso13400_2012)
            .expect("create test DoIPUdpSocket");

        let mut addr_map: HashMap<u16, usize> = HashMap::new();
        addr_map.insert(GATEWAY_ADDR, 0);

        let state = DoipGatewayState {
            doip_connections: Arc::new(RwLock::new(vec![conn])),
            logical_address_to_connection: Arc::new(RwLock::new(addr_map)),
            ecus: Arc::new(HashMap::new()),
            socket: Arc::new(Mutex::new(Some(udp_socket))),
            netmask: 0,
            topology: cda_interfaces::topology::TopologyRuntime::new(
                cda_interfaces::topology::DiscoveryStrategy::Vir,
            ),
            session: Arc::new(RwLock::new(None)),
        };

        DoipDiagGateway {
            state,
            config: DoipConfig::default(),
            variant_detection: VariantDetectionSender::new(mpsc::channel(1).0),
            connectivity_handler: Arc::new(RecordingConnectivityHandler::default()),
            lifecycle: Arc::new(GatewayLifecycle::new(TransportState::Enabled)),
        }
    }

    #[tokio::test]
    async fn registering_connection_task_does_not_wait_for_connection() {
        let tasks = Arc::new(ConnectionTasks::new());

        spawn_connection_task(&tasks, "pending-connection", std::future::pending());

        assert_eq!(tasks.lock().as_ref().map(Vec::len), Some(1));
        tasks.shutdown().await;
    }

    /// A task pushed after shutdown (e.g. a VAM or fallback connect racing with
    /// the transport stop) must not outlive it.
    #[tokio::test]
    async fn connection_task_pushed_after_shutdown_is_aborted() {
        let tasks = Arc::new(ConnectionTasks::new());
        tasks.shutdown().await;
        let task = tokio::spawn(std::future::pending::<()>());
        let abort = task.abort_handle();
        tasks.push(task);
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(10)).await;
        assert!(abort.is_finished());
    }

    /// A start that fails before any gateway is connected must not leave the
    /// discovery running, or waiters would hang until their timeout.
    /// [[ test~doip-aborted-discovery-finishes, The discovery is finished when the task that owns it is aborted, test ]]
    #[tokio::test]
    async fn aborted_discovery_task_finishes_the_discovery() {
        let topology = cda_interfaces::topology::TopologyRuntime::new(
            cda_interfaces::topology::DiscoveryStrategy::Vir,
        );
        let discovery = super::DiscoveryGuard::begin(&topology);
        let tasks = Arc::new(ConnectionTasks::new());
        spawn_connection_task(&tasks, "pending-discovery", async move {
            let _discovery = discovery;
            std::future::pending::<()>().await;
        });
        tasks.shutdown().await;

        assert!(
            topology
                .wait_settled(Duration::from_millis(100))
                .await
                .is_some(),
            "the aborted task's guard settled the discovery"
        );
    }

    /// Constructing a gateway must never create or bind a UDP socket,
    /// even though construction succeeds.
    /// The socket is created lazily inside `start()`, reached only through an
    /// authorized [`DoipDiagGateway::enable`]
    /// [[ test~deferred-doip-passive-construction, Gateway construction does not bind its discovery socket, test ]]
    #[tokio::test]
    async fn new_never_binds_the_doip_socket() {
        let gateway = DoipDiagGateway::<TestEcu>::new(
            &DoipConfig::default(),
            Arc::new(HashMap::new()),
            VariantDetectionSender::new(mpsc::channel(1).0),
            Arc::new(RecordingConnectivityHandler::default()),
        )
        .await
        .unwrap();

        assert!(
            gateway.state.socket.lock().await.is_none(),
            "DoipDiagGateway::new must not bind a socket"
        );
        assert_eq!(
            cda_interfaces::communication_control::TransportControl::state(&gateway).await,
            TransportState::Disabled
        );
    }

    const DIRECT_ECU_ADDR: u16 = 0x1234;

    /// Gateway with the gateway ECU `ecu_a`, configured by `config`.
    async fn direct_gateway(config: &DoipConfig) -> DoipDiagGateway<TestEcu> {
        let mut ecus = HashMap::new();
        ecus.insert(
            "ecu_a".to_owned(),
            RwLock::new(TestEcu::new(DIRECT_ECU_ADDR, DIRECT_ECU_ADDR)),
        );
        DoipDiagGateway::<TestEcu>::new(
            config,
            Arc::new(ecus),
            VariantDetectionSender::new(mpsc::channel(1).0),
            Arc::new(RecordingConnectivityHandler::default()),
        )
        .await
        .unwrap()
    }

    /// Gateway with one known ECU `ecu_a` that is already connected on `10.0.0.5`.
    async fn make_connected_direct_gateway(enabled: bool) -> DoipDiagGateway<TestEcu> {
        let gateway = direct_gateway(&DoipConfig::default()).await;

        let (doip_tx, _doip_rx) = mpsc::channel(1);
        let (_tx, rx) = broadcast::channel(1);
        let mut conn_ecus = HashMap::new();
        conn_ecus.insert(
            DIRECT_ECU_ADDR,
            Arc::new(Mutex::new(DoipEcu {
                sender: doip_tx,
                receiver: rx,
            })),
        );
        gateway
            .state
            .doip_connections
            .write()
            .await
            .push(Arc::new(DoipConnection {
                ecus: conn_ecus,
                ip: "10.0.0.5".to_owned(),
                activity: no_activity(),
            }));
        gateway
            .state
            .logical_address_to_connection
            .write()
            .await
            .insert(DIRECT_ECU_ADDR, 0);
        if enabled {
            mark_enabled(&gateway).await;
        }
        gateway
    }

    /// Makes the lifecycle look like it is enabled, with a session of its own,
    /// returns the token that disabling communication would cancel.
    async fn mark_enabled(gateway: &DoipDiagGateway<TestEcu>) -> CancellationToken {
        let cancel = CancellationToken::new();
        let connection_tasks = Arc::new(ConnectionTasks::new());
        let mut operation = gateway.lifecycle.operation.lock().await;
        operation.cancel = Some(cancel.clone());
        operation.connection_tasks = Some(Arc::clone(&connection_tasks));
        *gateway.state.session.write().await = Some(Arc::new(GatewaySession::new(
            gateway.transport_config(),
            connection_tasks,
            cancel.clone(),
            gateway.variant_detection.clone(),
            Arc::clone(&gateway.connectivity_handler),
            gateway.config.discovery,
        )));
        cancel
    }

    /// Whether a connect of the direct ECU is in flight in the current session.
    async fn is_connecting(gateway: &DoipDiagGateway<TestEcu>) -> bool {
        gateway
            .state
            .session
            .read()
            .await
            .as_ref()
            .is_some_and(|session| session.is_connecting(DIRECT_ECU_ADDR))
    }

    /// Enabled gateway with the gateway ECU `ecu_a` that is not connected yet.
    /// Connecting it goes to `port` on localhost.
    async fn make_unconnected_direct_gateway(port: u16) -> DoipDiagGateway<TestEcu> {
        let gateway = direct_gateway(&DoipConfig {
            gateway_port: port,
            ..DoipConfig::default()
        })
        .await;
        mark_enabled(&gateway).await;
        gateway
    }

    fn direct_endpoint() -> DoipEndpoint {
        DoipEndpoint {
            address: "127.0.0.1".parse().unwrap(),
            protocol_version: 0x02,
        }
    }

    #[tokio::test]
    async fn direct_connect_rejects_already_connected_ecu() {
        let gateway = make_connected_direct_gateway(true).await;

        let result = gateway
            .connect_ecu_direct(
                "ecu_a",
                DoipEndpoint {
                    address: "10.0.0.9".parse().unwrap(),
                    protocol_version: 0x02,
                },
            )
            .await;

        assert_eq!(
            result,
            Err(DiagServiceError::Conflict(
                "ECU 'ecu_a' is already connected on 10.0.0.5".to_owned()
            ))
        );
    }

    #[tokio::test]
    async fn direct_connect_rejects_unknown_ecu() {
        let gateway = make_connected_direct_gateway(true).await;

        let result = gateway
            .connect_ecu_direct(
                "missing",
                DoipEndpoint {
                    address: "10.0.0.9".parse().unwrap(),
                    protocol_version: 0x02,
                },
            )
            .await;

        assert!(matches!(result, Err(DiagServiceError::NotFound(_))));
    }

    #[tokio::test]
    async fn direct_connect_requires_enabled_communication() {
        let gateway = make_connected_direct_gateway(false).await;

        let result = gateway
            .connect_ecu_direct(
                "ecu_a",
                DoipEndpoint {
                    address: "10.0.0.9".parse().unwrap(),
                    protocol_version: 0x02,
                },
            )
            .await;

        assert!(matches!(
            result,
            Err(DiagServiceError::CommunicationDisabled(_))
        ));
    }

    #[tokio::test]
    async fn direct_connect_rejects_unknown_protocol_version() {
        let gateway = make_connected_direct_gateway(true).await;

        let result = gateway
            .connect_ecu_direct(
                "ecu_a",
                DoipEndpoint {
                    address: "10.0.0.9".parse().unwrap(),
                    protocol_version: 0x42,
                },
            )
            .await;

        assert!(matches!(result, Err(DiagServiceError::InvalidRequest(_))));
    }

    #[tokio::test]
    async fn direct_connect_rejects_non_gateway_ecu() {
        let mut ecus = HashMap::new();
        ecus.insert(
            "ecu_a".to_owned(),
            RwLock::new(TestEcu::new(DIRECT_ECU_ADDR, DIRECT_ECU_ADDR)),
        );
        ecus.insert(
            "ecu_b".to_owned(),
            RwLock::new(TestEcu::new(0x5678, DIRECT_ECU_ADDR)),
        );
        let gateway = DoipDiagGateway::<TestEcu>::new(
            &DoipConfig::default(),
            Arc::new(ecus),
            VariantDetectionSender::new(mpsc::channel(1).0),
            Arc::new(RecordingConnectivityHandler::default()),
        )
        .await
        .unwrap();
        mark_enabled(&gateway).await;

        let result = gateway
            .connect_ecu_direct(
                "ecu_b",
                DoipEndpoint {
                    address: "10.0.0.9".parse().unwrap(),
                    protocol_version: 0x02,
                },
            )
            .await;

        assert_eq!(
            result,
            Err(DiagServiceError::InvalidRequest(
                "ECU 'ecu_b' is not a gateway, only gateway ECUs can be connected directly"
                    .to_owned()
            ))
        );
        assert!(gateway.state.doip_connections.read().await.is_empty());
    }

    async fn enabled_gateway_with_discovery(
        discovery: DiscoveryMode,
    ) -> (DoipDiagGateway<TestEcu>, Duration) {
        let gateway = DoipDiagGateway::<TestEcu>::new(
            &DoipConfig {
                discovery,
                gateway_port: 0,
                ..DoipConfig::default()
            },
            Arc::new(HashMap::new()),
            VariantDetectionSender::new(mpsc::channel(1).0),
            Arc::new(RecordingConnectivityHandler::default()),
        )
        .await
        .unwrap();

        let start = std::time::Instant::now();
        cda_interfaces::communication_control::TransportControl::enable(&gateway)
            .await
            .unwrap();
        let elapsed = start.elapsed();
        assert_eq!(
            cda_interfaces::communication_control::TransportControl::state(&gateway).await,
            TransportState::Enabled
        );
        (gateway, elapsed)
    }

    #[tokio::test]
    async fn connection_ip_is_the_address_the_gateway_was_connected_on() {
        let gateway = make_connected_direct_gateway(true).await;

        assert_eq!(
            gateway
                .state
                .connection_ip(DIRECT_ECU_ADDR)
                .await
                .as_deref(),
            Some("10.0.0.5")
        );
        assert_eq!(gateway.state.connection_ip(0x4321).await, None);
    }

    #[tokio::test]
    async fn direct_connect_is_rejected_while_the_ecu_is_being_connected() {
        let (_listener, port) = silent_gateway();
        let gateway = make_unconnected_direct_gateway(port).await;
        let first = tokio::spawn({
            let gateway = gateway.clone();
            async move { gateway.connect_ecu_direct("ecu_a", direct_endpoint()).await }
        });
        wait_until(async || is_connecting(&gateway).await).await;

        let result = gateway.connect_ecu_direct("ecu_a", direct_endpoint()).await;

        assert_eq!(
            result,
            Err(DiagServiceError::Conflict(
                "ECU 'ecu_a' is currently being connected".to_owned()
            ))
        );
        cda_interfaces::communication_control::TransportControl::disable(&gateway)
            .await
            .unwrap();
        assert!(matches!(
            first.await.unwrap(),
            Err(DiagServiceError::CommunicationDisabled(_))
        ));
    }

    /// A gateway that accepts the connection but never answers the routing activation.
    fn silent_gateway() -> (std::net::TcpListener, u16) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        (listener, port)
    }

    #[tokio::test]
    async fn disabling_communication_cancels_a_running_connect() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let gateway = make_unconnected_direct_gateway(port).await;
        let cancel = gateway
            .lifecycle
            .operation
            .lock()
            .await
            .cancel
            .clone()
            .unwrap();

        let connecting = tokio::spawn({
            let gateway = gateway.clone();
            async move { gateway.connect_ecu_direct("ecu_a", direct_endpoint()).await }
        });
        wait_until(async || is_connecting(&gateway).await).await;
        let (_socket, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .expect("the connect should reach the gateway")
            .unwrap();
        cancel.cancel();

        let result = tokio::time::timeout(Duration::from_secs(2), connecting)
            .await
            .expect("cancelling must not wait for the connect timeouts")
            .unwrap();
        assert!(matches!(
            result,
            Err(DiagServiceError::CommunicationDisabled(_))
        ));
        assert!(
            gateway
                .state
                .logical_address_to_connection
                .read()
                .await
                .is_empty()
        );
        assert!(
            !is_connecting(&gateway).await,
            "the registration must be released"
        );
        let connection_tasks = gateway
            .lifecycle
            .operation
            .lock()
            .await
            .connection_tasks
            .clone()
            .unwrap();
        wait_until(async || {
            connection_tasks
                .lock()
                .as_ref()
                .is_some_and(|tasks| tasks.iter().all(tokio::task::JoinHandle::is_finished))
        })
        .await;
    }

    #[tokio::test]
    async fn disable_does_not_wait_for_a_running_connect() {
        let (_listener, port) = silent_gateway();
        let gateway = make_unconnected_direct_gateway(port).await;

        let connecting = tokio::spawn({
            let gateway = gateway.clone();
            async move { gateway.connect_ecu_direct("ecu_a", direct_endpoint()).await }
        });
        wait_until(async || is_connecting(&gateway).await).await;

        // The routing activation timeout of the test ECU is 5 s.
        tokio::time::timeout(
            Duration::from_secs(2),
            cda_interfaces::communication_control::TransportControl::disable(&gateway),
        )
        .await
        .expect("disable must not wait for the connect")
        .unwrap();

        let result = connecting.await.unwrap();
        assert!(matches!(
            result,
            Err(DiagServiceError::CommunicationDisabled(_))
        ));
        assert!(
            gateway
                .state
                .logical_address_to_connection
                .read()
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn giving_up_on_the_request_does_not_abort_the_connect() {
        let (_listener, port) = silent_gateway();
        let gateway = make_unconnected_direct_gateway(port).await;
        let cancel = gateway
            .lifecycle
            .operation
            .lock()
            .await
            .cancel
            .clone()
            .unwrap();

        // The caller goes away, like a client that disconnects or an HTTP timeout.
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            gateway.connect_ecu_direct("ecu_a", direct_endpoint()),
        )
        .await;
        assert!(result.is_err(), "the connect is still waiting for the ECU");

        assert!(
            is_connecting(&gateway).await,
            "the connect keeps running and keeps the gateway registered"
        );
        let second = gateway.connect_ecu_direct("ecu_a", direct_endpoint()).await;
        assert!(matches!(second, Err(DiagServiceError::Conflict(_))));

        cancel.cancel();
        wait_until(async || !is_connecting(&gateway).await).await;
    }

    /// Without VIR, a reconnect reports the gateways that failed their direct
    /// connect and the persisted gateways without a usable address, and does
    /// not search (nor report) the gateways not attempted or not persisted.
    /// [[ test~doip-vam-only-reconnect-without-search, Without VIR a reconnect searches no gateway and reports only failed connects, test ]]
    /// [[ test~doip-vam-only-reconnect-reports-unusable, Without VIR a persisted gateway without a usable address is reported unreachable, test ]]
    #[tokio::test]
    async fn vam_only_reconnect_reports_failed_and_unusable_gateways_without_search() {
        let fake = FakeGateway::start().await;
        let gateway =
            gateway_with_gateways(&[("gw1", 0x1000), ("gw2", 0x2000), ("gw3", 0x3000)]).await;
        let session = session_with_discovery(&fake, DiscoveryMode::VamOnly);
        let discovery = crate::DiscoveryGuard::begin(&gateway.state.topology);

        // gw1's direct connect failed, 0x2000 is persisted without a usable
        // address, 0x3000 not persisted.
        DoipDiagGateway::finish_reconnect(
            &gateway.state,
            &session,
            discovery,
            vec![(
                discovered("gw1", 0x1000),
                PendingConnect::done(ConnectOutcome::Failed),
            )],
            [0x2000, 0x3000].into_iter().collect(),
            std::iter::once(0x2000).collect(),
        )
        .await;

        let mut unreachable = gateway.state.topology.unreachable();
        unreachable.sort_unstable();
        assert_eq!(unreachable, [0x1000, 0x2000]);
        let outcome = gateway
            .state
            .topology
            .wait_settled(Duration::from_secs(1))
            .await
            .expect("the discovery must be finished");
        assert!(!outcome.full_vir_discovery);
    }

    /// Without VIR, a persisted gateway without a usable address that an
    /// announcement connected while the reconnect was running is not reported
    /// unreachable, neither if it is connected already nor if its connect is
    /// still in flight.
    #[tokio::test]
    async fn vam_only_reconnect_does_not_report_gateways_connected_by_an_announcement() {
        let fake = FakeGateway::start().await;
        let gateway =
            gateway_with_gateways(&[("gw1", 0x1000), ("gw2", 0x2000), ("gw3", 0x3000)]).await;
        let recorder = OrderRecorder::new(&gateway.state.topology);
        let session = session_with(&fake, Arc::clone(&recorder) as _, DiscoveryMode::VamOnly);
        *gateway.state.session.write().await = Some(Arc::clone(&session));
        let (_, names) = crate::gateway_session::gateway_ecu_maps(&gateway.state.ecus).await;
        let announce = |name: &'static str, logical_address: u16| {
            crate::vir_vam::handle_announcement(
                &gateway.state,
                &session,
                discovered(name, logical_address),
                &names,
                &gateway.variant_detection,
            )
        };
        // gw2 is connected by its announcement, gw3's connect is in flight.
        announce("gw2", 0x2000).await;
        wait_until(async || gateway.state.has_connection(0x2000).await).await;
        fake.block_connects();
        announce("gw3", 0x3000).await;
        wait_until(async || fake.connects() == 2).await;
        let discovery = crate::DiscoveryGuard::begin(&gateway.state.topology);

        // gw1's unicast failed, gw2 and gw3 are persisted without a usable address.
        let reconnect = DoipDiagGateway::finish_reconnect(
            &gateway.state,
            &session,
            discovery,
            vec![(
                discovered("gw1", 0x1000),
                PendingConnect::done(ConnectOutcome::Failed),
            )],
            cda_interfaces::HashSet::default(),
            [0x2000, 0x3000].into_iter().collect(),
        );
        // Released only once the reconnect waits for gw3's connect.
        tokio::join!(reconnect, async {
            cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(50)).await;
            fake.release_connects();
        });

        assert_eq!(gateway.state.topology.unreachable(), [0x1000]);
        assert_eq!(
            recorder.unreachable_at_disconnect.lock().unwrap().len(),
            1,
            "only gw1's ECUs are reported disconnected"
        );
        assert_eq!(
            gateway
                .state
                .logical_address_to_connection
                .read()
                .await
                .len(),
            2
        );
        session.connection_tasks.shutdown().await;
    }

    /// The startup VIR result is recorded at its announced address when it ends
    /// connected, also if a direct connect in flight connected the gateway.
    #[tokio::test]
    async fn startup_vir_address_is_recorded_after_a_direct_connect() {
        let fake = FakeGateway::start().await;
        fake.block_connects();
        let gateway = gateway_with_gateways(&[("gw", 0x1000)]).await;
        let session = session_for(&fake);
        let direct = gateway
            .state
            .start_direct_connect(
                &session,
                discovered("gw", 0x1000),
                connect_control(&session),
            )
            .await
            .expect("the direct connect must start");
        wait_until(async || fake.connects() == 1).await;
        let vir_result = discovered_at("gw", 0x1000, "0.0.0.0");
        let connect = gateway.state.start_connect(&session, vir_result.clone());
        let discovery = crate::DiscoveryGuard::begin(&gateway.state.topology);

        fake.release_connects();
        assert!(direct.await.unwrap().is_ok());
        DoipDiagGateway::finish_initial_discovery(
            &gateway.state,
            &session,
            discovery,
            vec![(vir_result, connect)],
        )
        .await;

        assert_eq!(
            fake.connects(),
            1,
            "the direct connect connected the gateway"
        );
        let connected = gateway.state.topology.connected();
        assert_eq!(connected.len(), 1);
        assert_eq!(
            connected.first().and_then(|g| g.network_address.as_deref()),
            Some("0.0.0.0")
        );
        session.connection_tasks.shutdown().await;
    }

    /// A start that was stopped meanwhile is not recorded as a complete
    /// discovery, and does not record gateways.
    #[tokio::test]
    async fn cancelled_initial_discovery_is_not_complete() {
        let fake = FakeGateway::start().await;
        let gateway = gateway_with_gateways(&[("gw", 0x1000)]).await;
        let session = session_for(&fake);
        let vir_result = discovered("gw", 0x1000);
        let connect = gateway.state.start_connect(&session, vir_result.clone());
        let discovery = crate::DiscoveryGuard::begin(&gateway.state.topology);
        session.cancel_token.cancel();

        DoipDiagGateway::finish_initial_discovery(
            &gateway.state,
            &session,
            discovery,
            vec![(vir_result, connect)],
        )
        .await;

        let outcome = gateway
            .state
            .topology
            .wait_settled(Duration::from_secs(1))
            .await
            .expect("the discovery must be finished");
        assert!(!outcome.full_vir_discovery);
        assert!(gateway.state.topology.connected().is_empty());
        session.connection_tasks.shutdown().await;
    }

    /// Records the ECU names of every disconnect report.
    #[derive(Default)]
    struct DisconnectRecorder(std::sync::Mutex<Vec<Vec<String>>>);

    #[async_trait::async_trait]
    impl cda_interfaces::EcuConnectivityHandler for DisconnectRecorder {
        async fn on_gateway_connected(&self, _ecu_names: &[String]) {}

        async fn on_gateway_disconnected(&self, ecu_names: &[String]) {
            self.0.lock().unwrap().push(ecu_names.to_vec());
        }

        async fn on_ecu_replied(&self, _ecu_name: &str) {}
    }

    /// A stop reverts the connected report of a connect it aborted, and leaves
    /// the ECUs of a connect that had not reported anything untouched.
    /// [[ test~doip-stop-reverts-aborted-connects, A stop reports the ECUs of a connect it aborted after their connected report disconnected again, test ]]
    #[tokio::test]
    async fn stop_reverts_only_connects_that_reported_connected() {
        let mut ecus = HashMap::new();
        ecus.insert(
            "reported".to_owned(),
            RwLock::new(TestEcu::new(0x1000, 0x1000)),
        );
        ecus.insert(
            "pending".to_owned(),
            RwLock::new(TestEcu::new(0x2000, 0x2000)),
        );
        let handler = Arc::new(DisconnectRecorder::default());
        let gateway = DoipDiagGateway::<TestEcu>::new(
            &DoipConfig::default(),
            Arc::new(ecus),
            VariantDetectionSender::new(mpsc::channel(16).0),
            Arc::clone(&handler) as _,
        )
        .await
        .unwrap();
        mark_enabled(&gateway).await;
        {
            let session = gateway.state.session.read().await;
            let session = session.as_ref().expect("the session of the start");
            // The connect of 0x1000 reported its ECUs connected, the one of
            // 0x2000 is still connecting.
            session.online_reports.lock().unwrap().insert(0x1000);
            assert!(!session.online_reports.lock().unwrap().contains(&0x2000));
        }

        let mut operation = gateway.lifecycle.operation.lock().await;
        gateway.stop(&mut operation).await;

        // The names come from the test ECU fixture; only one gateway is reverted.
        assert_eq!(*handler.0.lock().unwrap(), [vec!["test".to_owned()]]);
    }

    /// With discovery disabled a reconnect plan connects nothing, and the
    /// discovery is still finished. The session accepts a direct connect,
    /// which is not recorded in the topology.
    /// [[ test~doip-direct-connect-not-recorded, A direct connect is not recorded in the topology, test ]]
    #[tokio::test]
    async fn disabled_start_connects_nothing_but_accepts_a_direct_connect() {
        let fake = FakeGateway::start().await;
        let topology = cda_interfaces::topology::TopologyRuntime::new(
            cda_interfaces::topology::DiscoveryStrategy::Persisted {
                known: vec![cda_interfaces::topology::KnownGateway {
                    name: "ecu_a".to_owned(),
                    logical_address: DIRECT_ECU_ADDR,
                    network_address: Some("127.0.0.1".to_owned()),
                    doip_protocol_version: Some(0x02),
                }],
                search: Vec::new(),
            },
        );
        let gateway = direct_gateway(&DoipConfig {
            discovery: DiscoveryMode::Disabled,
            gateway_port: fake.port(),
            ..DoipConfig::default()
        })
        .await
        .with_topology_runtime(topology);
        TransportControl::enable(&gateway).await.unwrap();

        let outcome = gateway
            .state
            .topology
            .wait_settled(Duration::from_secs(1))
            .await
            .expect("the discovery must be finished");
        assert!(!outcome.full_vir_discovery);
        assert_eq!(fake.connects(), 0);

        let result = gateway.connect_ecu_direct("ecu_a", direct_endpoint()).await;

        assert_eq!(result, Ok(()));
        assert_eq!(
            gateway
                .state
                .connection_ip(DIRECT_ECU_ADDR)
                .await
                .as_deref(),
            Some("127.0.0.1")
        );
        assert!(
            gateway.state.topology.connected().is_empty(),
            "a direct connect must not be persisted"
        );
        TransportControl::disable(&gateway).await.unwrap();
    }

    #[tokio::test]
    async fn enable_fails_clearly_if_the_tester_address_is_not_assigned() {
        let gateway = DoipDiagGateway::<TestEcu>::new(
            &DoipConfig {
                // TEST-NET-1 (RFC 5737) is never assigned to a host interface.
                tester_address: "192.0.2.1".to_owned(),
                discovery: DiscoveryMode::Disabled,
                ..DoipConfig::default()
            },
            Arc::new(HashMap::new()),
            VariantDetectionSender::new(mpsc::channel(1).0),
            Arc::new(RecordingConnectivityHandler::default()),
        )
        .await
        .expect("construction must not check the network");

        let error = cda_interfaces::communication_control::TransportControl::enable(&gateway)
            .await
            .expect_err("enable must fail");

        assert!(
            matches!(&error, cda_interfaces::communication_control::CommControlError::InitFailed(message) if message.contains("tester_address")),
            "{error:?}"
        );
        assert_eq!(
            cda_interfaces::communication_control::TransportControl::state(&gateway).await,
            TransportState::Failed
        );
    }

    #[tokio::test]
    async fn disabled_discovery_starts_without_binding_a_socket() {
        let (gateway, _) = enabled_gateway_with_discovery(DiscoveryMode::Disabled).await;

        assert!(gateway.state.socket.lock().await.is_none());
        assert!(
            gateway
                .lifecycle
                .operation
                .lock()
                .await
                .vam_listener
                .is_none()
        );
        cda_interfaces::communication_control::TransportControl::disable(&gateway)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn vam_only_discovery_listens_without_waiting_for_a_vir_round() {
        let (gateway, elapsed) = enabled_gateway_with_discovery(DiscoveryMode::VamOnly).await;

        assert!(gateway.state.socket.lock().await.is_some());
        assert!(
            gateway
                .lifecycle
                .operation
                .lock()
                .await
                .vam_listener
                .is_some()
        );
        // The VIR round waits one second for VAMs, VAM only mode must skip it.
        assert!(elapsed < Duration::from_millis(500), "took {elapsed:?}");
        cda_interfaces::communication_control::TransportControl::disable(&gateway)
            .await
            .unwrap();
    }

    fn transmission_params() -> TransmissionParameters {
        TransmissionParameters {
            gateway_address: GATEWAY_ADDR,
            timeout_ack: Duration::from_secs(1),
            ecu_name: "test-ecu".to_owned(),
            repeat_request_count_transmission: 0,
        }
    }

    fn service_payload() -> ServicePayload {
        ServicePayload {
            data: REQUEST_DATA.to_vec(),
            source_address: TESTER_ADDR,
            target_address: ECU_ADDR,
            new_session: None,
            new_security: None,
        }
    }

    fn ecu_msg_response() -> DiagnosticResponse {
        DiagnosticResponse::Msg {
            source_address: ECU_ADDR,
            target_address: TESTER_ADDR,
            data: RESPONSE_DATA.to_vec(),
        }
    }

    fn diag_msg() -> DiagnosticMessage {
        DiagnosticMessage {
            source_address: TESTER_ADDR.to_be_bytes(),
            target_address: ECU_ADDR.to_be_bytes(),
            message: REQUEST_DATA.to_vec(),
        }
    }

    type BroadcastTx = broadcast::Sender<Result<DiagnosticResponse, crate::connections::EcuError>>;

    fn make_broadcast_pair() -> (
        BroadcastTx,
        broadcast::Receiver<Result<DiagnosticResponse, crate::connections::EcuError>>,
    ) {
        broadcast::channel(16)
    }

    type ResponseChannel = (
        mpsc::Sender<Result<Option<TransportResponse>, DiagServiceError>>,
        mpsc::Receiver<Result<Option<TransportResponse>, DiagServiceError>>,
    );

    fn make_response_channel() -> ResponseChannel {
        mpsc::channel(1)
    }

    type SendResult = Result<tokio::task::JoinHandle<()>, cda_interfaces::DiagServiceError>;
    type ResponseItem = Result<Option<TransportResponse>, cda_interfaces::DiagServiceError>;

    /// Shared test harness.
    ///
    /// Owns every channel handle that must stay alive for the duration of a
    /// test:
    /// - `broadcast_tx` - injects simulated ECU responses.
    /// - `_doip_payload_rx` - keeps the mpsc sender alive so `send_with_retries`
    ///   does not error out trying to write the outgoing `DoIP` frame.
    /// - `send_handle` - join handle for the background `send()` task.
    /// - `response_rx` - receives the UDS responses forwarded by `send()`.
    struct TestHarness {
        broadcast_tx: broadcast::Sender<Result<DiagnosticResponse, crate::connections::EcuError>>,
        _doip_payload_rx: mpsc::Receiver<DoipPayload>,
        send_handle: tokio::task::JoinHandle<SendResult>,
        response_rx: mpsc::Receiver<ResponseItem>,
    }

    impl TestHarness {
        /// Creates the gateway, spawns the `send()` task, and advances it past
        /// `clear_pending_messages` to the point where it is blocked on
        /// `ecu.receiver.recv()` inside the `'ack_waiting` loop.
        ///
        /// Uses `current_thread` flavor (see test attributes) so that
        /// `yield_now()` is a reliable synchronization primitive: on a
        /// cooperative single-threaded executor each yield hands control to
        /// exactly the next scheduled task.  The spawned task must pass through
        /// the following `.await` points before reaching `recv()`:
        ///
        ///   1. `ecu_mtx.lock().await` - acquires the ECU mutex
        ///   2. `send_with_retries(...).await` - writes the outgoing `DoIP` frame
        ///   3. `tokio::time::timeout(...)` - enters the ACK-wait future
        ///   4. `ecu.receiver.recv().await` - now blocked, ready for injection
        ///
        /// Crucially, `clear_pending_messages` runs between steps 1 and 2.
        /// We must yield past it before calling `broadcast_tx.send()`, otherwise
        /// the injected message would be drained and the task would block forever.
        /// One `yield_now()` per await point, plus one safety margin = 5 total.
        async fn new() -> Self {
            let (broadcast_tx, broadcast_rx) =
                broadcast::channel::<Result<DiagnosticResponse, crate::connections::EcuError>>(1);
            let (doip_payload_tx, doip_payload_rx) = mpsc::channel::<DoipPayload>(1);

            let gateway = make_gateway(broadcast_rx, doip_payload_tx);

            let (response_tx, response_rx) = mpsc::channel::<ResponseItem>(1);
            let send_handle = tokio::spawn({
                let gateway = gateway.clone();
                async move {
                    gateway
                        .send(transmission_params(), service_payload(), response_tx, true)
                        .await
                }
            });

            for _ in 0..5 {
                tokio::task::yield_now().await;
            }

            Self {
                broadcast_tx,
                _doip_payload_rx: doip_payload_rx,
                send_handle,
                response_rx,
            }
        }

        /// Waits for the next response from the background `send()` task.
        ///
        /// Uses `tokio::time::timeout` rather than `try_recv()`, so no
        /// yield counting is needed after injecting a broadcast message.
        async fn recv_response(&mut self) -> ResponseItem {
            tokio::time::timeout(Duration::from_millis(500), self.response_rx.recv())
                .await
                .expect("timed out waiting for response from send() task")
                .expect("response channel closed unexpectedly")
        }
    }

    // current_thread: yield_now() in TestHarness::new() must be a reliable sync point.
    #[tokio::test(flavor = "current_thread")]
    async fn implicit_ack_busy_retry_then_final_response() {
        let mut harness = TestHarness::new().await;

        // ECU sends BusyRepeatRequest (NRC 0x21) via the implicit-ACK path:
        // the DiagnosticMessage arrives before the ACK, so
        // wait_for_ack_or_response_until_timeout returns it directly as the
        // seed for read_ecu_responses instead of waiting for a separate ACK.
        harness
            .broadcast_tx
            .send(Ok(DiagnosticResponse::Msg {
                source_address: ECU_ADDR,
                target_address: TESTER_ADDR,
                data: vec![
                    service_ids::NEGATIVE_RESPONSE,
                    REQUEST_DATA[0],
                    nrc::BUSY_REPEAT_REQUEST,
                ],
            }))
            .expect("Failed to sent busy repeat request");
        let first = harness.recv_response().await;
        assert!(
            matches!(
                first,
                Ok(Some(TransportResponse::Pending(
                    PendingNrc::BusyRepeatRequest { .. }
                )))
            ),
            "expected BusyRepeatRequest, got {first:?}"
        );

        // ECU sends the final Msg.
        harness
            .broadcast_tx
            .send(Ok(ecu_msg_response()))
            .expect("Failed to sent final message");
        let second = harness.recv_response().await;
        assert!(
            matches!(second, Ok(Some(TransportResponse::UdsResponse(_)))),
            "expected Message, got {second:?}"
        );

        drop(harness.response_rx);
        tokio::time::timeout(Duration::from_secs(2), harness.send_handle)
            .await
            .expect("send task did not finish")
            .expect("send task panicked")
            .expect("send() returned an error");
    }

    // current_thread: yield_now() in TestHarness::new() must be a reliable sync point.
    #[tokio::test(flavor = "current_thread")]
    async fn implicit_ack_single_response() {
        let mut harness = TestHarness::new().await;

        // ECU sends a single Msg - no ACK (implicit ACK path).
        harness
            .broadcast_tx
            .send(Ok(ecu_msg_response()))
            .expect("Failed to sent message");
        let response = harness.recv_response().await;
        assert!(
            matches!(response, Ok(Some(TransportResponse::UdsResponse(_)))),
            "expected Message, got {response:?}"
        );

        // No further messages; dropping the receiver unblocks read_ecu_responses.
        drop(harness.response_rx);
        tokio::time::timeout(Duration::from_secs(2), harness.send_handle)
            .await
            .expect("send task did not finish")
            .expect("send task panicked")
            .expect("send() returned an error");
    }
    #[tokio::test]
    async fn wait_for_ack_or_response_ok_none_on_explicit_ack() {
        let (tx, mut rx) = make_broadcast_pair();
        let msg = diag_msg();
        tx.send(Ok(DiagnosticResponse::Ack((ECU_ADDR, vec![]))))
            .expect("Failed to send ack");

        let result = wait_for_ack_or_response_until_timeout(
            &mut rx,
            "test-ecu",
            &msg,
            Duration::from_secs(1),
            &no_activity(),
        )
        .await;
        assert!(
            matches!(result, Ok(None)),
            "expected Ok(None), got {result:?}"
        );
    }

    /// A `DiagnosticMessage` received before the ACK triggers the implicit-ACK
    /// path: the response is returned as `Ok(Some(_))` for the caller to seed
    /// into `read_ecu_responses`.
    #[tokio::test]
    async fn wait_for_ack_or_response_ok_some_on_diagnostic_msg() {
        let (tx, mut rx) = make_broadcast_pair();
        let msg = diag_msg();
        tx.send(Ok(ecu_msg_response()))
            .expect("Failed to send message");

        let result = wait_for_ack_or_response_until_timeout(
            &mut rx,
            "test-ecu",
            &msg,
            Duration::from_secs(1),
            &no_activity(),
        )
        .await;

        assert!(
            matches!(result, Ok(Some(DiagnosticResponse::Msg { .. }))),
            "expected Ok(Some(Diagnostic)), got {result:?}"
        );
    }

    /// `BusyRepeatRequest` before the ACK also returns `Ok(Some(_))`.
    #[tokio::test]
    async fn wait_for_ack_or_response_ok_some_on_busy_repeat_request() {
        let (tx, mut rx) = make_broadcast_pair();
        let msg = diag_msg();

        tx.send(Ok(DiagnosticResponse::Msg {
            source_address: ECU_ADDR,
            target_address: TESTER_ADDR,
            data: vec![
                service_ids::NEGATIVE_RESPONSE,
                REQUEST_DATA[0],
                nrc::BUSY_REPEAT_REQUEST,
            ],
        }))
        .expect("Failed to busy repeat request");

        let result = wait_for_ack_or_response_until_timeout(
            &mut rx,
            "test-ecu",
            &msg,
            Duration::from_secs(1),
            &no_activity(),
        )
        .await;

        assert!(
            matches!(result, Ok(Some(DiagnosticResponse::Msg { .. }))),
            "expected Ok(Some(Diagnostic(BusyRepeatRequest NRC))), got {result:?}"
        );
    }

    /// A `DiagnosticMessageNack` returns `Err(Nack(_))`.
    #[tokio::test]
    async fn wait_for_ack_or_response_err_on_nack() {
        use doip_definitions::payload::{DiagnosticMessageNack, DiagnosticNackCode};

        let (tx, mut rx) = make_broadcast_pair();
        let msg = diag_msg();

        tx.send(Ok(DiagnosticResponse::Nack(DiagnosticMessageNack {
            source_address: ECU_ADDR.to_be_bytes(),
            target_address: TESTER_ADDR.to_be_bytes(),
            nack_code: DiagnosticNackCode::UnknownTargetAddress,
        })))
        .expect("Failed to send nack");

        let result = wait_for_ack_or_response_until_timeout(
            &mut rx,
            "test-ecu",
            &msg,
            Duration::from_secs(1),
            &no_activity(),
        )
        .await;

        assert!(
            matches!(result, Err(DiagServiceError::Nack(_))),
            "expected Nack, got {result:?}"
        );
    }

    /// A `GenericNack` returns `Err(Nack(_))`.
    #[tokio::test]
    async fn wait_for_ack_or_response_err_on_generic_nack() {
        use doip_definitions::payload::{GenericNack, NackCode};

        let (tx, mut rx) = make_broadcast_pair();
        let msg = diag_msg();

        tx.send(Ok(DiagnosticResponse::GenericNack(GenericNack {
            nack_code: NackCode::InvalidPayloadLength,
        })))
        .expect("Failed to send generic nack");

        let result = wait_for_ack_or_response_until_timeout(
            &mut rx,
            "test-ecu",
            &msg,
            Duration::from_secs(1),
            &no_activity(),
        )
        .await;

        assert!(
            matches!(result, Err(DiagServiceError::Nack(_))),
            "expected Nack, got {result:?}"
        );
    }

    /// When the timeout expires with no message, `Err(Timeout)` is returned.
    #[tokio::test]
    async fn wait_for_ack_or_response_err_on_timeout() {
        let (_tx, mut rx) = make_broadcast_pair();
        let msg = diag_msg();

        let result = wait_for_ack_or_response_until_timeout(
            &mut rx,
            "test-ecu",
            &msg,
            Duration::from_millis(200),
            &no_activity(),
        )
        .await;

        assert!(
            matches!(result, Err(DiagServiceError::Timeout)),
            "expected Timeout, got {result:?}"
        );
    }

    /// When the broadcast receiver is closed, `Err(NoResponse(_))` is returned.
    #[tokio::test]
    async fn wait_for_ack_or_response_err_when_receiver_closed() {
        let (tx, mut rx) = make_broadcast_pair();
        let msg = diag_msg();

        drop(tx);

        let result = wait_for_ack_or_response_until_timeout(
            &mut rx,
            "test-ecu",
            &msg,
            Duration::from_secs(1),
            &no_activity(),
        )
        .await;

        assert!(
            matches!(result, Err(DiagServiceError::NoResponse(_))),
            "expected NoResponse, got {result:?}"
        );
    }

    /// An unrelated message type (e.g. `AliveCheckResponse`) must be skipped;
    /// the loop should continue until the real ACK arrives.
    #[tokio::test]
    async fn wait_for_ack_or_response_skips_unrelated_messages() {
        let (tx, mut rx) = make_broadcast_pair();
        let msg = diag_msg();

        tx.send(Ok(DiagnosticResponse::AliveCheckResponse))
            .expect("Failed to send alive check response");
        tx.send(Ok(DiagnosticResponse::Ack((ECU_ADDR, vec![]))))
            .expect("Failed to send ack");

        let result = wait_for_ack_or_response_until_timeout(
            &mut rx,
            "test-ecu",
            &msg,
            Duration::from_secs(1),
            &no_activity(),
        )
        .await;

        drop(tx);
        assert!(
            matches!(result, Ok(None)),
            "expected Ok(None), got {result:?}"
        );
    }

    /// A UDS frame with another SID before the ACK does not answer the request
    /// and is skipped, but it is reported as a reply of the request's ECU.
    #[tokio::test]
    async fn wait_for_ack_or_response_reports_skipped_frame_as_reply() {
        let (tx, mut rx) = make_broadcast_pair();
        let msg = diag_msg();
        let handler = Arc::new(RecordingConnectivityHandler::default());
        // No address map: the request's ECU is reported by its name.
        let activity = activity_reporter(&handler, &[]);

        tx.send(Ok(DiagnosticResponse::Msg {
            source_address: ECU_ADDR,
            target_address: TESTER_ADDR,
            data: vec![service_ids::SESSION_CONTROL | UDS_ID_RESPONSE_BITMASK, 0x01],
        }))
        .expect("Failed to send unrelated response");
        tx.send(Ok(DiagnosticResponse::Ack((ECU_ADDR, vec![]))))
            .expect("Failed to send ack");

        let result = wait_for_ack_or_response_until_timeout(
            &mut rx,
            "test-ecu",
            &msg,
            Duration::from_secs(1),
            &activity,
        )
        .await;

        drop(tx);
        assert!(
            matches!(result, Ok(None)),
            "expected Ok(None), got {result:?}"
        );
        assert_eq!(handler.replied(), vec!["test-ecu".to_owned()]);
    }

    #[tokio::test]
    async fn read_ecu_responses_forwards_message_and_exits_on_sender_close() {
        let (tx, mut rx) = make_broadcast_pair();
        let (resp_tx, mut resp_rx) = make_response_channel();

        tx.send(Ok(ecu_msg_response()))
            .expect("Failed to send message");

        // Spawn the response reader in a separate task.
        let handle = tokio::spawn(async move {
            read_ecu_responses(&mut rx, "test-ecu", &resp_tx, None).await;
        });

        // Read the forwarded Msg.
        let item = tokio::time::timeout(Duration::from_secs(1), resp_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert!(
            matches!(item, Ok(Some(TransportResponse::UdsResponse(_)))),
            "expected Message, got {item:?}"
        );

        // Drop the receiver to close the sender; the loop should exit.
        drop(resp_rx);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("read_ecu_responses did not exit after sender closed")
            .expect("task panicked");
    }

    #[tokio::test]
    async fn read_ecu_responses_forwards_multiple_responses() {
        let (tx, mut rx) = make_broadcast_pair();
        let (resp_tx, mut resp_rx) = make_response_channel();
        tx.send(Ok(DiagnosticResponse::Msg {
            source_address: ECU_ADDR,
            target_address: TESTER_ADDR,
            data: vec![
                service_ids::NEGATIVE_RESPONSE,
                REQUEST_DATA[0],
                nrc::RESPONSE_PENDING,
            ],
        }))
        .expect("Failed to send pending response");
        tx.send(Ok(ecu_msg_response()))
            .expect("Failed to send response");
        // Keep tx alive across awaits so the channel is not closed while the
        // spawned task is reading buffered messages.
        let _tx = tx;

        let handle = tokio::spawn(async move {
            read_ecu_responses(&mut rx, "test-ecu", &resp_tx, None).await;
        });

        let first = tokio::time::timeout(Duration::from_secs(1), resp_rx.recv())
            .await
            .expect("timeout")
            .expect("closed");
        assert!(
            matches!(
                first,
                Ok(Some(TransportResponse::Pending(
                    PendingNrc::ResponsePending { .. }
                )))
            ),
            "expected ResponsePending, got {first:?}"
        );

        let second = tokio::time::timeout(Duration::from_secs(1), resp_rx.recv())
            .await
            .expect("timeout")
            .expect("closed");
        assert!(
            matches!(second, Ok(Some(TransportResponse::UdsResponse(_)))),
            "expected Message, got {second:?}"
        );

        drop(resp_rx);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("task did not exit")
            .expect("task panicked");
    }

    /// When `first` is `Some`, it is forwarded before reading from the receiver -
    /// this is the implicit-ACK seed path.
    #[tokio::test]
    async fn read_ecu_responses_forwards_first_then_receiver() {
        let (tx, mut rx) = make_broadcast_pair();
        let (resp_tx, mut resp_rx) = make_response_channel();

        let first = ecu_msg_response();
        tx.send(Ok(DiagnosticResponse::Msg {
            source_address: ECU_ADDR,
            target_address: TESTER_ADDR,
            data: vec![
                service_ids::NEGATIVE_RESPONSE,
                REQUEST_DATA[0],
                nrc::RESPONSE_PENDING,
            ],
        }))
        .expect("Failed to send pending response");
        let _tx = tx;

        let handle = tokio::spawn(async move {
            read_ecu_responses(&mut rx, "test-ecu", &resp_tx, Some(first)).await;
        });

        let first_item = tokio::time::timeout(Duration::from_secs(1), resp_rx.recv())
            .await
            .expect("timeout")
            .expect("closed");
        assert!(
            matches!(first_item, Ok(Some(TransportResponse::UdsResponse(_)))),
            "expected Message from first, got {first_item:?}"
        );

        let second_item = tokio::time::timeout(Duration::from_secs(1), resp_rx.recv())
            .await
            .expect("timeout")
            .expect("closed");
        assert!(
            matches!(
                second_item,
                Ok(Some(TransportResponse::Pending(
                    PendingNrc::ResponsePending { .. }
                )))
            ),
            "expected ResponsePending from receiver, got {second_item:?}"
        );

        drop(resp_rx);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("task did not exit")
            .expect("task panicked");
    }
}
