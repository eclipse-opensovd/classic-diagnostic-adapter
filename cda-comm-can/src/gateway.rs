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

//! The CAN transport implementation, compiled only with the `can` feature.
//!
//! Everything below this module can assume the feature is enabled; the
//! feature gate lives on the single `mod gateway` declaration in `lib.rs`.

mod background;
pub(crate) mod can_id;
pub(crate) mod connection;
pub mod error;
pub mod keepalive;
mod probe;
mod rediscovery;
mod topology;

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use cda_interfaces::{
    DiagServiceError, EcuAddresses, FunctionalTransport, NetworkTopology, PhysicalTransport,
    ReloadComponent, Reloadable, ReloadableOwner, RouteStatus, ServicePayload, Shutdown,
    TransmissionParameters, TransportProbe, TransportResponse, VariantDetectionRequest,
    VariantDetectionSender,
    communication_control::{
        GatewayLifecycle, TransportControl, TransportState, error::CommControlError,
    },
    dlt_ctx, pending_nrc_from_raw, uds_response_from_raw,
};
use tokio::sync::{RwLock, mpsc};

pub use self::topology::{CanEcuAddressing, CanTopology, derive_can_topology};
use self::{
    background::BackgroundTask,
    connection::CanEcuConnection,
    error::{CanError, CanGatewaySetupError},
    probe::ProbeRequest,
};
use crate::config::CanConfig;

/// The instant `timeout` from now, saturating instead of panicking on the
/// (theoretical) overflow of the underlying monotonic clock.
fn deadline_in(timeout: Duration) -> tokio::time::Instant {
    let now = tokio::time::Instant::now();
    now.checked_add(timeout).unwrap_or(now)
}

/// CAN bus diagnostic gateway implementing the `EcuGateway` trait.
///
/// This gateway handles communication with ECUs over CAN bus using ISO-TP
/// (ISO 15765-2) for transport layer segmentation.
pub struct CanDiagGateway {
    /// CAN interface name
    interface: String,
    /// Read per use, because the gateway outlives any one topology.
    ///
    /// Lookups copy what they need out and drop the guard before any bus I/O,
    /// against [`Reloadable::read`]'s advice: holding it across a probe would
    /// stall a reload, and every lookup queued behind it, on an unreachable
    /// ECU. The trade is that an operation already in flight finishes against
    /// the addressing it started with, so `ReloadComponent::apply` can return
    /// while the old topology is still partly alive - accepted, since CAN
    /// addressing cannot be retargeted mid-frame.
    topology: Reloadable<CanTopology>,
    /// Set of ECU names that responded to discovery
    discovered_ecus: Arc<RwLock<cda_interfaces::HashSet<String>>>,
    /// Response timeout duration
    response_timeout: Duration,
    /// Probe timeout duration
    probe_timeout: Duration,
    /// Extra rounds through the probe sequence for unanswered ECUs; see
    /// `CanConfig::probe_retries`.
    probe_retries: u32,
    /// Delay between probe retry rounds.
    probe_retry_delay: Duration,
    /// Ordered list of discovery probes to try per ECU.
    probe_sequence: Arc<Vec<ProbeRequest>>,
    /// Configured keepalive interval. Zero disables keepalive.
    keepalive_interval: Duration,
    /// Notifies variant detection after discovery and rediscovery.
    variant_detection: VariantDetectionSender,
    /// Shared restartable lifecycle state and retained task configuration.
    lifecycle: Arc<GatewayLifecycle<CanGatewayOperation>>,
}

/// Background tasks owned by the current enabled lifecycle.
#[derive(Default)]
struct CanGatewayOperation {
    keepalive: Option<BackgroundTask>,
    rediscovery: Option<BackgroundTask>,
}

impl CanDiagGateway {
    /// Creates the CAN diagnostic gateway.
    ///
    /// Passive: no socket is opened and no ECU is probed until `enable()`.
    ///
    /// # Arguments
    /// * `config` - CAN configuration
    /// * `topology`: shared derived topology, resolved per use
    /// * `variant_detection` - Channel to notify about discovered ECUs
    ///
    /// # Returns
    /// The gateway and, separately, the sole authority to replace its
    /// topology: the gateway itself can only read what it was built with.
    /// Not named `new` precisely because it does not hand back only a `Self` -
    /// the caller cannot get one half without deciding where the other goes.
    ///
    /// # Errors
    /// Returns [`CanGatewaySetupError`] if the configured probe sequence is
    /// unusable.
    #[tracing::instrument(
        skip(config, topology, variant_detection),
        fields(
            interface = %config.interface,
            dlt_context = dlt_ctx!("CAN"),
        )
    )]
    pub fn build(
        config: &CanConfig,
        topology: CanTopology,
        variant_detection: VariantDetectionSender,
    ) -> Result<(CanDiagGateway, Arc<dyn ReloadComponent<CanTopology>>), CanGatewaySetupError> {
        tracing::info!("Initializing CanDiagGateway");
        let probe_sequence = Self::build_probe_sequence(config)?;

        let reloader = Arc::new(ReloadableOwner::new(topology));
        let gateway = Self {
            interface: config.interface.clone(),
            topology: reloader.reader(),
            discovered_ecus: Arc::new(RwLock::new(cda_interfaces::HashSet::default())),
            response_timeout: Duration::from_millis(config.response_timeout_ms),
            probe_timeout: Duration::from_millis(config.probe_timeout_ms),
            probe_retries: config.probe_retries,
            probe_retry_delay: Duration::from_millis(config.probe_retry_delay_ms),
            probe_sequence: Arc::new(probe_sequence),
            keepalive_interval: Duration::from_millis(config.keepalive_interval_ms),
            variant_detection,
            lifecycle: Arc::new(GatewayLifecycle::new(TransportState::Disabled)),
        };
        Ok((gateway, reloader as Arc<dyn ReloadComponent<CanTopology>>))
    }

    /// Checks if an ECU was discovered by logical address.
    ///
    /// Uses the topology's address lookup instead of iterating the shared ECU
    /// `RwLock`s, avoiding potential deadlocks.
    pub async fn is_ecu_discovered(&self, logical_addr: u16) -> bool {
        let topology = self.topology.read().await;
        if let Some(ecu_name) = topology.ecu_for_logical_address(logical_addr) {
            return self.discovered_ecus.read().await.contains(ecu_name);
        }
        false
    }

    /// Checks if a specific ECU was discovered by name.
    async fn is_ecu_discovered_by_name(&self, ecu_name: &str) -> bool {
        self.discovered_ecus.read().await.contains(ecu_name)
    }

    async fn probe_ecu_with_topology(&self, topology: &CanTopology, ecu_name: &str) -> bool {
        let ecu_name = ecu_name.to_lowercase();
        let Some(conn) = topology.connection(&ecu_name).map(CanEcuConnection::new) else {
            return false;
        };
        let logical_addr = topology
            .logical_address_for_ecu(&ecu_name)
            .unwrap_or_default();
        self.probe_and_record(&conn, logical_addr, ecu_name).await
    }

    /// Probes one ECU over a connection the caller already owns, recording
    /// the outcome in `discovered_ecus`.
    ///
    /// Takes the connection and address by value so a caller can release the
    /// topology guard first: `probe_connection` waits out `probe_timeout` x
    /// `probe_retries` plus `probe_retry_delay`, and holding the read guard
    /// across that makes a topology reload - and, because the lock is fair,
    /// every CAN lookup queued behind that reload - wait on an unreachable ECU.
    async fn probe_and_record(
        &self,
        conn: &CanEcuConnection,
        logical_addr: u16,
        ecu_name: String,
    ) -> bool {
        if self.probe_connection(conn, logical_addr).await.is_ok() {
            self.discovered_ecus.write().await.insert(ecu_name);
            true
        } else {
            self.discovered_ecus.write().await.remove(&ecu_name);
            false
        }
    }
}

impl PhysicalTransport for CanDiagGateway {
    #[tracing::instrument(skip_all, fields(
        ecu = %transmission_params.ecu_name,
        gateway_addr = transmission_params.gateway_address,
        dlt_context = dlt_ctx!("CAN"),
    ))]
    async fn send(
        &self,
        transmission_params: TransmissionParameters,
        message: ServicePayload,
        response_sender: mpsc::Sender<Result<Option<TransportResponse>, DiagServiceError>>,
        expect_uds_reply: bool,
    ) -> Result<tokio::task::JoinHandle<()>, DiagServiceError> {
        let ecu_name = transmission_params.ecu_name.to_lowercase();
        let topology = self.topology.read().await;
        let conn = topology
            .connection(&ecu_name)
            .map(CanEcuConnection::new)
            .ok_or_else(|| DiagServiceError::EcuOffline(transmission_params.ecu_name.clone()))?;
        // Copied out so the guard is released before the send; see `topology`.
        drop(topology);

        // Check if ECU was discovered
        if !self.is_ecu_discovered_by_name(&ecu_name).await {
            return Err(DiagServiceError::EcuOffline(
                transmission_params.ecu_name.clone(),
            ));
        }

        tracing::debug!(
            request_data = %hex::encode(&message.data),
            "Sending CAN message"
        );

        // Spawn a task to handle the send/receive cycle
        let response_timeout = self.response_timeout;
        let probe_timeout = self.probe_timeout;
        let discovered_ecus = Arc::clone(&self.discovered_ecus);
        let ecu_map_key = ecu_name;
        let ecu_name = transmission_params.ecu_name.clone();
        let source_address = message.source_address;
        let target_address = message.target_address;
        let request_data = message.data;

        let handle = cda_interfaces::spawn_named!(&format!("can-send-{ecu_name}"), {
            async move {
                // Open socket and send request, keeping the socket alive for the
                // entire exchange so response-pending follow-ups arrive on the
                // same transport session.
                // begin_exchange opens the socket and writes the request; it
                // has no timeout of its own, so every failure maps to
                // NoResponse.
                let exchange = match conn.begin_exchange(&request_data).await {
                    Ok(ex) => ex,
                    Err(e) => {
                        let _ = response_sender
                            .send(Err(DiagServiceError::NoResponse(e.to_string())))
                            .await;
                        return;
                    }
                };

                // No UDS reply expected (e.g. suppressPositiveResponse): the
                // request is on the bus, acknowledge immediately like the DoIP
                // gateway does instead of blocking on a response that will
                // never come (and holding the per-ECU semaphore meanwhile).
                if !expect_uds_reply {
                    let _ = response_sender.send(Ok(None)).await;
                    return;
                }

                // Read until a response that belongs to this request arrives
                // or the overall deadline expires. CAN is a shared medium:
                // frames can show up on the response ID that were never an
                // answer to our request - e.g. an ECU that rejects the
                // broadcast keep-alive replies `7F 3E 12` on its physical
                // response ID, and that lands on this socket if it arrives
                // inside the request/response window. Treating the first
                // frame read as "the" response would close the socket while
                // the real answer is still in flight, turning a healthy
                // exchange into a timeout. So frames whose SID does not echo
                // the request are dropped here and the read continues; the
                // socket closes as soon as a genuine final response has been
                // forwarded, keeping its lifetime short (two sockets open on
                // the same ID pair would both answer a segmented transfer
                // with flow control and abort it).
                //
                // The deadline is extended only when the ECU signals NRC
                // 0x78 (Response Pending), matching the caller's rc_78
                // policy. Dropped unsolicited frames do NOT extend it, so a
                // peer chattering on our response ID cannot keep a request
                // whose real response never arrives (e.g. its reassembly was
                // aborted by an interleaved frame) alive forever and wedge
                // the per-ECU request semaphore.
                let sent_sid = request_data.first().copied().unwrap_or_default();
                let mut deadline = deadline_in(response_timeout);
                // Whether any frame arrived on this exchange at all - see the
                // silence check after the loop.
                let mut received_any_frame = false;
                let exchange_start = tokio::time::Instant::now();
                loop {
                    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                    let response = tokio::select! {
                        () = response_sender.closed() => break,
                        response = exchange.read_response(remaining) => response,
                    };
                    match response {
                        Ok(data) => {
                            received_any_frame = true;

                            // Check for pending NRCs before SID-filtering: the
                            // ISO-TP socket must stay open for a follow-up
                            // response, so we extend the deadline when needed.
                            // pending_nrc_from_raw covers 0x78, 0x21, and 0x94.
                            if let Some(pending) = pending_nrc_from_raw(&data, source_address) {
                                deadline = deadline_in(response_timeout);
                                if response_sender
                                    .send(Ok(Some(TransportResponse::Pending(pending))))
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                                continue;
                            }

                            if !cda_interfaces::util::uds_response_matches_request_sid(
                                sent_sid, &data,
                            ) {
                                tracing::debug!(
                                    data = %hex::encode(&data),
                                    request_sid = format_args!("{sent_sid:#04x}"),
                                    "Dropping response not belonging to the pending \
                                     request, continue reading"
                                );
                                continue;
                            }

                            // Final response - classify via the shared function
                            // so NRC mapping is identical to the DoIP path.
                            let uds_response =
                                uds_response_from_raw(data, source_address, target_address);
                            let _ = response_sender
                                .send(Ok(Some(TransportResponse::UdsResponse(uds_response))))
                                .await;
                            break;
                        }
                        Err(CanError::Timeout) => {
                            let _ = response_sender.send(Err(DiagServiceError::Timeout)).await;
                            break;
                        }
                        Err(e) => {
                            let _ = response_sender
                                .send(Err(DiagServiceError::NoResponse(e.to_string())))
                                .await;
                            break;
                        }
                    }
                }

                // Zero frames for the whole exchange is the sleep
                // signature: drop the ECU from the discovered set so
                // background rediscovery (undiscovered ECUs only) recovers
                // it on wake. Checked after the loop because the caller's
                // receive window (CP_P6Max) usually closes the channel
                // before the gateway deadline; an awake ECU emits something
                // within P6Max. The probe-timeout floor keeps instant
                // client aborts from striking healthy ECUs.
                if !received_any_frame && exchange_start.elapsed() >= probe_timeout {
                    tracing::info!(
                        ecu = %ecu_name,
                        elapsed_ms =
                            u32::try_from(exchange_start.elapsed().as_millis()).unwrap_or(u32::MAX),
                        "No frame received for the whole exchange; marking the ECU undiscovered \
                         so background rediscovery re-probes it"
                    );
                    discovered_ecus.write().await.remove(&ecu_map_key);
                }
            }
        });

        Ok(handle)
    }

    #[tracing::instrument(skip(self, _ecu_db), fields(dlt_context = dlt_ctx!("CAN")))]
    async fn ecu_online<E: EcuAddresses>(
        &self,
        ecu_name: &str,
        _ecu_db: &RwLock<E>,
    ) -> Result<(), DiagServiceError> {
        let ecu_name = ecu_name.to_lowercase();
        // All lookups use the derived topology; no shared ECU RwLock is
        // touched. Everything the probe needs is copied out so the guard is
        // released before it runs - see `topology` for the trade that makes.
        let probe_target = {
            let topology = self.topology.read().await;
            topology.connection(&ecu_name).map(|addressing| {
                let logical_addr = topology
                    .logical_address_for_ecu(&ecu_name)
                    .unwrap_or_default();
                (CanEcuConnection::new(addressing), logical_addr)
            })
        };
        let Some((conn, logical_addr)) = probe_target else {
            return Err(DiagServiceError::EcuOffline(ecu_name));
        };
        if self.is_ecu_discovered_by_name(&ecu_name).await {
            return Ok(());
        }
        // On-demand re-detection: the ECU may have come online after the
        // startup discovery (or dropped off and rebooted). One bounded probe
        // per call; on success the ECU is marked discovered again.
        if self
            .probe_and_record(&conn, logical_addr, ecu_name.clone())
            .await
        {
            Ok(())
        } else {
            Err(DiagServiceError::EcuOffline(ecu_name))
        }
    }
}

impl NetworkTopology for CanDiagGateway {
    async fn get_gateway_network_address(&self, logical_address: u16) -> Option<String> {
        let topology = self.topology.read().await;
        let ecu_name = topology.ecu_for_logical_address(logical_address)?;
        if !self.is_ecu_discovered_by_name(ecu_name).await {
            return None;
        }
        topology
            .connection(ecu_name)
            .map(|addressing| addressing.network_address())
    }

    async fn get_ecu_network_address(&self, ecu_name: &str) -> Option<String> {
        let topology = self.topology.read().await;
        topology
            .connection(&ecu_name.to_lowercase())
            .map(|addressing| addressing.network_address())
    }
}

impl FunctionalTransport for CanDiagGateway {
    fn send_functional(
        &self,
        _transmission_params: cda_interfaces::TransmissionParameters,
        _message: cda_interfaces::ServicePayload,
        _expected_ecu_logical_addrs: cda_interfaces::HashMap<u16, String>,
        _timeout: std::time::Duration,
        _expect_positive_response: bool,
    ) -> impl Future<
        Output = Result<
            cda_interfaces::HashMap<
                String,
                Result<cda_interfaces::ServicePayload, DiagServiceError>,
            >,
            DiagServiceError,
        >,
    > + Send {
        // CAN functional addressing is not implemented yet, see #417.
        // Fail the whole request honestly; the UDS layer maps a gateway-level
        // error to a per-ECU error result, so clients see WHY it failed
        // instead of every ECU appearing to be offline.
        std::future::ready(Err(DiagServiceError::RequestNotSupported(
            "functional addressing is not implemented for the CAN transport".to_owned(),
        )))
    }
}

impl TransportProbe for CanDiagGateway {
    async fn route_status(&self, ecu_name: &str) -> RouteStatus {
        let ecu_name = ecu_name.to_lowercase();
        let topology = self.topology.read().await;
        if !topology.has_connection(&ecu_name) {
            return RouteStatus::NotConfigured;
        }
        if self.discovered_ecus.read().await.contains(&ecu_name) {
            RouteStatus::Ready
        } else {
            // CAN has a resolved ID pair and supports a bounded physical probe.
            RouteStatus::ProbeRequired
        }
    }

    async fn probe_ecu(&self, ecu_name: &str) -> bool {
        let topology = self.topology.read().await;
        self.probe_ecu_with_topology(&topology, ecu_name).await
    }
}

#[async_trait]
impl Shutdown for CanDiagGateway {
    async fn shutdown(&self) {
        if let Err(error) = self.disable().await {
            tracing::error!(%error, "Failed to disable CAN communication during shutdown");
        }
    }
}

#[async_trait]
impl TransportControl for CanDiagGateway {
    async fn enable(&self) -> Result<(), CommControlError> {
        let mut operation = self.lifecycle.operation.lock().await;
        if self.lifecycle.coordinator.active().await {
            return Ok(());
        }

        self.lifecycle
            .coordinator
            .transition(TransportState::Enabling)
            .await;
        // Released before discovery, which resolves the topology itself.
        let (functional_id, socket_check) = {
            let topology = self.topology.read().await;
            // The check needs one ECU to open a socket against. An empty
            // topology is an empty vehicle, not a broken interface: there is
            // nothing to address, so there is nothing to verify and no reason
            // to refuse the enable. A later update installs a real topology
            // and this runs again on the next enable.
            let socket_check = topology.connections().values().next().map_or_else(
                || Ok(()),
                |addressing| {
                    CanEcuConnection::new(Arc::clone(addressing))
                        .verify_socket_openable()
                        .map_err(|error| {
                            CommControlError::InitFailed(format!(
                                "Failed to open CAN interface {}: {error}",
                                self.interface
                            ))
                        })
                },
            );
            (topology.functional_id(), socket_check)
        };

        if let Err(error) = socket_check {
            self.lifecycle
                .coordinator
                .transition(TransportState::Failed)
                .await;
            return Err(error);
        }

        let discovered = self.discover_ecus().await;
        if discovered.is_empty() {
            tracing::info!("No ECUs discovered on CAN bus during probe");
        } else {
            tracing::info!(
                discovered_count = discovered.len(),
                ecus = ?discovered,
                "Initial CAN ECU discovery complete"
            );
        }

        if !discovered.is_empty()
            && let Err(error) = self
                .variant_detection
                .send(VariantDetectionRequest::new(discovered))
                .await
        {
            self.lifecycle
                .coordinator
                .transition(TransportState::Failed)
                .await;
            return Err(CommControlError::InitFailed(format!(
                "Failed to send discovered ECUs to variant detection: {error}"
            )));
        }

        if !self.keepalive_interval.is_zero() {
            operation.keepalive = Some(keepalive::start_keepalive_broadcast(
                self.interface.clone(),
                functional_id,
                self.keepalive_interval,
            ));
        }

        operation.rediscovery = Some(self.start_rediscovery(self.variant_detection.clone()));

        self.lifecycle
            .coordinator
            .transition(TransportState::Enabled)
            .await;
        Ok(())
    }

    async fn disable(&self) -> Result<(), CommControlError> {
        let mut operation = self.lifecycle.operation.lock().await;
        self.lifecycle
            .coordinator
            .transition(TransportState::Disabling)
            .await;
        // CAN uses per-transaction ISO-TP sockets (no long-lived connection
        // tasks); only the broadcast keep-alive and the rediscovery loop run
        // in the background. Rediscovery first: it holds a gateway clone, so
        // awaiting it here also breaks that reference cycle.
        if let Some(rediscovery) = operation.rediscovery.take() {
            rediscovery.shutdown().await;
        }
        if let Some(keepalive) = operation.keepalive.take() {
            keepalive.shutdown().await;
        }
        self.discovered_ecus.write().await.clear();
        self.lifecycle
            .coordinator
            .transition(TransportState::Disabled)
            .await;
        Ok(())
    }

    async fn state(&self) -> TransportState {
        self.lifecycle.coordinator.state().await
    }
}

impl Clone for CanDiagGateway {
    fn clone(&self) -> Self {
        Self {
            interface: self.interface.clone(),
            topology: self.topology.clone(),
            discovered_ecus: Arc::clone(&self.discovered_ecus),
            response_timeout: self.response_timeout,
            probe_timeout: self.probe_timeout,
            probe_retries: self.probe_retries,
            probe_retry_delay: self.probe_retry_delay,
            probe_sequence: Arc::clone(&self.probe_sequence),
            keepalive_interval: self.keepalive_interval,
            variant_detection: self.variant_detection.clone(),
            lifecycle: Arc::clone(&self.lifecycle),
        }
    }
}

#[cfg(test)]
impl CanDiagGateway {
    /// Drops all discovery state, simulating every ECU vanishing from the
    /// bus. Test-only counterpart to `probe` marking ECUs undiscovered.
    pub(crate) async fn clear_discovered(&self) {
        self.discovered_ecus.write().await.clear();
    }

    async fn test_functional_id(&self) -> cda_interfaces::CanId {
        self.topology.read().await.functional_id()
    }

    /// Builds a gateway instance for unit tests without touching any CAN
    /// interface: no init check, no discovery, keep-alive disabled.
    pub(crate) fn test_instance(topology: CanTopology, discovered: Vec<&str>) -> Self {
        let discovered: cda_interfaces::HashSet<String> =
            discovered.into_iter().map(str::to_lowercase).collect();
        let owner = ReloadableOwner::new(topology);
        Self {
            interface: "test0".to_owned(),
            topology: owner.reader(),
            discovered_ecus: Arc::new(RwLock::new(discovered)),
            response_timeout: Duration::from_millis(100),
            probe_timeout: Duration::from_millis(10),
            probe_retries: 0,
            probe_retry_delay: Duration::from_millis(10),
            probe_sequence: Arc::new(vec![ProbeRequest::tester_present()]),
            keepalive_interval: Duration::ZERO,
            variant_detection: VariantDetectionSender::new(mpsc::channel(1).0),
            lifecycle: Arc::new(GatewayLifecycle::new(TransportState::Enabled)),
        }
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use std::sync::Arc;

    use crate::{CanEcuAddressing, CanTopology};

    pub(crate) fn shared_topology(connections: Vec<(&str, CanEcuAddressing)>) -> CanTopology {
        let connections = connections
            .into_iter()
            .map(|(name, addressing)| (name.to_lowercase(), Arc::new(addressing)))
            .collect();
        CanTopology::new(
            connections,
            cda_interfaces::HashMap::default(),
            cda_interfaces::CanId::try_from(0x7DF).expect("valid test CAN ID"),
        )
    }
}

#[cfg(test)]
mod tests {
    use cda_interfaces::{CanId, HashMap};

    use super::{test_utils::shared_topology, *};

    /// A topology built directly, the way `shared_topology` does for the other
    /// modules. These tests are about reload propagation, not derivation:
    /// `derive_can_topology` is covered end to end by the integration tests,
    /// which drive it from a real `[can]` config against real databases.
    fn topology_with(ecus: Vec<(&str, u32, u32)>) -> CanTopology {
        shared_topology(
            ecus.into_iter()
                .map(|(name, request, response)| {
                    (
                        name,
                        CanEcuAddressing::new(
                            name.to_owned(),
                            "test0".to_owned(),
                            CanId::try_from(request).expect("valid test CAN ID"),
                            CanId::try_from(response).expect("valid test CAN ID"),
                        ),
                    )
                })
                .collect(),
        )
    }

    /// The probe sequence is validated where it is consumed - building the
    /// gateway - not while deriving a topology, which says nothing about probes.
    #[tokio::test]
    async fn probe_config_without_fallbacks_fails_gateway_construction() {
        let config = CanConfig {
            default_probes: false,
            ..CanConfig::default()
        };
        let topology = topology_with(vec![("ecu1", 0x700, 0x708)]);

        // `let Err(..) else`, not `expect_err`: the success type holds a
        // `dyn ReloadComponent`, which has no `Debug`.
        let Err(error) = CanDiagGateway::build(
            &config,
            topology,
            VariantDetectionSender::new(mpsc::channel(1).0),
        ) else {
            panic!("probe configuration without fallbacks must fail");
        };

        assert!(matches!(
            error,
            CanGatewaySetupError::InvalidConfiguration(message)
                if message == "can.default_probes = false requires at least one [[can.probe_fallbacks]] entry"
        ));
    }

    /// The gateway must route on the current topology rather than one
    /// captured at construction.
    #[tokio::test]
    async fn applying_a_topology_changes_can_routing() {
        let config = CanConfig {
            interface: "test0".to_owned(),
            ..CanConfig::default()
        };
        let can_topology = topology_with(vec![("ecu1", 0x700, 0x708)]);

        let (gateway, reload) = CanDiagGateway::build(
            &config,
            can_topology,
            VariantDetectionSender::new(mpsc::channel(1).0),
        )
        .expect("build test gateway");

        assert_eq!(
            gateway.route_status("ecu1").await,
            RouteStatus::ProbeRequired
        );
        assert_eq!(
            gateway.route_status("ecu2").await,
            RouteStatus::NotConfigured
        );
        assert!(gateway.get_ecu_network_address("ecu1").await.is_some());

        reload
            .apply(topology_with(vec![("ecu2", 0x710, 0x718)]))
            .await;

        // Same gateway instance, new topology.
        assert_eq!(
            gateway.route_status("ecu2").await,
            RouteStatus::ProbeRequired
        );
        assert_eq!(
            gateway.route_status("ecu1").await,
            RouteStatus::NotConfigured
        );
        assert!(gateway.get_ecu_network_address("ecu1").await.is_none());
        assert_eq!(
            gateway.get_ecu_network_address("ecu2").await,
            Some(format!(
                "test0:{}->{}",
                CanId::try_from(0x710).expect("valid ID"),
                CanId::try_from(0x718).expect("valid ID")
            ))
        );
    }

    /// Changing an existing ECU's CAN IDs must reach the live gateway.
    #[tokio::test]
    async fn changed_can_ids_reach_the_live_gateway() {
        let config = CanConfig {
            interface: "test0".to_owned(),
            ..CanConfig::default()
        };
        let can_topology = topology_with(vec![("ecu1", 0x700, 0x708)]);
        let (gateway, reload) = CanDiagGateway::build(
            &config,
            can_topology,
            VariantDetectionSender::new(mpsc::channel(1).0),
        )
        .expect("build test gateway");

        let before = gateway.get_ecu_network_address("ecu1").await;

        reload
            .apply(topology_with(vec![("ecu1", 0x7E0, 0x7E8)]))
            .await;

        let after = gateway.get_ecu_network_address("ecu1").await;
        assert!(after.is_some());
        assert_ne!(before, after);
    }

    fn marker_topology(id: u32) -> CanTopology {
        CanTopology::new(
            HashMap::default(),
            HashMap::default(),
            CanId::try_from(id).unwrap(),
        )
    }

    fn marker_gateway(id: u32) -> (CanDiagGateway, Arc<dyn ReloadComponent<CanTopology>>) {
        CanDiagGateway::build(
            &CanConfig::default(),
            marker_topology(id),
            VariantDetectionSender::new(mpsc::channel(1).0),
        )
        .unwrap()
    }

    /// Applying a new topology is what the running gateway reads next.
    #[tokio::test]
    async fn applying_a_topology_updates_what_the_gateway_reads() {
        let (gateway, reload) = marker_gateway(0x700);
        assert_eq!(gateway.test_functional_id().await.raw(), 0x700);

        reload.apply(marker_topology(0x701)).await;
        assert_eq!(gateway.test_functional_id().await.raw(), 0x701);

        reload.apply(marker_topology(0x702)).await;
        assert_eq!(gateway.test_functional_id().await.raw(), 0x702);
    }

    /// The gateway outlives the authority to replace its topology: both sides
    /// hold an `Arc` to the same data, so dropping the [`ReloadComponent`]
    /// leaves what the gateway was built with readable rather than freeing it.
    #[tokio::test]
    async fn gateway_keeps_its_topology_after_the_reload_authority_is_dropped() {
        let (gateway, reload) = marker_gateway(0x700);
        assert_eq!(gateway.test_functional_id().await.raw(), 0x700);

        drop(reload);

        assert_eq!(gateway.test_functional_id().await.raw(), 0x700);
    }
}
