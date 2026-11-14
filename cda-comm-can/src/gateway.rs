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
    CanId, DiagServiceError, EcuAddresses, EcuConnectivityHandler, FunctionalTransport,
    NetworkTopology, PhysicalTransport, ReloadComponent, Reloadable, ReloadableOwner, RouteStatus,
    ServicePayload, Shutdown, TransmissionParameters, TransportProbe, TransportResponse,
    VariantDetectionRequest, VariantDetectionSender,
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
use crate::config::{CanAddressingMode, CanConfig};

/// What a probe actually reached. Compared against the current topology, never used for I/O.
///
/// "Discovered" is a fact about the addressing that answered, not about the
/// ECU name it is stored under: an ECU counts as discovered only while this
/// equals the fingerprint of its addressing in the current topology. The
/// address-extension byte of extended addressing is part of `mode` and so of
/// the fingerprint, because on a shared ID pair it selects which ECU answers.
/// The interface is not: it is gateway-wide configuration
/// (`CanConfig::interface`), not topology.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct DiscoveredAs {
    request_id: CanId,
    response_id: CanId,
    mode: CanAddressingMode,
}

impl From<&CanEcuAddressing> for DiscoveredAs {
    fn from(addressing: &CanEcuAddressing) -> Self {
        Self {
            request_id: addressing.request_id,
            response_id: addressing.response_id,
            mode: addressing.addressing_mode,
        }
    }
}

impl From<&CanEcuConnection> for DiscoveredAs {
    fn from(conn: &CanEcuConnection) -> Self {
        Self::from(conn.addressing())
    }
}

type DiscoveredEcus = cda_interfaces::HashMap<String, DiscoveredAs>;

/// Whether `ecu_name` was discovered on the addressing `topology` holds for it
/// now. Callers take the topology guard before the `discovered` guard.
fn discovered_on_current(
    topology: &CanTopology,
    discovered: &DiscoveredEcus,
    ecu_name: &str,
) -> bool {
    topology.connection(ecu_name).is_some_and(|addressing| {
        discovered.get(ecu_name) == Some(&DiscoveredAs::from(addressing.as_ref()))
    })
}

/// Removes the discovery of `ecu_name` only if it is still the one recorded
/// for `observed_as`: a late failure on addressing a reload has since replaced
/// must not erase a discovery made on the new addressing.
async fn forget_discovery(
    discovered: &RwLock<DiscoveredEcus>,
    ecu_name: &str,
    observed_as: DiscoveredAs,
) {
    let mut discovered = discovered.write().await;
    if discovered.get(ecu_name) == Some(&observed_as) {
        discovered.remove(ecu_name);
    }
}

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
    /// Uses the copy-out style [`Reloadable::read`] allows for components that
    /// must not block on I/O: the guard is held for the lookup only, never
    /// across bus I/O or a channel send. Holding it across a probe would stall
    /// a reload, and, because the lock is fair, every lookup queued behind it,
    /// on an unreachable ECU. Callers resolve what they need under the guard -
    /// one ECU via `probe_target`, several in a scoped snapshot block as
    /// `discover_ecus` and `undiscovered_targets` do - drop it, and only then
    /// probe or send. Nothing takes `&CanTopology` and then awaits I/O.
    ///
    /// Lifetime rule: an addressing value copied out (`Arc<CanEcuAddressing>`,
    /// `CanEcuConnection`) lives for one operation only - a function body or
    /// one spawned exchange - and is never stored in `self` or in a long-lived
    /// task. `CanEcuConnection` is deliberately not `Clone`. The keepalive
    /// reads the functional ID on every tick instead of keeping a copy.
    ///
    /// The trade is that an operation already in flight finishes against
    /// the addressing it started with, so `ReloadComponent::apply` can return
    /// while the old topology is still partly alive - accepted, since CAN
    /// addressing cannot be retargeted mid-frame.
    ///
    /// Discovery is not part of the topology: `discovered_ecus` stores a
    /// fingerprint of the addressing that answered and every check re-validates
    /// it against this topology, so an `apply` needs no reconciliation.
    topology: Reloadable<CanTopology>,
    /// Per ECU name (lowercase), the addressing a probe last reached it on.
    /// The ECU counts as discovered only while this matches its addressing in
    /// the current `topology`; see [`DiscoveredAs`]. Lock order: `topology`
    /// first, then this.
    discovered_ecus: Arc<RwLock<DiscoveredEcus>>,
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
    /// Receives the frames of an ECU that are not passed on as answers, which
    /// still count as replies of the ECU.
    connectivity_handler: Arc<dyn EcuConnectivityHandler>,
    /// Shared restartable lifecycle state and retained task configuration.
    lifecycle: Arc<GatewayLifecycle<CanGatewayOperation>>,
}

/// Checks whether `data`, read on the exchange of `ecu_name`, answers the
/// request with `sent_sid`. Returns `false` for a frame that does not, which
/// the caller drops as an answer; such a frame is logged and reported here as
/// a reply of the ECU (e.g. a late answer to an earlier request, or a tester
/// present NRC).
async fn check_answer_or_report(
    connectivity_handler: &dyn EcuConnectivityHandler,
    ecu_name: &str,
    sent_sid: u8,
    data: &[u8],
) -> bool {
    if cda_interfaces::util::uds_response_matches_request_sid(sent_sid, data) {
        return true;
    }
    tracing::debug!(
        data = %hex::encode(data),
        request_sid = format_args!("{sent_sid:#04x}"),
        "Dropping response not belonging to the pending request, continue reading"
    );
    connectivity_handler.on_ecu_replied(ecu_name).await;
    false
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
    /// * `connectivity_handler` - Receives the frames of an ECU that are not
    ///   passed on as answers, which still count as replies of the ECU
    ///
    /// # Returns
    /// The gateway and, separately, the sole authority to replace its
    /// topology: the gateway itself can only read what it was built with.
    /// Not named `new` precisely because it does not hand back only a `Self` -
    /// the caller cannot get one half without deciding where the other goes.
    ///
    /// `apply` is safe while the gateway is enabled. Discovery is re-validated
    /// against the current topology through its fingerprint, so an ECU whose
    /// addressing changed needs a new probe, an unchanged one stays
    /// discovered, and a removed one is never matched again.
    ///
    /// # Errors
    /// Returns [`CanGatewaySetupError`] if the configured probe sequence is
    /// unusable.
    #[tracing::instrument(
        skip(config, topology, variant_detection, connectivity_handler),
        fields(
            interface = %config.interface,
            dlt_context = dlt_ctx!("CAN"),
        )
    )]
    pub fn build(
        config: &CanConfig,
        topology: CanTopology,
        variant_detection: VariantDetectionSender,
        connectivity_handler: Arc<dyn EcuConnectivityHandler>,
    ) -> Result<(CanDiagGateway, Arc<dyn ReloadComponent<CanTopology>>), CanGatewaySetupError> {
        tracing::info!("Initializing CanDiagGateway");
        let probe_sequence = Self::build_probe_sequence(config)?;

        let reloader = Arc::new(ReloadableOwner::new(topology));
        let gateway = Self {
            interface: config.interface.clone(),
            topology: reloader.reader(),
            discovered_ecus: Arc::new(RwLock::new(DiscoveredEcus::default())),
            response_timeout: Duration::from_millis(config.response_timeout_ms),
            probe_timeout: Duration::from_millis(config.probe_timeout_ms),
            probe_retries: config.probe_retries,
            probe_retry_delay: Duration::from_millis(config.probe_retry_delay_ms),
            probe_sequence: Arc::new(probe_sequence),
            keepalive_interval: Duration::from_millis(config.keepalive_interval_ms),
            variant_detection,
            connectivity_handler,
            lifecycle: Arc::new(GatewayLifecycle::new(TransportState::Disabled)),
        };
        Ok((gateway, reloader as Arc<dyn ReloadComponent<CanTopology>>))
    }

    /// Checks if an ECU was discovered by logical address, on the addressing
    /// the current topology holds for it.
    ///
    /// Uses the topology's address lookup instead of iterating the shared ECU
    /// `RwLock`s, avoiding potential deadlocks.
    pub async fn is_ecu_discovered(&self, logical_addr: u16) -> bool {
        let topology = self.topology.read().await;
        let Some(ecu_name) = topology.ecu_for_logical_address(logical_addr) else {
            return false;
        };
        discovered_on_current(&topology, &*self.discovered_ecus.read().await, ecu_name)
    }

    /// Checks if `ecu_name` was discovered on `current`, the fingerprint of
    /// the addressing the caller resolved from the topology for this operation.
    async fn is_ecu_discovered_by_name(&self, ecu_name: &str, current: DiscoveredAs) -> bool {
        self.discovered_ecus.read().await.get(ecu_name) == Some(&current)
    }

    /// Resolves everything a probe of `ecu_name` (lowercase) needs and
    /// releases the topology guard before returning, so no caller can hold it
    /// across the probe; see `topology`.
    async fn probe_target(&self, ecu_name: &str) -> Option<(CanEcuConnection, u16)> {
        let topology = self.topology.read().await;
        let conn = topology.connection(ecu_name).map(CanEcuConnection::new)?;
        let logical_addr = topology
            .logical_address_for_ecu(ecu_name)
            .unwrap_or_default();
        Some((conn, logical_addr))
    }

    /// Probes one ECU over a connection the caller already owns, recording
    /// the outcome in `discovered_ecus` as the fingerprint of `conn`, the
    /// addressing actually probed.
    ///
    /// Takes no topology: the caller resolves `conn` and `logical_addr` first
    /// (via `probe_target`, or a snapshot such as `undiscovered_targets`) and
    /// has dropped the guard before calling, because `probe_connection` waits
    /// out `probe_timeout` x `probe_retries` plus `probe_retry_delay`; see
    /// `topology`. A success that a reload overtook records the old
    /// fingerprint, which no longer matches, so the ECU is probed again; a
    /// failure only removes a discovery made on the same addressing.
    async fn probe_and_record(
        &self,
        conn: &CanEcuConnection,
        logical_addr: u16,
        ecu_name: String,
    ) -> bool {
        let probed_as = DiscoveredAs::from(conn);
        if self.probe_connection(conn, logical_addr).await.is_ok() {
            self.discovered_ecus
                .write()
                .await
                .insert(ecu_name, probed_as);
            true
        } else {
            forget_discovery(&self.discovered_ecus, &ecu_name, probed_as).await;
            false
        }
    }

    /// Drops the discovery of every ECU the current topology no longer
    /// contains. Such entries are never matched again, but would otherwise
    /// accumulate across reloads. Lock order is topology, then
    /// `discovered_ecus`.
    async fn prune_removed_ecus(&self) {
        let topology = self.topology.read().await;
        self.discovered_ecus
            .write()
            .await
            .retain(|ecu_name, _| topology.has_connection(ecu_name));
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

        // Discovered on exactly the addressing this exchange will use.
        let sent_as = DiscoveredAs::from(&conn);
        if !self.is_ecu_discovered_by_name(&ecu_name, sent_as).await {
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
        let connectivity_handler = Arc::clone(&self.connectivity_handler);
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

                            if !check_answer_or_report(
                                connectivity_handler.as_ref(),
                                &ecu_map_key,
                                sent_sid,
                                &data,
                            )
                            .await
                            {
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
                // client aborts from striking healthy ECUs. Only the
                // discovery this exchange relied on is removed, so a task
                // that outlived a reload cannot erase one on new IDs.
                if !received_any_frame && exchange_start.elapsed() >= probe_timeout {
                    tracing::info!(
                        ecu = %ecu_name,
                        elapsed_ms =
                            u32::try_from(exchange_start.elapsed().as_millis()).unwrap_or(u32::MAX),
                        "No frame received for the whole exchange; marking the ECU undiscovered \
                         so background rediscovery re-probes it"
                    );
                    forget_discovery(&discovered_ecus, &ecu_map_key, sent_as).await;
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
        // touched. The guard is released before the probe runs.
        let Some((conn, logical_addr)) = self.probe_target(&ecu_name).await else {
            return Err(DiagServiceError::EcuOffline(ecu_name));
        };
        if self
            .is_ecu_discovered_by_name(&ecu_name, DiscoveredAs::from(&conn))
            .await
        {
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
        let addressing = topology.connection(ecu_name)?;
        if !self
            .is_ecu_discovered_by_name(ecu_name, DiscoveredAs::from(addressing.as_ref()))
            .await
        {
            return None;
        }
        Some(addressing.network_address())
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
        if discovered_on_current(&topology, &*self.discovered_ecus.read().await, &ecu_name) {
            RouteStatus::Ready
        } else {
            // CAN has a resolved ID pair and supports a bounded physical probe.
            RouteStatus::ProbeRequired
        }
    }

    async fn probe_ecu(&self, ecu_name: &str) -> bool {
        let ecu_name = ecu_name.to_lowercase();
        let Some((conn, logical_addr)) = self.probe_target(&ecu_name).await else {
            return false;
        };
        self.probe_and_record(&conn, logical_addr, ecu_name).await
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
        // The check needs one ECU to open a socket against. An empty topology
        // is an empty vehicle, not a broken interface: there is nothing to
        // address, so there is nothing to verify and no reason to refuse the
        // enable. A later update installs a real topology and this runs again
        // on the next enable. Copied out so the socket is opened without the
        // guard; see `topology`.
        let check_target = self
            .topology
            .read()
            .await
            .connections()
            .values()
            .next()
            .map(|addressing| CanEcuConnection::new(Arc::clone(addressing)));
        let socket_check = check_target.map_or(Ok(()), |conn| {
            conn.verify_socket_openable().map_err(|error| {
                CommControlError::InitFailed(format!(
                    "Failed to open CAN interface {}: {error}",
                    self.interface
                ))
            })
        });

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
                self.topology.clone(),
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
            connectivity_handler: Arc::clone(&self.connectivity_handler),
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

    /// Records `ecu_name` as discovered on `addressing`, as a probe reaching
    /// it there would.
    async fn seed_discovered(&self, ecu_name: &str, addressing: &CanEcuAddressing) {
        self.discovered_ecus
            .write()
            .await
            .insert(ecu_name.to_lowercase(), DiscoveredAs::from(addressing));
    }

    /// The names with a recorded discovery, whether or not it still matches.
    async fn discovered_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.discovered_ecus.read().await.keys().cloned().collect();
        names.sort();
        names
    }

    /// Builds a gateway instance for unit tests without touching any CAN
    /// interface: no init check, no discovery, keep-alive disabled.
    pub(crate) fn test_instance(
        topology: CanTopology,
        discovered: Vec<&str>,
        connectivity_handler: Arc<dyn EcuConnectivityHandler>,
    ) -> Self {
        Self::reloadable_test_instance(topology, discovered, connectivity_handler).0
    }

    /// [`Self::test_instance`] plus the authority to replace its topology, for
    /// applying a reload to a gateway that is `Enabled`.
    ///
    /// Each name in `discovered` is recorded as discovered on its addressing
    /// in `topology`; a name the topology does not contain panics.
    fn reloadable_test_instance(
        topology: CanTopology,
        discovered: Vec<&str>,
        connectivity_handler: Arc<dyn EcuConnectivityHandler>,
    ) -> (Self, Arc<dyn ReloadComponent<CanTopology>>) {
        let discovered: DiscoveredEcus = discovered
            .into_iter()
            .map(|name| {
                let name = name.to_lowercase();
                let addressing = topology
                    .connection(&name)
                    .unwrap_or_else(|| panic!("discovered test ECU {name} is not in the topology"));
                let discovered_as = DiscoveredAs::from(addressing.as_ref());
                (name, discovered_as)
            })
            .collect();
        let owner = Arc::new(ReloadableOwner::new(topology));
        let gateway = Self {
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
            connectivity_handler,
            lifecycle: Arc::new(GatewayLifecycle::new(TransportState::Enabled)),
        };
        (gateway, owner as Arc<dyn ReloadComponent<CanTopology>>)
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use std::sync::Arc;

    use cda_interfaces::CanId;

    use crate::{CanEcuAddressing, CanTopology, config::CanAddressingMode};

    /// Longer than the 15 character interface name limit, so no backend can
    /// resolve it and opening a socket fails immediately (no daemon connect).
    pub(crate) const UNOPENABLE_INTERFACE: &str = "cda-test-does-not-exist0";

    /// A topology with one ECU on [`UNOPENABLE_INTERFACE`]: `enable()` fails at
    /// its socket check before any discovery or bus I/O.
    pub(crate) fn unopenable_interface_topology() -> CanTopology {
        shared_topology(vec![(
            "ecu1",
            CanEcuAddressing::new(
                "ecu1".to_owned(),
                UNOPENABLE_INTERFACE.to_owned(),
                CanId::try_from(0x700).expect("valid test CAN ID"),
                CanId::try_from(0x708).expect("valid test CAN ID"),
                CanAddressingMode::Standard,
            ),
        )])
    }

    pub(crate) fn shared_topology(connections: Vec<(&str, CanEcuAddressing)>) -> CanTopology {
        let connections = connections
            .into_iter()
            .map(|(name, addressing)| (name.to_lowercase(), Arc::new(addressing)))
            .collect();
        CanTopology::new(
            connections,
            cda_interfaces::HashMap::default(),
            cda_interfaces::HashMap::default(),
            cda_interfaces::CanId::try_from(0x7DF).expect("valid test CAN ID"),
        )
    }
}

#[cfg(test)]
mod tests {
    use cda_interfaces::{CanId, HashMap};

    use super::{
        test_utils::{UNOPENABLE_INTERFACE, shared_topology, unopenable_interface_topology},
        *,
    };

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
                            crate::config::CanAddressingMode::Standard,
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
            Arc::new(cda_interfaces::util::test_utils::RecordingConnectivityHandler::default()),
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
            Arc::new(cda_interfaces::util::test_utils::RecordingConnectivityHandler::default()),
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

    /// Changing an existing ECU's CAN IDs must reach the live gateway, and its
    /// discovery on the old IDs must not carry over to the new ones.
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
            Arc::new(cda_interfaces::util::test_utils::RecordingConnectivityHandler::default()),
        )
        .expect("build test gateway");
        gateway
            .seed_discovered("ecu1", &addressing("ecu1", 0x700, 0x708))
            .await;
        assert_eq!(gateway.route_status("ecu1").await, RouteStatus::Ready);

        let before = gateway.get_ecu_network_address("ecu1").await;

        reload
            .apply(topology_with(vec![("ecu1", 0x7E0, 0x7E8)]))
            .await;

        let after = gateway.get_ecu_network_address("ecu1").await;
        assert!(after.is_some());
        assert_ne!(before, after);
        assert_eq!(
            gateway.route_status("ecu1").await,
            RouteStatus::ProbeRequired
        );
        let targets = gateway.undiscovered_targets().await;
        assert_eq!(
            targets
                .iter()
                .map(|(name, conn, _)| (name.as_str(), conn.network_address()))
                .collect::<Vec<_>>(),
            vec![("ecu1", after.expect("checked above"))],
            "rediscovery must re-probe ecu1 on its new IDs"
        );
    }

    const ECU1_ADDRESS: u16 = 0x1000;
    const ECU2_ADDRESS: u16 = 0x2000;

    fn addressing(name: &str, request: u32, response: u32) -> CanEcuAddressing {
        CanEcuAddressing::new(
            name.to_owned(),
            "test0".to_owned(),
            CanId::try_from(request).expect("valid test CAN ID"),
            CanId::try_from(response).expect("valid test CAN ID"),
            CanAddressingMode::Standard,
        )
    }

    /// Like `topology_with`, plus each ECU's logical address, for the
    /// address-based lookups.
    fn addressed_topology(ecus: Vec<(CanEcuAddressing, u16)>) -> CanTopology {
        let mut connections = HashMap::default();
        let mut logical_address_to_ecu = HashMap::default();
        let mut ecu_to_logical_address = HashMap::default();
        for (addressing, logical_address) in ecus {
            let name = addressing.ecu_name.to_lowercase();
            logical_address_to_ecu.insert(logical_address, name.clone());
            ecu_to_logical_address.insert(name.clone(), logical_address);
            connections.insert(name, Arc::new(addressing));
        }
        CanTopology::new(
            connections,
            logical_address_to_ecu,
            ecu_to_logical_address,
            CanId::try_from(0x7DF).expect("valid test CAN ID"),
        )
    }

    fn handler() -> Arc<dyn EcuConnectivityHandler> {
        Arc::new(cda_interfaces::util::test_utils::RecordingConnectivityHandler::default())
    }

    async fn send_to_ecu1(
        gateway: &CanDiagGateway,
    ) -> Result<tokio::task::JoinHandle<()>, DiagServiceError> {
        let (response_sender, _response_receiver) = mpsc::channel(1);
        gateway
            .send(
                TransmissionParameters {
                    gateway_address: ECU1_ADDRESS,
                    timeout_ack: Duration::from_millis(100),
                    ecu_name: "ecu1".to_owned(),
                    repeat_request_count_transmission: 0,
                },
                ServicePayload {
                    data: vec![0x3E, 0x00],
                    source_address: 0x0E80,
                    target_address: ECU1_ADDRESS,
                    new_session: None,
                    new_security: None,
                },
                response_sender,
                true,
            )
            .await
    }

    /// An ECU discovered on 0x700/0x708 whose IDs an `apply` on the enabled
    /// gateway changes is not discovered on the new IDs: every check reports
    /// it as needing a probe, and a send is rejected before reaching the bus.
    #[tokio::test]
    async fn changed_ids_of_a_discovered_ecu_require_a_new_probe() {
        let (gateway, reload) = CanDiagGateway::reloadable_test_instance(
            addressed_topology(vec![(addressing("ecu1", 0x700, 0x708), ECU1_ADDRESS)]),
            vec!["ecu1"],
            handler(),
        );
        assert_eq!(gateway.state().await, TransportState::Enabled);
        assert_eq!(gateway.route_status("ecu1").await, RouteStatus::Ready);
        assert!(gateway.is_ecu_discovered(ECU1_ADDRESS).await);
        assert!(
            gateway
                .get_gateway_network_address(ECU1_ADDRESS)
                .await
                .is_some()
        );

        reload
            .apply(addressed_topology(vec![(
                addressing("ecu1", 0x7E0, 0x7E8),
                ECU1_ADDRESS,
            )]))
            .await;

        assert_eq!(
            gateway.route_status("ecu1").await,
            RouteStatus::ProbeRequired
        );
        assert!(!gateway.is_ecu_discovered(ECU1_ADDRESS).await);
        assert_eq!(
            gateway.get_gateway_network_address(ECU1_ADDRESS).await,
            None
        );
        assert!(matches!(
            send_to_ecu1(&gateway).await,
            Err(DiagServiceError::EcuOffline(name)) if name == "ecu1"
        ));
    }

    /// The address-extension byte selects which ECU answers on a shared ID
    /// pair, so changing only it also requires a new probe.
    #[tokio::test]
    async fn changed_address_extension_requires_a_new_probe() {
        let (gateway, reload) = CanDiagGateway::reloadable_test_instance(
            topology_with(vec![("ecu1", 0x700, 0x708)]),
            vec!["ecu1"],
            handler(),
        );

        let mut extended = addressing("ecu1", 0x700, 0x708);
        extended.addressing_mode = CanAddressingMode::Extended(0xF1);
        reload
            .apply(shared_topology(vec![("ecu1", extended)]))
            .await;

        assert_eq!(
            gateway.route_status("ecu1").await,
            RouteStatus::ProbeRequired
        );
    }

    /// A new topology with the same addressing for an ECU keeps it discovered:
    /// no false offline period after an `apply` that did not change it.
    #[tokio::test]
    async fn identical_addressing_stays_discovered_across_apply() {
        let (gateway, reload) = CanDiagGateway::reloadable_test_instance(
            addressed_topology(vec![(addressing("ecu1", 0x700, 0x708), ECU1_ADDRESS)]),
            vec!["ecu1"],
            handler(),
        );

        reload
            .apply(addressed_topology(vec![(
                addressing("ecu1", 0x700, 0x708),
                ECU1_ADDRESS,
            )]))
            .await;

        assert_eq!(gateway.route_status("ecu1").await, RouteStatus::Ready);
        assert!(gateway.is_ecu_discovered(ECU1_ADDRESS).await);
        assert_eq!(
            gateway.get_gateway_network_address(ECU1_ADDRESS).await,
            Some(addressing("ecu1", 0x700, 0x708).network_address())
        );
        assert!(gateway.undiscovered_targets().await.is_empty());
        send_to_ecu1(&gateway)
            .await
            .expect("a discovered ECU is sent to")
            .abort();
    }

    /// A removed ECU is not configured and matches nothing; its entry stays
    /// until the next rediscovery round prunes it, which keeps the entries of
    /// ECUs still in the topology.
    #[tokio::test]
    async fn removed_ecu_is_not_configured_and_pruned() {
        let (gateway, reload) = CanDiagGateway::reloadable_test_instance(
            addressed_topology(vec![
                (addressing("ecu1", 0x700, 0x708), ECU1_ADDRESS),
                (addressing("ecu2", 0x710, 0x718), ECU2_ADDRESS),
            ]),
            vec!["ecu1", "ecu2"],
            handler(),
        );

        reload
            .apply(addressed_topology(vec![(
                addressing("ecu2", 0x710, 0x718),
                ECU2_ADDRESS,
            )]))
            .await;

        assert_eq!(
            gateway.route_status("ecu1").await,
            RouteStatus::NotConfigured
        );
        assert!(!gateway.is_ecu_discovered(ECU1_ADDRESS).await);
        assert_eq!(
            gateway.get_gateway_network_address(ECU1_ADDRESS).await,
            None
        );
        assert!(matches!(
            send_to_ecu1(&gateway).await,
            Err(DiagServiceError::EcuOffline(_))
        ));
        assert_eq!(gateway.route_status("ecu2").await, RouteStatus::Ready);
        assert_eq!(gateway.discovered_names().await, ["ecu1", "ecu2"]);

        gateway.prune_removed_ecus().await;
        assert_eq!(gateway.discovered_names().await, ["ecu2"]);

        // Pruned, so re-adding it even on the same IDs needs a probe.
        reload
            .apply(addressed_topology(vec![
                (addressing("ecu1", 0x700, 0x708), ECU1_ADDRESS),
                (addressing("ecu2", 0x710, 0x718), ECU2_ADDRESS),
            ]))
            .await;
        assert_eq!(
            gateway.route_status("ecu1").await,
            RouteStatus::ProbeRequired
        );
        assert_eq!(gateway.route_status("ecu2").await, RouteStatus::Ready);
    }

    /// The silent-exchange path removes only the discovery its exchange used:
    /// one on IDs a reload has since replaced leaves the newer one alone.
    #[tokio::test]
    async fn forgetting_an_older_discovery_keeps_a_newer_one() {
        let discovered = RwLock::new(DiscoveredEcus::default());
        let older = DiscoveredAs::from(&addressing("ecu1", 0x700, 0x708));
        let newer = DiscoveredAs::from(&addressing("ecu1", 0x7E0, 0x7E8));
        discovered.write().await.insert("ecu1".to_owned(), newer);

        forget_discovery(&discovered, "ecu1", older).await;
        assert_eq!(discovered.read().await.get("ecu1"), Some(&newer));

        forget_discovery(&discovered, "ecu1", newer).await;
        assert!(discovered.read().await.is_empty());
    }

    /// A failed probe on addressing a reload has replaced must not remove the
    /// discovery made on the new addressing; on the same addressing it does.
    #[tokio::test]
    async fn failed_probe_removes_only_its_own_discovery() {
        let gateway =
            CanDiagGateway::test_instance(unopenable_interface_topology(), vec![], handler());
        let (conn, logical_addr) = gateway
            .probe_target("ecu1")
            .await
            .expect("ecu1 is in the topology");
        let newer = addressing("ecu1", 0x7E0, 0x7E8);
        gateway.seed_discovered("ecu1", &newer).await;

        let probed = tokio::time::timeout(
            Duration::from_secs(2),
            gateway.probe_and_record(&conn, logical_addr, "ecu1".to_owned()),
        )
        .await
        .expect("a probe on an unopenable interface fails fast");
        assert!(!probed);
        assert_eq!(
            gateway.discovered_ecus.read().await.get("ecu1"),
            Some(&DiscoveredAs::from(&newer))
        );

        gateway.seed_discovered("ecu1", conn.addressing()).await;
        let probed = tokio::time::timeout(
            Duration::from_secs(2),
            gateway.probe_and_record(&conn, logical_addr, "ecu1".to_owned()),
        )
        .await
        .expect("a probe on an unopenable interface fails fast");
        assert!(!probed);
        assert!(gateway.discovered_names().await.is_empty());
    }

    fn marker_topology(id: u32) -> CanTopology {
        CanTopology::new(
            HashMap::default(),
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
            Arc::new(cda_interfaces::util::test_utils::RecordingConnectivityHandler::default()),
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

    /// An ECU whose interface cannot be opened fails `enable()` at the socket
    /// check: no background task may be left running and the gateway is
    /// `Failed`.
    #[tokio::test]
    async fn enable_fails_when_the_ecu_interface_cannot_be_opened() {
        let gateway = CanDiagGateway::test_instance(
            unopenable_interface_topology(),
            vec![],
            Arc::new(cda_interfaces::util::test_utils::RecordingConnectivityHandler::default()),
        );
        gateway.disable().await.expect("disable test CAN gateway");

        let result = tokio::time::timeout(Duration::from_secs(2), gateway.enable())
            .await
            .expect("enable must fail fast, not wait on the interface");

        let Err(CommControlError::InitFailed(message)) = result else {
            panic!("expected InitFailed, got {result:?}");
        };
        assert!(
            message.contains(UNOPENABLE_INTERFACE),
            "message should name the interface: {message}"
        );
        assert_eq!(gateway.state().await, TransportState::Failed);
        let operation = gateway.lifecycle.operation.lock().await;
        assert!(operation.keepalive.is_none());
        assert!(operation.rediscovery.is_none());
    }

    /// An empty topology is an empty vehicle, not a broken interface: there is
    /// nothing to open a socket for, so `enable()` succeeds.
    #[tokio::test]
    async fn enable_succeeds_with_an_empty_topology() {
        let gateway = CanDiagGateway::test_instance(
            shared_topology(vec![]),
            vec![],
            Arc::new(cda_interfaces::util::test_utils::RecordingConnectivityHandler::default()),
        );
        gateway.disable().await.expect("disable test CAN gateway");

        tokio::time::timeout(Duration::from_secs(2), gateway.enable())
            .await
            .expect("enable must not block")
            .expect("an empty topology enables");

        assert_eq!(gateway.state().await, TransportState::Enabled);
        assert!(gateway.discover_ecus().await.is_empty());

        gateway.disable().await.expect("disable stops rediscovery");
        assert_eq!(gateway.state().await, TransportState::Disabled);
    }

    /// A probe against an ECU nobody answers must not keep the topology
    /// locked: a reload and the lookups queued behind it complete while the
    /// probe is still waiting out its timeout.
    ///
    /// Needs `can-socketcand`: opening a socketcand port succeeds at once and
    /// the daemon connection is made in the background, so the probe really
    /// waits for `probe_timeout` without a daemon or a bus. A nonexistent
    /// kernel interface would fail the open immediately and prove nothing.
    #[cfg(feature = "can-socketcand")]
    #[tokio::test]
    async fn reload_and_lookups_do_not_wait_for_an_inflight_probe() {
        const INTERFACE: &str = "socketcand:127.0.0.1:29536:vcan0";
        const BOUND: Duration = Duration::from_millis(200);

        let unanswered = shared_topology(vec![(
            "ecu1",
            CanEcuAddressing::new(
                "ecu1".to_owned(),
                INTERFACE.to_owned(),
                CanId::try_from(0x6F0).expect("valid test CAN ID"),
                CanId::try_from(0x6F8).expect("valid test CAN ID"),
                crate::config::CanAddressingMode::Standard,
            ),
        )]);
        let (gateway, reload) = CanDiagGateway::build(
            &CanConfig {
                interface: INTERFACE.to_owned(),
                probe_timeout_ms: 2_000,
                probe_retries: 0,
                ..CanConfig::default()
            },
            unanswered,
            VariantDetectionSender::new(mpsc::channel(1).0),
            Arc::new(cda_interfaces::util::test_utils::RecordingConnectivityHandler::default()),
        )
        .expect("build test gateway");

        let probing = gateway.clone();
        let probe = tokio::spawn(async move { probing.probe_ecu("ecu1").await });
        // Lets the probe resolve its target and get onto the bus.
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(50)).await;
        assert!(!probe.is_finished(), "the probe must still be waiting");

        tokio::time::timeout(
            BOUND,
            reload.apply(topology_with(vec![("ecu2", 0x710, 0x718)])),
        )
        .await
        .expect("apply must not wait for the in-flight probe");
        let status = tokio::time::timeout(BOUND, gateway.route_status("ecu2"))
            .await
            .expect("route_status must not wait for the in-flight probe");

        assert_eq!(status, RouteStatus::ProbeRequired);
        assert!(
            !probe.is_finished(),
            "the probe must still be in flight, otherwise this proves nothing"
        );
        probe.abort();
    }

    /// A frame with another SID (here a tester present NRC) is dropped as the
    /// answer but reported as a reply of the ECU; the answer is not reported.
    #[tokio::test]
    async fn frame_with_other_sid_is_dropped_and_reported_as_reply() {
        let handler = cda_interfaces::util::test_utils::RecordingConnectivityHandler::default();

        assert!(!check_answer_or_report(&handler, "ecu1", 0x22, &[0x7F, 0x3E, 0x12]).await);
        assert!(check_answer_or_report(&handler, "ecu1", 0x22, &[0x62, 0xF1, 0x90]).await);

        assert_eq!(handler.replied(), vec!["ecu1".to_owned()]);
    }
}
