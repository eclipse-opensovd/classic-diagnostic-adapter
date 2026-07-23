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

use std::{sync::Arc, time::Duration};

use cda_interfaces::{
    CanComParamProvider, CanId, DiagServiceError, EcuAddresses, EcuGateway, HashMap,
    ServicePayload, TransmissionParameters, UdsResponse, dlt_ctx,
};
use tokio::sync::{RwLock, mpsc};

use self::{
    background::BackgroundTask,
    connection::CanEcuConnection,
    error::{CanError, CanGatewaySetupError},
    probe::ProbeRequest,
};
use crate::config::CanConfig;

const NRC_RESPONSE_PENDING: u8 = 0x78;

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
    /// Map of ECU name (lowercase) to CAN connection info. Never written
    /// after construction, so no lock is needed.
    connections: Arc<HashMap<String, Arc<CanEcuConnection>>>,
    /// Set of ECU names that responded to discovery
    discovered_ecus: Arc<RwLock<cda_interfaces::HashSet<String>>>,
    /// Owned mapping from logical address to ECU name (lowercase).
    /// Populated once during construction so that runtime lookups never
    /// need to touch the shared ECU `RwLock`s.
    logical_address_to_ecu: Arc<HashMap<u16, String>>,
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
    /// Keep-alive broadcast handle; `None` when disabled via
    /// `keepalive_interval_ms = 0`. Stopped in [`EcuGateway::shutdown`];
    /// dropping the last clone aborts the task as a fallback.
    keepalive_handle: Option<Arc<BackgroundTask>>,
    /// Rediscovery task handle; empty only in unit-test instances. Set once
    /// right after construction (the task needs a gateway clone, so it
    /// cannot be spawned before the struct exists).
    rediscovery_handle: Arc<std::sync::OnceLock<BackgroundTask>>,
}

impl CanDiagGateway {
    /// Creates a new CAN diagnostic gateway.
    ///
    /// This constructor sets up the gateway and performs initial ECU discovery.
    /// Discovered ECUs are sent through the `variant_detection` channel to trigger
    /// variant detection.
    ///
    /// The shared `ecus` map is only borrowed during construction to extract
    /// CAN IDs and build an owned address-to-name lookup table. It is **not**
    /// stored, so no runtime `RwLock` contention with the UDS layer can occur.
    ///
    /// # Arguments
    /// * `config` - CAN configuration
    /// * `ecus` - Map of ECU names to ECU managers (borrowed, not stored)
    /// * `variant_detection` - Channel to notify about discovered ECUs
    ///
    /// # Errors
    /// Returns error if the CAN interface cannot be opened or configured.
    #[tracing::instrument(
        skip(config, ecus, variant_detection),
        fields(
            interface = %config.interface,
            ecu_count = ecus.len(),
            dlt_context = dlt_ctx!("CAN"),
        )
    )]
    pub async fn new<T: EcuAddresses + CanComParamProvider>(
        config: &CanConfig,
        ecus: &HashMap<String, RwLock<T>>,
        variant_detection: mpsc::Sender<Vec<String>>,
    ) -> Result<Self, CanGatewaySetupError> {
        tracing::info!("Initializing CanDiagGateway");

        let probe_sequence = Self::build_probe_sequence(config)?;

        // Functional broadcast ID for the TesterPresent keep-alive: prefer the
        // MDD com-params (CP_CanFuncReqId), fall back to the ISO 15765-4
        // default 0x7DF. May be an 11-bit standard or a 29-bit extended ID
        // (e.g. 0x18DB33F1 for normal fixed addressing). Resolved before the
        // connections so their IDs can be checked against it.
        let mut functional_id = Self::validate_can_id(
            "<functional>",
            "default",
            keepalive::DEFAULT_FUNCTIONAL_BROADCAST_ID,
        )?;
        for ecu_lock in ecus.values() {
            // Already range-validated at MDD extraction.
            if let Some(id) = ecu_lock.read().await.can_functional_id() {
                functional_id = id;
                break;
            }
        }

        let mut connections: HashMap<String, Arc<CanEcuConnection>> = HashMap::default();
        let mut logical_address_to_ecu: HashMap<u16, String> = HashMap::default();

        // Initialize connections from explicit mappings first
        for mapping in &config.ecu_mappings {
            let request_id =
                Self::validate_can_id(&mapping.ecu_name, "request_id", mapping.request_id)?;
            let response_id =
                Self::validate_can_id(&mapping.ecu_name, "response_id", mapping.response_id)?;
            // Reserved IDs (broadcast, keep-alive RX) cannot address an
            // ECU; config values are user-controlled, so fail setup.
            for (field, id) in [("request_id", request_id), ("response_id", response_id)] {
                if Self::is_reserved_can_id(id, functional_id) {
                    return Err(CanGatewaySetupError::InvalidConfiguration(format!(
                        "ECU {}: {field} {id} collides with the functional broadcast ID \
                         ({functional_id}) or a reserved keep-alive ID",
                        mapping.ecu_name
                    )));
                }
            }
            let ecu_name = mapping.ecu_name.to_lowercase();
            if let Some(ecu_lock) = ecus.get(&ecu_name) {
                let ecu = ecu_lock.read().await;
                let logical_addr = ecu.logical_address();

                let conn = CanEcuConnection::new(
                    mapping.ecu_name.clone(),
                    config.interface.clone(),
                    request_id,
                    response_id,
                );

                tracing::debug!(
                    ecu = %mapping.ecu_name,
                    logical_addr = logical_addr,
                    request_id = %request_id,
                    response_id = %response_id,
                    "Added CAN connection from config mapping"
                );

                Self::register_logical_address(
                    &mut logical_address_to_ecu,
                    logical_addr,
                    &ecu_name,
                );
                connections.insert(ecu_name, Arc::new(conn));
            } else {
                tracing::warn!(
                    ecu = %mapping.ecu_name,
                    "ECU mapping specified but ECU not found in database"
                );
            }
        }

        Self::add_connections_from_com_params(
            config,
            ecus,
            functional_id,
            &mut connections,
            &mut logical_address_to_ecu,
        )
        .await;

        Self::validate_can_pins(config, ecus, &connections)?;

        // Fail fast on configurations that cannot work: a [can] section with
        // no usable ECU addressing means every request would fail at runtime
        // with nothing pointing at the actual mistake.
        if connections.is_empty() {
            return Err(CanGatewaySetupError::NoEcuMappings);
        }

        // Fail fast when the CAN interface itself is unusable (interface
        // missing, vcan module not loaded, socketcand unreachable). Opening a
        // socket for a real connection exercises the exact same path every
        // later request uses.
        if let Some(conn) = connections.values().next() {
            conn.verify_socket_openable().map_err(|e| {
                CanGatewaySetupError::InterfaceOpenFailed(config.interface.clone(), e.to_string())
            })?;
        }

        // Keeps ECUs awake while CDA runs; disabled (= 0) for resident
        // deployments, see CanConfig::keepalive_interval_ms.
        let keepalive_handle = if config.keepalive_interval_ms == 0 {
            tracing::info!("Functional broadcast keep-alive disabled by config");
            None
        } else {
            Some(Arc::new(keepalive::start_keepalive_broadcast(
                config.interface.clone(),
                functional_id,
                Duration::from_millis(config.keepalive_interval_ms),
            )))
        };

        let gateway = Self {
            interface: config.interface.clone(),
            connections: Arc::new(connections),
            discovered_ecus: Arc::new(RwLock::new(cda_interfaces::HashSet::default())),
            logical_address_to_ecu: Arc::new(logical_address_to_ecu),
            response_timeout: Duration::from_millis(config.response_timeout_ms),
            probe_timeout: Duration::from_millis(config.probe_timeout_ms),
            probe_retries: config.probe_retries,
            probe_retry_delay: Duration::from_millis(config.probe_retry_delay_ms),
            probe_sequence: Arc::new(probe_sequence),
            keepalive_handle,
            rediscovery_handle: Arc::new(std::sync::OnceLock::new()),
        };

        // Perform initial discovery
        let discovered = gateway.discover_ecus().await;
        if discovered.is_empty() {
            tracing::info!("No ECUs discovered on CAN bus during initial probe");
        } else {
            tracing::info!(
                discovered_count = discovered.len(),
                ecus = ?discovered,
                "Initial CAN ECU discovery complete"
            );
            // Send discovered ECUs to trigger variant detection
            if let Err(e) = variant_detection.send(discovered).await {
                tracing::warn!(
                    error = %e,
                    "Failed to send variant detection notification"
                );
            }
        }

        // Start after the initial sweep so the two never probe concurrently.
        let _ = gateway
            .rediscovery_handle
            .set(gateway.start_rediscovery(variant_detection));

        Ok(gateway)
    }

    /// Adds connections for ECUs whose CAN addressing comes from the MDD
    /// com-params (ECUs with an explicit `[[can.ecu_mappings]]` entry are
    /// skipped - config overrides the database).
    ///
    /// Unlike config mappings, database values are not under the user's
    /// control, so a bad value skips the ECU (with a warning) instead of
    /// failing setup: one malformed MDD must not take down diagnostics for
    /// the whole vehicle. Several ECU descriptions may legitimately share
    /// one ID pair - candidate models of the same physical node (e.g. the
    /// radio variants of a duplicate group); each gets its own connection
    /// and variant detection decides which one is actually installed,
    /// exactly like `DoIP` address duplicates.
    async fn add_connections_from_com_params<T: EcuAddresses + CanComParamProvider>(
        config: &CanConfig,
        ecus: &HashMap<String, RwLock<T>>,
        functional_id: CanId,
        connections: &mut HashMap<String, Arc<CanEcuConnection>>,
        logical_address_to_ecu: &mut HashMap<u16, String>,
    ) {
        for (name, ecu_lock) in ecus {
            let ecu = ecu_lock.read().await;
            let logical_addr = ecu.logical_address();
            let ecu_name = name.to_lowercase();

            if connections.contains_key(&ecu_name) {
                continue;
            }
            // Normal for DoIP-only ECUs in a mixed fleet, so debug level;
            // an all-miss CAN-only setup still fails via NoEcuMappings.
            let Some(ids) = ecu.can_ids() else {
                tracing::debug!(
                    ecu = %name,
                    "No CAN addressing in MDD com-params and no [[can.ecu_mappings]] entry, \
                     ECU gets no CAN connection"
                );
                continue;
            };

            if ids.request == ids.response {
                tracing::warn!(
                    ecu = %name,
                    can_id = %ids.request,
                    "MDD CAN addressing uses the same ID for request and response, skipping \
                     this ECU (a [[can.ecu_mappings]] entry can override)"
                );
                continue;
            }
            // Same reserved-ID rule, but MDD values are not
            // user-controlled: warn and skip instead of failing setup.
            if Self::is_reserved_can_id(ids.request, functional_id)
                || Self::is_reserved_can_id(ids.response, functional_id)
            {
                tracing::warn!(
                    ecu = %name,
                    request_id = %ids.request,
                    response_id = %ids.response,
                    functional_id = %functional_id,
                    "MDD CAN addressing collides with the functional broadcast ID or a \
                     reserved keep-alive ID, skipping this ECU (a [[can.ecu_mappings]] entry \
                     can override)"
                );
                continue;
            }
            let conn = CanEcuConnection::new(
                name.clone(),
                config.interface.clone(),
                ids.request,
                ids.response,
            );
            tracing::debug!(
                ecu = %name,
                logical_addr = logical_addr,
                request_id = %ids.request,
                response_id = %ids.response,
                "Added CAN connection from MDD COM params"
            );
            Self::register_logical_address(logical_address_to_ecu, logical_addr, &ecu_name);
            connections.insert(ecu_name, Arc::new(conn));
        }
    }

    /// Transport pins to CAN are validated here rather than in the config
    /// sanity check: whether an ECU has CAN addressing may only be known
    /// once the database is loaded (MDD com-params), which the config layer
    /// cannot see.
    ///
    /// A pin for an ECU that is not in the loaded database at all is moot,
    /// not an error: the configuration legitimately outlives the currently
    /// loaded fleet (runtime file updates add and remove ECU databases while
    /// the config stays put), and an absent ECU has no routes the pin could
    /// misdirect.
    fn validate_can_pins<T>(
        config: &CanConfig,
        ecus: &HashMap<String, RwLock<T>>,
        connections: &HashMap<String, Arc<CanEcuConnection>>,
    ) -> Result<(), CanGatewaySetupError> {
        for pinned in config
            .transport_overrides
            .iter()
            .filter(|o| o.transport == crate::multi_transport::TransportType::Can)
        {
            let ecu_name = pinned.ecu_name.to_lowercase();
            if connections.contains_key(&ecu_name) {
                continue;
            }
            if !ecus.contains_key(&ecu_name) {
                tracing::debug!(
                    ecu = %pinned.ecu_name,
                    "Transport pin to CAN for an ECU without a loaded database, ignoring"
                );
                continue;
            }
            return Err(CanGatewaySetupError::InvalidConfiguration(format!(
                "transport_overrides pins ECU '{}' to CAN, but it has neither a \
                 [[can.ecu_mappings]] entry nor CAN addressing in its MDD com-params",
                pinned.ecu_name
            )));
        }
        Ok(())
    }

    /// Records the logical-address -> ECU lookup used by the
    /// address-oriented `EcuGateway` methods (network structure, discovery
    /// checks). ECUs of CAN-only databases have no `DoIP` addressing and all
    /// carry the unresolved fallback address `0x0000` - registering that
    /// would map the shared "address" onto whichever ECU came last, so those
    /// ECUs stay unregistered here and are served by the name-based paths
    /// only.
    fn register_logical_address(
        logical_address_to_ecu: &mut HashMap<u16, String>,
        logical_addr: u16,
        ecu_name: &str,
    ) {
        if logical_addr == 0 {
            tracing::debug!(
                ecu = %ecu_name,
                "No resolved logical address; ECU reachable via name-based lookups only"
            );
            return;
        }
        logical_address_to_ecu.insert(logical_addr, ecu_name.to_owned());
    }

    /// IDs no ECU pair may use: the functional broadcast ID and the
    /// reserved RX IDs backing the keep-alive socket.
    fn is_reserved_can_id(id: CanId, functional_id: CanId) -> bool {
        id == functional_id
            || id.raw() == keepalive::UNUSED_RX_ID_STANDARD
            || id.raw() == keepalive::UNUSED_RX_ID_EXTENDED
    }

    /// Converts a raw configured/com-param CAN ID into a validated [`CanId`]
    /// at setup time, attaching the ECU/field context to range errors. Both
    /// 11-bit standard and 29-bit extended (e.g. ISO 15765-4 normal fixed
    /// addressing `0x18DA10F1`) identifiers are accepted.
    fn validate_can_id(
        ecu_name: &str,
        field: &str,
        id: u32,
    ) -> Result<CanId, CanGatewaySetupError> {
        CanId::try_from(id).map_err(|e| {
            CanGatewaySetupError::InvalidConfiguration(format!("ECU {ecu_name}: {field}: {e}"))
        })
    }

    /// Checks if an ECU was discovered by logical address.
    ///
    /// Uses the owned `logical_address_to_ecu` map instead of iterating the
    /// shared ECU `RwLock`s, avoiding potential deadlocks.
    pub async fn is_ecu_discovered(&self, logical_addr: u16) -> bool {
        if let Some(ecu_name) = self.logical_address_to_ecu.get(&logical_addr) {
            return self.discovered_ecus.read().await.contains(ecu_name);
        }
        false
    }

    /// Resolves a logical address to an ECU name from the owned lookup table.
    fn logical_address_for_ecu(&self, ecu_name: &str) -> u16 {
        self.logical_address_to_ecu
            .iter()
            .find_map(|(addr, name)| if name == ecu_name { Some(*addr) } else { None })
            .unwrap_or(0)
    }

    /// Checks if a specific ECU was discovered (responded to probe).
    pub(crate) async fn is_ecu_discovered_by_name(&self, ecu_name: &str) -> bool {
        self.discovered_ecus.read().await.contains(ecu_name)
    }

    /// Returns whether this gateway has CAN addressing for the ECU
    /// (regardless of whether the ECU answered a probe yet).
    pub(crate) fn knows_ecu(&self, ecu_name: &str) -> bool {
        self.connections.contains_key(ecu_name)
    }

    /// Gets a connection for the given ECU name.
    fn get_connection(&self, ecu_name: &str) -> Option<Arc<CanEcuConnection>> {
        self.connections.get(ecu_name).cloned()
    }
}

impl EcuGateway for CanDiagGateway {
    async fn shutdown(&mut self) {
        // CAN uses per-transaction ISO-TP sockets (no long-lived connection
        // tasks); only the broadcast keep-alive and the rediscovery loop run
        // in the background. Rediscovery first: it holds a gateway clone, so
        // awaiting it here also breaks that reference cycle.
        if let Some(rediscovery) = self.rediscovery_handle.get() {
            rediscovery.shutdown().await;
        }
        if let Some(ref keepalive) = self.keepalive_handle {
            keepalive.shutdown().await;
        }
    }

    async fn get_gateway_network_address(&self, logical_address: u16) -> Option<String> {
        let ecu_name = self.logical_address_to_ecu.get(&logical_address)?;
        if !self.is_ecu_discovered_by_name(ecu_name).await {
            return None;
        }
        self.connections
            .get(ecu_name)
            .map(|conn| conn.network_address())
    }

    #[tracing::instrument(skip_all, fields(
        ecu = %transmission_params.ecu_name,
        gateway_addr = transmission_params.gateway_address,
        dlt_context = dlt_ctx!("CAN"),
    ))]
    async fn send(
        &self,
        transmission_params: TransmissionParameters,
        message: ServicePayload,
        response_sender: mpsc::Sender<Result<Option<UdsResponse>, DiagServiceError>>,
        expect_uds_reply: bool,
    ) -> Result<(), DiagServiceError> {
        let ecu_name = transmission_params.ecu_name.to_lowercase();
        let conn = self
            .get_connection(&ecu_name)
            .ok_or_else(|| DiagServiceError::EcuOffline(transmission_params.ecu_name.clone()))?;

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

        cda_interfaces::spawn_named!(&format!("can-send-{ecu_name}"), {
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
                            let is_negative = data.first()
                                == Some(&cda_interfaces::service_ids::NEGATIVE_RESPONSE);
                            if is_negative
                                && data.len() >= 3
                                && data.get(2) == Some(&NRC_RESPONSE_PENDING)
                            {
                                // NRC 0x78 (Response Pending): typed so the
                                // UDS layer applies its completion policy;
                                // the next response arrives on this socket.
                                deadline = deadline_in(response_timeout);
                                if response_sender
                                    .send(Ok(Some(UdsResponse::ResponsePending(source_address))))
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

                            // Final response (positive or negative)
                            let uds_response = UdsResponse::Message(ServicePayload {
                                data,
                                source_address,
                                target_address,
                                new_session: None,
                                new_security: None,
                            });
                            let _ = response_sender.send(Ok(Some(uds_response))).await;
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

        Ok(())
    }

    #[tracing::instrument(skip(self, _ecu_db), fields(dlt_context = dlt_ctx!("CAN")))]
    async fn ecu_online<E: EcuAddresses>(
        &self,
        ecu_name: &str,
        _ecu_db: &RwLock<E>,
    ) -> Result<(), DiagServiceError> {
        let ecu_name = ecu_name.to_lowercase();

        // All lookups use owned data - no shared ECU RwLock is touched.
        if !self.connections.contains_key(&ecu_name) {
            return Err(DiagServiceError::EcuOffline(ecu_name.clone()));
        }
        if self.is_ecu_discovered_by_name(&ecu_name).await {
            return Ok(());
        }
        // On-demand re-detection: the ECU may have come online after the
        // startup discovery (or dropped off and rebooted). One bounded probe
        // per call; on success the ECU is marked discovered again.
        if self.probe_ecu(&ecu_name).await {
            Ok(())
        } else {
            Err(DiagServiceError::EcuOffline(ecu_name.clone()))
        }
    }

    async fn get_ecu_network_address(&self, ecu_name: &str) -> Option<String> {
        self.get_connection(&ecu_name.to_lowercase())
            .map(|conn| conn.network_address())
    }

    async fn send_functional(
        &self,
        _transmission_params: cda_interfaces::TransmissionParameters,
        _message: cda_interfaces::ServicePayload,
        _expected_ecu_logical_addrs: cda_interfaces::HashMap<u16, String>,
        _timeout: std::time::Duration,
        _expect_positive_response: bool,
    ) -> Result<
        cda_interfaces::HashMap<String, Result<cda_interfaces::UdsResponse, DiagServiceError>>,
        DiagServiceError,
    > {
        // CAN functional addressing is not implemented yet, see #417.
        // Fail the whole request honestly; the UDS layer maps a gateway-level
        // error to a per-ECU error result, so clients see WHY it failed
        // instead of every ECU appearing to be offline.
        Err(DiagServiceError::RequestNotSupported(
            "functional addressing is not implemented for the CAN transport".to_owned(),
        ))
    }
}

impl Clone for CanDiagGateway {
    fn clone(&self) -> Self {
        Self {
            interface: self.interface.clone(),
            connections: Arc::clone(&self.connections),
            discovered_ecus: Arc::clone(&self.discovered_ecus),
            logical_address_to_ecu: Arc::clone(&self.logical_address_to_ecu),
            response_timeout: self.response_timeout,
            probe_timeout: self.probe_timeout,
            probe_retries: self.probe_retries,
            probe_retry_delay: self.probe_retry_delay,
            probe_sequence: Arc::clone(&self.probe_sequence),
            keepalive_handle: self.keepalive_handle.clone(),
            rediscovery_handle: Arc::clone(&self.rediscovery_handle),
        }
    }
}

#[cfg(test)]
impl CanDiagGateway {
    /// Drops all discovery state, simulating every ECU vanishing from the
    /// bus. Test-only counterpart to `probe_ecu` marking ECUs undiscovered.
    pub(crate) async fn clear_discovered(&self) {
        self.discovered_ecus.write().await.clear();
    }

    /// Builds a gateway instance for unit tests without touching any CAN
    /// interface: no init check, no discovery, keep-alive disabled.
    pub(crate) fn test_instance(
        connections: Vec<(&str, CanEcuConnection)>,
        discovered: Vec<&str>,
    ) -> Self {
        let connections: HashMap<String, Arc<CanEcuConnection>> = connections
            .into_iter()
            .map(|(name, conn)| (name.to_lowercase(), Arc::new(conn)))
            .collect();
        let discovered: cda_interfaces::HashSet<String> =
            discovered.into_iter().map(str::to_lowercase).collect();
        Self {
            interface: "test0".to_owned(),
            connections: Arc::new(connections),
            discovered_ecus: Arc::new(RwLock::new(discovered)),
            logical_address_to_ecu: Arc::new(HashMap::default()),
            response_timeout: Duration::from_millis(100),
            probe_timeout: Duration::from_millis(10),
            probe_retries: 0,
            probe_retry_delay: Duration::from_millis(10),
            probe_sequence: Arc::new(vec![ProbeRequest::tester_present()]),
            rediscovery_handle: Arc::new(std::sync::OnceLock::new()),
            keepalive_handle: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_ids_cover_broadcast_and_keepalive_rx() {
        let functional = CanId::try_from(0x7DF).expect("valid ID");
        for reserved in [0x7DF, 0x7FF, 0x1FFF_FFFF] {
            assert!(CanDiagGateway::is_reserved_can_id(
                CanId::try_from(reserved).expect("valid ID"),
                functional
            ));
        }
        assert!(!CanDiagGateway::is_reserved_can_id(
            CanId::try_from(0x7E0).expect("valid ID"),
            functional
        ));
    }

    #[test]
    fn validate_can_id_accepts_standard_and_extended() {
        // 11-bit standard and 29-bit extended (ISO 15765-4) IDs are both
        // valid; anything wider must fail setup instead of being truncated
        // when the ISO-TP socket is opened.
        assert!(CanDiagGateway::validate_can_id("ecu1", "request_id", 0x7E0).is_ok());
        assert!(CanDiagGateway::validate_can_id("ecu1", "request_id", 0x7FF).is_ok());
        assert!(CanDiagGateway::validate_can_id("ecu1", "request_id", 0x18DA_10F1).is_ok());
        assert!(CanDiagGateway::validate_can_id("ecu1", "request_id", 0x1FFF_FFFF).is_ok());
        assert!(CanDiagGateway::validate_can_id("ecu1", "request_id", 0x2000_0000).is_err());
        assert!(CanDiagGateway::validate_can_id("ecu1", "request_id", u32::MAX).is_err());
    }
}
