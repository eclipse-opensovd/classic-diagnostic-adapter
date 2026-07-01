/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 */

// The `can` feature alone relies on Linux SocketCAN ISO-TP sockets
// (tokio-socketcan-isotp). Off Linux it is only usable together with a
// platform-independent transport: `can-tcp` (`tcp:<host>:<port>`) or
// `can-socketcand` (`socketcand:<host>:<port>:<bus>`). Fail early with an
// actionable message instead of letting socket creation fail at runtime
// with a cryptic error.
#[cfg(all(
    feature = "can",
    not(target_os = "linux"),
    not(feature = "can-tcp"),
    not(feature = "can-socketcand")
))]
compile_error!(
    "The `can` feature requires Linux (SocketCAN/ISO-TP). On other platforms enable `can-tcp` or \
     `can-socketcand` to use a TCP-based frame transport."
);

pub mod config;
pub mod multi_transport;

// Re-export types that are always available
pub use multi_transport::{MultiTransportGateway, TransportStats, TransportType};

// The following modules and types are only available when the `can` feature is enabled
#[cfg(feature = "can")]
mod connection;
#[cfg(feature = "can")]
pub mod error;
#[cfg(feature = "can")]
pub mod keepalive;

#[cfg(feature = "can")]
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

#[cfg(feature = "can")]
use cda_interfaces::{
    CanComParamProvider, DiagServiceError, EcuAddresses, EcuGateway, HashMap, ServicePayload,
    TransmissionParameters, UdsResponse,
};
#[cfg(feature = "can")]
pub use keepalive::{KeepAliveHandle, start_keepalive_broadcast};
#[cfg(feature = "can")]
use tokio::sync::{RwLock, mpsc};

#[cfg(feature = "can")]
use crate::{
    config::CanConfig,
    connection::CanEcuConnection,
    error::{CanError, CanGatewaySetupError},
};

#[cfg(feature = "can")]
const NRC_RESPONSE_PENDING: u8 = 0x78;

#[cfg(feature = "can")]
#[derive(Clone, Debug)]
struct ProbeRequest {
    name: String,
    payload: Vec<u8>,
}

#[cfg(feature = "can")]
impl ProbeRequest {
    fn tester_present() -> Self {
        Self {
            name: "tester_present".to_owned(),
            payload: vec![0x3E, 0x00],
        }
    }
}

/// CAN bus diagnostic gateway implementing the `EcuGateway` trait.
///
/// This gateway handles communication with ECUs over CAN bus using ISO-TP
/// (ISO 15765-2) for transport layer segmentation.
#[cfg(feature = "can")]
pub struct CanDiagGateway {
    /// CAN interface name
    interface: String,
    /// Map of ECU name (lowercase) to CAN connection info
    connections: Arc<RwLock<HashMap<String, Arc<CanEcuConnection>>>>,
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
    /// Ordered list of discovery probes to try per ECU.
    probe_sequence: Arc<Vec<ProbeRequest>>,
    /// Keep-alive broadcast handle. Stored here so the task is aborted when
    /// the last clone of the gateway is dropped (via Arc refcount).
    keepalive_handle: Arc<KeepAliveHandle>,
}

#[cfg(feature = "can")]
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
        )
    )]
    pub async fn new<T: EcuAddresses + CanComParamProvider>(
        config: &CanConfig,
        ecus: &HashMap<String, RwLock<T>>,
        variant_detection: mpsc::Sender<Vec<String>>,
    ) -> Result<Self, CanGatewaySetupError> {
        tracing::info!("Initializing CanDiagGateway");

        let probe_sequence = Self::build_probe_sequence(config)?;

        // Start functional-broadcast TesterPresent keep-alive to prevent
        // ECUs from going to sleep while CDA is running.
        let keepalive_handle = keepalive::start_keepalive_broadcast(
            config.interface.clone(),
            None, // use default 2s interval
        );

        let mut connections: HashMap<String, Arc<CanEcuConnection>> = HashMap::default();
        let mut logical_address_to_ecu: HashMap<u16, String> = HashMap::default();

        // Initialize connections from explicit mappings first
        for mapping in &config.ecu_mappings {
            let ecu_name_lower = mapping.ecu_name.to_lowercase();
            if let Some(ecu_lock) = ecus.get(&ecu_name_lower) {
                let ecu = ecu_lock.read().await;
                let logical_addr = ecu.logical_address();

                let conn = CanEcuConnection::new(
                    mapping.ecu_name.clone(),
                    config.interface.clone(),
                    mapping.request_id,
                    mapping.response_id,
                );

                tracing::debug!(
                    ecu = %mapping.ecu_name,
                    logical_addr = logical_addr,
                    request_id = format!("0x{:03X}", mapping.request_id),
                    response_id = format!("0x{:03X}", mapping.response_id),
                    "Added CAN connection from config mapping"
                );

                logical_address_to_ecu.insert(logical_addr, ecu_name_lower.clone());
                connections.insert(ecu_name_lower, Arc::new(conn));
            } else {
                tracing::warn!(
                    ecu = %mapping.ecu_name,
                    "ECU mapping specified but ECU not found in database"
                );
            }
        }

        // Try to get CAN IDs from MDD COM parameters for ECUs without explicit mappings
        for (name, ecu_lock) in ecus {
            let ecu = ecu_lock.read().await;
            let logical_addr = ecu.logical_address();
            let ecu_name = name.to_lowercase();

            // Skip if already have a mapping
            if connections.contains_key(&ecu_name) {
                continue;
            }

            // Try to get CAN IDs from COM parameters
            if let (Some(req_id), Some(resp_id)) = (ecu.can_request_id(), ecu.can_response_id()) {
                let conn =
                    CanEcuConnection::new(name.clone(), config.interface.clone(), req_id, resp_id);
                tracing::debug!(
                    ecu = %name,
                    logical_addr = logical_addr,
                    request_id = format!("0x{:03X}", req_id),
                    response_id = format!("0x{:03X}", resp_id),
                    "Added CAN connection from MDD COM params"
                );
                logical_address_to_ecu.insert(logical_addr, ecu_name.clone());
                connections.insert(ecu_name, Arc::new(conn));
            }
        }

        let gateway = Self {
            interface: config.interface.clone(),
            connections: Arc::new(RwLock::new(connections)),
            discovered_ecus: Arc::new(RwLock::new(cda_interfaces::HashSet::default())),
            logical_address_to_ecu: Arc::new(logical_address_to_ecu),
            response_timeout: Duration::from_millis(config.response_timeout_ms),
            probe_timeout: Duration::from_millis(config.probe_timeout_ms),
            probe_sequence: Arc::new(probe_sequence),
            keepalive_handle: Arc::new(keepalive_handle),
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

        Ok(gateway)
    }

    fn build_probe_sequence(config: &CanConfig) -> Result<Vec<ProbeRequest>, CanGatewaySetupError> {
        let mut probes = vec![ProbeRequest::tester_present()];

        for fallback in &config.probe_fallbacks {
            let payload = fallback
                .payload_bytes()
                .map_err(CanGatewaySetupError::InvalidConfiguration)?;

            if probes.iter().any(|existing| existing.payload == payload) {
                continue;
            }

            let name = fallback
                .name
                .clone()
                .unwrap_or_else(|| format!("probe_{}", hex::encode_upper(&payload)));

            probes.push(ProbeRequest { name, payload });
        }

        Ok(probes)
    }

    async fn probe_connection(
        &self,
        conn: &CanEcuConnection,
        logical_addr: u16,
        discovery_index: usize,
        discovery_total: usize,
    ) -> Result<(), CanError> {
        let mut last_error = None;

        #[allow(clippy::arithmetic_side_effects)] // 1-based display index; overflow impossible
        for (probe_index_0, probe) in self.probe_sequence.iter().enumerate() {
            let probe_index = probe_index_0 + 1;
            let start = Instant::now();
            tracing::debug!(
                ecu = %conn.ecu_name,
                logical_addr,
                network_addr = %conn.network_address(),
                discovery_index,
                discovery_total,
                probe_index,
                probe_total = self.probe_sequence.len(),
                probe_name = %probe.name,
                probe_payload = %hex::encode_upper(&probe.payload),
                timeout_ms = u32::try_from(self.probe_timeout.as_millis()).unwrap_or(u32::MAX),
                "Starting CAN discovery probe"
            );

            match conn
                .probe_with_payload(&probe.payload, self.probe_timeout)
                .await
            {
                Ok(response) => {
                    let elapsed = start.elapsed();
                    let response_kind = if response.first() == Some(&0x7F) {
                        format!(
                            "negative-response nrc=0x{:02X}",
                            response.get(2).copied().unwrap_or(0)
                        )
                    } else {
                        format!(
                            "positive-response sid=0x{:02X}",
                            response.first().copied().unwrap_or(0)
                        )
                    };

                    tracing::info!(
                        ecu = %conn.ecu_name,
                        logical_addr,
                        network_addr = %conn.network_address(),
                        discovery_index,
                        discovery_total,
                        probe_index,
                        probe_total = self.probe_sequence.len(),
                        probe_name = %probe.name,
                        probe_payload = %hex::encode_upper(&probe.payload),
                        response_kind,
                        response_data = %hex::encode_upper(&response),
                        elapsed_ms = u32::try_from(elapsed.as_millis()).unwrap_or(u32::MAX),
                        "CAN discovery probe succeeded"
                    );
                    return Ok(());
                }
                Err(error) => {
                    let elapsed = start.elapsed();
                    tracing::debug!(
                        ecu = %conn.ecu_name,
                        logical_addr,
                        network_addr = %conn.network_address(),
                        discovery_index,
                        discovery_total,
                        probe_index,
                        probe_total = self.probe_sequence.len(),
                        probe_name = %probe.name,
                        probe_payload = %hex::encode_upper(&probe.payload),
                        elapsed_ms = u32::try_from(elapsed.as_millis()).unwrap_or(u32::MAX),
                        error = %error,
                        "CAN discovery probe failed"
                    );
                    last_error = Some(error);
                }
            }
        }

        Err(last_error.unwrap_or(CanError::EcuNotResponding(conn.request_id)))
    }

    /// Discovers ECUs on the CAN bus by probing with `TesterPresent`.
    ///
    /// Sends a `TesterPresent` (0x3E 0x00) request to each configured ECU
    /// and waits for a response. ECUs that respond are considered online.
    ///
    /// # Returns
    /// A list of ECU names that responded to the probe.
    pub async fn discover_ecus(&self) -> Vec<String> {
        let mut discovered = Vec::new();
        let connections = self.connections.read().await;
        let discovery_total = connections.len();

        for (discovery_index, (ecu_name, conn)) in connections.iter().enumerate() {
            let logical_addr = self.logical_address_for_ecu(ecu_name);

            match self
                .probe_connection(
                    conn,
                    logical_addr,
                    discovery_index.saturating_add(1),
                    discovery_total,
                )
                .await
            {
                Ok(()) => {
                    tracing::info!(
                        ecu = %conn.ecu_name,
                        logical_addr = logical_addr,
                        network_addr = %conn.network_address(),
                        "ECU discovered on CAN"
                    );
                    // Mark as discovered
                    self.discovered_ecus.write().await.insert(ecu_name.clone());
                    discovered.push(conn.ecu_name.clone());
                }
                Err(e) => {
                    tracing::debug!(
                        ecu = %conn.ecu_name,
                        logical_addr = logical_addr,
                        error = %e,
                        "ECU not responding on CAN"
                    );
                    // Remove from discovered if previously discovered
                    self.discovered_ecus.write().await.remove(ecu_name);
                }
            }
        }

        discovered
    }

    /// Re-probes a specific ECU to check if it's online.
    ///
    /// # Arguments
    /// * `ecu_name` - Name of the ECU to probe
    ///
    /// # Returns
    /// `true` if the ECU responded, `false` otherwise.
    pub async fn probe_ecu(&self, ecu_name: &str) -> bool {
        let ecu_name_lower = ecu_name.to_lowercase();
        if let Some(conn) = self.connections.read().await.get(&ecu_name_lower) {
            let logical_addr = self.logical_address_for_ecu(&ecu_name_lower);

            if self
                .probe_connection(conn, logical_addr, 1, 1)
                .await
                .is_ok()
            {
                self.discovered_ecus
                    .write()
                    .await
                    .insert(ecu_name_lower.clone());
                return true;
            }
            self.discovered_ecus.write().await.remove(&ecu_name_lower);
        }
        false
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
    async fn is_ecu_discovered_by_name(&self, ecu_name: &str) -> bool {
        self.discovered_ecus.read().await.contains(ecu_name)
    }

    /// Gets a connection for the given ECU name.
    async fn get_connection(&self, ecu_name: &str) -> Option<Arc<CanEcuConnection>> {
        self.connections.read().await.get(ecu_name).cloned()
    }

    /// Returns the CAN interface name.
    #[must_use]
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Returns the number of configured ECU connections.
    pub async fn connection_count(&self) -> usize {
        self.connections.read().await.len()
    }

    /// Returns the number of discovered (online) ECUs.
    pub async fn discovered_count(&self) -> usize {
        self.discovered_ecus.read().await.len()
    }
}

#[cfg(feature = "can")]
impl EcuGateway for CanDiagGateway {
    fn shutdown(&self) {
        // CAN uses per-transaction ISO-TP sockets (no long-lived connection
        // tasks), and the keep-alive broadcast is aborted when the last clone
        // of the gateway is dropped (its `KeepAliveHandle` aborts on Drop), so
        // there is nothing to cancel proactively here.
    }

    async fn get_gateway_network_address(&self, logical_address: u16) -> Option<String> {
        let ecu_name = self.logical_address_to_ecu.get(&logical_address)?;
        if !self.is_ecu_discovered_by_name(ecu_name).await {
            return None;
        }
        self.connections
            .read()
            .await
            .get(ecu_name)
            .map(|conn| conn.network_address())
    }

    #[tracing::instrument(skip_all, fields(
        ecu = %transmission_params.ecu_name,
        gateway_addr = transmission_params.gateway_address
    ))]
    async fn send(
        &self,
        transmission_params: TransmissionParameters,
        message: ServicePayload,
        response_sender: mpsc::Sender<Result<Option<UdsResponse>, DiagServiceError>>,
        expect_uds_reply: bool,
    ) -> Result<(), DiagServiceError> {
        let ecu_name_lower = transmission_params.ecu_name.to_lowercase();
        let conn = self
            .get_connection(&ecu_name_lower)
            .await
            .ok_or_else(|| DiagServiceError::EcuOffline(transmission_params.ecu_name.clone()))?;

        // Check if ECU was discovered
        if !self.is_ecu_discovered_by_name(&ecu_name_lower).await {
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
        let ecu_name = transmission_params.ecu_name.clone();
        let source_address = message.source_address;
        let target_address = message.target_address;
        let request_data = message.data.clone();

        cda_interfaces::spawn_named!(&format!("can-send-{ecu_name}"), {
            async move {
                // Open socket and send request, keeping the socket alive for the
                // entire exchange so response-pending follow-ups arrive on the
                // same transport session.
                let exchange = match conn.begin_exchange(&request_data).await {
                    Ok(ex) => ex,
                    Err(CanError::Timeout) => {
                        let _ = response_sender.send(Err(DiagServiceError::Timeout)).await;
                        return;
                    }
                    Err(e) => {
                        let _ = response_sender
                            .send(Err(DiagServiceError::NoResponse(e.to_string())))
                            .await;
                        return;
                    }
                };

                // Read initial response
                let first_response = match exchange.read_response(response_timeout).await {
                    Ok(data) => data,
                    Err(CanError::Timeout) => {
                        let _ = response_sender.send(Err(DiagServiceError::Timeout)).await;
                        return;
                    }
                    Err(e) => {
                        let _ = response_sender
                            .send(Err(DiagServiceError::NoResponse(e.to_string())))
                            .await;
                        return;
                    }
                };

                if !expect_uds_reply {
                    let _ = response_sender.send(Ok(None)).await;
                    return;
                }

                // Process response, handling NRC 0x78 (Response Pending) by
                // reading follow-up responses on the same socket.
                let mut current_response = first_response;
                loop {
                    if current_response.first() == Some(&0x7F)
                        && current_response.len() >= 3
                        && current_response.get(2) == Some(&NRC_RESPONSE_PENDING)
                    {
                        if response_sender
                            .send(Ok(Some(UdsResponse::ResponsePending(source_address))))
                            .await
                            .is_err()
                        {
                            break;
                        }

                        // Read next response on the SAME socket - no re-send
                        match exchange.read_response(response_timeout).await {
                            Ok(next_response) => {
                                current_response = next_response;
                                continue;
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

                    // Final response (positive or negative)
                    let uds_response = UdsResponse::Message(ServicePayload {
                        data: current_response,
                        source_address,
                        target_address,
                        new_session: None,
                        new_security: None,
                    });

                    let _ = response_sender.send(Ok(Some(uds_response))).await;
                    break;
                }
            }
        });

        Ok(())
    }

    async fn ecu_online<E: EcuAddresses>(
        &self,
        ecu_name: &str,
        _ecu_db: &RwLock<E>,
    ) -> Result<(), DiagServiceError> {
        let ecu_name_lower = ecu_name.to_lowercase();

        // Check if we have a connection AND the ECU was discovered.
        // All lookups use owned data - no shared ECU RwLock is touched.
        if self.connections.read().await.contains_key(&ecu_name_lower)
            && (self.is_ecu_discovered_by_name(&ecu_name_lower).await
                || self
                    .is_ecu_discovered(self.logical_address_for_ecu(&ecu_name_lower))
                    .await)
        {
            Ok(())
        } else {
            Err(DiagServiceError::EcuOffline(ecu_name.to_owned()))
        }
    }

    async fn send_functional(
        &self,
        _transmission_params: cda_interfaces::TransmissionParameters,
        _message: cda_interfaces::ServicePayload,
        expected_ecu_logical_addrs: cda_interfaces::HashMap<u16, String>,
        _timeout: std::time::Duration,
        _expect_positive_response: bool,
    ) -> Result<
        cda_interfaces::HashMap<String, Result<cda_interfaces::UdsResponse, DiagServiceError>>,
        DiagServiceError,
    > {
        // CAN functional addressing (11-bit broadcast) is not implemented in this
        // gateway. We return Ok with one error per expected ECU so the UDS layer
        // can fall back gracefully.
        Ok(expected_ecu_logical_addrs
            .into_values()
            .map(|name| {
                (
                    name,
                    Err(DiagServiceError::EcuOffline(
                        "CAN functional not supported".to_owned(),
                    )),
                )
            })
            .collect())
    }
}

#[cfg(feature = "can")]
impl Clone for CanDiagGateway {
    fn clone(&self) -> Self {
        Self {
            interface: self.interface.clone(),
            connections: Arc::clone(&self.connections),
            discovered_ecus: Arc::clone(&self.discovered_ecus),
            logical_address_to_ecu: Arc::clone(&self.logical_address_to_ecu),
            response_timeout: self.response_timeout,
            probe_timeout: self.probe_timeout,
            probe_sequence: Arc::clone(&self.probe_sequence),
            keepalive_handle: Arc::clone(&self.keepalive_handle),
        }
    }
}

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

// The stub methods must keep the `async` signatures of the real
// implementation because `MultiTransportGateway::transport_stats` awaits
// them in both builds.
#[allow(clippy::unused_async)]
#[cfg(not(feature = "can"))]
impl CanDiagGateway {
    /// Returns 0. Unreachable (the stub cannot be constructed); exists so
    /// `MultiTransportGateway::transport_stats` type-checks in both builds.
    pub async fn connection_count(&self) -> usize {
        0
    }

    /// Returns 0. Unreachable; see [`Self::connection_count`].
    pub async fn discovered_count(&self) -> usize {
        0
    }
}

#[cfg(not(feature = "can"))]
impl cda_interfaces::EcuGateway for CanDiagGateway {
    fn shutdown(&self) {}

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
