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

//! CAN topology ownership and derivation from the `[can]` configuration and
//! ECU databases.
//!
//! Derivation runs while building reload data, not while applying it: every
//! check here is fallible, and a reload must fail before anything is committed.

use std::sync::Arc;

use cda_interfaces::{CanComParamProvider, CanId, EcuAddresses, HashMap};
use tokio::sync::RwLock;

use super::{error::CanGatewaySetupError, keepalive};
use crate::config::{CanAddressingMode, CanConfig};

/// The CAN addressing of a single ECU.
#[derive(Clone, PartialEq, Eq)]
pub struct CanEcuAddressing {
    pub ecu_name: String,
    pub interface: String,
    pub request_id: CanId,
    pub response_id: CanId,
    /// ISO-TP addressing mode for this ECU.
    pub addressing_mode: CanAddressingMode,
}

impl CanEcuAddressing {
    #[must_use]
    pub fn new(
        ecu_name: String,
        interface: String,
        request_id: CanId,
        response_id: CanId,
        addressing_mode: CanAddressingMode,
    ) -> Self {
        Self {
            ecu_name,
            interface,
            request_id,
            response_id,
            addressing_mode,
        }
    }

    #[must_use]
    pub fn network_address(&self) -> String {
        format!(
            "{}:{}->{}",
            self.interface, self.request_id, self.response_id
        )
    }
}

impl std::fmt::Debug for CanEcuAddressing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CanEcuAddressing")
            .field("ecu_name", &self.ecu_name)
            .field("interface", &self.interface)
            .field("request_id", &self.request_id.to_string())
            .field("response_id", &self.response_id.to_string())
            .field("addressing_mode", &self.addressing_mode)
            .finish()
    }
}

/// Everything the CAN transport derives from the databases and configuration.
#[derive(Debug)]
pub struct CanTopology {
    connections: HashMap<String, Arc<CanEcuAddressing>>,
    logical_address_to_ecu: HashMap<u16, String>,
    ecu_to_logical_address: HashMap<String, u16>,
    functional_id: CanId,
}

impl CanTopology {
    /// Both logical-address maps are passed separately: members of a
    /// duplicate group share one logical address, so the ECU -> address map
    /// holds every member while the address -> ECU map holds only one, and
    /// neither can be derived from the other.
    #[must_use]
    pub fn new(
        connections: HashMap<String, Arc<CanEcuAddressing>>,
        logical_address_to_ecu: HashMap<u16, String>,
        ecu_to_logical_address: HashMap<String, u16>,
        functional_id: CanId,
    ) -> Self {
        Self {
            connections,
            logical_address_to_ecu,
            ecu_to_logical_address,
            functional_id,
        }
    }

    #[must_use]
    pub fn connections(&self) -> &HashMap<String, Arc<CanEcuAddressing>> {
        &self.connections
    }

    #[must_use]
    pub fn connection(&self, ecu_name: &str) -> Option<Arc<CanEcuAddressing>> {
        self.connections.get(ecu_name).map(Arc::clone)
    }

    #[must_use]
    pub fn has_connection(&self, ecu_name: &str) -> bool {
        self.connections.contains_key(ecu_name)
    }

    #[must_use]
    pub fn ecu_for_logical_address(&self, logical_address: u16) -> Option<&String> {
        self.logical_address_to_ecu.get(&logical_address)
    }

    #[must_use]
    pub fn logical_address_for_ecu(&self, ecu_name: &str) -> Option<u16> {
        self.ecu_to_logical_address.get(ecu_name).copied()
    }

    #[must_use]
    pub fn functional_id(&self) -> CanId {
        self.functional_id
    }
}

/// Derives the CAN topology from one ECU-data value.
///
/// The ECU databases are only borrowed here: the result is owned, so runtime
/// lookups in the transport never touch the shared ECU `RwLock`s.
///
/// # Errors
/// Returns [`CanGatewaySetupError`] for a configuration that cannot work: an
/// out-of-range CAN ID, a mapping colliding with a reserved ID, a transport pin
/// to CAN for an ECU without CAN addressing, or a non-empty ECU set in which
/// none is addressable.
#[allow(
    clippy::implicit_hasher,
    reason = "Type alias doesn't allow specifying hasher"
)]
pub async fn derive_can_topology<T: EcuAddresses + CanComParamProvider>(
    config: &CanConfig,
    ecus: &HashMap<String, RwLock<T>>,
) -> Result<CanTopology, CanGatewaySetupError> {
    // Functional broadcast ID for the TesterPresent keep-alive: prefer the
    // MDD com-params (CP_CanFuncReqId), fall back to the ISO 15765-4
    // default 0x7DF. May be an 11-bit standard or a 29-bit extended ID
    // (e.g. 0x18DB33F1 for normal fixed addressing). Resolved before the
    // connections so their IDs can be checked against it.
    let mut functional_id = validate_can_id(
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

    let mut connections: HashMap<String, Arc<CanEcuAddressing>> = HashMap::default();
    let mut logical_addresses = LogicalAddresses::default();

    // Initialize connections from explicit mappings first
    for mapping in &config.ecu_mappings {
        let request_id = validate_can_id(&mapping.ecu_name, "request_id", mapping.request_id)?;
        let response_id = validate_can_id(&mapping.ecu_name, "response_id", mapping.response_id)?;
        // Reserved IDs (broadcast, keep-alive RX) cannot address an
        // ECU; config values are user-controlled, so fail setup.
        for (field, id) in [("request_id", request_id), ("response_id", response_id)] {
            if is_reserved_can_id(id, functional_id) {
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

            let addressing = CanEcuAddressing::new(
                mapping.ecu_name.clone(),
                config.interface.clone(),
                request_id,
                response_id,
                mapping.addressing_mode,
            );

            tracing::debug!(
                ecu = %mapping.ecu_name,
                logical_addr = logical_addr,
                request_id = %request_id,
                response_id = %response_id,
                "Added CAN connection from config mapping"
            );

            logical_addresses.register(logical_addr, &ecu_name);
            connections.insert(ecu_name, Arc::new(addressing));
        } else {
            tracing::warn!(
                ecu = %mapping.ecu_name,
                "ECU mapping specified but ECU not found in database"
            );
        }
    }

    add_connections_from_com_params(
        config,
        ecus,
        functional_id,
        &mut connections,
        &mut logical_addresses,
    )
    .await;

    validate_can_pins(config, ecus, &connections)?;

    // Fail fast on configurations that cannot work: a [can] section with
    // no usable ECU addressing means every request would fail at runtime
    // with nothing pointing at the actual mistake. An empty vehicle is not
    // that mistake: a runtime update may legitimately make an empty database
    // set live, and the configuration is only wrong once there is an ECU it
    // fails to address.
    if connections.is_empty() && !ecus.is_empty() {
        return Err(CanGatewaySetupError::NoEcuMappings);
    }

    Ok(CanTopology::new(
        connections,
        logical_addresses.to_ecu,
        logical_addresses.of_ecu,
        functional_id,
    ))
}

/// Adds connections for ECUs whose CAN addressing comes from the MDD
/// com-params (ECUs with an explicit `[[can.ecu_mappings]]` entry are
/// skipped: config overrides the database).
///
/// Unlike config mappings, database values are not under the user's
/// control, so a bad value skips the ECU (with a warning) instead of
/// failing setup: one malformed MDD must not take down diagnostics for
/// the whole vehicle. Several ECU descriptions may legitimately share
/// one ID pair: candidate models of the same physical node (e.g. the
/// radio variants of a duplicate group); each gets its own connection
/// and variant detection decides which one is actually installed,
/// exactly like `DoIP` address duplicates.
///
/// ECUs are visited in name order so that the member of a duplicate group
/// registered for a shared logical address does not depend on `HashMap`
/// iteration order.
async fn add_connections_from_com_params<T: EcuAddresses + CanComParamProvider>(
    config: &CanConfig,
    ecus: &HashMap<String, RwLock<T>>,
    functional_id: CanId,
    connections: &mut HashMap<String, Arc<CanEcuAddressing>>,
    logical_addresses: &mut LogicalAddresses,
) {
    let mut sorted_ecus: Vec<_> = ecus.iter().collect();
    sorted_ecus.sort_unstable_by_key(|(name, _)| *name);
    for (name, ecu_lock) in sorted_ecus {
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
        if is_reserved_can_id(ids.request, functional_id)
            || is_reserved_can_id(ids.response, functional_id)
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
        let addressing = CanEcuAddressing::new(
            name.clone(),
            config.interface.clone(),
            ids.request,
            ids.response,
            CanAddressingMode::Standard,
        );
        tracing::debug!(
            ecu = %name,
            logical_addr = logical_addr,
            request_id = %ids.request,
            response_id = %ids.response,
            "Added CAN connection from MDD COM params"
        );
        logical_addresses.register(logical_addr, &ecu_name);
        connections.insert(ecu_name, Arc::new(addressing));
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
    connections: &HashMap<String, Arc<CanEcuAddressing>>,
) -> Result<(), CanGatewaySetupError> {
    for pinned in config
        .transport_overrides
        .iter()
        .filter(|o| o.transport == cda_interfaces::TransportType::Can)
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
            "transport_overrides pins ECU '{}' to CAN, but it has neither a [[can.ecu_mappings]] \
             entry nor CAN addressing in its MDD com-params",
            pinned.ecu_name
        )));
    }
    Ok(())
}

/// The logical-address lookups used by the address-oriented `EcuGateway`
/// methods (network structure, discovery checks) and for log fields.
#[derive(Default)]
struct LogicalAddresses {
    to_ecu: HashMap<u16, String>,
    of_ecu: HashMap<String, u16>,
}

impl LogicalAddresses {
    /// ECUs of CAN-only databases have no `DoIP` addressing and all carry the
    /// unresolved fallback address `0x0000`. Registering that would map the
    /// shared "address" onto an arbitrary ECU, so those ECUs stay unregistered
    /// in both directions and are served by the name-based paths only.
    ///
    /// A resolved address shared by several ECUs is a duplicate group
    /// (variant detection decides which member is installed), not an error:
    /// every member keeps its own address, and the address lookup keeps the
    /// first registration (config mappings in config order, then MDD ECUs in
    /// name order).
    fn register(&mut self, logical_addr: u16, ecu_name: &str) {
        if logical_addr == 0 {
            tracing::debug!(
                ecu = %ecu_name,
                "No resolved logical address; ECU reachable via name-based lookups only"
            );
            return;
        }
        self.of_ecu.insert(ecu_name.to_owned(), logical_addr);
        match self.to_ecu.get(&logical_addr) {
            Some(existing) if existing != ecu_name => {
                tracing::debug!(
                    ecu = %ecu_name,
                    registered_ecu = %existing,
                    logical_addr = logical_addr,
                    "Logical address shared with another ECU (duplicate group), \
                     address lookups resolve to the ECU registered first"
                );
            }
            Some(_) => {}
            None => {
                self.to_ecu.insert(logical_addr, ecu_name.to_owned());
            }
        }
    }
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
fn validate_can_id(ecu_name: &str, field: &str, id: u32) -> Result<CanId, CanGatewaySetupError> {
    CanId::try_from(id).map_err(|e| {
        CanGatewaySetupError::InvalidConfiguration(format!("ECU {ecu_name}: {field}: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_ids_cover_broadcast_and_keepalive_rx() {
        let functional = CanId::try_from(0x7DF).expect("valid ID");
        for reserved in [0x7DF, 0x7FF, 0x1FFF_FFFF] {
            assert!(is_reserved_can_id(
                CanId::try_from(reserved).expect("valid ID"),
                functional
            ));
        }
        assert!(!is_reserved_can_id(
            CanId::try_from(0x7E0).expect("valid ID"),
            functional
        ));
    }

    #[test]
    fn validate_can_id_accepts_standard_and_extended() {
        // 11-bit standard and 29-bit extended (ISO 15765-4) IDs are both
        // valid; anything wider must fail setup instead of being truncated
        // when the ISO-TP socket is opened.
        assert!(validate_can_id("ecu1", "request_id", 0x7E0).is_ok());
        assert!(validate_can_id("ecu1", "request_id", 0x7FF).is_ok());
        assert!(validate_can_id("ecu1", "request_id", 0x18DA_10F1).is_ok());
        assert!(validate_can_id("ecu1", "request_id", 0x1FFF_FFFF).is_ok());
        assert!(validate_can_id("ecu1", "request_id", 0x2000_0000).is_err());
        assert!(validate_can_id("ecu1", "request_id", u32::MAX).is_err());
    }

    struct FakeEcu {
        name: String,
        logical_address: u16,
        can_ids: Option<cda_interfaces::CanIds>,
    }

    impl EcuAddresses for FakeEcu {
        fn tester_address(&self) -> u16 {
            0x0E80
        }
        fn logical_address(&self) -> u16 {
            self.logical_address
        }
        fn logical_gateway_address(&self) -> u16 {
            self.logical_address
        }
        fn logical_functional_address(&self) -> u16 {
            0xE400
        }
        fn ecu_name(&self) -> String {
            self.name.clone()
        }
        fn logical_address_eq<T: EcuAddresses>(&self, other: &T) -> bool {
            self.logical_address == other.logical_address()
        }
    }

    impl CanComParamProvider for FakeEcu {
        fn can_ids(&self) -> Option<cda_interfaces::CanIds> {
            self.can_ids
        }
        fn can_functional_id(&self) -> Option<CanId> {
            None
        }
    }

    /// `(name, logical address, request ID, response ID)`, inserted in order.
    fn ecus(entries: &[(&str, u16, u32, u32)]) -> HashMap<String, RwLock<FakeEcu>> {
        let mut ecus = HashMap::default();
        for &(name, logical_address, request, response) in entries {
            ecus.insert(
                name.to_owned(),
                RwLock::new(FakeEcu {
                    name: name.to_owned(),
                    logical_address,
                    can_ids: Some(
                        cda_interfaces::CanIds::try_from_raw(request, response)
                            .expect("valid test CAN IDs"),
                    ),
                }),
            );
        }
        ecus
    }

    async fn derive(entries: &[(&str, u16, u32, u32)]) -> CanTopology {
        derive_can_topology(&CanConfig::default(), &ecus(entries))
            .await
            .expect("topology derivation succeeds")
    }

    /// Members of a duplicate group share a resolved logical address; that is
    /// valid data, so derivation succeeds and every member keeps its address.
    #[tokio::test]
    async fn shared_logical_address_with_different_can_ids_is_accepted() {
        let topology = derive(&[
            ("ecu_a", 0x1010, 0x700, 0x708),
            ("ecu_b", 0x1010, 0x710, 0x718),
        ])
        .await;

        assert!(topology.has_connection("ecu_a"));
        assert!(topology.has_connection("ecu_b"));
        assert_eq!(topology.logical_address_for_ecu("ecu_a"), Some(0x1010));
        assert_eq!(topology.logical_address_for_ecu("ecu_b"), Some(0x1010));
        assert_eq!(
            topology.ecu_for_logical_address(0x1010).map(String::as_str),
            Some("ecu_a")
        );
    }

    /// Candidate descriptions of one physical node also share the CAN ID
    /// pair: each still gets its own connection.
    #[tokio::test]
    async fn shared_logical_address_with_identical_can_ids_is_accepted() {
        let topology = derive(&[
            ("ecu_a", 0x1010, 0x700, 0x708),
            ("ecu_b", 0x1010, 0x700, 0x708),
        ])
        .await;

        let a = topology.connection("ecu_a").expect("ecu_a connected");
        let b = topology.connection("ecu_b").expect("ecu_b connected");
        assert_eq!(a.network_address(), b.network_address());
        assert_eq!(topology.logical_address_for_ecu("ecu_a"), Some(0x1010));
        assert_eq!(topology.logical_address_for_ecu("ecu_b"), Some(0x1010));
    }

    /// The ECU an address lookup resolves to must not depend on `HashMap`
    /// iteration order: the first ECU name wins. The map's hasher is fixed,
    /// so insertion order alone does not change iteration order; enough
    /// group members make it unlikely that the hash order happens to start
    /// with the lexicographically first name.
    #[tokio::test]
    async fn shared_logical_address_resolves_to_first_ecu_name() {
        let names: Vec<String> = (0..16).map(|i| format!("ecu_{i:02}")).collect();
        let entries: Vec<(&str, u16, u32, u32)> = names
            .iter()
            .zip(0x700u32..)
            .map(|(name, request)| {
                let response = request.checked_add(0x80).expect("small test CAN ID");
                (name.as_str(), 0x1010, request, response)
            })
            .collect();
        let mut reversed = entries.clone();
        reversed.reverse();

        for order in [&entries, &reversed] {
            let topology = derive(order).await;
            assert_eq!(
                topology.ecu_for_logical_address(0x1010).map(String::as_str),
                Some("ecu_00")
            );
            for name in &names {
                assert_eq!(topology.logical_address_for_ecu(name), Some(0x1010));
            }
        }
    }

    /// `0x0000` is the unresolved fallback of CAN-only databases, not a real
    /// address: it is registered in neither direction.
    #[tokio::test]
    async fn unresolved_logical_address_is_not_registered() {
        let topology = derive(&[("ecu_a", 0, 0x700, 0x708), ("ecu_b", 0, 0x710, 0x718)]).await;

        assert!(topology.has_connection("ecu_a"));
        assert!(topology.has_connection("ecu_b"));
        assert_eq!(topology.ecu_for_logical_address(0), None);
        assert_eq!(topology.logical_address_for_ecu("ecu_a"), None);
        assert_eq!(topology.logical_address_for_ecu("ecu_b"), None);
    }
}
