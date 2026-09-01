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
use crate::config::CanConfig;

/// The CAN addressing of a single ECU.
#[derive(Clone, PartialEq, Eq)]
pub struct CanEcuAddressing {
    pub ecu_name: String,
    pub interface: String,
    pub request_id: CanId,
    pub response_id: CanId,
}

impl CanEcuAddressing {
    #[must_use]
    pub fn new(ecu_name: String, interface: String, request_id: CanId, response_id: CanId) -> Self {
        Self {
            ecu_name,
            interface,
            request_id,
            response_id,
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
    #[must_use]
    pub fn new(
        connections: HashMap<String, Arc<CanEcuAddressing>>,
        logical_address_to_ecu: HashMap<u16, String>,
        functional_id: CanId,
    ) -> Self {
        let ecu_to_logical_address = logical_address_to_ecu
            .iter()
            .map(|(address, ecu)| (ecu.clone(), *address))
            .collect();
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
/// to CAN for an ECU without CAN addressing, or no addressable ECU at all.
#[allow(
    clippy::implicit_hasher,
    reason = "Type alias doesn't allow specifying hasher"
)]
pub async fn derive_can_topology<T: EcuAddresses + CanComParamProvider>(
    config: &CanConfig,
    ecus: &HashMap<String, Arc<RwLock<T>>>,
) -> Result<CanTopology, CanGatewaySetupError> {
    let _ = super::CanDiagGateway::build_probe_sequence(config)?;

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
    let mut logical_address_to_ecu: HashMap<u16, String> = HashMap::default();

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
            );

            tracing::debug!(
                ecu = %mapping.ecu_name,
                logical_addr = logical_addr,
                request_id = %request_id,
                response_id = %response_id,
                "Added CAN connection from config mapping"
            );

            register_logical_address(&mut logical_address_to_ecu, logical_addr, &ecu_name)?;
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
        &mut logical_address_to_ecu,
    )
    .await?;

    validate_can_pins(config, ecus, &connections)?;

    // Fail fast on configurations that cannot work: a [can] section with
    // no usable ECU addressing means every request would fail at runtime
    // with nothing pointing at the actual mistake.
    if connections.is_empty() {
        return Err(CanGatewaySetupError::NoEcuMappings);
    }

    Ok(CanTopology::new(
        connections,
        logical_address_to_ecu,
        functional_id,
    ))
}

/// Adds connections for ECUs whose CAN addressing comes from the MDD
/// com-params (ECUs with an explicit `[[can.ecu_mappings]]` entry are
/// skipped—config overrides the database).
///
/// Unlike config mappings, database values are not under the user's
/// control, so a bad value skips the ECU (with a warning) instead of
/// failing setup: one malformed MDD must not take down diagnostics for
/// the whole vehicle. Several ECU descriptions may legitimately share
/// one ID pair—candidate models of the same physical node (e.g. the
/// radio variants of a duplicate group); each gets its own connection
/// and variant detection decides which one is actually installed,
/// exactly like `DoIP` address duplicates.
async fn add_connections_from_com_params<T: EcuAddresses + CanComParamProvider>(
    config: &CanConfig,
    ecus: &HashMap<String, Arc<RwLock<T>>>,
    functional_id: CanId,
    connections: &mut HashMap<String, Arc<CanEcuAddressing>>,
    logical_address_to_ecu: &mut HashMap<u16, String>,
) -> Result<(), CanGatewaySetupError> {
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
        );
        tracing::debug!(
            ecu = %name,
            logical_addr = logical_addr,
            request_id = %ids.request,
            response_id = %ids.response,
            "Added CAN connection from MDD COM params"
        );
        register_logical_address(logical_address_to_ecu, logical_addr, &ecu_name)?;
        connections.insert(ecu_name, Arc::new(addressing));
    }
    Ok(())
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
    ecus: &HashMap<String, Arc<RwLock<T>>>,
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

/// Records the logical-address -> ECU lookup used by the
/// address-oriented `EcuGateway` methods (network structure, discovery
/// checks). ECUs of CAN-only databases have no `DoIP` addressing and all
/// carry the unresolved fallback address `0x0000`—registering that
/// would map the shared "address" onto whichever ECU came last, so those
/// ECUs stay unregistered here and are served by the name-based paths
/// only.
fn register_logical_address(
    logical_address_to_ecu: &mut HashMap<u16, String>,
    logical_addr: u16,
    ecu_name: &str,
) -> Result<(), CanGatewaySetupError> {
    if logical_addr == 0 {
        tracing::debug!(
            ecu = %ecu_name,
            "No resolved logical address; ECU reachable via name-based lookups only"
        );
        return Ok(());
    }
    if let Some(existing) = logical_address_to_ecu.get(&logical_addr) {
        if existing != ecu_name {
            return Err(CanGatewaySetupError::InvalidConfiguration(format!(
                "ECUs '{existing}' and '{ecu_name}' share logical address {logical_addr:#06x}"
            )));
        }
        return Ok(());
    }
    logical_address_to_ecu.insert(logical_addr, ecu_name.to_owned());
    Ok(())
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
}
