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

//! Restores ECU states from the persisted topology at startup.

use cda_interfaces::{
    EcuAddresses as _, EcuManager as _, HashMap, HashMapExtensions as _, HashSet,
    VariantDetection as _,
    topology::{PersistedEcu, PersistedEcuState, PersistedTopology},
};
use cda_plugin_security::SecurityPlugin;

use crate::vehicle::DatabaseMap;

/// Outcome of [`restore_ecu_states`], for logging.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RestoreReport {
    /// ECUs registered as `AssumedOnline` with their persisted variant.
    pub assumed_online: usize,
    /// ECUs registered as Duplicate.
    pub duplicates: usize,
    /// ECUs whose `last_seen` was restored.
    pub last_seen: usize,
}

/// A persisted ECU together with the gateway it was persisted under.
struct Persisted<'a> {
    ecu: &'a PersistedEcu,
    gateway_address: u16,
}

/// Restores the persisted ECU states.
///
/// `last_seen` is restored for every ECU found unchanged in the databases. With
/// `assume_online`, an ECU last known Online with a variant still in its database
/// is registered as `AssumedOnline` instead of `NotTested`, so it is not detected
/// again until contacted. Everything else keeps its initial state and gets a
/// regular variant detection:
///
/// - ECUs or gateways missing from the databases, or with changed addresses
/// - ECUs pinned to CAN (`can_pinned`, lowercase names)
/// - ECUs not last known Online, or whose variant no longer exists
/// - duplicate groups that were not persisted consistently (exactly one member
///   Online, all others Duplicate)
///
/// [[ dimpl~ecu-topology-restore, Restore ECU states from the persisted topology, dimpl ]]
#[allow(
    clippy::implicit_hasher,
    reason = "Type alias does not allow specifying hasher. Hasher is set globally"
)]
pub async fn restore_ecu_states<S: SecurityPlugin>(
    databases: &DatabaseMap<S>,
    topology: &PersistedTopology,
    assume_online: bool,
    can_pinned: &HashSet<String>,
) -> RestoreReport {
    let mut report = RestoreReport::default();
    let persisted = index_persisted(topology);

    for (name, ecu) in databases {
        let lower = name.to_lowercase();
        let Some(entry) = persisted.get(&lower) else {
            continue;
        };
        let mut ecu = ecu.write().await;
        if !ecu.is_physical_ecu()
            || ecu.logical_address() != entry.ecu.logical_address
            || ecu.logical_gateway_address() != entry.gateway_address
        {
            tracing::info!(
                ecu = %name,
                "Persisted ECU does not match the database, it will be detected again"
            );
            continue;
        }
        if let Some(last_seen) = entry.ecu.last_seen {
            ecu.runtime_state().restore_last_seen(last_seen);
            report.last_seen = report.last_seen.saturating_add(1);
        }
        if !assume_online || can_pinned.contains(&lower) {
            continue;
        }

        let group = ecu
            .duplicating_ecu_names()
            .filter(|names| !names.is_empty())
            .cloned();
        if let Some(group) = group {
            let mut members: Vec<String> = group.iter().map(|n| n.to_lowercase()).collect();
            members.push(lower.clone());
            if !group_is_consistent(&members, &persisted) {
                tracing::info!(
                    ecu = %name,
                    "Duplicate group not persisted consistently, it will be detected again"
                );
                continue;
            }
            if entry.ecu.state == PersistedEcuState::Duplicate {
                ecu.mark_as_duplicate().await;
                report.duplicates = report.duplicates.saturating_add(1);
                continue;
            }
        }

        if entry.ecu.state != PersistedEcuState::Online {
            continue;
        }
        let Some(variant) = entry.ecu.variant.as_ref() else {
            continue;
        };
        match ecu.restore_persisted_variant(variant).await {
            Ok(true) => report.assumed_online = report.assumed_online.saturating_add(1),
            Ok(false) => tracing::info!(
                ecu = %name,
                variant = %variant.name,
                "Persisted variant is not in the database, it will be detected again"
            ),
            Err(error) => tracing::warn!(
                ecu = %name,
                %error,
                "Failed to restore the persisted variant, it will be detected again"
            ),
        }
    }
    report
}

fn index_persisted(topology: &PersistedTopology) -> HashMap<String, Persisted<'_>> {
    let mut persisted = HashMap::new();
    for gateway in &topology.gateways {
        for ecu in &gateway.ecus {
            persisted.insert(
                ecu.name.to_lowercase(),
                Persisted {
                    ecu,
                    gateway_address: gateway.logical_address,
                },
            );
        }
    }
    persisted
}

/// Exactly one member persisted Online with a variant, all others Duplicate.
fn group_is_consistent(members: &[String], persisted: &HashMap<String, Persisted<'_>>) -> bool {
    let mut online = 0usize;
    for member in members {
        match persisted
            .get(member)
            .map(|entry| (entry.ecu.state, &entry.ecu.variant))
        {
            Some((PersistedEcuState::Online, Some(_))) => online = online.saturating_add(1),
            Some((PersistedEcuState::Duplicate, _)) => {}
            _ => return false,
        }
    }
    online == 1
}
