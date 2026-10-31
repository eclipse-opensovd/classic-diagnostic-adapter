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
    Connectivity, EcuAddresses as _, EcuManager as _, HashMap, HashMapExtensions as _, HashSet,
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
#[expect(
    clippy::implicit_hasher,
    reason = "`can_pinned` is the crate-wide `HashSet` alias, whose hasher is set globally"
)]
pub async fn restore_ecu_states<S: SecurityPlugin>(
    databases: &DatabaseMap<S>,
    topology: &PersistedTopology,
    assume_online: bool,
    can_pinned: &HashSet<String>,
) -> RestoreReport {
    let mut report = RestoreReport::default();
    let persisted = index_persisted(topology);
    let mut restored_online: HashSet<String> = HashSet::default();
    let mut deferred_duplicates = Vec::new();

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
                // Only restored once the group's Online member was restored.
                deferred_duplicates.push((name, members));
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
            Ok(true) => {
                report.assumed_online = report.assumed_online.saturating_add(1);
                restored_online.insert(lower);
            }
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

    for (name, members) in deferred_duplicates {
        if !members
            .iter()
            .any(|member| restored_online.contains(member))
        {
            tracing::info!(
                ecu = %name,
                "Online member of the duplicate group was not restored, it will be detected again"
            );
            continue;
        }
        let Some(ecu) = databases.get(name) else {
            continue;
        };
        let mut ecu = ecu.write().await;
        ecu.mark_as_duplicate().await;
        // The losing member belongs to the restored resolution too. An
        // Offline member would invalidate the entire group on connect.
        cda_interfaces::util::std_ext::lock_write(&ecu.runtime_state().ecu_state).connectivity =
            Connectivity::AssumedOnline;
        report.duplicates = report.duplicates.saturating_add(1);
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

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use cda_interfaces::{
        EcuState, VariantState,
        topology::{PersistedGateway, PersistedVariant},
    };
    use cda_plugin_security::mock::TestSecurityPlugin;

    use super::*;
    use crate::topology::test_support::{databases, ecu_manager};

    const GATEWAY: u16 = 0x1000;
    const LAST_SEEN_SECS: u64 = 1_700_000_000;

    fn last_seen() -> SystemTime {
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(LAST_SEEN_SECS))
            .unwrap()
    }

    fn persisted_ecu(
        name: &str,
        logical_address: u16,
        state: PersistedEcuState,
        variant: Option<&str>,
    ) -> PersistedEcu {
        PersistedEcu {
            name: name.to_owned(),
            logical_address,
            variant: variant.map(|name| PersistedVariant {
                name: name.to_owned(),
                is_base_variant: false,
                is_fallback: false,
            }),
            state,
            last_seen: Some(last_seen()),
        }
    }

    fn topology(ecus: Vec<PersistedEcu>) -> PersistedTopology {
        PersistedTopology {
            gateways: vec![PersistedGateway {
                name: "GW".to_owned(),
                logical_address: GATEWAY,
                network_address: Some("10.2.1.10".to_owned()),
                doip_protocol_version: Some(3),
                ecus,
            }],
        }
    }

    fn key(state: &EcuState) -> (Connectivity, VariantState) {
        (state.connectivity, state.variant_state.clone())
    }

    async fn status(databases: &DatabaseMap<TestSecurityPlugin>, name: &str) -> EcuState {
        databases
            .get(name)
            .expect("ecu")
            .read()
            .await
            .runtime_state()
            .status()
    }

    async fn seen(databases: &DatabaseMap<TestSecurityPlugin>, name: &str) -> Option<SystemTime> {
        databases
            .get(name)
            .expect("ecu")
            .read()
            .await
            .runtime_state()
            .last_seen()
    }

    /// Restores `ECU_A`, persisted Online with `variant` at `persisted_address`,
    /// into a database with `ECU_A` at 0x1001 behind `gateway`. Returns the
    /// databases, the report and the state of `ECU_A` before the restore.
    async fn restore_one(
        gateway: u16,
        persisted_address: u16,
        variant: &str,
        assume_online: bool,
        can_pinned: &HashSet<String>,
    ) -> (DatabaseMap<TestSecurityPlugin>, RestoreReport, EcuState) {
        let databases = databases([("ECU_A", ecu_manager(0x1001, gateway, &["App"]))]);
        let before = status(&databases, "ECU_A").await;
        let persisted = topology(vec![persisted_ecu(
            "ECU_A",
            persisted_address,
            PersistedEcuState::Online,
            Some(variant),
        )]);
        let report = restore_ecu_states(&databases, &persisted, assume_online, can_pinned).await;
        (databases, report, before)
    }

    async fn duplicate_pair(
        a: PersistedEcu,
        b: PersistedEcu,
    ) -> (DatabaseMap<TestSecurityPlugin>, RestoreReport) {
        let mut first = ecu_manager(0x1001, GATEWAY, &["App"]);
        first.set_duplicating_ecu_names(["ECU_B".to_owned()].into_iter().collect());
        let mut second = ecu_manager(0x1002, GATEWAY, &["App"]);
        second.set_duplicating_ecu_names(["ECU_A".to_owned()].into_iter().collect());
        let databases = databases([("ECU_A", first), ("ECU_B", second)]);
        let report =
            restore_ecu_states(&databases, &topology(vec![a, b]), true, &HashSet::default()).await;
        (databases, report)
    }

    /// [[ test~ecu-state-restore-without-assume-online-only-last-seen-is-restored, With `init_mode` Always only `last_seen` is restored, test ]]
    #[tokio::test]
    async fn without_assume_online_only_last_seen_is_restored() {
        let (databases, report, before) =
            restore_one(GATEWAY, 0x1001, "App", false, &HashSet::default()).await;

        assert_eq!(report.assumed_online, 0);
        assert_eq!(report.last_seen, 1);
        assert_eq!(key(&status(&databases, "ECU_A").await), key(&before));
        assert_eq!(seen(&databases, "ECU_A").await, Some(last_seen()));
    }

    /// [[ test~ecu-state-restore-inconsistent-duplicate-group-is-detected-again, An inconsistently persisted duplicate group is detected again, test ]]
    #[tokio::test]
    async fn inconsistent_duplicate_group_is_detected_again() {
        // Two members persisted Online: the group cannot have been resolved.
        let (databases, report) = duplicate_pair(
            persisted_ecu("ECU_A", 0x1001, PersistedEcuState::Online, Some("App")),
            persisted_ecu("ECU_B", 0x1002, PersistedEcuState::Online, Some("App")),
        )
        .await;

        assert_eq!(report.assumed_online, 0);
        assert_eq!(report.duplicates, 0);
        for name in ["ECU_A", "ECU_B"] {
            let state = status(&databases, name).await;
            assert_ne!(state.connectivity, Connectivity::AssumedOnline, "{name}");
            assert_eq!(state.variant_state, VariantState::NotTested, "{name}");
        }
        // Not a statement about the states: last_seen is still restored.
        assert_eq!(report.last_seen, 2);
    }

    /// [[ test~ecu-state-restore-can-pinned-ecu-is-not-assumed-online, An ECU pinned to CAN is not restored as `AssumedOnline`, test ]]
    #[tokio::test]
    async fn can_pinned_ecu_is_not_assumed_online() {
        let can_pinned: HashSet<String> = ["ecu_a".to_owned()].into_iter().collect();

        let (databases, report, _) = restore_one(GATEWAY, 0x1001, "App", true, &can_pinned).await;

        assert_eq!(report.assumed_online, 0);
        assert_ne!(
            status(&databases, "ECU_A").await.connectivity,
            Connectivity::AssumedOnline
        );
        assert_eq!(seen(&databases, "ECU_A").await, Some(last_seen()));
    }

    /// [[ test~ecu-state-restore-address-mismatch-restores-nothing, A changed ECU address restores nothing, test ]]
    #[tokio::test]
    async fn address_mismatch_restores_nothing() {
        // Logical address, and gateway address, of the ECU changed in the database.
        for (gateway, persisted_address) in [(GATEWAY, 0x1999), (0x2000, 0x1001)] {
            let (databases, report, _) =
                restore_one(gateway, persisted_address, "App", true, &HashSet::default()).await;
            assert_eq!(report, RestoreReport::default());
            assert_eq!(seen(&databases, "ECU_A").await, None);
        }
    }

    /// [[ test~ecu-state-restore-variant-missing-from-the-database-is-detected-again, A persisted variant missing from the database is detected again, test ]]
    #[tokio::test]
    async fn variant_missing_from_the_database_is_detected_again() {
        let (databases, report, before) =
            restore_one(GATEWAY, 0x1001, "RemovedVariant", true, &HashSet::default()).await;

        assert_eq!(report.assumed_online, 0);
        assert_eq!(key(&status(&databases, "ECU_A").await), key(&before));
    }
}
