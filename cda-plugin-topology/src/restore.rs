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
    HashMap, HashSet,
    topology::{PersistedEcu, PersistedEcuState, PersistedTopology},
};

use crate::plugin::TopologyDatabases;

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
    reason = "`ecus_pinned_to_can_transport` is the crate-wide `HashSet` alias, whose hasher is \
              set globally"
)]
pub async fn restore_ecu_states(
    databases: &dyn TopologyDatabases,
    topology: &PersistedTopology,
    assume_online: bool,
    ecus_pinned_to_can_transport: &HashSet<String>,
) -> RestoreReport {
    let mut report = RestoreReport::default();
    let persisted = index_persisted(topology);
    let mut restored_online: HashSet<String> = HashSet::default();
    let mut deferred_duplicates = Vec::new();

    let ecus = databases.ecus().await;
    for ecu in &ecus {
        let name = &ecu.name;
        let lower = name.to_lowercase();
        let Some(entry) = persisted.get(&lower) else {
            continue;
        };
        if !ecu.is_physical
            || ecu.logical_address != entry.ecu.logical_address
            || ecu.gateway_address != entry.gateway_address
        {
            tracing::info!(
                ecu = %name,
                "Persisted ECU does not match the database, it will be detected again"
            );
            continue;
        }
        if let Some(last_seen) = entry.ecu.last_seen {
            databases.restore_last_seen(name, last_seen).await;
            report.last_seen = report.last_seen.saturating_add(1);
        }
        if !assume_online || ecus_pinned_to_can_transport.contains(&lower) {
            continue;
        }

        if !ecu.duplicating_ecu_names.is_empty() {
            let mut members: Vec<String> = ecu
                .duplicating_ecu_names
                .iter()
                .map(|n| n.to_lowercase())
                .collect();
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
        match databases.restore_variant(name, variant).await {
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
        databases.restore_duplicate(name).await;
        report.duplicates = report.duplicates.saturating_add(1);
    }
    report
}

fn index_persisted(topology: &PersistedTopology) -> HashMap<String, Persisted<'_>> {
    topology
        .gateways
        .iter()
        .flat_map(|gateway| {
            gateway.ecus.iter().map(move |ecu| {
                (
                    ecu.name.to_lowercase(),
                    Persisted {
                        ecu,
                        gateway_address: gateway.logical_address,
                    },
                )
            })
        })
        .collect()
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

    use async_trait::async_trait;
    use cda_interfaces::{
        DiagServiceError, HashMap, HashSet,
        topology::{
            PersistedEcu, PersistedEcuState, PersistedGateway, PersistedTopology, PersistedVariant,
        },
    };
    use tokio::sync::RwLock;

    use super::{RestoreReport, restore_ecu_states};
    use crate::{DatabaseEcu, TopologyDatabases};

    const GATEWAY: u16 = 0x1000;
    const LAST_SEEN_SECS: u64 = 1_700_000_000;

    struct TestDatabases {
        ecus: Vec<DatabaseEcu>,
        variants: HashMap<String, HashSet<String>>,
        restored_variants: RwLock<HashSet<String>>,
        restored_duplicates: RwLock<HashSet<String>>,
        last_seen: RwLock<HashMap<String, SystemTime>>,
    }

    impl TestDatabases {
        fn new(ecus: Vec<(DatabaseEcu, Vec<&str>)>) -> Self {
            let variants = ecus
                .iter()
                .map(|(ecu, variants)| {
                    (
                        ecu.name.clone(),
                        variants.iter().map(|name| (*name).to_owned()).collect(),
                    )
                })
                .collect();
            Self {
                ecus: ecus.into_iter().map(|(ecu, _)| ecu).collect(),
                variants,
                restored_variants: RwLock::default(),
                restored_duplicates: RwLock::default(),
                last_seen: RwLock::default(),
            }
        }

        async fn restored_variants(&self) -> HashSet<String> {
            self.restored_variants.read().await.clone()
        }

        async fn restored_duplicates(&self) -> HashSet<String> {
            self.restored_duplicates.read().await.clone()
        }

        async fn last_seen(&self, ecu: &str) -> Option<SystemTime> {
            self.last_seen.read().await.get(ecu).copied()
        }
    }

    #[async_trait]
    impl TopologyDatabases for TestDatabases {
        async fn ecus(&self) -> Vec<DatabaseEcu> {
            self.ecus.clone()
        }

        async fn restore_last_seen(&self, ecu: &str, at: SystemTime) {
            self.last_seen.write().await.insert(ecu.to_owned(), at);
        }

        async fn restore_variant(
            &self,
            ecu: &str,
            variant: &PersistedVariant,
        ) -> Result<bool, DiagServiceError> {
            if !self
                .variants
                .get(ecu)
                .is_some_and(|variants| variants.contains(&variant.name))
            {
                return Ok(false);
            }
            self.restored_variants.write().await.insert(ecu.to_owned());
            Ok(true)
        }

        async fn restore_duplicate(&self, ecu: &str) {
            self.restored_duplicates
                .write()
                .await
                .insert(ecu.to_owned());
        }
    }

    fn ecu(
        name: &str,
        logical_address: u16,
        gateway_address: u16,
        duplicating_ecu_names: &[&str],
    ) -> DatabaseEcu {
        DatabaseEcu {
            name: name.to_owned(),
            logical_address,
            gateway_address,
            is_physical: true,
            duplicating_ecu_names: duplicating_ecu_names
                .iter()
                .map(|name| (*name).to_owned())
                .collect(),
        }
    }

    fn last_seen() -> SystemTime {
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(LAST_SEEN_SECS))
            .expect("valid timestamp")
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

    /// [[ test~ecu-state-restore-without-assume-online-only-last-seen-is-restored, With `init_mode` Always only `last_seen` is restored, test ]]
    #[tokio::test]
    async fn without_assume_online_only_last_seen_is_restored() {
        let databases = TestDatabases::new(vec![(ecu("ECU_A", 0x1001, GATEWAY, &[]), vec!["App"])]);
        let report = restore_ecu_states(
            &databases,
            &topology(vec![persisted_ecu(
                "ECU_A",
                0x1001,
                PersistedEcuState::Online,
                Some("App"),
            )]),
            false,
            &HashSet::default(),
        )
        .await;

        assert_eq!(report.assumed_online, 0);
        assert_eq!(report.last_seen, 1);
        assert!(databases.restored_variants().await.is_empty());
        assert_eq!(databases.last_seen("ECU_A").await, Some(last_seen()));
    }

    /// [[ test~ecu-state-restore-inconsistent-duplicate-group-is-detected-again, An inconsistently persisted duplicate group is detected again, test ]]
    #[tokio::test]
    async fn inconsistent_duplicate_group_is_detected_again() {
        let databases = TestDatabases::new(vec![
            (ecu("ECU_A", 0x1001, GATEWAY, &["ECU_B"]), vec!["App"]),
            (ecu("ECU_B", 0x1002, GATEWAY, &["ECU_A"]), vec!["App"]),
        ]);
        let report = restore_ecu_states(
            &databases,
            &topology(vec![
                persisted_ecu("ECU_A", 0x1001, PersistedEcuState::Online, Some("App")),
                persisted_ecu("ECU_B", 0x1002, PersistedEcuState::Online, Some("App")),
            ]),
            true,
            &HashSet::default(),
        )
        .await;

        assert_eq!(report.assumed_online, 0);
        assert_eq!(report.duplicates, 0);
        assert!(databases.restored_variants().await.is_empty());
        assert!(databases.restored_duplicates().await.is_empty());
        assert_eq!(report.last_seen, 2);
    }

    /// [[ test~ecu-state-restore-can-pinned-ecu-is-not-assumed-online, An ECU pinned to CAN is not restored as `AssumedOnline`, test ]]
    #[tokio::test]
    async fn can_pinned_ecu_is_not_assumed_online() {
        let databases = TestDatabases::new(vec![(ecu("ECU_A", 0x1001, GATEWAY, &[]), vec!["App"])]);
        let can_pinned: HashSet<String> = ["ecu_a".to_owned()].into_iter().collect();
        let report = restore_ecu_states(
            &databases,
            &topology(vec![persisted_ecu(
                "ECU_A",
                0x1001,
                PersistedEcuState::Online,
                Some("App"),
            )]),
            true,
            &can_pinned,
        )
        .await;

        assert_eq!(report.assumed_online, 0);
        assert!(databases.restored_variants().await.is_empty());
        assert_eq!(databases.last_seen("ECU_A").await, Some(last_seen()));
    }

    /// [[ test~ecu-state-restore-address-mismatch-restores-nothing, A changed ECU address restores nothing, test ]]
    #[tokio::test]
    async fn address_mismatch_restores_nothing() {
        for (gateway, persisted_address) in [(GATEWAY, 0x1999), (0x2000, 0x1001)] {
            let databases =
                TestDatabases::new(vec![(ecu("ECU_A", 0x1001, gateway, &[]), vec!["App"])]);
            let report = restore_ecu_states(
                &databases,
                &topology(vec![persisted_ecu(
                    "ECU_A",
                    persisted_address,
                    PersistedEcuState::Online,
                    Some("App"),
                )]),
                true,
                &HashSet::default(),
            )
            .await;

            assert_eq!(report, RestoreReport::default());
            assert_eq!(databases.last_seen("ECU_A").await, None);
        }
    }

    /// [[ test~ecu-state-restore-variant-missing-from-the-database-is-detected-again, A persisted variant missing from the database is detected again, test ]]
    #[tokio::test]
    async fn variant_missing_from_the_database_is_detected_again() {
        let databases = TestDatabases::new(vec![(ecu("ECU_A", 0x1001, GATEWAY, &[]), vec!["App"])]);
        let report = restore_ecu_states(
            &databases,
            &topology(vec![persisted_ecu(
                "ECU_A",
                0x1001,
                PersistedEcuState::Online,
                Some("RemovedVariant"),
            )]),
            true,
            &HashSet::default(),
        )
        .await;

        assert_eq!(report.assumed_online, 0);
        assert!(databases.restored_variants().await.is_empty());
        assert_eq!(databases.last_seen("ECU_A").await, Some(last_seen()));
    }
}
