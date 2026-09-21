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

//! Database-derived state shared by the UDS layer and the transports built over
//! it.

use std::sync::Arc;

use tokio::sync::RwLock;

use crate::{FunctionalDescriptionConfig, HashMap, datatypes::FaultConfig};

/// State derived from the vehicle databases, replaced as a unit by an update.
///
/// Grouped so a runtime update replaces them together, and so sites needing both
/// `ecus` and `functional_description_database` cannot observe two
/// inconsistent snapshots.
///
/// `C` is the ECU state coordinator. The UDS layer needs its concrete API,
/// while a transport only ever sees it as an [`EcuConnectivityHandler`], so it
/// stays a type parameter instead of being erased for everyone.
pub struct EcuData<T, C> {
    ecus: HashMap<String, RwLock<T>>,
    functional_description_database: String,
    fault_config: FaultConfig,
    state_coordinator: Arc<C>,
}

impl<T, C> EcuData<T, C> {
    #[must_use]
    pub fn new(
        ecus: HashMap<String, RwLock<T>>,
        functional_description_config: &FunctionalDescriptionConfig,
        fault_config: FaultConfig,
        state_coordinator: Arc<C>,
    ) -> Self {
        let functional_description_database = ecus
            .keys()
            .find(|name| {
                name.eq_ignore_ascii_case(&functional_description_config.description_database)
            })
            .cloned()
            .unwrap_or_else(|| {
                functional_description_config
                    .description_database
                    .to_lowercase()
            });
        Self {
            ecus,
            functional_description_database,
            fault_config,
            state_coordinator,
        }
    }

    /// Every loaded ECU database, including the functional-description one.
    #[must_use]
    pub fn ecus(&self) -> &HashMap<String, RwLock<T>> {
        &self.ecus
    }

    /// One loaded ECU database, borrowed from the load it belongs to.
    ///
    /// The caller holds the read guard this was resolved under for its whole
    /// operation, so the ECU cannot be replaced while it is in use.
    #[must_use]
    pub fn ecu(&self, ecu_name: &str) -> Option<&RwLock<T>> {
        self.ecus.get(ecu_name)
    }

    /// Name of the ECU holding the functional-group definitions.
    #[must_use]
    pub fn functional_description_database(&self) -> &str {
        &self.functional_description_database
    }

    /// The fault-handling configuration this data was loaded with.
    #[must_use]
    pub fn fault_config(&self) -> &FaultConfig {
        &self.fault_config
    }

    /// The ECU state coordinator this data was loaded with.
    #[must_use]
    pub fn state_coordinator(&self) -> &Arc<C> {
        &self.state_coordinator
    }

    /// Every loaded ECU name, including the functional-description database.
    #[must_use]
    pub fn all_ecu_names(&self) -> Vec<String> {
        self.ecus.keys().cloned().collect()
    }

    /// Physical ECU names: every loaded ECU except the functional-description
    /// database.
    ///
    /// An exact compare is enough because [`Self::new`] already resolved the
    /// configured name to the map key it matches; a name that is not a key
    /// cannot filter anything out.
    #[must_use]
    pub fn physical_ecu_names(&self) -> Vec<String> {
        self.ecus
            .keys()
            .filter(|ecu| **ecu != self.functional_description_database)
            .cloned()
            .collect()
    }
}

impl<T: crate::EcuManager, C> EcuData<T, C> {
    /// Physical ECUs of this load that belong to `functional_group`.
    ///
    /// A method on the load rather than on a manager, so a caller holding a
    /// borrowed load asks it directly instead of going back through a handle
    /// that would have to resolve the load again.
    pub async fn ecus_for_functional_group(
        &self,
        functional_group: &str,
        gateway_only: bool,
    ) -> Vec<String> {
        let mut ecu_names = Vec::new();
        for (name, ecu) in &self.ecus {
            let ecu_guard = ecu.read().await;
            if gateway_only && ecu_guard.logical_address() != ecu_guard.logical_gateway_address() {
                continue; // skip non gateway ECUs
            }
            if !ecu_guard.is_physical_ecu() {
                continue; // skip functional description database
            }
            if !ecu_guard
                .functional_groups()
                .iter()
                .any(|group| group.eq_ignore_ascii_case(functional_group))
            {
                continue; // skip ECUs not in the functional group
            }
            ecu_names.push(name.clone());
        }
        ecu_names
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use tokio::sync::RwLock;

    use super::*;
    use crate::{EcuConnectivityHandler, ReloadComponent, ReloadableOwner};

    struct StateHandler {
        state_id: usize,
        observed: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl EcuConnectivityHandler for StateHandler {
        async fn on_gateway_connected(&self, _ecu_names: &[String]) {
            self.observed.store(self.state_id, Ordering::SeqCst);
        }

        async fn on_gateway_disconnected(&self, _ecu_names: &[String]) {
            self.observed.store(self.state_id, Ordering::SeqCst);
        }
    }

    fn state_id(id: usize, observed: &Arc<AtomicUsize>) -> EcuData<usize, StateHandler> {
        EcuData::new(
            HashMap::from_iter([(id.to_string(), RwLock::new(id))]),
            &FunctionalDescriptionConfig::default(),
            FaultConfig::default(),
            Arc::new(StateHandler {
                state_id: id,
                observed: Arc::clone(observed),
            }),
        )
    }

    #[test]
    fn functional_description_uses_canonical_loaded_key() {
        let ecus = HashMap::from_iter([
            ("physical_ecu".to_owned(), RwLock::new(1)),
            ("functional_groups".to_owned(), RwLock::new(2)),
        ]);
        let config = FunctionalDescriptionConfig {
            description_database: "FUNCTIONAL_GROUPS".to_owned(),
            ..Default::default()
        };
        let data = EcuData::new(
            ecus,
            &config,
            FaultConfig::default(),
            Arc::new(StateHandler {
                state_id: 0,
                observed: Arc::new(AtomicUsize::new(0)),
            }),
        );

        assert_eq!(data.functional_description_database(), "functional_groups");
        assert_eq!(data.physical_ecu_names(), vec!["physical_ecu"]);
    }

    /// A resolved borrow holds the load: an update waits for it rather than
    /// replacing the databases the transport is still reading.
    #[tokio::test]
    async fn a_resolved_borrow_holds_the_load() {
        let observed = Arc::new(AtomicUsize::new(usize::MAX));
        let owner = Arc::new(ReloadableOwner::new(state_id(7, &observed)));
        let reader = owner.reader();

        let data = reader.read().await;
        assert_eq!(
            *data.ecus().values().next().expect("one ECU").read().await,
            7
        );

        let update = tokio::spawn({
            let owner = Arc::clone(&owner);
            let observed = Arc::clone(&observed);
            async move { owner.apply(state_id(9, &observed)).await }
        });

        tokio::task::yield_now().await;
        assert!(
            !update.is_finished(),
            "the update must wait while the load is still borrowed"
        );
        assert_eq!(
            *data.ecus().values().next().expect("one ECU").read().await,
            7,
            "the borrow still reads the load it was resolved from"
        );

        drop(data);
        update
            .await
            .expect("the update completes once the borrow is dropped");
        let data = reader.read().await;
        assert_eq!(
            *data.ecus().values().next().expect("one ECU").read().await,
            9,
            "the next resolve sees the new load"
        );
    }

    /// The coordinator is the one handle a connection task keeps past the
    /// borrow, so it must belong to the load it was resolved from.
    #[tokio::test]
    async fn a_retained_coordinator_belongs_to_the_load_it_came_from() {
        let observed = Arc::new(AtomicUsize::new(usize::MAX));
        let owner = ReloadableOwner::new(state_id(7, &observed));
        let reader = owner.reader();

        let coordinator = Arc::clone(reader.read().await.state_coordinator());
        owner.apply(state_id(9, &observed)).await;

        coordinator.on_gateway_connected(&[]).await;
        assert_eq!(observed.load(Ordering::SeqCst), 7);
    }
}
