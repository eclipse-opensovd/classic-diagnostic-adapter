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

use crate::{
    EcuConnectivityHandler, FunctionalDescriptionConfig, HashMap, Reloadable,
    datatypes::FaultConfig,
};

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
    ecus: Arc<HashMap<String, Arc<RwLock<T>>>>,
    functional_description_database: String,
    fault_config: FaultConfig,
    state_coordinator: Arc<C>,
}

impl<T, C> EcuData<T, C> {
    #[must_use]
    pub fn new(
        ecus: Arc<HashMap<String, Arc<RwLock<T>>>>,
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
    pub fn ecus(&self) -> &Arc<HashMap<String, Arc<RwLock<T>>>> {
        &self.ecus
    }

    /// One loaded ECU database as an owned handle, so a caller can drop the
    /// data it came from instead of borrowing it for the whole
    /// operation.
    #[must_use]
    pub fn ecu(&self, ecu_name: &str) -> Option<Arc<RwLock<T>>> {
        self.ecus.get(ecu_name).map(Arc::clone)
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

    /// Physical ECU names: every loaded ECU except the functional-description
    /// database.
    #[must_use]
    pub fn ecu_names(&self) -> Vec<String> {
        self.ecus
            .keys()
            .filter(|ecu| !ecu.eq_ignore_ascii_case(&self.functional_description_database))
            .cloned()
            .collect()
    }
}

/// The ECU map and connectivity coordinator of one load, borrowed.
///
/// Returned behind a read guard, so a runtime update waits for the reader
/// rather than replacing the data underneath it: the same contract every
/// other reader gets from [`Reloadable::read`](crate::Reloadable::read).
///
/// A trait rather than a tuple because the guard's type names the coordinator,
/// which callers here are deliberately generic over.
pub trait TransportData<T>: Send + Sync {
    /// The ECU databases of this load.
    fn ecus(&self) -> &Arc<HashMap<String, Arc<RwLock<T>>>>;

    /// The connectivity coordinator of this load, owned.
    ///
    /// Owned because a `DoIP` connection-reset task notifies the coordinator for
    /// as long as the connection lives, which outlasts any guard. That single
    /// handle is all a transport task retains: no ECU database escapes this
    /// borrow, so a runtime update tears the databases down on schedule.
    fn connectivity_handler(&self) -> Arc<dyn EcuConnectivityHandler>;
}

/// Read-only database-derived state needed by transports.
///
/// Erases the coordinator type so a transport generic only over its ECU
/// database can still reach the connectivity coordinator.
#[async_trait::async_trait]
pub trait EcuDataView<T>: Send + Sync + 'static {
    /// Borrows the current ECU map and connectivity coordinator.
    ///
    /// Hold the result for the whole operation and resolve again for the next
    /// one. The lock is uncontended outside a runtime update.
    async fn transport_data(&self) -> Box<dyn TransportData<T> + '_>;
}

struct GuardedTransportData<'a, T, C: EcuConnectivityHandler>(
    tokio::sync::RwLockReadGuard<'a, EcuData<T, C>>,
);

impl<T: Send + Sync, C: EcuConnectivityHandler> TransportData<T>
    for GuardedTransportData<'_, T, C>
{
    fn ecus(&self) -> &Arc<HashMap<String, Arc<RwLock<T>>>> {
        self.0.ecus()
    }

    fn connectivity_handler(&self) -> Arc<dyn EcuConnectivityHandler> {
        Arc::clone(self.0.state_coordinator()) as Arc<dyn EcuConnectivityHandler>
    }
}

#[async_trait::async_trait]
impl<T: Send + Sync + 'static, C: EcuConnectivityHandler> EcuDataView<T>
    for Reloadable<EcuData<T, C>>
{
    async fn transport_data(&self) -> Box<dyn TransportData<T> + '_> {
        Box::new(GuardedTransportData(self.read().await))
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
    use crate::ReloadableOwner;

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
            Arc::new(HashMap::from_iter([(
                id.to_string(),
                Arc::new(RwLock::new(id)),
            )])),
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
        let ecus = Arc::new(HashMap::from_iter([
            ("physical_ecu".to_owned(), Arc::new(RwLock::new(1))),
            ("functional_groups".to_owned(), Arc::new(RwLock::new(2))),
        ]));
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
        assert_eq!(data.ecu_names(), vec!["physical_ecu"]);
    }

    /// Transports get the same contract as every other reader: an update waits
    /// for the borrow instead of replacing the databases underneath it.
    #[tokio::test]
    async fn transport_data_blocks_a_runtime_update_until_it_is_dropped() {
        let observed = Arc::new(AtomicUsize::new(usize::MAX));
        let owner = Arc::new(ReloadableOwner::new(state_id(7, &observed)));
        let reader = owner.reader();

        let data = reader.transport_data().await;
        assert_eq!(
            *data.ecus().values().next().expect("one ECU").read().await,
            7
        );

        let updating = tokio::spawn({
            let owner = Arc::clone(&owner);
            let observed = Arc::clone(&observed);
            async move { owner.apply(state_id(9, &observed)).await }
        });
        tokio::task::yield_now().await;
        assert!(
            !updating.is_finished(),
            "an update must not replace data a transport is still reading"
        );

        drop(data);
        updating
            .await
            .expect("update completes once the borrow ends");

        let data = reader.transport_data().await;
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

        let coordinator = reader.transport_data().await.connectivity_handler();
        owner.apply(state_id(9, &observed)).await;

        coordinator.on_gateway_connected(&[]).await;
        assert_eq!(observed.load(Ordering::SeqCst), 7);
    }
}
