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

use std::sync::{Arc, atomic::AtomicBool};

use cda_interfaces::{
    DiagComm, DiagServiceError, EcuGateway, EcuManager, FunctionalDescriptionConfig, HashMap,
    HashMapExtensions, HashSet, HashSetExtensions, SchemaDescription, SchemaProvider, UdsEcu,
    UdsEcuDb, datatypes::FaultConfig,
};
use tokio::{
    sync::{Mutex, RwLock, Semaphore, mpsc},
    task::JoinHandle,
};

pub mod coordinator;
mod data_transfer;
mod dtc;
mod functional_group;
mod query;
mod security;
mod session;
pub mod state_coordinator;
mod tester_present;
mod transport;
mod types;
mod util;
mod variant;

#[cfg(test)]
mod test_helpers;

pub use state_coordinator::EcuStateCoordinator;
pub use types::TesterPresentTask;
use types::{EcuDataTransfer, EcuIdentifier};

pub struct UdsManager<S: EcuGateway, T: UdsEcuDb> {
    ecus: Arc<HashMap<String, RwLock<T>>>,
    gateway: S,
    data_transfers: Arc<Mutex<HashMap<EcuIdentifier, EcuDataTransfer>>>,
    ecu_semaphores: Arc<Mutex<HashMap<String, Arc<Semaphore>>>>,
    tester_present_tasks: Arc<RwLock<HashMap<EcuIdentifier, TesterPresentTask>>>,
    session_reset_tasks: Arc<RwLock<HashMap<EcuIdentifier, JoinHandle<()>>>>,
    security_reset_tasks: Arc<RwLock<HashMap<EcuIdentifier, JoinHandle<()>>>>,
    state_coordinator: EcuStateCoordinator,
    functional_description_database: String,
    fault_config: FaultConfig,
    update_in_progress: Arc<AtomicBool>,
}

/// Guard that reports whether any ECU flash data transfers are currently active.
///
/// Used by the runtime update plugin to block updates while transfers are in progress.
/// Implements [`cda_interfaces::runtime_update_api::ActivityGuard`] with a conservative
/// locking strategy: if the internal mutex is contended, it reports active transfers
/// to prevent TOCTOU races.
pub struct FlashTransferObserver {
    data_transfers: Arc<Mutex<HashMap<EcuIdentifier, EcuDataTransfer>>>,
}

impl cda_interfaces::runtime_update_api::ActivityGuard for FlashTransferObserver {
    fn is_active(&self) -> bool {
        self.data_transfers
            .try_lock()
            .map_or(true, |guard| !guard.is_empty())
    }
}

impl<S: EcuGateway, T: UdsEcuDb> UdsManager<S, T> {
    fn uds_ecu_db(&self, ecu_name: &str) -> Result<&RwLock<T>, DiagServiceError> {
        self.ecus
            .get(ecu_name)
            .ok_or_else(|| DiagServiceError::NotFound(format!("ECU {ecu_name} not found")))
    }
}

impl<S: EcuGateway, T: EcuManager> UdsManager<S, T> {
    /// Create a new [`UdsManager`].
    pub fn new(
        gateway: S,
        ecus: Arc<HashMap<String, RwLock<T>>>,
        mut variant_detection_receiver: mpsc::Receiver<Vec<String>>,
        state_coordinator: EcuStateCoordinator,
        functional_description_config: &FunctionalDescriptionConfig,
        fault_config: FaultConfig,
        update_in_progress: Arc<AtomicBool>,
    ) -> Self {
        let manager = Self {
            ecus,
            gateway,
            data_transfers: Arc::new(Mutex::new(HashMap::new())),
            ecu_semaphores: Arc::new(Mutex::new(HashMap::new())),
            tester_present_tasks: Arc::new(RwLock::new(HashMap::new())),
            session_reset_tasks: Arc::new(RwLock::new(HashMap::new())),
            security_reset_tasks: Arc::new(RwLock::new(HashMap::new())),
            state_coordinator,
            functional_description_database: functional_description_config
                .description_database
                .clone(),
            fault_config,
            update_in_progress,
        };

        let vd_uds_clone = manager.clone();
        cda_interfaces::spawn_named!("variant-detection-receiver", async move {
            while let Some(ecus) = variant_detection_receiver.recv().await {
                let mut processed_duplicates = HashSet::new();
                let mut deduplicated_ecus = Vec::new();

                for ecu_name in ecus {
                    if processed_duplicates.contains(&ecu_name) {
                        continue;
                    }

                    if let Some(ecu) = vd_uds_clone.ecus.get(&ecu_name) {
                        let ecu_read = ecu.read().await;
                        if let Some(duplicates) = ecu_read.duplicating_ecu_names() {
                            processed_duplicates.extend(duplicates.iter().cloned());
                        }
                        deduplicated_ecus.push(ecu_name);
                    } else {
                        // A silent drop here once masked a casing mismatch
                        // between a transport's discovery names and the
                        // lowercase-keyed ECU map, leaving discovered ECUs
                        // NotTested until their first request.
                        tracing::warn!(
                            ecu_name,
                            "Variant detection trigger for unknown ECU dropped"
                        );
                    }
                }

                vd_uds_clone
                    .start_variant_detection_for_ecus(deduplicated_ecus)
                    .await;
            }
        });

        manager
    }

    pub fn flash_transfer_guard(&self) -> FlashTransferObserver {
        FlashTransferObserver {
            data_transfers: Arc::clone(&self.data_transfers),
        }
    }

    /// Returns a clone of the state coordinator for use by the `DoIP` layer.
    /// The coordinator implements `EcuStateEvents` and propagates disconnect events.
    pub fn state_coordinator(&self) -> EcuStateCoordinator {
        self.state_coordinator.clone()
    }

    /// Abort all background tasks owned by this instance. Idempotent.
    pub async fn shutdown(&self) {
        let mut tester_present_tasks = self.tester_present_tasks.write().await;
        let mut session_reset_tasks = self.session_reset_tasks.write().await;
        let mut security_reset_tasks = self.security_reset_tasks.write().await;
        let mut data_transfers = self.data_transfers.lock().await;
        tester_present_tasks
            .drain()
            .map(|(_, tp)| tp.task)
            .chain(session_reset_tasks.drain().map(|(_, h)| h))
            .chain(security_reset_tasks.drain().map(|(_, h)| h))
            .chain(data_transfers.drain().map(|(_, t)| t.task))
            .for_each(|h| h.abort());
    }
}

impl<S: Clone + EcuGateway, T: UdsEcuDb> Clone for UdsManager<S, T> {
    fn clone(&self) -> Self {
        Self {
            ecus: Arc::clone(&self.ecus),
            gateway: self.gateway.clone(),
            data_transfers: Arc::clone(&self.data_transfers),
            ecu_semaphores: Arc::clone(&self.ecu_semaphores),
            tester_present_tasks: Arc::clone(&self.tester_present_tasks),
            session_reset_tasks: Arc::clone(&self.session_reset_tasks),
            security_reset_tasks: Arc::clone(&self.security_reset_tasks),
            state_coordinator: self.state_coordinator.clone(),
            functional_description_database: self.functional_description_database.clone(),
            fault_config: self.fault_config.clone(),
            update_in_progress: Arc::clone(&self.update_in_progress),
        }
    }
}

impl<S: EcuGateway, T: EcuManager> UdsEcu for UdsManager<S, T> {}

impl<S: EcuGateway, T: EcuManager> SchemaProvider for UdsManager<S, T> {
    async fn schema_for_request(
        &self,
        ecu: &str,
        service: &DiagComm,
    ) -> Result<SchemaDescription, DiagServiceError> {
        self.uds_ecu_db(ecu)?
            .read()
            .await
            .schema_for_request(service)
            .await
    }

    async fn schema_for_responses(
        &self,
        ecu: &str,
        service: &DiagComm,
    ) -> Result<SchemaDescription, DiagServiceError> {
        self.uds_ecu_db(ecu)?
            .read()
            .await
            .schema_for_responses(service)
            .await
    }

    async fn schema_for_fg_request(
        &self,
        service: &DiagComm,
        functional_group_name: &str,
    ) -> Result<SchemaDescription, DiagServiceError> {
        self.uds_ecu_db(&self.functional_description_database)?
            .read()
            .await
            .schema_for_fg_request(service, functional_group_name)
            .await
    }
}
