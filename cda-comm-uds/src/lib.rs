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

use std::{sync::Arc, time::Duration};

use cda_interfaces::{
    DiagComm, DiagServiceError, DynamicPlugin, EcuGateway, EcuManager, FunctionalDescriptionConfig,
    HashMap, HashMapExtensions, HashSet, HashSetExtensions, SchemaDescription, SchemaProvider,
    TesterPresentType, UdsEcu, UdsEcuDb, UdsTransport, VariantDetectionReceiver,
    communication_control::{
        ActivationCause, CommunicationAccess, CommunicationGuard, error::CommControlError,
    },
    datatypes::FaultConfig,
    diagservices::UdsPayloadData,
};
use tokio::{
    sync::{Mutex, RwLock, Semaphore},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

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

/// The running variant-detection listener task, with the token that cancels it.
///
/// The task hands the receiver back when canceled, so a later
/// [`UdsManager::start_variant_detection_listener`] can resume reading from the
/// same channel rather than losing queued discoveries.
type VariantDetectionListener =
    Arc<Mutex<Option<(CancellationToken, JoinHandle<VariantDetectionReceiver>)>>>;

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
    communication_access: Arc<dyn CommunicationAccess>,
    /// Configured retry hint surfaced on [`DiagServiceError::CommunicationNotReady`].
    communication_retry_after: Duration,
    /// Held until [`UdsManager::start_variant_detection_listener`] takes it
    /// from the initializer chain. Deferred rather than spawned in [`UdsManager::new`]
    /// so no VAM-triggered detection work runs before an authorized activation;
    variant_detection_receiver: Arc<Mutex<Option<VariantDetectionReceiver>>>,
    variant_detection_listener: VariantDetectionListener,
    /// Tester-present types that were running at the last `deinitialize()` call,
    /// to be restarted in the next `initialize()` call when communication is
    /// re-enabled.
    tester_present_snapshot: Arc<Mutex<Vec<TesterPresentType>>>,
}

impl<S: EcuGateway, T: UdsEcuDb> UdsManager<S, T> {
    fn uds_ecu_db(&self, ecu_name: &str) -> Result<&RwLock<T>, DiagServiceError> {
        self.ecus
            .get(ecu_name)
            .ok_or_else(|| DiagServiceError::NotFound(format!("ECU {ecu_name} not found")))
    }

    /// Requires diagnostic communication to already be enabled before
    /// sending a UDS request. When it is not, this fires a non-blocking
    /// activation request (on demand, when `init_mode` allows it) and
    /// returns [`DiagServiceError::CommunicationNotReady`] immediately,
    /// rather than awaiting the full activation sequence inline, which can
    /// take seconds due to variant detection, and would otherwise turn the
    /// first diagnostic request into a long hang instead of a fast "not
    /// ready, retry" response. The returned guard must be held for the
    /// duration of the send so a concurrent disable cannot tear down the
    /// transport underneath it.
    ///
    /// Must never be called from the variant-detection path ([`UdsManager::detect_variant`]
    /// and everything it reaches, i.e. [`UdsManager::send_without_variant_guard`]:
    /// detection runs as part of *becoming* enabled, before the state
    /// reaches `Enabled`, so gating it here would deadlock activation
    /// against itself.
    ///
    /// # Errors
    ///
    /// Returns [`DiagServiceError::CommunicationNotReady`] when communication
    /// is not currently enabled.
    pub(crate) fn require_communication_ready(
        &self,
    ) -> Result<CommunicationGuard, DiagServiceError> {
        if let Ok(guard) = self.communication_access.acquire() {
            return Ok(guard);
        }
        self.communication_access
            .request_activate(ActivationCause::DiagnosticRequest);
        Err(self.communication_not_ready("Communication is not currently enabled"))
    }

    /// Builds a [`DiagServiceError::CommunicationNotReady`] carrying this
    /// manager's configured retry hint.
    pub(crate) fn communication_not_ready(&self, message: impl Into<String>) -> DiagServiceError {
        DiagServiceError::CommunicationNotReady {
            message: message.into(),
            retry_after: self.communication_retry_after,
        }
    }
}

impl<S: EcuGateway, T: EcuManager> UdsManager<S, T> {
    /// Create a new [`UdsManager`].
    #[allow(
        clippy::too_many_arguments,
        reason = "Combining parameters into a struct is not preferred here, to keep constructor \
                  call semantics explicit"
    )]
    pub fn new(
        gateway: S,
        ecus: Arc<HashMap<String, RwLock<T>>>,
        variant_detection_receiver: VariantDetectionReceiver,
        state_coordinator: EcuStateCoordinator,
        functional_description_config: &FunctionalDescriptionConfig,
        fault_config: FaultConfig,
        communication_access: Arc<dyn CommunicationAccess>,
        communication_retry_after: Duration,
    ) -> Self {
        Self {
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
            communication_access,
            communication_retry_after,
            variant_detection_receiver: Arc::new(Mutex::new(Some(variant_detection_receiver))),
            variant_detection_listener: Arc::new(Mutex::new(None)),
            tester_present_snapshot: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Takes ownership of the variant-detection-trigger receiver and spawns
    /// the task that drains it, dispatching spontaneous VAM-discovery
    /// triggers (arriving after startup) to [`Self::start_variant_detection_for_ecus`].
    ///
    /// Deliberately **not** spawned in [`Self::new`]: doing so would run
    /// detection-triggering work before any authorized activation. Called
    /// once from [`CommunicationLifecycle::initialize`] before the initial
    /// sweep runs. The initial discovery burst during
    /// `transport_control.enable()` simply buffers in the channel until then
    /// (bounded by the channel's capacity; see the caller), since the first
    /// full sweep does not depend on this listener at all.
    ///
    /// The receiver is returned by the previous listener when communication is
    /// disabled, allowing a new listener to be started on reactivation.
    pub(crate) async fn start_variant_detection_listener(&self) -> Result<(), CommControlError> {
        let Some(mut variant_detection_receiver) =
            self.variant_detection_receiver.lock().await.take()
        else {
            return Ok(());
        };

        let vd_uds_clone = self.clone();
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let listener = cda_interfaces::spawn_named!("variant-detection-receiver", async move {
            loop {
                let ecus = tokio::select! {
                    biased; // prefer cancellation over variant detection
                    () = task_cancel.cancelled() => break,
                    ecus = variant_detection_receiver.recv() => {
                        let Some(ecus) = ecus else { break };
                        ecus.into_ecus()
                    }
                };
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

                tokio::select! {
                    () = task_cancel.cancelled() => break,
                    () = vd_uds_clone.start_variant_detection_for_ecus(deduplicated_ecus) => {}
                }
            }
            variant_detection_receiver
        });
        *self.variant_detection_listener.lock().await = Some((cancel, listener));

        Ok(())
    }

    /// Cancels the listener task spawned by [`Self::start_variant_detection_listener`]
    /// and awaits it for the `mpsc::Receiver` it hands back.
    ///
    /// `retain_receiver` controls what happens to that receiver:
    ///
    /// - `true` (used by [`CommunicationLifecycle::deinitialize`]): the
    ///   receiver is drained of stale triggers and stored back in
    ///   [`Self::variant_detection_receiver`] so the next
    ///   [`Self::start_variant_detection_listener`] call can resume reading
    ///   from it. This is required rather than just building a fresh channel
    ///   on reactivation: the `Sender` side is cloned out once at startup to
    ///   long-lived components (e.g. `EcuStateCoordinator`) and is never
    ///   replaced, so the original receiver is the only thing that can still
    ///   observe messages sent through those clones.
    /// - `false` (used by [`cda_interfaces::Shutdown::shutdown`]): the
    ///   receiver is simply dropped, since shutdown is permanent and there is
    ///   no future `initialize()` to resume into.
    async fn stop_variant_detection_listener(&self, retain_receiver: bool) {
        let Some((cancel_token, listener)) = self.variant_detection_listener.lock().await.take()
        else {
            return;
        };
        cancel_token.cancel();
        match listener.await {
            Ok(mut receiver) if retain_receiver => {
                while receiver.try_recv().is_ok() {}
                *self.variant_detection_receiver.lock().await = Some(receiver);
            }
            Ok(_) => {}
            Err(error) => {
                tracing::error!(%error, "Variant detection listener failed during shutdown");
            }
        }
    }

    /// Returns a clone of the state coordinator for use by the `DoIP` layer.
    /// The coordinator implements `EcuStateEvents` and propagates disconnect events.
    pub fn state_coordinator(&self) -> EcuStateCoordinator {
        self.state_coordinator.clone()
    }

    /// Send a diagnostic service by its request prefix, looking up the service definition
    /// in the MDD database and encoding JSON parameters according to the
    /// service's parameter definitions.
    ///
    /// This method resolves the matching service definition(s) from the supplied
    /// request prefix via
    /// `lookup_diagcomms_by_request_prefix` (matching against coded constant
    /// parameters in the MDD database), and sends the first match with the
    /// provided parameters encoded through `create_uds_payload`.
    ///
    /// The `service_bytes` prefix starts with the service ID and may include
    /// additional bytes. This allows services that
    /// use coded constant parameters (e.g., specific DID values) to be
    /// resolved by matching the exact byte sequence.
    ///
    /// # Errors
    /// Returns `DiagServiceError` if the service is not found or if the
    /// request fails.
    ///
    /// # Example
    /// ```ignore
    /// // ReadDataByIdentifier DID 0xF190
    /// uds.send_by_sid(
    ///     "ECU_NAME",
    ///     &[0x22, 0xF1, 0x90],               // SID and DID bytes
    ///     &security_plugin,
    ///     HashMap::from([("did".into(), json!(0xF190))]),
    ///     true,
    /// ).await?;
    /// ```
    pub async fn send_by_sid(
        &self,
        ecu_name: &str,
        service_bytes: &[u8],
        security_plugin: &DynamicPlugin,
        params: HashMap<String, serde_json::Value>,
        map_to_json: bool,
    ) -> Result<<T as cda_interfaces::PayloadDecoder>::Response, DiagServiceError> {
        // Look up the service definition in the MDD database using the same
        // approach as lookup_diagcomms_by_request_prefix - matches against
        // coded constant parameter values in the database.
        let ecu = self.uds_ecu_db(ecu_name)?;
        let services = ecu
            .read()
            .await
            .lookup_diagcomms_by_request_prefix(service_bytes)?;

        let diag_comm = services.into_iter().next().ok_or_else(|| {
            DiagServiceError::NotFound(format!(
                "No diagnostic service found matching request prefix: {service_bytes:02X?}"
            ))
        })?;

        self.send(
            ecu_name,
            diag_comm,
            security_plugin,
            Some(UdsPayloadData::ParameterMap(params)),
            map_to_json,
        )
        .await
    }

    /// Send a diagnostic service by its SID and name, looking up the service
    /// definition via `lookup_service_by_sid_and_name` and encoding JSON
    /// parameters according to the service's parameter definitions.
    ///
    /// This method performs prefix/suffix matching on the service short name
    /// in the MDD database using the `database_naming_convention` settings.
    /// The `name` argument is matched against the trimmed short name of all
    /// services with the given `service_id`.
    ///
    ///
    /// # Errors
    /// Returns `DiagServiceError` if the service is not found or if the
    /// request fails.
    ///
    /// # Example
    /// ```ignore
    /// // PeriodicReadDID matching name "myReadService" with SID 0xBB
    /// uds.send_by_sid_and_name(
    ///     "ECU_NAME",
    ///     0xBB,                              // SID
    ///     "myReadService",                   // name to match
    ///     &security_plugin,
    ///     HashMap::from([("did".into(), json!(0xF190))]),
    ///     true,
    /// ).await?;
    /// ```
    pub async fn send_by_sid_and_name(
        &self,
        ecu_name: &str,
        service_id: u8,
        name: &str,
        security_plugin: &DynamicPlugin,
        params: HashMap<String, serde_json::Value>,
        map_to_json: bool,
    ) -> Result<<T as cda_interfaces::PayloadDecoder>::Response, DiagServiceError> {
        let ecu = self.uds_ecu_db(ecu_name)?;
        let diag_comm = ecu
            .read()
            .await
            .lookup_service_by_sid_and_name(service_id, name, None)?;

        self.send(
            ecu_name,
            diag_comm,
            security_plugin,
            Some(UdsPayloadData::ParameterMap(params)),
            map_to_json,
        )
        .await
    }

    /// Aborts all running tester-present tasks and saves their types in the
    /// snapshot so they can be restarted after communication is re-enabled.
    ///
    /// Called by the [`CommunicationLifecycle::deinitialize`] hook before the
    /// transport goes down.
    pub async fn snapshot_and_abort_tester_present(&self) {
        let mut tasks = self.tester_present_tasks.write().await;
        let snapshot: Vec<TesterPresentType> = tasks.values().map(|tp| tp.type_.clone()).collect();
        if !snapshot.is_empty() {
            tracing::debug!(
                count = snapshot.len(),
                "Communication disabling; aborting tester-present tasks and saving snapshot"
            );
        }
        let handles: Vec<_> = tasks.drain().map(|(_, tp)| tp.task).collect();
        drop(tasks);
        for handle in handles {
            handle.abort();
            let _ = handle.await;
        }
        *self.tester_present_snapshot.lock().await = snapshot;
    }

    /// Takes the snapshot saved by [`snapshot_and_abort_tester_present`],
    /// leaving it empty, and returns the types to be restarted.
    ///
    /// Called from [`UdsManager::restart_tester_present_snapshot`],
    /// which the [`CommunicationLifecycle::initialize`] hook runs after
    /// communication is re-enabled.
    pub async fn take_tester_present_snapshot(&self) -> Vec<TesterPresentType> {
        std::mem::take(&mut *self.tester_present_snapshot.lock().await)
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
            communication_access: Arc::clone(&self.communication_access),
            communication_retry_after: self.communication_retry_after,
            variant_detection_receiver: Arc::clone(&self.variant_detection_receiver),
            variant_detection_listener: Arc::clone(&self.variant_detection_listener),
            tester_present_snapshot: Arc::clone(&self.tester_present_snapshot),
        }
    }
}

#[async_trait::async_trait]
impl<S: EcuGateway, T: EcuManager> cda_interfaces::Shutdown for UdsManager<S, T> {
    async fn shutdown(&self) {
        self.stop_variant_detection_listener(false).await;
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

impl<S: EcuGateway, T: EcuManager> UdsEcu for UdsManager<S, T> {}

impl<S: EcuGateway, T: EcuManager> SchemaProvider for UdsManager<S, T> {
    async fn schema_for_request(
        &self,
        ecu: &str,
        service: &DiagComm,
    ) -> Result<SchemaDescription, DiagServiceError> {
        let ecu = self.uds_ecu_variant_detection_concluded(ecu).await?;
        ecu.read().await.schema_for_request(service).await
    }

    async fn schema_for_responses(
        &self,
        ecu: &str,
        service: &DiagComm,
    ) -> Result<SchemaDescription, DiagServiceError> {
        let ecu = self.uds_ecu_variant_detection_concluded(ecu).await?;
        ecu.read().await.schema_for_responses(service).await
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
