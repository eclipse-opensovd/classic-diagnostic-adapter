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
    DiagComm, DiagServiceError, DynamicPlugin, EcuGateway, EcuManager, HashMap, HashMapExtensions,
    ReloadComponent, Reloadable, SchemaDescription, SchemaProvider, TesterPresentType, UdsEcu,
    UdsEcuDb, UdsTransport, VariantDetectionReceiver,
    communication_control::{ActivationCause, CommunicationAccess, CommunicationGuard},
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
/// The task hands the receiver back when canceled, so the next communication
/// initialization can resume reading from the same channel rather than losing
/// queued discoveries.
type VariantDetectionListener =
    Arc<Mutex<Option<(CancellationToken, JoinHandle<VariantDetectionReceiver>)>>>;

enum ReceiverRetention {
    /// Keep the receiver when the listener may be restarted later.
    Keep,
    /// Discard the receiver when the listener will not be restarted.
    Discard,
}

/// [`EcuData`](cda_interfaces::ecu_data::EcuData) as used by the UDS layer.
pub type VehicleEcuData<T> = cda_interfaces::ecu_data::EcuData<T, EcuStateCoordinator>;

/// Opaque composition result for UDS database-derived state.
pub struct UdsDataParts<T: UdsEcuDb> {
    pub data: Reloadable<VehicleEcuData<T>>,
    pub reload: Arc<dyn ReloadComponent<VehicleEcuData<T>>>,
}

/// Creates UDS state with installation authority exposed only as opaque traits.
#[must_use]
pub fn prepare_ecu_data<T: UdsEcuDb>(data: VehicleEcuData<T>) -> UdsDataParts<T> {
    let reloader = Arc::new(cda_interfaces::ReloadableOwner::new(data));
    UdsDataParts {
        data: reloader.reader(),
        reload: reloader as Arc<dyn ReloadComponent<VehicleEcuData<T>>>,
    }
}

/// Runtime UDS API with read-only reload state.
pub struct UdsManager<S: EcuGateway, T: UdsEcuDb> {
    ecu_data: Reloadable<VehicleEcuData<T>>,
    gateway: Arc<S>,
    data_transfers: Arc<Mutex<HashMap<EcuIdentifier, EcuDataTransfer>>>,
    ecu_semaphores: Arc<Mutex<HashMap<String, Arc<Semaphore>>>>,
    tester_present_tasks: Arc<RwLock<HashMap<EcuIdentifier, TesterPresentTask>>>,
    session_reset_tasks: Arc<RwLock<HashMap<EcuIdentifier, JoinHandle<()>>>>,
    security_reset_tasks: Arc<RwLock<HashMap<EcuIdentifier, JoinHandle<()>>>>,
    communication_access: Arc<dyn CommunicationAccess>,
    /// Configured retry hint surfaced on [`DiagServiceError::CommunicationNotReady`].
    communication_retry_after: Duration,
    /// Held until communication initialization starts the listener. Deferred
    /// rather than spawned in [`UdsManager::new`] so no VAM-triggered detection
    /// work runs before an authorized activation.
    variant_detection_receiver: Arc<Mutex<Option<VariantDetectionReceiver>>>,
    variant_detection_listener: VariantDetectionListener,
    /// Tester-present types that were running at the last `deinitialize()` call,
    /// to be restarted in the next `initialize()` call when communication is
    /// re-enabled.
    tester_present_snapshot: Arc<Mutex<Vec<TesterPresentType>>>,
}

impl<S: EcuGateway, T: UdsEcuDb> UdsManager<S, T> {
    /// The persistent gateway used by this manager.
    fn gateway(&self) -> &S {
        &self.gateway
    }

    /// One ECU database, for callers that need a single ECU and nothing else
    /// from the vehicle data.
    ///
    /// Holds the read guard only for the lookup. A caller that needs more than
    /// one field should take the guard itself and keep it for the operation.
    async fn uds_ecu_db(&self, ecu_name: &str) -> Result<Arc<RwLock<T>>, DiagServiceError> {
        Self::ecu_in(&*self.ecu_data.read().await, ecu_name)
    }

    /// Resolves the functional-description database outof vehicle data the
    /// caller already holds, so both halves come from the same load.
    fn fd_in(data: &VehicleEcuData<T>) -> Result<Arc<RwLock<T>>, DiagServiceError> {
        Self::ecu_in(data, data.functional_description_database())
    }

    /// Resolves an ECU out of vehicle data the caller already holds.
    fn ecu_in(
        data: &VehicleEcuData<T>,
        ecu_name: &str,
    ) -> Result<Arc<RwLock<T>>, DiagServiceError> {
        data.ecu(ecu_name)
            .ok_or_else(|| DiagServiceError::NotFound(format!("ECU {ecu_name} not found")))
    }

    /// The ECU state coordinator of the current vehicle data.
    async fn state_coordinator(&self) -> Arc<EcuStateCoordinator> {
        Arc::clone(self.ecu_data.read().await.state_coordinator())
    }

    /// Requires diagnostic communication to be enabled before sending a UDS
    /// request. Otherwise, requests activation when permitted by `init_mode`
    /// and immediately returns [`DiagServiceError::CommunicationNotReady`].
    ///
    /// The returned guard must be held for the duration of the send.
    ///
    /// # Constraints
    ///
    /// Internal variant-detection sends must not call this method because framework
    /// detection runs before communication reaches the enabled state. The direct public
    /// detection entry point calls it before entering the internal detection path.
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
        Err(self.build_communication_not_ready_err("Communication is not currently enabled"))
    }

    /// Builds a [`DiagServiceError::CommunicationNotReady`] carrying this
    /// manager's configured retry hint.
    pub(crate) fn build_communication_not_ready_err(
        &self,
        message: impl Into<String>,
    ) -> DiagServiceError {
        DiagServiceError::CommunicationNotReady {
            message: message.into(),
            retry_after: self.communication_retry_after,
        }
    }
}

impl<S: EcuGateway, T: EcuManager> UdsManager<S, T> {
    /// Creates the runtime manager from read-only ECU state.
    pub fn new(
        gateway: Arc<S>,
        data: Reloadable<VehicleEcuData<T>>,
        variant_detection_receiver: VariantDetectionReceiver,
        communication_access: Arc<dyn CommunicationAccess>,
        communication_retry_after: Duration,
    ) -> Self {
        Self {
            ecu_data: data,
            gateway,
            data_transfers: Arc::new(Mutex::new(HashMap::new())),
            ecu_semaphores: Arc::new(Mutex::new(HashMap::new())),
            tester_present_tasks: Arc::new(RwLock::new(HashMap::new())),
            session_reset_tasks: Arc::new(RwLock::new(HashMap::new())),
            security_reset_tasks: Arc::new(RwLock::new(HashMap::new())),
            communication_access,
            communication_retry_after,
            variant_detection_receiver: Arc::new(Mutex::new(Some(variant_detection_receiver))),
            variant_detection_listener: Arc::new(Mutex::new(None)),
            tester_present_snapshot: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Stops the listener, then either drops its receiver or drains and retains
    /// it for the next initialization, which preserves the channel held by
    /// long-lived senders.
    async fn stop_variant_detection_listener(&self, receiver_retention: ReceiverRetention) {
        let Some((cancel_token, listener)) = self.variant_detection_listener.lock().await.take()
        else {
            return;
        };
        cancel_token.cancel();
        match listener.await {
            Ok(mut receiver) if matches!(receiver_retention, ReceiverRetention::Keep) => {
                while receiver.try_recv().is_ok() {}
                *self.variant_detection_receiver.lock().await = Some(receiver);
            }
            Ok(_) => {}
            Err(error) => {
                tracing::error!(%error, "Variant detection listener failed during shutdown");
            }
        }
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
        let _communication_guard = self.require_communication_ready()?;
        // Look up the service definition in the MDD database using the same
        // approach as lookup_diagcomms_by_request_prefix - matches against
        // coded constant parameter values in the database.
        let ecu = self.uds_ecu_db(ecu_name).await?;
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
        let _communication_guard = self.require_communication_ready()?;
        let ecu = self.uds_ecu_db(ecu_name).await?;
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
}

impl<S: EcuGateway, T: UdsEcuDb> Clone for UdsManager<S, T> {
    fn clone(&self) -> Self {
        Self {
            ecu_data: self.ecu_data.clone(),
            gateway: Arc::clone(&self.gateway),
            data_transfers: Arc::clone(&self.data_transfers),
            ecu_semaphores: Arc::clone(&self.ecu_semaphores),
            tester_present_tasks: Arc::clone(&self.tester_present_tasks),
            session_reset_tasks: Arc::clone(&self.session_reset_tasks),
            security_reset_tasks: Arc::clone(&self.security_reset_tasks),
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
        self.stop_variant_detection_listener(ReceiverRetention::Discard)
            .await;
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
        Self::fd_in(&*self.ecu_data.read().await)?
            .read()
            .await
            .schema_for_fg_request(service, functional_group_name)
            .await
    }
}

impl<S: EcuGateway, T: EcuManager> cda_interfaces::file_manager::EmbeddedFilesProvider
    for UdsManager<S, T>
{
    async fn embedded_files_list(
        &self,
        ecu_name: &str,
    ) -> Result<HashMap<String, cda_interfaces::file_manager::ChunkMetaData>, DiagServiceError>
    {
        Ok(self.uds_ecu_db(ecu_name).await?.read().await.list().await)
    }

    async fn embedded_file(
        &self,
        ecu_name: &str,
        id: &str,
    ) -> Result<(cda_interfaces::file_manager::ChunkMetaData, Vec<u8>), DiagServiceError> {
        self.uds_ecu_db(ecu_name)
            .await?
            .read()
            .await
            .get(id)
            .await
            .map_err(|e| DiagServiceError::NotFound(e.to_string()))
    }
}
