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
    HashMap, HashMapExtensions, SchemaDescription, SchemaProvider, TesterPresentType, UdsEcu,
    UdsEcuDb, UdsTransport, VariantDetectionReceiver,
    communication_control::{ActivationCause, CommunicationAccess, CommunicationGuard},
    datatypes::FaultConfig,
    diagservices::UdsPayloadData,
};
use tokio::{
    sync::{Mutex, OwnedSemaphorePermit, RwLock, Semaphore},
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
use types::{EcuDataTransfer, EcuIdentifier, TesterPresentTaskId};

const PERMIT_AQUISITION_TIMEOUT: Duration = Duration::from_secs(10);

async fn request_permits(
    registry: &Mutex<HashMap<String, Arc<Semaphore>>>,
    mut keys: Vec<String>,
) -> Result<Box<[OwnedSemaphorePermit]>, DiagServiceError> {
    keys.sort_unstable();
    keys.dedup();

    tokio::time::timeout(PERMIT_AQUISITION_TIMEOUT, async {
        let semaphores = {
            let mut registry = registry.lock().await;
            keys.into_iter()
                .map(|key| {
                    Arc::clone(
                        registry
                            .entry(key)
                            .or_insert_with(|| Arc::new(Semaphore::new(1))),
                    )
                })
                .collect::<Vec<_>>()
        };

        let mut permits = Vec::with_capacity(semaphores.len());
        for semaphore in semaphores {
            permits.push(semaphore.acquire_owned().await.map_err(|_| {
                DiagServiceError::ResourceError("Request gate was closed".to_owned())
            })?);
        }
        Ok(permits.into_boxed_slice())
    })
    .await
    .map_err(|_| DiagServiceError::Timeout)?
}

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

pub struct UdsManager<S: EcuGateway, T: UdsEcuDb> {
    ecus: Arc<HashMap<String, RwLock<T>>>,
    gateway: S,
    data_transfers: Arc<Mutex<HashMap<EcuIdentifier, EcuDataTransfer>>>,
    ecu_semaphores: Arc<Mutex<HashMap<String, Arc<Semaphore>>>>,
    tester_present_tasks: Arc<RwLock<HashMap<TesterPresentTaskId, JoinHandle<()>>>>,
    session_reset_tasks: Arc<RwLock<HashMap<EcuIdentifier, JoinHandle<()>>>>,
    security_reset_tasks: Arc<RwLock<HashMap<EcuIdentifier, JoinHandle<()>>>>,
    state_coordinator: EcuStateCoordinator,
    functional_description_database: String,
    fault_config: FaultConfig,
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
    async fn request_ecu_permits(
        &self,
        keys: Vec<String>,
    ) -> Result<Box<[OwnedSemaphorePermit]>, DiagServiceError> {
        request_permits(&self.ecu_semaphores, keys).await
    }

    fn uds_ecu_db(&self, ecu_name: &str) -> Result<&RwLock<T>, DiagServiceError> {
        self.ecus
            .get(ecu_name)
            .ok_or_else(|| DiagServiceError::NotFound(format!("ECU {ecu_name} not found")))
    }

    /// Requires diagnostic communication to be enabled before sending a UDS
    /// request. Otherwise, requests activation when permitted by `init_mode`
    /// and immediately returns [`DiagServiceError::CommunicationNotReady`].
    ///
    /// The returned guard must be held for the duration of the send.
    ///
    /// # Constraints
    ///
    /// Must not be called from [`UdsManager::detect_variant`] or anything it
    /// invokes, including [`UdsManager::send_without_variant_guard`], because
    /// variant detection runs before communication reaches the enabled state.
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
        self.stop_variant_detection_listener(ReceiverRetention::Discard)
            .await;
        let mut tester_present_tasks = self.tester_present_tasks.write().await;
        let mut session_reset_tasks = self.session_reset_tasks.write().await;
        let mut security_reset_tasks = self.security_reset_tasks.write().await;
        let mut data_transfers = self.data_transfers.lock().await;
        tester_present_tasks
            .drain()
            .map(|(_, task)| task)
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

#[cfg(test)]
mod request_gate_tests {
    use std::{sync::Arc, time::Duration};

    use cda_interfaces::HashMap;
    use tokio::sync::{Mutex, Semaphore, mpsc, oneshot};

    use super::request_permits;

    fn registry(keys: &[&str]) -> Arc<Mutex<HashMap<String, Arc<Semaphore>>>> {
        Arc::new(Mutex::new(
            keys.iter()
                .map(|key| ((*key).to_owned(), Arc::new(Semaphore::new(1))))
                .collect(),
        ))
    }

    async fn semaphore(
        registry: &Mutex<HashMap<String, Arc<Semaphore>>>,
        key: &str,
    ) -> Arc<Semaphore> {
        Arc::clone(registry.lock().await.get(key).expect("gate must exist"))
    }

    #[tokio::test]
    async fn duplicate_keys_acquire_one_permit() {
        let registry = registry(&["same"]);
        let permits = request_permits(&registry, vec!["same".to_owned(), "same".to_owned()])
            .await
            .expect("duplicate request keys should acquire successfully");

        assert_eq!(permits.len(), 1);
        assert_eq!(semaphore(&registry, "same").await.available_permits(), 0);
        drop(permits);
        assert_eq!(semaphore(&registry, "same").await.available_permits(), 1);
    }

    #[tokio::test]
    async fn reverse_key_order_does_not_deadlock() {
        let registry = registry(&["a", "b"]);
        let first = request_permits(&registry, vec!["b".to_owned(), "a".to_owned()])
            .await
            .expect("first request should acquire permits");
        let second_registry = Arc::clone(&registry);
        let second = tokio::spawn(async move {
            request_permits(&second_registry, vec!["a".to_owned(), "b".to_owned()]).await
        });

        drop(first);
        tokio::time::timeout(Duration::from_secs(1), second)
            .await
            .expect("reverse-order request must not deadlock")
            .expect("request task must complete")
            .expect("request should acquire permits after release");
    }

    #[tokio::test]
    async fn overlapping_key_sets_serialize() {
        let registry = registry(&["a", "b", "c"]);
        let first = request_permits(&registry, vec!["a".to_owned(), "b".to_owned()])
            .await
            .expect("first request should acquire permits");
        let second_registry = Arc::clone(&registry);
        let (acquired_tx, mut acquired_rx) = mpsc::channel(1);
        let second = tokio::spawn(async move {
            let permits = request_permits(&second_registry, vec!["b".to_owned(), "c".to_owned()])
                .await
                .expect("second request should acquire permits");
            acquired_tx
                .send(())
                .await
                .expect("receiver must remain open");
            permits
        });

        tokio::task::yield_now().await;
        assert!(matches!(
            acquired_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        drop(first);
        acquired_rx
            .recv()
            .await
            .expect("second request must proceed");
        second.await.expect("request task must complete");
    }

    #[tokio::test]
    async fn disjoint_key_sets_run_concurrently() {
        let registry = registry(&["a", "b"]);
        let first = request_permits(&registry, vec!["a".to_owned()])
            .await
            .expect("first request should acquire its gate");

        let second = request_permits(&registry, vec!["b".to_owned()]);
        let second = tokio::time::timeout(Duration::from_secs(1), second)
            .await
            .expect("disjoint request should not wait")
            .expect("disjoint request should acquire its gate");

        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
    }

    #[tokio::test]
    async fn cancellation_releases_partially_acquired_permits() {
        let registry = registry(&["a", "b"]);
        let blocked_gate = semaphore(&registry, "b")
            .await
            .acquire_owned()
            .await
            .expect("gate must be open");
        let request_registry = Arc::clone(&registry);
        let (started_tx, started_rx) = oneshot::channel();
        let request = tokio::spawn(async move {
            started_tx.send(()).expect("receiver must remain open");
            request_permits(&request_registry, vec!["b".to_owned(), "a".to_owned()]).await
        });
        started_rx.await.expect("request must start");

        let first_gate = semaphore(&registry, "a").await;
        tokio::time::timeout(Duration::from_secs(1), async {
            while first_gate.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("request should acquire first sorted gate");

        request.abort();
        let _ = request.await;
        assert_eq!(first_gate.available_permits(), 1);
        drop(blocked_gate);
    }
}
