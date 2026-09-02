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

//! Variant detection uses two communication hooks. [`CommunicationLifecycle`]
//! manages the transport-bound VAM listener and tester-present tasks, and
//! [`CommunicationVariantDetection`] runs whole-vehicle variant detection
//! afterwards. That keeps the listener aligned with transport availability and
//! gives it a matching teardown, including when variant detection finds
//! nothing.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use cda_interfaces::{
    DiagComm, DiagServiceError, DynamicPlugin, EcuGateway, EcuManager, EcuState, HashMap,
    HashMapExtensions, PayloadDecoder, UdsVariant, VariantState,
    communication_control::{
        ActivationCause, CommunicationLifecycle, CommunicationState, CommunicationVariantDetection,
        VariantDetectionMode, error::CommControlError,
    },
    dlt_ctx,
};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use crate::{
    ReceiverRetention, UdsManager,
    coordinator::EcuCoordinatorHandle,
    transport::{CommunicationReadiness, needs_variant_detection},
};

#[derive(Clone, Copy)]
enum DetectionTrigger {
    Forced,
    IfNeeded,
}

enum DetectionPermit {
    Skip,
    Run(Option<tokio::sync::OwnedMutexGuard<()>>),
}

async fn claim_detection(
    lock_handle: Option<&EcuCoordinatorHandle>,
    state_handle: Option<&EcuCoordinatorHandle>,
    trigger: DetectionTrigger,
) -> DetectionPermit {
    let Some(lock_handle) = lock_handle else {
        return DetectionPermit::Run(None);
    };
    let Some(guard) = lock_handle.begin_detection().await else {
        return DetectionPermit::Skip;
    };
    if matches!(trigger, DetectionTrigger::IfNeeded)
        && state_handle.is_some_and(|handle| !needs_variant_detection(&handle.ecu_status()))
    {
        return DetectionPermit::Skip;
    }
    DetectionPermit::Run(Some(guard))
}

/// Result of evaluating every member of a duplicate group against one set of
/// detection responses.
#[derive(Debug)]
enum GroupDetectionResult {
    /// Exactly this member matched a specific (non-fallback) variant.
    ExactMatch(String),
    /// Members are online, but none matched a specific variant.
    AllFallbacks,
    /// No member of the group is online.
    NoOnlineEcu,
    /// Members are online, but detection failed for all of them.
    NoDetection,
}

impl<S: EcuGateway, T: EcuManager> UdsManager<S, T> {
    pub(crate) async fn detect_variant_if_needed_in(
        &self,
        data: &crate::VehicleEcuData<T>,
        ecu_name: &str,
    ) -> Result<(), DiagServiceError> {
        self.detect_variant_with_trigger_in(data, ecu_name, DetectionTrigger::IfNeeded)
            .await
    }

    /// Runs detection for one ECU if needed, taking its own data snapshot.
    ///
    /// The snapshot-taking counterpart of
    /// [`detect_variant_if_needed_in`](Self::detect_variant_if_needed_in), for
    /// callers that hold an ECU handle but no snapshot.
    pub(crate) async fn detect_variant_if_needed(
        &self,
        ecu_name: &str,
    ) -> Result<(), DiagServiceError> {
        self.detect_variant_with_trigger(ecu_name, DetectionTrigger::IfNeeded)
            .await
    }

    async fn detect_variant_with_trigger(
        &self,
        ecu_name: &str,
        trigger: DetectionTrigger,
    ) -> Result<(), DiagServiceError> {
        // One guarded snapshot for every lookup, duplicate decision, coordinator access,
        // send, result construction, and state write in this attempt.
        let data = self.ecu_data.read().await;
        self.detect_variant_with_trigger_in(&data, ecu_name, trigger)
            .await
    }

    async fn detect_variant_with_trigger_in(
        &self,
        data: &crate::VehicleEcuData<T>,
        ecu_name: &str,
        trigger: DetectionTrigger,
    ) -> Result<(), DiagServiceError> {
        let ecu = data
            .ecus()
            .get(ecu_name)
            .ok_or_else(|| DiagServiceError::NotFound(format!("ECU {ecu_name} not found")))?;
        let Some(group_representative) = self.duplicate_group_representative(data, ecu_name).await
        else {
            return Ok(());
        };
        let DetectionPermit::Run(_detection_guard) = claim_detection(
            data.state_coordinator().get_handle(&group_representative),
            data.state_coordinator().get_handle(ecu_name),
            trigger,
        )
        .await
        else {
            tracing::debug!(ecu_name, "Variant detection trigger obsolete, skipping");
            return Ok(());
        };

        let service_responses = self.gather_detection_responses(ecu_name, ecu).await?;
        if service_responses.is_empty() {
            return self.mark_group_unreachable(data, ecu).await;
        }

        let ecu_read = ecu.read().await;
        let duplicated_ecus = ecu_read
            .duplicating_ecu_names()
            .cloned()
            .filter(|d| !d.is_empty());
        drop(ecu_read);
        let Some(mut duplicated_ecus) = duplicated_ecus else {
            let mut ecu_write = ecu.write().await;
            let result = ecu_write.detect_variant(service_responses).await;
            return result.map_err(|e| {
                DiagServiceError::VariantDetectionError(format!("Failed to detect variant: {e:?}"))
            });
        };

        duplicated_ecus.insert(ecu_name.to_owned());
        let detection_result = self
            .evaluate_duplicate_group(data, &duplicated_ecus, &service_responses)
            .await;
        tracing::debug!(?detection_result, "ECU variant detection result");
        self.apply_group_result(data, &detection_result, &duplicated_ecus)
            .await;

        Ok(())
    }

    /// Ensures variant detection has concluded for `ecu_name` before serving
    /// variant-dependent content.
    ///
    /// Returns the ECU database handle when ready. If communication or variant
    /// detection is not ready, requests activation when needed and returns
    /// [`DiagServiceError::CommunicationNotReady`] so the caller can retry.
    pub(crate) async fn uds_ecu_variant_detection_concluded(
        &self,
        ecu_name: &str,
    ) -> Result<Arc<RwLock<T>>, DiagServiceError> {
        let ecu = self.uds_ecu_db(ecu_name).await?;
        self.uds_ecu_handle_variant_detection_concluded(&ecu)
            .await?;
        Ok(ecu)
    }

    pub(crate) async fn uds_ecu_handle_variant_detection_concluded(
        &self,
        ecu: &RwLock<T>,
    ) -> Result<(), DiagServiceError> {
        if ecu.read().await.ecu_status().variant_state != VariantState::NotTested {
            return Ok(());
        }

        let variant_state = ecu.read().await.runtime_state().variant_state_rx();
        let detection_in_flight = matches!(
            self.communication_access.state(),
            CommunicationState::Enabling(_) | CommunicationState::Enabled
        );

        if !detection_in_flight {
            self.communication_access
                .request_activate(ActivationCause::DiagnosticRequest);
            return Err(
                self.build_communication_not_ready_err("Communication is not currently enabled")
            );
        }

        if self.communication_access.variant_detection() == VariantDetectionMode::Never {
            return Err(self.build_communication_not_ready_err(
                "Variant detection is not running automatically; awaiting an explicit detection \
                 trigger",
            ));
        }

        if *variant_state.borrow() == VariantState::NotTested {
            Err(self.build_communication_not_ready_err("Variant detection has not concluded"))
        } else {
            Ok(())
        }
    }

    #[tracing::instrument(skip_all,
        fields(dlt_context = dlt_ctx!("UDS"))
    )]
    pub(crate) async fn start_variant_detection_for_ecus(&self, ecus: Vec<String>) {
        if self.communication_access.variant_detection() == VariantDetectionMode::Never {
            return;
        }
        let data = self.ecu_data.read().await;
        self.start_variant_detection_for_ecus_in(&data, ecus).await;
    }

    async fn start_variant_detection_for_ecus_in(
        &self,
        data: &crate::VehicleEcuData<T>,
        ecus: Vec<String>,
    ) {
        // Map every name to its duplicate-group representative before scheduling.
        let mut representatives = std::collections::BTreeSet::new();
        for ecu_name in ecus {
            if !data.ecus().contains_key(&ecu_name) {
                continue;
            }
            let Some(representative) = self.duplicate_group_representative(data, &ecu_name).await
            else {
                return;
            };
            representatives.insert(representative);
        }

        let tasks = representatives.into_iter().map(|ecu_name| {
            let data = &data;
            async move {
                const OFFLINE_VERDICT_RETRIES: u32 = 3;
                const OFFLINE_VERDICT_RETRY_DELAY: Duration = Duration::from_secs(1);

                for attempt in 0..=OFFLINE_VERDICT_RETRIES {
                    if attempt > 0 {
                        cda_interfaces::util::tokio_ext::sleep_for(OFFLINE_VERDICT_RETRY_DELAY)
                            .await;
                    }
                    let result = self.detect_variant_if_needed_in(data, &ecu_name).await;
                    match result {
                        Ok(()) => tracing::trace!("Variant detection successful"),
                        Err(e) => tracing::info!(error = %e, "Variant detection failed"),
                    }
                    let offline =
                        data.state_coordinator()
                            .get_handle(&ecu_name)
                            .is_some_and(|handle| {
                                handle.connectivity() == cda_interfaces::Connectivity::Offline
                            });
                    if !offline {
                        break;
                    }
                    tracing::debug!(
                        ecu_name,
                        attempt,
                        "Variant detection concluded offline, retrying"
                    );
                }
            }
        });
        futures::future::join_all(tasks).await;
    }

    /// Runs the initial variant detection over all ECUs, for the reachable
    /// ones. Offline ECUs get their state set immediately. Duplicate groups run
    /// one detection per physical node.
    #[tracing::instrument(skip_all,
        fields(dlt_context = dlt_ctx!("UDS"))
    )]
    async fn start_variant_detection(&self) {
        let data = self.ecu_data.read().await;
        let mut ecus = Vec::new();
        for (ecu_name, db) in data.ecus().iter() {
            let db_read = db.read().await;
            if !db_read.is_physical_ecu() {
                tracing::debug!(
                    ecu_name = %ecu_name,
                    "Skip variant detection for functional description"
                );
                continue;
            }
            // Offline ECUs deliberately use the same coordinated per-ECU path as
            // reachable ECUs; an empty response set then produces the common offline verdict.
            ecus.push(ecu_name.to_owned());
        }
        self.start_variant_detection_for_ecus_in(&data, ecus).await;
    }

    /// Deterministic representative of the ECU's duplicate group: the
    /// smallest member name (including the ECU itself) that is present in
    /// the loaded ECU map.
    async fn duplicate_group_representative(
        &self,
        data: &crate::VehicleEcuData<T>,
        ecu_name: &str,
    ) -> Option<String> {
        let Some(db) = data.ecus().get(ecu_name) else {
            return Some(ecu_name.to_owned());
        };
        let db_read = db.read().await;
        Some(
            db_read
                .duplicating_ecu_names()
                .into_iter()
                .flatten()
                .filter(|name| data.ecus().contains_key(*name))
                .map(String::as_str)
                .chain(std::iter::once(ecu_name))
                .min()
                .unwrap_or(ecu_name)
                .to_owned(),
        )
    }

    /// Sends the ECU's variant-detection requests and returns the responses that arrived.
    /// Detection sends leave timeout reachability mutation to the aggregate result, and gathering
    /// stops at the first send failure (no need to continue if one fails).
    async fn gather_detection_responses(
        &self,
        ecu_name: &str,
        ecu: &RwLock<T>,
    ) -> Result<HashMap<String, <T as PayloadDecoder>::Response>, DiagServiceError> {
        let ecu_read = ecu.read().await;
        let requests = ecu_read
            .get_variant_detection_requests()
            .iter()
            .map(|(name, service)| Ok((name.to_owned(), service.clone())))
            .collect::<Result<Vec<(String, DiagComm)>, DiagServiceError>>()?;
        drop(ecu_read);

        let ecu_read = ecu.read().await;
        let is_loaded = ecu_read.is_loaded();
        drop(ecu_read);
        if !is_loaded {
            let mut ecu_write = ecu.write().await;
            ecu_write.load().map_err(|e| {
                DiagServiceError::ResourceError(format!("Failed to load ECU data: {e:?}"))
            })?;
        }

        // Seed the session/security map before sending detection requests so
        // that check_service_preconditions can validate them. This only
        // works for ECUS whose state charts are defined on the base variant level.
        let ecu_read = ecu.read().await;
        if let Err(e) = ecu_read.set_default_states().await {
            tracing::debug!(
                error = %e,
                "Could not pre-initialize ECU default states"
            );
        }
        drop(ecu_read);

        let mut service_responses = HashMap::new();
        // Detection owns the final reachability verdict, so intermediate
        // disconnects must not publish one. One coordinator handle for both
        // calls, so a reload between them cannot split suppress from restore.
        let coordinator = self.state_coordinator().await;
        coordinator.suppress_disconnect_handling(ecu_name).await;
        for (name, service) in requests {
            let security_plugin = Box::new(()) as DynamicPlugin;
            let result = self
                .send_without_variant_guard(
                    ecu,
                    service,
                    &security_plugin,
                    None,
                    true,
                    // Use the ECU's configured response timeout (`CP_P6Max`,
                    // via `UdsComParams::timeout_default`) instead of a
                    // hardcoded value, so variant-detection sends respect the
                    // same, correctly configured comparam as every other UDS
                    // send (see `send_with_raw_payload`'s `rx_timeout`).
                    None,
                    CommunicationReadiness::AssumeReady,
                )
                .await;
            match result {
                Ok(response) => {
                    service_responses.insert(name, response);
                }
                Err(e) => {
                    tracing::debug!(
                        request_name = %name,
                        error = %e,
                        "Failed to send variant detection request"
                    );
                    break;
                }
            }
        }
        coordinator.restore_disconnect_handling(ecu_name).await;
        Ok(service_responses)
    }

    /// Marks the ECU and every member of its duplicate group as unreachable
    /// by running detection with an empty response set (Disconnected if it
    /// was online before, Offline if never tested).
    async fn mark_group_unreachable(
        &self,
        data: &crate::VehicleEcuData<T>,
        ecu: &RwLock<T>,
    ) -> Result<(), DiagServiceError> {
        let mut ecu_write = ecu.write().await;
        let result = ecu_write
            .detect_variant::<<T as PayloadDecoder>::Response>(HashMap::new())
            .await;
        result.map_err(|e| {
            DiagServiceError::VariantDetectionError(format!("Failed to detect variant: {e:?}"))
        })?;
        drop(ecu_write);

        let ecu_read = ecu.read().await;
        let duplicates = ecu_read
            .duplicating_ecu_names()
            .cloned()
            .filter(|d| !d.is_empty());
        drop(ecu_read);
        if let Some(duplicates) = duplicates {
            for dup_name in &duplicates {
                if let Some(dup_ecu) = data.ecus().get(dup_name) {
                    let mut dup_write = dup_ecu.write().await;
                    // Best effort: one failing member must not stop
                    // marking the rest; the primary error is propagated.
                    if let Err(e) = dup_write
                        .detect_variant::<<T as PayloadDecoder>::Response>(HashMap::new())
                        .await
                    {
                        tracing::debug!(
                            ecu_name = %dup_name,
                            error = ?e,
                            "Failed to mark duplicate as unreachable"
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Runs detection for every member of a duplicate group against the same
    /// responses and derives the group verdict: the first member matching a
    /// specific variant wins; otherwise the group is all-fallbacks, failed,
    /// or entirely offline.
    async fn evaluate_duplicate_group(
        &self,
        data: &crate::VehicleEcuData<T>,
        duplicated_ecus: &cda_interfaces::HashSet<String>,
        service_responses: &HashMap<String, <T as PayloadDecoder>::Response>,
    ) -> GroupDetectionResult {
        // First ECU that is online and fell back to base variant (no specific match).
        let mut first_fallback = None;
        // Tracked independently of detection success: an online member
        // with failed detection must yield NoDetection, not NoOnlineEcu.
        let mut any_online = false;

        for ecu_name in duplicated_ecus {
            let Some(ecu) = data.ecus().get(ecu_name) else {
                continue;
            };

            let mut ecu_write = ecu.write().await;
            let result = ecu_write.detect_variant(service_responses.clone()).await;
            drop(ecu_write);
            if let Err(e) = result {
                tracing::warn!(
                    "Variant detection failed for ECU {ecu_name}: {e:?}, marking as undetected"
                );
                let ecu_read = ecu.read().await;
                any_online |=
                    ecu_read.ecu_status().connectivity == cda_interfaces::Connectivity::Online;
                continue;
            }

            let ecu_read = ecu.read().await;
            let status = ecu_read.ecu_status();
            any_online |= status.connectivity == cda_interfaces::Connectivity::Online;
            if !status.is_online_and_detected() {
                continue;
            }

            if status.is_fallback() {
                first_fallback.get_or_insert(ecu_name);
            } else {
                return GroupDetectionResult::ExactMatch(ecu_name.clone());
            }
        }

        match (first_fallback, any_online) {
            (Some(_), true) => GroupDetectionResult::AllFallbacks,
            (None, true) => GroupDetectionResult::NoDetection,
            (_, false) => GroupDetectionResult::NoOnlineEcu,
        }
    }

    /// Applies a duplicate-group verdict to every member's state.
    async fn apply_group_result(
        &self,
        data: &crate::VehicleEcuData<T>,
        detection_result: &GroupDetectionResult,
        duplicated_ecus: &cda_interfaces::HashSet<String>,
    ) {
        match detection_result {
            GroupDetectionResult::ExactMatch(the_chosen_one) => {
                // Mark all other duplicates, the chosen one keeps its detected variant.
                for ecu_name in duplicated_ecus {
                    if ecu_name == the_chosen_one {
                        continue;
                    }
                    if let Some(ecu) = data.ecus().get(ecu_name) {
                        let mut ecu_write = ecu.write().await;
                        ecu_write.mark_as_duplicate().await;
                    }
                }
            }
            GroupDetectionResult::AllFallbacks => {
                // No specific variant found despite online ECUs - mark all as undetected.
                // Falling back to base variant is only allowed when there are no duplicates.
                for ecu_name in duplicated_ecus {
                    if let Some(ecu) = data.ecus().get(ecu_name) {
                        let mut ecu_write = ecu.write().await;
                        ecu_write.mark_as_no_variant_detected().await;
                    }
                }
            }
            GroupDetectionResult::NoOnlineEcu | GroupDetectionResult::NoDetection => {}
        }
    }
}

#[async_trait]
impl<S: EcuGateway, T: EcuManager> UdsVariant for UdsManager<S, T> {
    #[tracing::instrument(skip(self), err,
        fields(
            dlt_context = dlt_ctx!("UDS")
        )
    )]
    async fn detect_variant(&self, ecu_name: &str) -> Result<(), DiagServiceError> {
        self.detect_variant_with_trigger(ecu_name, DetectionTrigger::Forced)
            .await
    }

    async fn get_ecu_state(&self, ecu_name: &str) -> Result<EcuState, DiagServiceError> {
        let ecu = self.uds_ecu_db(ecu_name).await?;
        let status = ecu.read().await.ecu_status();
        Ok(status)
    }

    async fn get_logical_address(&self, ecu_name: &str) -> Result<u16, DiagServiceError> {
        let ecu = self.uds_ecu_db(ecu_name).await?;
        let logical_address = ecu.read().await.logical_address();
        Ok(logical_address)
    }

    async fn variant_state_rx(
        &self,
        ecu_name: &str,
    ) -> Option<tokio::sync::watch::Receiver<VariantState>> {
        let data = self.ecu_data.read().await;
        let ecu = data.ecus().get(ecu_name)?;
        Some(ecu.read().await.runtime_state().variant_state_rx())
    }
}

#[async_trait::async_trait]
impl<S: EcuGateway, T: EcuManager> CommunicationLifecycle for UdsManager<S, T> {
    fn name(&self) -> &'static str {
        "variant-detection-listener"
    }

    async fn initialize(&self) -> Result<(), CommControlError> {
        // Start the variant-detection listener if it is not already running.
        if let Some(mut receiver) = self.variant_detection_receiver.lock().await.take() {
            let uds_manager = self.clone();
            let cancel = CancellationToken::new();
            let task_cancel = cancel.clone();
            let listener = cda_interfaces::spawn_named!("variant-detection-receiver", async move {
                loop {
                    let ecus = tokio::select! {
                        biased; // prefer cancellation over variant detection
                        () = task_cancel.cancelled() => break,
                        ecus = receiver.recv() => {
                            let Some(ecus) = ecus else { break };
                            ecus.into_ecus()
                        }
                    };
                    uds_manager.start_variant_detection_for_ecus(ecus).await;
                }
                receiver
            });
            *self.variant_detection_listener.lock().await = Some((cancel, listener));
        }
        self.restart_tester_present_snapshot().await;
        Ok(())
    }

    async fn deinitialize(&self) {
        self.stop_variant_detection_listener(ReceiverRetention::Keep)
            .await;
        self.snapshot_and_abort_tester_present().await;
        let mut reset_tasks: Vec<_> = self
            .session_reset_tasks
            .write()
            .await
            .drain()
            .map(|(_, task)| task)
            .collect();
        reset_tasks.extend(
            self.security_reset_tasks
                .write()
                .await
                .drain()
                .map(|(_, task)| task),
        );
        for task in reset_tasks {
            task.abort();
            let _ = task.await;
        }
    }
}

#[async_trait::async_trait]
impl<S: EcuGateway, T: EcuManager> CommunicationVariantDetection for UdsManager<S, T> {
    fn name(&self) -> &'static str {
        "variant-detection"
    }

    async fn detect(&self) -> Result<(), CommControlError> {
        self.start_variant_detection().await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use cda_interfaces::{
        Connectivity, DiagServiceError, EcuAddresses, EcuManager, FunctionalTransport, HashMap,
        HashMapExtensions, NetworkTopology, PhysicalTransport, ServicePayload,
        TransmissionParameters, TransportResponse, UdsVariant, VariantDetection,
        VariantDetectionSender, VariantState, communication_control::CommunicationLifecycle,
    };
    use cda_plugin_communication_management::lifecycle::enabled_communication_access_for_test;
    use tokio::sync::{RwLock, mpsc};

    use super::{DetectionPermit, DetectionTrigger, claim_detection};
    use crate::{
        UdsManager, VehicleEcuData, coordinator::EcuCoordinatorHandle,
        state_coordinator::EcuStateCoordinator, test_helpers::TestEcuDb,
    };

    #[derive(Clone)]
    struct DetectionGateway {
        control: Arc<DetectionGatewayControl>,
        close_immediately: bool,
    }

    struct DetectionGatewayControl {
        sends: AtomicUsize,
        active_children: AtomicUsize,
        completed_children: AtomicUsize,
    }

    struct ChildCompletion(Arc<DetectionGatewayControl>);

    impl Drop for ChildCompletion {
        fn drop(&mut self) {
            self.0.active_children.fetch_sub(1, Ordering::SeqCst);
            self.0.completed_children.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl PhysicalTransport for DetectionGateway {
        fn send(
            &self,
            _transmission_params: TransmissionParameters,
            _message: ServicePayload,
            response_sender: mpsc::Sender<Result<Option<TransportResponse>, DiagServiceError>>,
            _expect_uds_reply: bool,
        ) -> impl Future<Output = Result<tokio::task::JoinHandle<()>, DiagServiceError>> + Send
        {
            self.control.sends.fetch_add(1, Ordering::SeqCst);
            let control = Arc::clone(&self.control);
            let close_immediately = self.close_immediately;
            async move {
                Ok(tokio::spawn(async move {
                    control.active_children.fetch_add(1, Ordering::SeqCst);
                    let _completion = ChildCompletion(Arc::clone(&control));
                    if !close_immediately {
                        response_sender.closed().await;
                    }
                }))
            }
        }

        fn ecu_online<T: EcuAddresses>(
            &self,
            _ecu_name: &str,
            _ecu_db: &RwLock<T>,
        ) -> impl Future<Output = Result<(), DiagServiceError>> + Send {
            std::future::ready(Ok(()))
        }
    }

    impl FunctionalTransport for DetectionGateway {
        fn send_functional(
            &self,
            _transmission_params: TransmissionParameters,
            _message: ServicePayload,
            _expected_ecu_logical_addrs: HashMap<u16, String>,
            _timeout: Duration,
            _expect_positive_response: bool,
        ) -> impl Future<
            Output = Result<
                HashMap<String, Result<ServicePayload, DiagServiceError>>,
                DiagServiceError,
            >,
        > + Send {
            std::future::ready(Ok(HashMap::new()))
        }
    }

    impl NetworkTopology for DetectionGateway {
        fn get_gateway_network_address(
            &self,
            _logical_address: u16,
        ) -> impl Future<Output = Option<String>> + Send {
            std::future::ready(None)
        }
    }

    #[async_trait::async_trait]
    impl cda_interfaces::Shutdown for DetectionGateway {
        async fn shutdown(&self) {}
    }

    struct DetectionFixture {
        manager: UdsManager<DetectionGateway, TestEcuDb>,
        gateway: Arc<DetectionGatewayControl>,
    }

    impl DetectionFixture {
        fn new(close_immediately: bool) -> Self {
            Self::new_with_options(close_immediately, false)
        }

        fn new_duplicate() -> Self {
            Self::new_with_options(false, true)
        }

        fn new_with_options(close_immediately: bool, with_duplicate: bool) -> Self {
            let mut primary = TestEcuDb::for_detection();
            let duplicate_ecu = with_duplicate.then(|| {
                primary.set_duplicating_ecu_names(cda_interfaces::HashSet::from_iter([
                    "DuplicateECU".to_owned(),
                ]));
                TestEcuDb::for_detection_with_identity("DuplicateECU", 0x0002)
            });
            let mut runtime_states =
                HashMap::from_iter([("TestECU".to_owned(), primary.runtime_state())]);
            let mut ecus =
                HashMap::from_iter([("TestECU".to_owned(), Arc::new(RwLock::new(primary)))]);
            if let Some(duplicate) = duplicate_ecu {
                runtime_states.insert("DuplicateECU".to_owned(), duplicate.runtime_state());
                ecus.insert("DuplicateECU".to_owned(), Arc::new(RwLock::new(duplicate)));
            }
            let (redetect_tx, redetect_rx) = mpsc::channel(8);
            let redetect = VariantDetectionSender::new(redetect_tx);
            let coordinator = Arc::new(EcuStateCoordinator::new(runtime_states, redetect.clone()));
            let data = VehicleEcuData::new(
                Arc::new(ecus),
                &cda_interfaces::FunctionalDescriptionConfig::default(),
                cda_interfaces::datatypes::FaultConfig::default(),
                Arc::clone(&coordinator),
            );
            let parts = crate::prepare_ecu_data(data);
            let gateway = Arc::new(DetectionGatewayControl {
                sends: AtomicUsize::new(0),
                active_children: AtomicUsize::new(0),
                completed_children: AtomicUsize::new(0),
            });
            let manager = UdsManager::new(
                Arc::new(DetectionGateway {
                    control: Arc::clone(&gateway),
                    close_immediately,
                }),
                parts.data,
                cda_interfaces::VariantDetectionReceiver::new(redetect_rx),
                enabled_communication_access_for_test(),
                Duration::from_secs(1),
            );
            Self { manager, gateway }
        }

        async fn initialize(&self) {
            CommunicationLifecycle::initialize(&self.manager)
                .await
                .expect("initialize detection lifecycle");
        }

        async fn deinitialize(&self) {
            CommunicationLifecycle::deinitialize(&self.manager).await;
        }

        async fn detection_mutations(&self, ecu_name: &str) -> Arc<AtomicUsize> {
            let data = self.manager.ecu_data.read().await;
            data.ecus()
                .get(ecu_name)
                .expect("test ECU")
                .read()
                .await
                .detection_mutations()
        }

        async fn connectivity(&self, ecu_name: &str) -> Connectivity {
            let data = self.manager.ecu_data.read().await;
            data.ecus()
                .get(ecu_name)
                .expect("test ECU")
                .read()
                .await
                .ecu_status()
                .connectivity
        }
    }

    #[tokio::test]
    async fn detection_timeout_uses_production_aggregation_to_mark_ecu_offline() {
        let fixture = DetectionFixture::new(false);
        fixture.initialize().await;
        let mutations = fixture.detection_mutations("TestECU").await;

        UdsVariant::detect_variant(&fixture.manager, "TestECU")
            .await
            .expect("production variant detection");

        assert_eq!(fixture.gateway.sends.load(Ordering::SeqCst), 1);
        assert_eq!(mutations.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.connectivity("TestECU").await, Connectivity::Offline);
        assert_eq!(fixture.gateway.active_children.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.gateway.completed_children.load(Ordering::SeqCst), 1);
        fixture.deinitialize().await;
    }

    #[tokio::test]
    async fn detection_timeout_aggregation_marks_every_duplicate_offline() {
        let fixture = DetectionFixture::new_duplicate();
        fixture.initialize().await;
        let primary_mutations = fixture.detection_mutations("TestECU").await;
        let duplicate_mutations = fixture.detection_mutations("DuplicateECU").await;

        UdsVariant::detect_variant(&fixture.manager, "TestECU")
            .await
            .expect("duplicate-group detection");

        assert_eq!(primary_mutations.load(Ordering::SeqCst), 1);
        assert_eq!(duplicate_mutations.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.connectivity("TestECU").await, Connectivity::Offline);
        assert_eq!(
            fixture.connectivity("DuplicateECU").await,
            Connectivity::Offline
        );
        fixture.deinitialize().await;
    }

    #[tokio::test]
    async fn queued_automatic_detection_is_skipped_after_success() {
        let handle = EcuCoordinatorHandle::spawn("TestECU".to_owned());
        let in_flight = handle.begin_detection().await.expect("first entrant");

        let queued_handle = handle.clone();
        let queued = tokio::spawn(async move {
            claim_detection(
                Some(&queued_handle),
                Some(&queued_handle),
                DetectionTrigger::IfNeeded,
            )
            .await
        });
        tokio::task::yield_now().await;

        {
            let mut state = handle.state.ecu_state.write().unwrap();
            state.connectivity = Connectivity::Online;
            state.variant_state = VariantState::Detected {
                name: "MyVariant".to_owned(),
                is_base_variant: false,
                is_fallback: false,
            };
        }
        drop(in_flight);

        assert!(
            matches!(queued.await.expect("queued trigger"), DetectionPermit::Skip),
            "successful detection must suppress queued automatic trigger"
        );
    }

    #[tokio::test]
    async fn queued_automatic_detection_runs_when_still_needed() {
        let handle = EcuCoordinatorHandle::spawn("TestECU".to_owned());
        let in_flight = handle.begin_detection().await.expect("first entrant");

        let queued_handle = handle.clone();
        let queued = tokio::spawn(async move {
            claim_detection(
                Some(&queued_handle),
                Some(&queued_handle),
                DetectionTrigger::IfNeeded,
            )
            .await
        });
        tokio::task::yield_now().await;
        drop(in_flight);

        assert!(
            matches!(
                queued.await.expect("queued trigger"),
                DetectionPermit::Run(Some(_))
            ),
            "unresolved state must permit queued automatic trigger"
        );
    }

    #[tokio::test]
    async fn forced_detection_runs_when_state_is_healthy() {
        let handle = EcuCoordinatorHandle::spawn("TestECU".to_owned());
        {
            let mut state = handle.state.ecu_state.write().unwrap();
            state.connectivity = Connectivity::Online;
            state.variant_state = VariantState::Detected {
                name: "MyVariant".to_owned(),
                is_base_variant: false,
                is_fallback: false,
            };
        }

        assert!(
            matches!(
                claim_detection(Some(&handle), Some(&handle), DetectionTrigger::Forced,).await,
                DetectionPermit::Run(Some(_))
            ),
            "explicit detection must not be suppressed by healthy state"
        );
    }

    #[tokio::test]
    async fn dropped_old_coordinator_releases_before_new_coordinator_runs() {
        let handle = EcuCoordinatorHandle::spawn("TestECU".to_owned());
        let old_guard = handle.begin_detection().await.expect("old guard");
        let queued = {
            let handle = handle.clone();
            tokio::spawn(async move { handle.begin_detection().await })
        };
        tokio::task::yield_now().await;
        assert!(!queued.is_finished());
        drop(old_guard);
        assert!(queued.await.expect("new task").is_some());
    }

    #[tokio::test]
    async fn automatic_detection_checks_triggering_duplicate_state() {
        let representative = EcuCoordinatorHandle::spawn("Representative".to_owned());
        let duplicate = EcuCoordinatorHandle::spawn("Duplicate".to_owned());
        {
            let mut state = representative.state.ecu_state.write().unwrap();
            state.connectivity = Connectivity::Online;
            state.variant_state = VariantState::Detected {
                name: "MyVariant".to_owned(),
                is_base_variant: false,
                is_fallback: false,
            };
        }

        assert!(
            matches!(
                claim_detection(
                    Some(&representative),
                    Some(&duplicate),
                    DetectionTrigger::IfNeeded,
                )
                .await,
                DetectionPermit::Run(Some(_))
            ),
            "triggering duplicate still needs detection"
        );
    }
}
