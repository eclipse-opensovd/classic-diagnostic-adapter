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

use std::time::Duration;

use async_trait::async_trait;
use cda_interfaces::{
    DiagComm, DiagServiceError, DynamicPlugin, EcuGateway, EcuManager, EcuState, HashMap,
    HashMapExtensions, PayloadDecoder, UdsVariant, VariantState,
    communication_control::{CommunicationInitializer, error::CommControlError},
    dlt_ctx,
};
use cda_plugin_communication_management::lifecycle::{
    operation::ActivationCause, state::CommunicationState,
};
use tokio::sync::RwLock;

use crate::UdsManager;

/// Bound on how long [`UdsManager::ecu_concluded_variant_detection`] awaits a specific ECU's
/// variant detection before giving up and returning a pending response.
///
/// Detection's own worst-case retry budget runs longer than this (up to
/// `OFFLINE_VERDICT_RETRIES` (3) retries at `OFFLINE_VERDICT_RETRY_DELAY` (1s)
/// intervals, each preceded by sending every detection request with its own
/// ~10s timeout, for a worst case around 43s), so this gate can time out
/// before a detection genuinely in flight concludes. That is by design, not a
/// bug: detection keeps running in the background regardless of this gate, so
/// timing out here only means this particular call returns
/// `CommunicationNotReady` instead of blocking further; a following retry
/// picks up the result once detection actually settles. Kept comfortably
/// under the 30s/60s defaults common to HTTP clients and reverse proxies.
const VARIANT_READINESS_TIMEOUT: Duration = Duration::from_secs(1);

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
    #[tracing::instrument(skip_all,
        fields(dlt_context = dlt_ctx!("UDS"))
    )]
    pub(crate) async fn start_variant_detection_for_ecus(&self, ecus: Vec<String>) {
        // detect_variant on any member of a duplicate group evaluates and
        // writes the state of every member. Different callers pick different
        // members (the boot path iterates a HashMap, the reconnect path
        // forwards the gateway ECU list), so map every name to its group
        // representative before scheduling: one trigger batch then spawns at
        // most one detection per group. Concurrent detections across trigger
        // batches are serialized by the coordinator's detection lock inside
        // detect_variant.
        let mut representatives = std::collections::BTreeSet::new();
        for ecu_name in ecus {
            if !self.ecus.contains_key(&ecu_name) {
                continue;
            }
            representatives.insert(self.duplicate_group_representative(&ecu_name).await);
        }

        for ecu_name in representatives {
            let vd = self.clone();
            cda_interfaces::spawn_named!(&format!("variant-detection-{ecu_name}"), async move {
                // Retry budget for detections that conclude offline: such a
                // verdict is usually transient here (the detection raced the
                // tail of a reconnect churn and its request or response was
                // lost on a connection that was being replaced), and since it
                // does not break the now-healthy connection, no further
                // reconnect event would ever correct it. The delay runs
                // outside the detection (and its disconnect suppression), so
                // real connectivity events flow between attempts; genuinely
                // offline ECUs still settle at Offline after the retries.
                const OFFLINE_VERDICT_RETRIES: u32 = 3;
                const OFFLINE_VERDICT_RETRY_DELAY: Duration = Duration::from_secs(1);

                for attempt in 0..=OFFLINE_VERDICT_RETRIES {
                    if attempt > 0 {
                        cda_interfaces::util::tokio_ext::sleep_for(OFFLINE_VERDICT_RETRY_DELAY)
                            .await;
                    }
                    match vd.detect_variant(&ecu_name).await {
                        Ok(()) => {
                            tracing::trace!("Variant detection successful");
                        }
                        Err(e) => {
                            tracing::info!(error = %e, "Variant detection failed");
                        }
                    }
                    let offline =
                        vd.state_coordinator
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
            });
        }
    }

    /// Deterministic representative of the ECU's duplicate group: the
    /// smallest member name (including the ECU itself) that is present in
    /// the loaded ECU map.
    async fn duplicate_group_representative(&self, ecu_name: &str) -> String {
        let Some(db) = self.ecus.get(ecu_name) else {
            return ecu_name.to_owned();
        };
        db.read()
            .await
            .duplicating_ecu_names()
            .into_iter()
            .flatten()
            .filter(|name| self.ecus.contains_key(*name))
            .map(String::as_str)
            .chain(std::iter::once(ecu_name))
            .min()
            .unwrap_or(ecu_name)
            .to_owned()
    }

    /// Sends the ECU's variant-detection requests and returns the responses
    /// that arrived. Disconnect events are suppressed while the requests are
    /// in flight to prevent a timeout from re-triggering variant detection
    /// in a loop; gathering stops at the first send failure (no need to
    /// continue if one fails).
    async fn gather_detection_responses(
        &self,
        ecu_name: &str,
        ecu: &RwLock<T>,
    ) -> Result<HashMap<String, <T as PayloadDecoder>::Response>, DiagServiceError> {
        let requests = ecu
            .read()
            .await
            .get_variant_detection_requests()
            .iter()
            .map(|(name, service)| Ok((name.to_owned(), service.clone())))
            .collect::<Result<Vec<(String, DiagComm)>, DiagServiceError>>()?;

        if !ecu.read().await.is_loaded() {
            ecu.write().await.load().map_err(|e| {
                DiagServiceError::ResourceError(format!("Failed to load ECU data: {e:?}"))
            })?;
        }

        // Seed the session/security map before sending detection requests so
        // that check_service_preconditions can validate them. This only
        // works for ECUS whose state charts are defined on the base variant level
        if let Err(e) = ecu.read().await.set_default_states().await {
            tracing::debug!(
                error = %e,
                "Could not pre-initialize ECU default states"
            );
        }

        let mut service_responses = HashMap::new();
        self.state_coordinator
            .suppress_disconnect_handling(ecu_name)
            .await;
        for (name, service) in requests {
            match self
                .send_without_variant_guard(
                    ecu_name,
                    service,
                    &(Box::new(()) as DynamicPlugin),
                    None,
                    true,
                    Some(Duration::from_secs(10)),
                )
                .await
            {
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
        self.state_coordinator
            .restore_disconnect_handling(ecu_name)
            .await;

        Ok(service_responses)
    }

    /// Marks the ECU and every member of its duplicate group as unreachable
    /// by running detection with an empty response set (Disconnected if it
    /// was online before, Offline if never tested).
    async fn mark_group_unreachable(&self, ecu: &RwLock<T>) -> Result<(), DiagServiceError> {
        ecu.write()
            .await
            .detect_variant::<<T as PayloadDecoder>::Response>(HashMap::new())
            .await
            .map_err(|e| {
                DiagServiceError::VariantDetectionError(format!("Failed to detect variant: {e:?}"))
            })?;

        if let Some(duplicates) = ecu
            .read()
            .await
            .duplicating_ecu_names()
            .cloned()
            .filter(|d| !d.is_empty())
        {
            for dup_name in &duplicates {
                if let Some(dup_ecu) = self.ecus.get(dup_name) {
                    // Best effort: one failing member must not stop
                    // marking the rest; the primary error is propagated.
                    if let Err(e) = dup_ecu
                        .write()
                        .await
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
        duplicated_ecus: &cda_interfaces::HashSet<String>,
        service_responses: &HashMap<String, <T as PayloadDecoder>::Response>,
    ) -> GroupDetectionResult {
        // First ECU that is online and fell back to base variant (no specific match).
        let mut first_fallback = None;
        // Tracked independently of detection success: an online member
        // with failed detection must yield NoDetection, not NoOnlineEcu.
        let mut any_online = false;

        for ecu_name in duplicated_ecus {
            let Some(ecu) = self.ecus.get(ecu_name) else {
                continue;
            };

            if let Err(e) = ecu
                .write()
                .await
                .detect_variant(service_responses.clone())
                .await
            {
                tracing::warn!(
                    "Variant detection failed for ECU {ecu_name}: {e:?}, marking as undetected"
                );
                any_online |= ecu.read().await.ecu_status().connectivity
                    == cda_interfaces::Connectivity::Online;
                continue;
            }

            let status = ecu.read().await.ecu_status();
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
                    if let Some(ecu) = self.ecus.get(ecu_name) {
                        ecu.write().await.mark_as_duplicate().await;
                    }
                }
            }
            GroupDetectionResult::AllFallbacks => {
                // No specific variant found despite online ECUs - mark all as undetected.
                // Falling back to base variant is only allowed when there are no duplicates.
                for ecu_name in duplicated_ecus {
                    if let Some(ecu) = self.ecus.get(ecu_name) {
                        ecu.write().await.mark_as_no_variant_detected().await;
                    }
                }
            }
            GroupDetectionResult::NoOnlineEcu | GroupDetectionResult::NoDetection => {}
        }
    }

    /// Requires `ecu_name`'s variant detection to have concluded before serving
    /// variant-dependent content (service catalogs, session/security/mode state,
    /// DTCs, or a data/config/operation send).
    ///
    /// Returns the ECU's database handle on success, so callers that need it
    /// anyway (almost all of them, right after this call) can reuse this
    /// lookup instead of a second `uds_ecu_db` call.
    ///
    /// `CommunicationState::Enabled` means activation completed, **not** that
    /// variant detection concluded: detection is dispatched per ECU and settles
    /// asynchronously (see ADR-006). Per-ECU [`VariantState`] is the actual
    /// readiness signal.
    ///
    /// - Steady state: if the ECU's `VariantState` has already left
    ///   `NotTested`, returns immediately.
    /// - Unknown ECU: the initial lookup itself fails with `NotFound`, so
    ///   there's no separate case to special-case here -- the caller gets the
    ///   same error it would have gotten from its own follow-up lookup.
    /// - If an activation is in flight (`Enabling`), or communication is already
    ///   `Enabled`, awaits the ECU's variant-state watch receiver, bounded by
    ///   [`VARIANT_READINESS_TIMEOUT`], then serves.
    /// - On timeout, returns [`DiagServiceError::CommunicationNotReady`], so the
    ///   caller keeps retrying against a detection that is (per D3/ADR-006)
    ///   guaranteed to eventually settle every ECU into a defined state.
    /// - Otherwise (`Disabled`/`Error`, nothing in flight): fires a non-blocking
    ///   activation request (mode-gated -- a no-op under `Disabled`, matching its
    ///   "stay quiet" contract) so a later request finds a generation in flight
    ///   and waits, then returns `CommunicationNotReady` immediately without
    ///   blocking this request.
    pub(crate) async fn ecu_concluded_variant_detection(
        &self,
        ecu_name: &str,
    ) -> Result<&RwLock<T>, DiagServiceError> {
        let ecu = self.uds_ecu_db(ecu_name)?;

        if ecu.read().await.ecu_status().variant_state != VariantState::NotTested {
            return Ok(ecu);
        }

        let mut rx = ecu.read().await.runtime_state().variant_state_rx();

        let detection_in_flight = matches!(
            self.communication_access.state(),
            CommunicationState::Enabling | CommunicationState::Enabled
        );

        if !detection_in_flight {
            self.communication_access
                .request_activate(ActivationCause::DiagnosticRequest);
            return Err(DiagServiceError::CommunicationNotReady {
                message: "communication is not currently enabled".to_owned(),
                retry_after_seconds: self.communication_retry_after_seconds,
            });
        }

        match tokio::time::timeout(
            VARIANT_READINESS_TIMEOUT,
            rx.wait_for(|state| *state != VariantState::NotTested),
        )
        .await
        {
            Ok(Ok(_)) => Ok(ecu),
            // Timeout, or the watch sender was dropped (ECU torn down mid-wait).
            _ => Err(DiagServiceError::CommunicationNotReady {
                message: "Variant detection has not concluded".to_owned(),
                retry_after_seconds: self.communication_retry_after_seconds,
            }),
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
        let ecu = self.uds_ecu_db(ecu_name)?;

        // Serialize detections per duplicate group and coalesce trigger
        // bursts (a detection writes the state of every group member, so
        // callers claim the group representative's slot); see
        // [`crate::coordinator::EcuCoordinatorHandle::begin_detection`].
        // All callers (boot, reconnect, pre-send guard) funnel through here.
        let group_representative = self.duplicate_group_representative(ecu_name).await;
        let mut _detection_guard = None;
        if let Some(handle) = self.state_coordinator.get_handle(&group_representative) {
            _detection_guard = handle.begin_detection().await;
            if _detection_guard.is_none() {
                tracing::debug!(
                    ecu_name,
                    "Variant detection superseded by a newer trigger, skipping"
                );
                return Ok(());
            }
        }

        let service_responses = self.gather_detection_responses(ecu_name, ecu).await?;

        // No responses gathered -> the ECU (and thus its whole duplicate
        // group, which shares the physical node) is unreachable.
        if service_responses.is_empty() {
            return self.mark_group_unreachable(ecu).await;
        }

        let Some(mut duplicated_ecus) = ecu
            .read()
            .await
            .duplicating_ecu_names()
            .cloned()
            .filter(|d| !d.is_empty())
        else {
            // No duplicated ECUs, proceed with normal variant detection
            return ecu
                .write()
                .await
                .detect_variant(service_responses)
                .await
                .map_err(|e| {
                    DiagServiceError::VariantDetectionError(format!(
                        "Failed to detect variant: {e:?}"
                    ))
                });
        };

        // Detect variants for all duplicated ECUs; the group verdict decides
        // each member's final state.
        duplicated_ecus.insert(ecu_name.to_owned());
        let detection_result = self
            .evaluate_duplicate_group(&duplicated_ecus, &service_responses)
            .await;
        tracing::debug!(?detection_result, "ECU variant detection result");
        self.apply_group_result(&detection_result, &duplicated_ecus)
            .await;

        Ok(())
    }

    async fn get_ecu_state(&self, ecu_name: &str) -> Result<EcuState, DiagServiceError> {
        let ecu = self.uds_ecu_db(ecu_name)?;
        let status = ecu.read().await.ecu_status();
        Ok(status)
    }

    #[tracing::instrument(skip_all,
        fields(dlt_context = dlt_ctx!("UDS"))
    )]
    async fn start_variant_detection(&self) {
        let mut ecus = Vec::new();
        for (ecu_name, db) in self.ecus.iter() {
            if !db.read().await.is_physical_ecu() {
                tracing::debug!(
                    ecu_name = %ecu_name,
                    "Skip variant detection for functional description"
                );
                continue;
            }
            if let Err(DiagServiceError::EcuOffline(_)) =
                self.gateway.ecu_online(ecu_name, db).await
            {
                // ECU is offline -> call detect_variant with empty responses to set
                // appropriate state (Disconnected if was online, Offline if never tested)
                if let Err(e) = db
                    .write()
                    .await
                    .detect_variant::<<T as PayloadDecoder>::Response>(HashMap::new())
                    .await
                {
                    tracing::error!(ecu_name = %ecu_name,
                        "Failed to set ECU offline during variant detection: {e:?}");
                }
                continue;
            }

            if db
                .read()
                .await
                .duplicating_ecu_names()
                .is_some_and(|d| ecus.iter().any(|e| d.contains(e)))
            {
                continue; // Only do one variant detection for duplicated ECUs
            }

            ecus.push(ecu_name.to_owned());
        }
        let cloned = self.clone();
        cloned.start_variant_detection_for_ecus(ecus).await;
    }

    async fn get_logical_address(&self, ecu_name: &str) -> Result<u16, DiagServiceError> {
        let ecu = self.uds_ecu_db(ecu_name)?;
        let logical_address = ecu.read().await.logical_address();
        Ok(logical_address)
    }

    async fn variant_state_rx(
        &self,
        ecu_name: &str,
    ) -> Option<tokio::sync::watch::Receiver<VariantState>> {
        let ecu = self.ecus.get(ecu_name)?;
        Some(ecu.read().await.runtime_state().variant_state_rx())
    }
}

#[async_trait::async_trait]
impl<S: EcuGateway, T: EcuManager> CommunicationInitializer for UdsManager<S, T> {
    fn name(&self) -> &'static str {
        "variant-detection"
    }

    async fn initialize(&self) -> Result<(), CommControlError> {
        self.start_variant_detection_listener().await?;
        self.start_variant_detection().await;
        Ok(())
    }
}
