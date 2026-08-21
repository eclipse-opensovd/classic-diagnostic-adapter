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
    HashMapExtensions, PayloadDecoder, UdsVariant, dlt_ctx,
};
use tokio::sync::RwLock;

use crate::{UdsManager, coordinator::EcuCoordinatorHandle, transport::needs_variant_detection};

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
        let ecu = self.uds_ecu_db(ecu_name)?;

        // A queued automatic trigger may become obsolete while an earlier
        // detection runs. Re-check state only after claiming the slot so a
        // successful run suppresses another detection request.
        let group_representative = self.duplicate_group_representative(ecu_name).await;
        let DetectionPermit::Run(_detection_guard) = claim_detection(
            self.state_coordinator.get_handle(&group_representative),
            self.state_coordinator.get_handle(ecu_name),
            trigger,
        )
        .await
        else {
            tracing::debug!(ecu_name, "Variant detection trigger obsolete, skipping");
            return Ok(());
        };

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
                    match vd.detect_variant_if_needed(&ecu_name).await {
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
                    // Use the ECU's configured response timeout (`CP_P6Max`,
                    // via `UdsComParams::timeout_default`) instead of a
                    // hardcoded value, so variant-detection sends respect the
                    // same, correctly configured comparam as every other UDS
                    // send (see `send_with_raw_payload`'s `rx_timeout`).
                    None,
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
}

#[cfg(test)]
mod tests {
    use cda_interfaces::{Connectivity, VariantState};

    use super::{DetectionPermit, DetectionTrigger, claim_detection};
    use crate::coordinator::EcuCoordinatorHandle;

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
                claim_detection(Some(&handle), Some(&handle), DetectionTrigger::Forced).await,
                DetectionPermit::Run(Some(_))
            ),
            "explicit detection must not be suppressed by healthy state"
        );
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
                    DetectionTrigger::IfNeeded
                )
                .await,
                DetectionPermit::Run(Some(_))
            ),
            "triggering duplicate still needs detection"
        );
    }
}
