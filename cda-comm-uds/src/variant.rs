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

use std::time::Duration;

use async_trait::async_trait;
use cda_interfaces::{
    DiagComm, DiagServiceError, DynamicPlugin, EcuGateway, EcuManager, EcuState, HashMap,
    HashMapExtensions, HashSet, HashSetExtensions, PayloadDecoder, ServicePayload, UdsVariant,
    VariantState,
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

    if matches!(trigger, DetectionTrigger::Forced) {
        return DetectionPermit::Run(Some(lock_handle.begin_forced_detection().await));
    }

    let Some(guard) = lock_handle.begin_detection().await else {
        return DetectionPermit::Skip;
    };
    if state_handle.is_some_and(|handle| !needs_variant_detection(&handle.ecu_status())) {
        return DetectionPermit::Skip;
    }
    DetectionPermit::Run(Some(guard))
}

/// Outcome of detecting schema-bearing members of a duplicate group.
#[derive(Debug)]
enum GroupDetectionResult {
    /// No member has variant detection services.
    NoDetectionServices,
    /// A failed detection request already marked the group unreachable.
    MarkedUnreachable,
    /// Exactly this member matched a specific (non-fallback) variant.
    ExactMatch(String),
    /// Members are online, but none matched a specific variant.
    AllFallbacks,
    /// No member of the group is online.
    NoOnlineEcu,
    /// Members are online, but detection failed for all of them.
    NoDetection,
}

struct DetectionResponses<R> {
    responses: HashMap<String, R>,
    skipped_error: Option<DiagServiceError>,
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

        let Some(mut duplicated_ecus) = ecu
            .read()
            .await
            .duplicating_ecu_names()
            .cloned()
            .filter(|d| !d.is_empty())
        else {
            if ecu.read().await.get_variant_detection_requests().is_empty() {
                return self.detect_without_schema(ecu_name, ecu).await;
            }
            return self.detect_single_ecu(ecu_name, ecu).await;
        };
        duplicated_ecus.insert(ecu_name.to_owned());
        self.detect_duplicate_group(duplicated_ecus).await
    }

    async fn detect_single_ecu(
        &self,
        ecu_name: &str,
        ecu: &RwLock<T>,
    ) -> Result<(), DiagServiceError> {
        let Some(gathered) = self.gather_or_mark_unreachable(ecu_name, ecu).await? else {
            return Ok(());
        };
        ecu.write()
            .await
            .detect_variant(gathered.responses)
            .await
            .map_err(|e| {
                DiagServiceError::VariantDetectionError(format!("Failed to detect variant: {e:?}"))
            })
    }

    /// Detection for an ECU without detection services and without
    /// duplicates: it always runs the base variant, so only reachability
    /// decides its state.
    async fn detect_without_schema(
        &self,
        ecu_name: &str,
        ecu: &RwLock<T>,
    ) -> Result<(), DiagServiceError> {
        if self
            .probe_reachability_or_mark_unreachable(ecu_name, ecu)
            .await?
        {
            ecu.write().await.set_base_variant_online().await
        } else {
            // No probe response; the helper already marked the ECU unreachable.
            Ok(())
        }
    }

    /// Detection for a duplicate group. Members with detection services are
    /// evaluated against the responses to their requests. If none of them
    /// matched a specific variant, the group is probed once for reachability.
    /// If the ECU responds, a single member without detection services takes
    /// the base variant. Several such members leave the group unresolved.
    async fn detect_duplicate_group(
        &self,
        duplicated_ecus: HashSet<String>,
    ) -> Result<(), DiagServiceError> {
        let (with_schema, without_schema) =
            self.partition_duplicate_members(&duplicated_ecus).await;
        let detection_result = if with_schema.is_empty() {
            GroupDetectionResult::NoDetectionServices
        } else {
            self.detect_schema_members(&with_schema).await?
        };

        if matches!(detection_result, GroupDetectionResult::MarkedUnreachable) {
            // Gathering already marked the ECU and its duplicates unreachable.
            return Ok(());
        }

        // check if we have exactly one match. if yes, apply the group result and return early
        if matches!(detection_result, GroupDetectionResult::ExactMatch(_)) {
            self.apply_group_result(&detection_result, &duplicated_ecus)
                .await;
            return Ok(());
        }

        // If no exact match was found, proceed with probing members without detection services.
        // if there are no members without detection services, apply the group result and return early
        let Some(probe_name) = without_schema.first() else {
            self.apply_group_result(&detection_result, &duplicated_ecus)
                .await;
            return Ok(());
        };

        // All members share one logical address, so a single probe answers
        // reachability for the whole group.
        let probe_ecu = self.uds_ecu_db(probe_name)?;
        if !self.probe_reachability(probe_name, probe_ecu).await? {
            if matches!(detection_result, GroupDetectionResult::NoDetectionServices) {
                self.mark_group_unreachable(probe_ecu).await?;
            } else {
                self.apply_group_result(&detection_result, &duplicated_ecus)
                    .await;
            }
            return Ok(());
        }

        if without_schema.len() == 1 {
            tracing::debug!(
                ecu_name = %probe_name,
                "No duplicate matched a specific variant, selecting base variant of the only \
                 member without detection services"
            );
            probe_ecu.write().await.set_base_variant_online().await?;
            for name in duplicated_ecus.iter().filter(|name| *name != probe_name) {
                if let Some(member) = self.ecus.get(name) {
                    member.write().await.mark_as_duplicate().await;
                }
            }
        } else {
            tracing::warn!(
                candidates = ?without_schema,
                "Multiple duplicates define no variant detection services, cannot select one"
            );
            for name in &duplicated_ecus {
                if let Some(member) = self.ecus.get(name) {
                    member.write().await.mark_as_no_variant_detected().await;
                }
            }
        }
        Ok(())
    }

    async fn partition_duplicate_members(
        &self,
        duplicated_ecus: &HashSet<String>,
    ) -> (Vec<String>, Vec<String>) {
        let mut names: Vec<_> = duplicated_ecus.iter().cloned().collect();
        names.sort();
        let mut with_schema = Vec::new();
        let mut without_schema = Vec::new();
        for name in names {
            let Some(member) = self.ecus.get(&name) else {
                continue;
            };
            if member
                .read()
                .await
                .get_variant_detection_requests()
                .is_empty()
            {
                without_schema.push(name);
            } else {
                with_schema.push(name);
            }
        }
        (with_schema, without_schema)
    }

    async fn detect_schema_members(
        &self,
        with_schema: &[String],
    ) -> Result<GroupDetectionResult, DiagServiceError> {
        let mut responses_by_member = HashMap::new();
        let mut connectivity_error = None;
        for name in with_schema {
            let ecu = self.uds_ecu_db(name)?;
            // A member that cannot be reached (e.g. it has no route on the
            // active transport) must not mark the whole group unreachable
            // while another member of the same ECU answers.
            let gathered = match self.gather_detection_responses(name, ecu).await {
                Ok(gathered) => gathered,
                Err(error) if is_connectivity_failure(&error) => {
                    tracing::debug!(
                        ecu_name = %name,
                        error = %error,
                        "Duplicate member unreachable during variant detection"
                    );
                    connectivity_error = Some(error);
                    continue;
                }
                Err(error) => return Err(error),
            };
            // A missing response may be the only evidence for a specific variant.
            // Do not resolve duplicates from incomplete detection results.
            if let Some(error) = gathered.skipped_error {
                return Err(error);
            }
            if !gathered.responses.is_empty() {
                responses_by_member.insert(name.clone(), gathered.responses);
            }
        }

        if responses_by_member.is_empty() {
            if let Some(first) = with_schema.first() {
                let first_ecu = self.uds_ecu_db(first)?;
                if let Err(mark_err) = self.mark_group_unreachable(first_ecu).await {
                    tracing::warn!(
                        ecu_name = %first,
                        error = %mark_err,
                        "Failed to mark ECU group unreachable after connectivity failure"
                    );
                }
            }
            return match connectivity_error {
                Some(error) => Err(error),
                None => Ok(GroupDetectionResult::MarkedUnreachable),
            };
        }

        let result = self
            .evaluate_duplicate_group(with_schema, &responses_by_member)
            .await;
        tracing::debug!(?result, "ECU variant detection result");
        Ok(result)
    }

    /// Gathers detection responses. Connectivity failures and unanswered
    /// requests mark the group unreachable; configuration errors are returned
    /// instead. `Ok(None)` means the state was already settled.
    async fn gather_or_mark_unreachable(
        &self,
        ecu_name: &str,
        ecu: &RwLock<T>,
    ) -> Result<Option<DetectionResponses<<T as PayloadDecoder>::Response>>, DiagServiceError> {
        let gathered = match self.gather_detection_responses(ecu_name, ecu).await {
            Ok(responses) => responses,
            Err(error) if is_connectivity_failure(&error) => {
                if let Err(mark_err) = self.mark_group_unreachable(ecu).await {
                    tracing::warn!(
                        ecu_name,
                        error = %mark_err,
                        "Failed to mark ECU group unreachable after connectivity failure"
                    );
                }
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        if gathered.responses.is_empty() {
            if let Some(error) = gathered.skipped_error {
                return Err(error);
            }
            self.mark_group_unreachable(ecu).await?;
            return Ok(None);
        }
        Ok(Some(gathered))
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
    ) -> Result<&RwLock<T>, DiagServiceError> {
        let ecu = self.uds_ecu_db(ecu_name)?;

        if ecu.read().await.ecu_status().variant_state != VariantState::NotTested {
            return Ok(ecu);
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
            Ok(ecu)
        }
    }

    #[tracing::instrument(skip_all,
        fields(dlt_context = dlt_ctx!("UDS"))
    )]
    pub(crate) async fn start_variant_detection_for_ecus(&self, ecus: Vec<String>) {
        if self.communication_access.variant_detection() == VariantDetectionMode::Never {
            return;
        }

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

    /// Runs the initial variant detection over all ECUs, for the reachable
    /// ones. Offline ECUs get their state set immediately. Duplicate groups run
    /// one detection per physical node.
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
    /// in a loop. Gathering stops at the first connectivity failure. Other
    /// per-request failures are logged and retained while later requests run.
    async fn gather_detection_responses(
        &self,
        ecu_name: &str,
        ecu: &RwLock<T>,
    ) -> Result<DetectionResponses<<T as PayloadDecoder>::Response>, DiagServiceError> {
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
        let mut last_error = None;
        let mut connectivity_failed = false;
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
                    CommunicationReadiness::AssumeReady,
                )
                .await
            {
                Ok(response) => {
                    service_responses.insert(name, response);
                }
                Err(e) if is_connectivity_failure(&e) => {
                    tracing::warn!(
                        ecu_name,
                        request_name = %name,
                        error = %e,
                        "Connectivity failure during variant detection, aborting"
                    );
                    last_error = Some(e);
                    connectivity_failed = true;
                    break;
                }
                Err(e) => {
                    tracing::warn!(
                        ecu_name,
                        request_name = %name,
                        error = %e,
                        "Variant detection request failed, continuing with remaining requests"
                    );
                    last_error = Some(e);
                }
            }
        }
        self.state_coordinator
            .restore_disconnect_handling(ecu_name)
            .await;

        // A connectivity failure invalidates any partial responses: the
        // caller marks the group unreachable and detection can be retried.
        match last_error {
            Some(error) if connectivity_failed => Err(error),
            skipped_error => Ok(DetectionResponses {
                responses: service_responses,
                skipped_error,
            }),
        }
    }

    /// Checks whether an ECU without detection services is reachable by
    /// reading the `UDSVersionDataIdentifier` (`22 FF 00`). Any response,
    /// positive or negative, counts as reachable.
    async fn send_reachability_probe(
        &self,
        ecu_name: &str,
        ecu: &RwLock<T>,
    ) -> Result<Option<ServicePayload>, DiagServiceError> {
        const UDS_VERSION_PROBE: [u8; 3] = [0x22, 0xFF, 0x00];

        let payload = {
            let ecu = ecu.read().await;
            ServicePayload {
                data: UDS_VERSION_PROBE.to_vec(),
                source_address: ecu.tester_address(),
                target_address: ecu.logical_address(),
                new_session: None,
                new_security: None,
            }
        };

        tracing::debug!(
            ecu_name,
            "No variant detection services configured, probing reachability"
        );
        self.state_coordinator
            .suppress_disconnect_handling(ecu_name)
            .await;
        let result = self
            .send_with_raw_payload(
                ecu_name,
                payload,
                None,
                true,
                CommunicationReadiness::AssumeReady,
            )
            .await;
        self.state_coordinator
            .restore_disconnect_handling(ecu_name)
            .await;

        result
    }

    /// Probes reachability without changing any state. Connectivity failures
    /// count as unreachable, so other detection results can still decide.
    async fn probe_reachability(
        &self,
        ecu_name: &str,
        ecu: &RwLock<T>,
    ) -> Result<bool, DiagServiceError> {
        match self.send_reachability_probe(ecu_name, ecu).await {
            Ok(response) => Ok(response.is_some()),
            Err(error) if is_connectivity_failure(&error) => {
                tracing::debug!(ecu_name, error = %error, "Reachability probe failed");
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    /// Probes reachability and marks the group unreachable when the ECU does
    /// not answer. On connectivity failures the original error is returned.
    async fn probe_reachability_or_mark_unreachable(
        &self,
        ecu_name: &str,
        ecu: &RwLock<T>,
    ) -> Result<bool, DiagServiceError> {
        match self.send_reachability_probe(ecu_name, ecu).await {
            Ok(Some(_)) => Ok(true),
            Ok(None) => {
                self.mark_group_unreachable(ecu).await?;
                Ok(false)
            }
            Err(error) if is_connectivity_failure(&error) => {
                if let Err(mark_err) = self.mark_group_unreachable(ecu).await {
                    tracing::warn!(
                        ecu_name,
                        error = %mark_err,
                        "Failed to mark ECU unreachable after failed reachability probe"
                    );
                }
                Err(error)
            }
            Err(error) => Err(error),
        }
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
        duplicated_ecus: &[String],
        responses_by_member: &HashMap<String, HashMap<String, <T as PayloadDecoder>::Response>>,
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
            let Some(service_responses) = responses_by_member.get(ecu_name) else {
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
            GroupDetectionResult::NoOnlineEcu
            | GroupDetectionResult::NoDetection
            | GroupDetectionResult::NoDetectionServices
            | GroupDetectionResult::MarkedUnreachable => {}
        }
    }
}

fn is_connectivity_failure(error: &DiagServiceError) -> bool {
    matches!(
        error,
        DiagServiceError::ConnectionClosed(_)
            | DiagServiceError::EcuOffline(_)
            | DiagServiceError::NoResponse(_)
            | DiagServiceError::SendFailed(_)
            | DiagServiceError::Timeout
    )
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
                    let mut processed_duplicates = HashSet::new();
                    let mut deduplicated_ecus = Vec::new();

                    for ecu_name in ecus {
                        if processed_duplicates.contains(&ecu_name) {
                            continue;
                        }

                        if let Some(ecu) = uds_manager.ecus.get(&ecu_name) {
                            let ecu_read = ecu.read().await;
                            if let Some(duplicates) = ecu_read.duplicating_ecu_names() {
                                processed_duplicates.extend(duplicates.iter().cloned());
                            }
                            deduplicated_ecus.push(ecu_name);
                        } else {
                            tracing::warn!(
                                ecu_name,
                                "Variant detection trigger for unknown ECU dropped"
                            );
                        }
                    }

                    tokio::select! {
                        () = task_cancel.cancelled() => break,
                        () = uds_manager.start_variant_detection_for_ecus(deduplicated_ecus) => {}
                    }
                }
                receiver
            });
            *self.variant_detection_listener.lock().await = Some((cancel, listener));
        }
        Ok(())
    }

    async fn on_enabled(&self) {
        self.resume_tester_present().await;
        self.resume_deferred_resets().await;
    }

    async fn deinitialize(&self) {
        self.suspend_tester_present().await;
        self.stop_variant_detection_listener(ReceiverRetention::Keep)
            .await;
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
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use cda_interfaces::{
        Connectivity, DiagServiceError, EcuState, HashMap, ServicePayload, TransportResponse,
        UdsVariant, VariantDetection, VariantState, datatypes::FaultConfig, service_ids,
    };
    use cda_plugin_communication_management::lifecycle::enabled_communication_access_for_test;
    use tokio::sync::RwLock;

    use super::{DetectionPermit, DetectionTrigger, claim_detection};
    use crate::{
        UdsManager,
        coordinator::EcuCoordinatorHandle,
        test_helpers::{TestEcuDb, TestGateway},
    };

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
    async fn forced_detection_is_not_superseded_by_automatic_trigger() {
        let handle = EcuCoordinatorHandle::spawn("TestECU".to_owned());
        let in_flight = handle.begin_detection().await.expect("first entrant");

        let forced_handle = handle.clone();
        let forced = tokio::spawn(async move {
            claim_detection(
                Some(&forced_handle),
                Some(&forced_handle),
                DetectionTrigger::Forced,
            )
            .await
        });
        tokio::task::yield_now().await;

        let automatic_handle = handle.clone();
        let automatic = tokio::spawn(async move {
            claim_detection(
                Some(&automatic_handle),
                Some(&automatic_handle),
                DetectionTrigger::IfNeeded,
            )
            .await
        });
        tokio::task::yield_now().await;
        drop(in_flight);

        let forced_permit = forced.await.expect("forced trigger");
        assert!(
            matches!(forced_permit, DetectionPermit::Run(Some(_))),
            "explicit detection must not be coalesced"
        );
        drop(forced_permit);

        assert!(
            matches!(
                automatic.await.expect("automatic trigger"),
                DetectionPermit::Run(Some(_))
            ),
            "latest unresolved automatic trigger must still run"
        );
    }

    #[test]
    fn only_transport_failures_are_connectivity_failures() {
        assert!(super::is_connectivity_failure(&DiagServiceError::Timeout));
        assert!(super::is_connectivity_failure(
            &DiagServiceError::NoResponse("TestECU".to_owned())
        ));
        assert!(!super::is_connectivity_failure(
            &DiagServiceError::VariantDetectionError("No services".to_owned())
        ));
        assert!(!super::is_connectivity_failure(
            &DiagServiceError::BadPayload("Invalid request".to_owned())
        ));
    }

    fn probe_reply_gateway(reply: Vec<u8>, send_count: Arc<AtomicUsize>) -> TestGateway {
        TestGateway {
            send_fn: Arc::new(move |response_tx, _| {
                send_count.fetch_add(1, Ordering::SeqCst);
                let msg = TransportResponse::UdsResponse(ServicePayload {
                    data: reply.clone(),
                    source_address: 0x0001,
                    target_address: 0x0E00,
                    new_session: None,
                    new_security: None,
                });
                response_tx.try_send(Ok(Some(msg))).ok();
                Ok(())
            }),
        }
    }

    async fn detect_schema_less_ecu(
        gateway: TestGateway,
        ecu_db: TestEcuDb,
    ) -> (Result<(), DiagServiceError>, bool) {
        let ecus = Arc::new(HashMap::from_iter([(
            "TestECU".to_owned(),
            RwLock::new(ecu_db),
        )]));
        let manager = UdsManager::new_for_raw_payload_tests(
            gateway,
            Arc::clone(&ecus),
            FaultConfig::default(),
            enabled_communication_access_for_test(),
        );
        let result = manager.detect_variant("TestECU").await;
        let selected = ecus
            .get("TestECU")
            .expect("test ECU")
            .read()
            .await
            .base_variant_selected
            .load(Ordering::SeqCst);
        (result, selected)
    }

    #[tokio::test]
    async fn detection_without_requests_selects_base_variant_on_probe_response() {
        let send_count = Arc::new(AtomicUsize::new(0));
        let gateway = probe_reply_gateway(vec![0x62, 0xFF, 0x00, 0x01], Arc::clone(&send_count));

        let (result, selected) = detect_schema_less_ecu(gateway, TestEcuDb::new()).await;

        assert_eq!(result, Ok(()));
        assert!(selected, "a reachable ECU must run its base variant");
        assert_eq!(send_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn detection_without_requests_selects_base_variant_on_negative_probe_response() {
        let send_count = Arc::new(AtomicUsize::new(0));
        let gateway = probe_reply_gateway(
            vec![service_ids::NEGATIVE_RESPONSE, 0x22, 0x31],
            Arc::clone(&send_count),
        );

        let (result, selected) = detect_schema_less_ecu(gateway, TestEcuDb::new()).await;

        assert_eq!(result, Ok(()));
        assert!(
            selected,
            "a negative response still proves the ECU is reachable"
        );
    }

    #[tokio::test]
    async fn detection_without_requests_returns_timeout_when_probe_unanswered() {
        let send_count = Arc::new(AtomicUsize::new(0));
        let gateway_send_count = Arc::clone(&send_count);
        let gateway = TestGateway {
            send_fn: Arc::new(move |_, _| {
                gateway_send_count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
        };

        let (result, selected) = detect_schema_less_ecu(
            gateway,
            TestEcuDb::with_timeout_default_and_repeat_req_count_app(
                std::time::Duration::from_millis(1),
                0,
            ),
        )
        .await;

        assert_eq!(result, Err(DiagServiceError::Timeout));
        assert!(!selected, "an unreachable ECU must not select a variant");
        assert_eq!(send_count.load(Ordering::SeqCst), 1);
    }

    /// Replies to consecutive sends with the given payloads in order. Sends
    /// beyond the list stay unanswered.
    fn scripted_gateway(replies: Vec<Vec<u8>>, send_count: Arc<AtomicUsize>) -> TestGateway {
        let replies = std::sync::Mutex::new(std::collections::VecDeque::from(replies));
        TestGateway {
            send_fn: Arc::new(move |response_tx, _| {
                send_count.fetch_add(1, Ordering::SeqCst);
                if let Some(reply) = replies.lock().expect("replies lock").pop_front() {
                    let msg = TransportResponse::UdsResponse(ServicePayload {
                        data: reply,
                        source_address: 0x0001,
                        target_address: 0x0E00,
                        new_session: None,
                        new_security: None,
                    });
                    response_tx.try_send(Ok(Some(msg))).ok();
                }
                Ok(())
            }),
        }
    }

    const SESSION_REPLY: [u8; 2] = [0x50, 0x02];
    const PROBE_REPLY: [u8; 4] = [0x62, 0xFF, 0x00, 0x01];

    fn fallback_outcome() -> EcuState {
        EcuState {
            connectivity: Connectivity::Online,
            variant_state: VariantState::Detected {
                name: "BaseVariant".to_owned(),
                is_base_variant: true,
                is_fallback: true,
            },
            variant_index: Some(0),
        }
    }

    fn short_timeout() -> std::time::Duration {
        std::time::Duration::from_millis(1)
    }

    fn schema_less_member(group: &[&str]) -> TestEcuDb {
        TestEcuDb::with_timeout_default_and_repeat_req_count_app(short_timeout(), 0)
            .with_duplicates(group)
    }

    async fn detect_group(
        gateway: TestGateway,
        members: Vec<(&str, TestEcuDb)>,
        trigger: &str,
    ) -> (
        Result<(), DiagServiceError>,
        Arc<HashMap<String, RwLock<TestEcuDb>>>,
    ) {
        let ecus: Arc<HashMap<String, RwLock<TestEcuDb>>> = Arc::new(
            members
                .into_iter()
                .map(|(name, db)| (name.to_owned(), RwLock::new(db)))
                .collect(),
        );
        let manager = UdsManager::new_for_raw_payload_tests(
            gateway,
            Arc::clone(&ecus),
            FaultConfig::default(),
            enabled_communication_access_for_test(),
        );
        let result = manager.detect_variant(trigger).await;
        (result, ecus)
    }

    async fn state_of(ecus: &HashMap<String, RwLock<TestEcuDb>>, name: &str) -> EcuState {
        ecus.get(name).expect("member").read().await.ecu_status()
    }

    #[tokio::test]
    async fn group_exact_match_skips_probe_and_marks_schema_less_member_duplicate() {
        let send_count = Arc::new(AtomicUsize::new(0));
        let gateway = scripted_gateway(
            vec![SESSION_REPLY.to_vec(), PROBE_REPLY.to_vec()],
            Arc::clone(&send_count),
        );
        let members = vec![
            (
                "A",
                TestEcuDb::with_variant_detection_request(short_timeout()).with_duplicates(&["B"]),
            ),
            ("B", schema_less_member(&["A"])),
        ];

        let (result, ecus) = detect_group(gateway, members, "B").await;

        assert_eq!(result, Ok(()));
        assert_eq!(
            send_count.load(Ordering::SeqCst),
            1,
            "no probe after exact match"
        );
        assert!(state_of(&ecus, "A").await.is_online_and_detected());
        assert_eq!(
            state_of(&ecus, "B").await.variant_state,
            VariantState::Duplicate
        );
    }

    #[tokio::test]
    async fn group_unreachable_member_does_not_mark_responding_member_unreachable() {
        let send_count = Arc::new(AtomicUsize::new(0));
        // A answers, B's request stays unanswered (e.g. no route on this transport).
        let gateway = scripted_gateway(vec![SESSION_REPLY.to_vec()], Arc::clone(&send_count));
        let members = vec![
            (
                "A",
                TestEcuDb::with_variant_detection_request(short_timeout()).with_duplicates(&["B"]),
            ),
            (
                "B",
                TestEcuDb::with_variant_detection_request(short_timeout()).with_duplicates(&["A"]),
            ),
        ];

        let (result, ecus) = detect_group(gateway, members, "A").await;

        assert_eq!(result, Ok(()));
        assert_eq!(send_count.load(Ordering::SeqCst), 2);
        assert!(state_of(&ecus, "A").await.is_online_and_detected());
        assert_eq!(
            state_of(&ecus, "B").await.variant_state,
            VariantState::Duplicate
        );
    }

    #[tokio::test]
    async fn group_is_unreachable_when_no_member_responds() {
        let send_count = Arc::new(AtomicUsize::new(0));
        let gateway = scripted_gateway(Vec::new(), Arc::clone(&send_count));
        let members = vec![
            (
                "A",
                TestEcuDb::with_variant_detection_request(short_timeout()).with_duplicates(&["B"]),
            ),
            (
                "B",
                TestEcuDb::with_variant_detection_request(short_timeout()).with_duplicates(&["A"]),
            ),
        ];

        let (result, ecus) = detect_group(gateway, members, "A").await;

        assert_eq!(result, Err(DiagServiceError::Timeout));
        for name in ["A", "B"] {
            assert_eq!(
                state_of(&ecus, name).await.connectivity,
                Connectivity::Offline,
                "{name} must be marked unreachable"
            );
        }
    }

    #[tokio::test]
    async fn group_evaluates_each_schema_against_its_own_requests() {
        let send_count = Arc::new(AtomicUsize::new(0));
        let gateway = scripted_gateway(
            vec![SESSION_REPLY.to_vec(), vec![0x50, 0x03]],
            Arc::clone(&send_count),
        );
        let members = vec![
            (
                "A",
                TestEcuDb::with_variant_detection_request(short_timeout())
                    .with_duplicates(&["B"])
                    .with_detection_outcome(fallback_outcome()),
            ),
            (
                "B",
                TestEcuDb::with_variant_detection_session(short_timeout(), 0x03)
                    .with_duplicates(&["A"])
                    .with_detection_outcome(TestEcuDb::new().ecu_status()),
            ),
        ];

        let (result, ecus) = detect_group(gateway, members, "A").await;

        assert_eq!(result, Ok(()));
        assert_eq!(send_count.load(Ordering::SeqCst), 2);
        assert_eq!(
            state_of(&ecus, "A").await.variant_state,
            VariantState::Duplicate
        );
        assert!(state_of(&ecus, "B").await.is_online_and_detected());
    }

    #[tokio::test]
    async fn incomplete_schema_cannot_select_schema_less_duplicate() {
        let send_count = Arc::new(AtomicUsize::new(0));
        let gateway_send_count = Arc::clone(&send_count);
        let gateway = TestGateway {
            send_fn: Arc::new(move |response_tx, _| {
                if gateway_send_count.fetch_add(1, Ordering::SeqCst) == 0 {
                    response_tx
                        .try_send(Ok(Some(TransportResponse::UdsResponse(ServicePayload {
                            data: SESSION_REPLY.to_vec(),
                            source_address: 0x0001,
                            target_address: 0x0E00,
                            new_session: None,
                            new_security: None,
                        }))))
                        .ok();
                    Ok(())
                } else {
                    Err(DiagServiceError::BadPayload(
                        "Invalid detection request".to_owned(),
                    ))
                }
            }),
        };
        let members = vec![
            (
                "A",
                TestEcuDb::with_variant_detection_request(short_timeout())
                    .with_additional_detection_session(0x03)
                    .with_duplicates(&["B"])
                    .with_detection_outcome(fallback_outcome()),
            ),
            ("B", schema_less_member(&["A"])),
        ];

        let (result, ecus) = detect_group(gateway, members, "A").await;

        assert_eq!(
            result,
            Err(DiagServiceError::BadPayload(
                "Invalid detection request".to_owned()
            ))
        );
        assert_eq!(send_count.load(Ordering::SeqCst), 2);
        assert!(
            !ecus
                .get("B")
                .expect("member")
                .read()
                .await
                .base_variant_selected
                .load(Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn schema_less_group_propagates_non_connectivity_probe_error() {
        let gateway = TestGateway {
            send_fn: Arc::new(|_, _| Err(DiagServiceError::BadPayload("Invalid probe".to_owned()))),
        };
        let members = vec![
            ("B", schema_less_member(&["C"])),
            ("C", schema_less_member(&["B"])),
        ];

        let (result, ecus) = detect_group(gateway, members, "B").await;

        assert_eq!(
            result,
            Err(DiagServiceError::BadPayload("Invalid probe".to_owned()))
        );
        for name in ["B", "C"] {
            assert!(state_of(&ecus, name).await.is_online_and_detected());
        }
    }

    #[tokio::test]
    async fn group_without_match_selects_single_schema_less_member_on_probe_response() {
        let send_count = Arc::new(AtomicUsize::new(0));
        let gateway = scripted_gateway(
            vec![SESSION_REPLY.to_vec(), PROBE_REPLY.to_vec()],
            Arc::clone(&send_count),
        );
        let members = vec![
            (
                "A",
                TestEcuDb::with_variant_detection_request(short_timeout())
                    .with_duplicates(&["B"])
                    .with_detection_outcome(fallback_outcome()),
            ),
            ("B", schema_less_member(&["A"])),
        ];

        let (result, ecus) = detect_group(gateway, members, "A").await;

        assert_eq!(result, Ok(()));
        assert_eq!(send_count.load(Ordering::SeqCst), 2);
        let b = ecus.get("B").expect("member").read().await;
        assert!(b.base_variant_selected.load(Ordering::SeqCst));
        assert_eq!(b.ecu_status().connectivity, Connectivity::Online);
        drop(b);
        assert_eq!(
            state_of(&ecus, "A").await.variant_state,
            VariantState::Duplicate
        );
    }

    #[tokio::test]
    async fn group_without_match_applies_group_result_when_probe_unanswered() {
        let send_count = Arc::new(AtomicUsize::new(0));
        let gateway = scripted_gateway(vec![SESSION_REPLY.to_vec()], Arc::clone(&send_count));
        let members = vec![
            (
                "A",
                TestEcuDb::with_variant_detection_request(short_timeout())
                    .with_duplicates(&["B"])
                    .with_detection_outcome(fallback_outcome()),
            ),
            ("B", schema_less_member(&["A"])),
        ];

        let (result, ecus) = detect_group(gateway, members, "A").await;

        assert_eq!(result, Ok(()));
        assert_eq!(send_count.load(Ordering::SeqCst), 2);
        for name in ["A", "B"] {
            assert_eq!(
                state_of(&ecus, name).await.variant_state,
                VariantState::NotDetected,
                "all-fallback group result must apply to {name}"
            );
        }
    }

    #[tokio::test]
    async fn group_with_several_schema_less_members_is_unresolved_on_single_probe_response() {
        let send_count = Arc::new(AtomicUsize::new(0));
        let gateway = scripted_gateway(vec![PROBE_REPLY.to_vec()], Arc::clone(&send_count));
        let members = vec![
            ("B", schema_less_member(&["C"])),
            ("C", schema_less_member(&["B"])),
        ];

        let (result, ecus) = detect_group(gateway, members, "B").await;

        assert_eq!(result, Ok(()));
        assert_eq!(send_count.load(Ordering::SeqCst), 1, "group is probed once");
        for name in ["B", "C"] {
            let member = ecus.get(name).expect("member").read().await;
            assert!(!member.base_variant_selected.load(Ordering::SeqCst));
            assert_eq!(member.ecu_status().variant_state, VariantState::NotDetected);
        }
    }

    #[tokio::test]
    async fn group_with_only_schema_less_members_is_unreachable_without_probe_response() {
        let send_count = Arc::new(AtomicUsize::new(0));
        let gateway = scripted_gateway(Vec::new(), Arc::clone(&send_count));
        let members = vec![
            ("B", schema_less_member(&["C"])),
            ("C", schema_less_member(&["B"])),
        ];

        let (result, ecus) = detect_group(gateway, members, "C").await;

        assert_eq!(result, Ok(()));
        assert_eq!(send_count.load(Ordering::SeqCst), 1);
        for name in ["B", "C"] {
            assert_eq!(
                state_of(&ecus, name).await.connectivity,
                Connectivity::Offline,
                "{name} must be marked unreachable"
            );
        }
    }

    #[tokio::test]
    async fn forced_detection_timeout_is_returned_after_sending() {
        let send_count = Arc::new(AtomicUsize::new(0));
        let gateway_send_count = Arc::clone(&send_count);
        let gateway = TestGateway {
            send_fn: Arc::new(move |_, _| {
                gateway_send_count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
        };
        let ecus = Arc::new(HashMap::from_iter([(
            "TestECU".to_owned(),
            RwLock::new(TestEcuDb::with_variant_detection_request(
                std::time::Duration::from_millis(1),
            )),
        )]));
        let manager = UdsManager::new_for_raw_payload_tests(
            gateway,
            ecus,
            FaultConfig::default(),
            enabled_communication_access_for_test(),
        );

        let result = manager.detect_variant("TestECU").await;

        assert_eq!(result, Err(DiagServiceError::Timeout));
        assert_eq!(
            send_count.load(Ordering::SeqCst),
            1,
            "forced detection must make one gateway send before reporting the timeout"
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
