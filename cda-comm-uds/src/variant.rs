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

use std::{ops::Deref, time::Duration};

use async_trait::async_trait;
use cda_interfaces::{
    Connectivity, DiagComm, DiagServiceError, DynamicPlugin, EcuGateway, EcuManager, EcuState,
    HashMap, HashMapExtensions, HashSet, PayloadDecoder, ServicePayload, UdsVariant, VariantState,
    communication_control::{
        ActivationCause, CommunicationLifecycle, CommunicationState, CommunicationVariantDetection,
        VariantDetectionMode, error::CommControlError,
    },
    dlt_ctx,
};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use crate::{
    ReceiverRetention, ResolvedEcu, UdsManager, coordinator::EcuCoordinatorHandle,
    transport::needs_variant_detection,
};

/// A [`ResolvedEcu`] whose variant gate has run.
///
/// The inner field is private to this module, so
/// [`UdsManager::uds_ecu_variant_detection_concluded`] is the only place in the
/// crate that can build one - holding it is proof the gate ran, the same idiom
/// as `ResolvedEcu` proving the caller holds the load guard.
///
/// It proves the check *ran*, not that its result still holds: the coordinator
/// clears `variant_state` back to `NotTested` when an ECU disconnects, since it
/// may have rebooted while offline. The send path therefore still re-checks.
pub(crate) struct VariantReadyEcu<'a, T>(ResolvedEcu<'a, T>);

impl<'a, T> Deref for VariantReadyEcu<'a, T> {
    type Target = ResolvedEcu<'a, T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Why detection was requested, which decides whether an already-settled
/// variant still counts as a reason to skip.
#[derive(Clone, Copy)]
enum DetectionTrigger {
    /// An explicit request: run even when the current state needs no detection.
    Forced,
    /// A scheduled or on-demand trigger: run only while detection is still
    /// needed, re-checked once the group lock is held.
    IfNeeded,
}

/// Outcome of claiming the right to detect one duplicate group.
enum DetectionPermit {
    /// Another detection owns the group, or the trigger went obsolete while
    /// this one waited for it. The caller returns without touching ECU state.
    Skip,
    /// The caller may detect. The guard is held for the duration and released
    /// on drop.
    Run(tokio::sync::OwnedMutexGuard<()>),
}

/// Claims the exclusive right to run detection for one duplicate group.
///
/// `lock_handle` is the group representative's handle, so every member of a
/// group contends for the same lock. `state_handles` are the members of the
/// duplicate group the detection covers, read only to decide whether the
/// trigger is still worth acting on.
///
/// A `Forced` trigger waits for a running detection and then always runs. An
/// automatic (`IfNeeded`) trigger skips on contention: the detection already
/// running for the group publishes a verdict for every member, so queueing
/// behind it would buy nothing but a redundant second pass.
///
/// The `IfNeeded` re-check deliberately happens *after* the lock is held. The
/// detection this call waited for may have just concluded and made the trigger
/// obsolete; checking before acquiring would miss that and detect again. It
/// runs only if at least one member still needs detection. Checking just the
/// lock holder (the group representative) is not enough: a reconnect resets
/// each member separately, so a non-representative member can be left
/// `NotTested` while the representative is already detected.
///
/// A missing `lock_handle` skips. It is unreachable in production -
/// `assemble_vehicle_data_source` builds the coordinator's handles from the
/// same database map that becomes the ECU data, so every ECU that resolves has
/// a handle - and skipping is the safe reading should that ever stop holding:
/// no detection beats two unsynchronised ones writing the same group's state.
async fn claim_detection(
    lock_handle: Option<&EcuCoordinatorHandle>,
    state_handles: &[&EcuCoordinatorHandle],
    trigger: DetectionTrigger,
) -> DetectionPermit {
    let Some(lock_handle) = lock_handle else {
        return DetectionPermit::Skip;
    };

    if matches!(trigger, DetectionTrigger::Forced) {
        return DetectionPermit::Run(lock_handle.begin_forced_detection().await);
    }

    let Some(guard) = lock_handle.begin_detection().await else {
        return DetectionPermit::Skip;
    };
    if !state_handles.is_empty()
        && !state_handles
            .iter()
            .any(|handle| needs_variant_detection(&handle.ecu_status()))
    {
        return DetectionPermit::Skip;
    }
    DetectionPermit::Run(guard)
}

/// Whether an automatic detection that just concluded should be retried.
///
/// Retrying only helps if some member is offline *and* would pass the
/// [`claim_detection`] gate again. An offline `Duplicate` member does not
/// need detection, so every retry would be skipped and only add delay.
fn needs_offline_retry(state_handles: &[&EcuCoordinatorHandle]) -> bool {
    state_handles.iter().any(|handle| {
        let status = handle.ecu_status();
        status.connectivity == cda_interfaces::Connectivity::Offline
            && needs_variant_detection(&status)
    })
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
    /// Runs detection if needed for an ECU resolved from the active data snapshot.
    pub(crate) async fn detect_variant_if_needed(
        &self,
        ecu: &ResolvedEcu<'_, T>,
    ) -> Result<(), DiagServiceError> {
        self.detect_variant_with_trigger(ecu.data(), ecu.name(), DetectionTrigger::IfNeeded)
            .await
    }

    async fn detect_variant_with_trigger(
        &self,
        data: &crate::VehicleEcuData<T>,
        ecu_name: &str,
        trigger: DetectionTrigger,
    ) -> Result<(), DiagServiceError> {
        let ecu = Self::resolve_ecu(data, ecu_name)?;
        let group_representative = self.duplicate_group_representative(&ecu).await;
        let group_members = Self::duplicate_group_members(&ecu).await;
        let state_handles: Vec<_> = group_members
            .iter()
            .filter_map(|name| data.state_coordinator().get_handle(name))
            .collect();
        let DetectionPermit::Run(_detection_guard) = claim_detection(
            data.state_coordinator().get_handle(&group_representative),
            &state_handles,
            trigger,
        )
        .await
        else {
            tracing::debug!(ecu_name, "Variant detection trigger obsolete, skipping");
            return Ok(());
        };

        let ecu_read = ecu.read().await;
        let duplicated_ecus = ecu_read
            .duplicating_ecu_names()
            .cloned()
            .filter(|d| !d.is_empty());
        let has_detection_requests = !ecu_read.get_variant_detection_requests().is_empty();
        // The paths below take the write guard on this same lock.
        drop(ecu_read);
        let Some(mut duplicated_ecus) = duplicated_ecus else {
            if !has_detection_requests {
                return self.detect_without_schema(&ecu).await;
            }
            return self.detect_single_ecu(&ecu).await;
        };
        duplicated_ecus.insert(ecu_name.to_owned());
        self.detect_duplicate_group(data, duplicated_ecus).await
    }

    async fn detect_single_ecu(&self, ecu: &ResolvedEcu<'_, T>) -> Result<(), DiagServiceError> {
        let Some(gathered) = self.gather_or_mark_unreachable(ecu).await? else {
            return Ok(());
        };
        let mut ecu_write = ecu.write().await;
        let result = ecu_write.detect_variant(gathered.responses).await;
        result.map_err(|e| {
            DiagServiceError::VariantDetectionError(format!("Failed to detect variant: {e:?}"))
        })
    }

    /// Detection for an ECU without detection services and without
    /// duplicates: it always runs the base variant, so only reachability
    /// decides its state.
    async fn detect_without_schema(
        &self,
        ecu: &ResolvedEcu<'_, T>,
    ) -> Result<(), DiagServiceError> {
        if self.probe_reachability_or_mark_unreachable(ecu).await? {
            let mut ecu_write = ecu.write().await;
            ecu_write.set_base_variant_online().await
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
        data: &crate::VehicleEcuData<T>,
        duplicated_ecus: HashSet<String>,
    ) -> Result<(), DiagServiceError> {
        let (with_schema, without_schema) =
            Self::partition_duplicate_members(data, &duplicated_ecus).await;
        let detection_result = if with_schema.is_empty() {
            GroupDetectionResult::NoDetectionServices
        } else {
            self.detect_schema_members(data, &with_schema).await?
        };

        if matches!(detection_result, GroupDetectionResult::MarkedUnreachable) {
            // Gathering already marked the ECU and its duplicates unreachable.
            return Ok(());
        }

        // check if we have exactly one match. if yes, apply the group result and return early
        if matches!(detection_result, GroupDetectionResult::ExactMatch(_)) {
            Self::apply_group_result(data, &detection_result, &duplicated_ecus).await;
            return Ok(());
        }

        // If no exact match was found, proceed with probing members without detection services.
        // if there are no members without detection services, apply the group result and return early
        let Some(probe_name) = without_schema.first() else {
            Self::apply_group_result(data, &detection_result, &duplicated_ecus).await;
            return Ok(());
        };

        // All members share one logical address, so a single probe answers
        // reachability for the whole group.
        let probe_ecu = Self::resolve_ecu(data, probe_name)?;
        if !self.probe_reachability(&probe_ecu).await? {
            if matches!(detection_result, GroupDetectionResult::NoDetectionServices) {
                self.mark_group_unreachable(&probe_ecu).await?;
            } else {
                Self::apply_group_result(data, &detection_result, &duplicated_ecus).await;
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
                if let Some(member) = data.ecus().get(name) {
                    member.write().await.mark_as_duplicate().await;
                }
            }
        } else {
            tracing::warn!(
                candidates = ?without_schema,
                "Multiple duplicates define no variant detection services, cannot select one"
            );
            for name in &duplicated_ecus {
                if let Some(member) = data.ecus().get(name) {
                    member.write().await.mark_as_no_variant_detected().await;
                }
            }
        }
        Ok(())
    }

    async fn partition_duplicate_members(
        data: &crate::VehicleEcuData<T>,
        duplicated_ecus: &HashSet<String>,
    ) -> (Vec<String>, Vec<String>) {
        let mut names: Vec<_> = duplicated_ecus.iter().cloned().collect();
        names.sort();
        let mut with_schema = Vec::new();
        let mut without_schema = Vec::new();
        for name in names {
            let Some(member) = data.ecus().get(&name) else {
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
        data: &crate::VehicleEcuData<T>,
        with_schema: &[String],
    ) -> Result<GroupDetectionResult, DiagServiceError> {
        let mut responses_by_member = HashMap::new();
        let mut connectivity_error = None;
        for name in with_schema {
            let ecu = Self::resolve_ecu(data, name)?;
            // A member that cannot be reached (e.g. it has no route on the
            // active transport) must not mark the whole group unreachable
            // while another member of the same ECU answers.
            let gathered = match self.gather_detection_responses(&ecu).await {
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
                let first_ecu = Self::resolve_ecu(data, first)?;
                if let Err(mark_err) = self.mark_group_unreachable(&first_ecu).await {
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

        let result = Self::evaluate_duplicate_group(data, with_schema, &responses_by_member).await;
        tracing::debug!(?result, "ECU variant detection result");
        Ok(result)
    }

    /// Gathers detection responses. Connectivity failures and unanswered
    /// requests mark the group unreachable; configuration errors are returned
    /// instead. `Ok(None)` means the state was already settled.
    async fn gather_or_mark_unreachable(
        &self,
        ecu: &ResolvedEcu<'_, T>,
    ) -> Result<Option<DetectionResponses<<T as PayloadDecoder>::Response>>, DiagServiceError> {
        let gathered = match self.gather_detection_responses(ecu).await {
            Ok(responses) => responses,
            Err(error) if is_connectivity_failure(&error) => {
                if let Err(mark_err) = self.mark_group_unreachable(ecu).await {
                    tracing::warn!(
                        ecu_name = ecu.name(),
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

    /// The pre-send variant gate, owned here rather than inlined in the send
    /// path so it sits next to the pre-lookup gate it builds on.
    ///
    /// Two distinct conditions have to hold before a service can go out:
    /// the variant must be known (otherwise there is nothing to encode
    /// against), and an ECU that is `Offline` with an already known variant
    /// has to be probed for reachability first.
    ///
    /// The [`VariantReadyEcu`] proves every caller already ran
    /// [`Self::uds_ecu_variant_detection_concluded`] before looking up its
    /// variant-specific service definition, so once the variant is known this
    /// reduces to a single status read.
    pub(crate) async fn ensure_variant_ready_for_send(
        &self,
        ecu: &VariantReadyEcu<'_, T>,
    ) -> Result<(), DiagServiceError> {
        let status = ecu.read().await.ecu_status();

        // `VariantState::NotTested`: the token proves the gate ran, but the
        // coordinator clears the variant state back to `NotTested` when the ECU
        // disconnects, so this re-check catches that race. The concluded-gate
        // owns the case from here: it either reports
        // `CommunicationNotReady` so the caller can retry, or returns `Ok` once
        // detection has settled - in which case detection has just run and the
        // reachability probe below would be pointless.
        if status.variant_state == VariantState::NotTested {
            return self.uds_ecu_handle_variant_detection_concluded(ecu).await;
        }

        // Only the `Offline`-with-known-variant arm of the predicate can still
        // be true here; `NotTested` returned above. Kept as the shared
        // predicate so this gate cannot drift from the send path's own check.
        if !needs_variant_detection(&status) {
            return Ok(());
        }

        // Known variant, but `Offline`: ECUs behind a gateway share its
        // transport connection and never receive a per-ECU reconnect event, so
        // detection doubles as a reachability probe.
        let name = ecu.name();
        tracing::info!(
            name,
            connectivity = ?status.connectivity,
            variant_state = ?status.variant_state,
            "Triggering variant detection before send"
        );
        // The variant is already known, so this call is only a reachability
        // probe: a detection error says nothing about whether the ECU can be
        // reached, and the connectivity check below is the actual verdict.
        if let Err(e) = self.detect_variant_if_needed(ecu).await {
            tracing::warn!(
                name,
                error = %e,
                "Pre-send variant detection failed"
            );
        }

        // If the ECU is still Offline afterwards, the actual send is doomed to
        // time out as well - fail fast instead of waiting for a second timeout.
        if ecu.read().await.ecu_status().connectivity == Connectivity::Offline {
            return Err(DiagServiceError::EcuOffline(name.to_owned()));
        }

        Ok(())
    }

    /// Ensures variant detection has concluded for `ecu_name` before serving
    /// variant-dependent content.
    ///
    /// This is the pre-*lookup* gate: it makes the variant known so that
    /// variant-specific service definitions resolve, and deliberately does not
    /// probe reachability, so a pure lookup never triggers bus traffic. The
    /// send path adds that probe via [`Self::ensure_variant_ready_for_send`].
    ///
    /// Returns the ECU database, borrowed from the vehicle data the caller
    /// already holds. If communication or variant detection is not ready,
    /// requests activation when needed and returns
    /// [`DiagServiceError::CommunicationNotReady`] so the caller can retry.
    pub(crate) async fn uds_ecu_variant_detection_concluded<'a>(
        &self,
        data: &'a crate::VehicleEcuData<T>,
        ecu_name: &str,
    ) -> Result<VariantReadyEcu<'a, T>, DiagServiceError> {
        let ecu = Self::resolve_ecu(data, ecu_name)?;
        self.uds_ecu_handle_variant_detection_concluded(&ecu)
            .await?;
        Ok(VariantReadyEcu(ecu))
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
    pub(crate) async fn start_variant_detection_for_ecus(
        &self,
        data: &crate::VehicleEcuData<T>,
        ecus: Vec<String>,
        cancel: &CancellationToken,
    ) {
        // `detect_variant` on any member of a duplicate group evaluates and
        // writes the state of every member. Different callers pick different
        // members (the boot path iterates a HashMap, the reconnect path
        // forwards the gateway ECU list), so map every name to its group
        // representative before scheduling: one trigger batch then spawns at
        // most one detection per group. Concurrent detections across trigger
        // batches are serialized by the coordinator's detection lock inside
        // detect_variant.
        let mut representatives = std::collections::BTreeSet::new();
        for ecu_name in ecus {
            let Ok(ecu) = Self::resolve_ecu(data, &ecu_name) else {
                continue;
            };
            representatives.insert(self.duplicate_group_representative(&ecu).await);
        }

        for ecu_name in representatives {
            let vd = self.clone();
            let cancel = cancel.clone();
            cda_interfaces::spawn_named!(&format!("variant-detection-{ecu_name}"), async move {
                // Retry budget for detections that conclude offline: such a
                // verdict is usually transient here (the detection raced the
                // tail of a reconnect churn and its request or response was
                // lost on a connection that was being replaced), and since it
                // does not break the now-healthy connection, no further
                // reconnect event would ever correct it. The delay runs
                // outside the detection (and its disconnect suppression) and
                // outside the `ecu_data` read guard, which is taken per
                // attempt, so real connectivity events flow between attempts
                // and a runtime update can land between retries; genuinely
                // offline ECUs still settle at Offline after the retries.
                const OFFLINE_VERDICT_RETRIES: u32 = 3;
                const OFFLINE_VERDICT_RETRY_DELAY: Duration = Duration::from_secs(1);

                // Cancellation ends the retry loop and cuts a pending retry
                // delay short, but it never interrupts a detection that is
                // already in flight: `gather_detection_responses` suppresses
                // disconnect handling for the ECU around its send loop and
                // restores it afterwards, so dropping that future in between
                // would leak the suppression for the rest of the process
                // lifetime and the coordinator would never publish a disconnect
                // for that ECU again. An in-flight detection is bounded by the
                // per-send timeouts, so it is left to run to completion.
                for attempt in 0..=OFFLINE_VERDICT_RETRIES {
                    if attempt > 0 {
                        tokio::select! {
                            biased; // prefer cancellation over the retry delay
                            () = cancel.cancelled() => {}
                            () = cda_interfaces::util::tokio_ext::sleep_for(
                                OFFLINE_VERDICT_RETRY_DELAY,
                            ) => {}
                        }
                    }
                    if cancel.is_cancelled() {
                        tracing::debug!(ecu_name, attempt, "Variant detection cancelled, stopping");
                        break;
                    }
                    let data = vd.ecu_data.read().await;
                    let result = vd
                        .detect_variant_with_trigger(&data, &ecu_name, DetectionTrigger::IfNeeded)
                        .await;
                    match result {
                        Ok(()) => tracing::trace!("Variant detection successful"),
                        Err(e) => tracing::info!(error = %e, "Variant detection failed"),
                    }
                    // Any member counts: a member whose disconnect was not
                    // suppressed can conclude offline while the
                    // representative itself stays online. Members that no
                    // longer need detection (e.g. Duplicate) are ignored,
                    // the next attempt would skip them anyway.
                    let retry = match Self::resolve_ecu(&data, &ecu_name) {
                        Ok(ecu) => {
                            let group_members = Self::duplicate_group_members(&ecu).await;
                            let state_handles: Vec<_> = group_members
                                .iter()
                                .filter_map(|name| data.state_coordinator().get_handle(name))
                                .collect();
                            needs_offline_retry(&state_handles)
                        }
                        Err(_) => false,
                    };
                    // Release the snapshot before the retry delay, so a runtime
                    // update is not blocked while this task sleeps.
                    drop(data);
                    if !retry {
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
        // Taken before the data guard: `stop_variant_detection_listener` holds
        // this mutex while awaiting the listener task, which itself takes the
        // `ecu_data` read guard.
        let cancel = self.variant_detection_cancel_token().await;
        let data = self.ecu_data.read().await;
        let mut ecus = Vec::new();
        for (ecu_name, db) in data.ecus() {
            let db_read = db.read().await;
            if !db_read.is_physical_ecu() {
                tracing::debug!(
                    ecu_name = %ecu_name,
                    "Skip variant detection for functional description"
                );
                continue;
            }
            drop(db_read);
            // An ECU whose gateway is not connected yet gets no detection request:
            // it would only fail, start the offline retries and queue requests on a
            // connection that is still being established. An empty response set sets
            // the offline state; the gateway connection triggers detection later.
            if let Err(DiagServiceError::EcuOffline(_)) =
                self.gateway.ecu_online(ecu_name, db).await
            {
                if let Err(e) = db
                    .write()
                    .await
                    .detect_variant::<<T as PayloadDecoder>::Response>(HashMap::new())
                    .await
                {
                    tracing::error!(
                        ecu_name = %ecu_name,
                        "Failed to set ECU offline during variant detection: {e:?}"
                    );
                }
                continue;
            }
            ecus.push(ecu_name.to_owned());
        }
        self.start_variant_detection_for_ecus(&data, ecus, &cancel)
            .await;
    }

    /// The token that scopes spawned detections to the lifetime of the running
    /// variant-detection listener, so deinitialization or shutdown stops them.
    ///
    /// When no listener is running, nothing owns this detection's lifecycle, so
    /// a fresh - and therefore never cancelled - token is returned and the task
    /// simply runs to completion.
    async fn variant_detection_cancel_token(&self) -> CancellationToken {
        self.variant_detection_listener
            .lock()
            .await
            .as_ref()
            .map_or_else(CancellationToken::new, |(cancel, _)| cancel.clone())
    }

    /// Smallest name among the ECU and its duplicating peers present in this
    /// data snapshot, so every group member derives the same representative and
    /// claims the same [`claim_detection`] handle - that shared handle is what
    /// makes group detection mutually exclusive. `.min()` is only a
    /// deterministic tie-break, not a preference for any particular ECU.
    async fn duplicate_group_representative(&self, ecu: &ResolvedEcu<'_, T>) -> String {
        let data = ecu.data();
        let ecu_name = ecu.name();
        let db_read = ecu.read().await;
        db_read
            .duplicating_ecu_names()
            .into_iter()
            .flatten()
            .filter(|name| data.ecus().contains_key(*name))
            .map(String::as_str)
            .chain(std::iter::once(ecu_name))
            .min()
            .unwrap_or(ecu_name)
            .to_owned()
    }

    /// All members of the ECU's duplicate group (including the ECU itself)
    /// that are present in this data snapshot, sorted by name.
    async fn duplicate_group_members(ecu: &ResolvedEcu<'_, T>) -> Vec<String> {
        let data = ecu.data();
        let mut members = std::collections::BTreeSet::new();
        members.insert(ecu.name().to_owned());
        members.extend(
            ecu.read()
                .await
                .duplicating_ecu_names()
                .into_iter()
                .flatten()
                .filter(|name| data.ecus().contains_key(*name))
                .cloned(),
        );
        members.into_iter().collect()
    }

    /// Sends the ECU's variant-detection requests and returns the responses that arrived.
    /// Detection sends leave timeout reachability mutation to the aggregate result. Gathering
    /// stops at the first connectivity failure. Other per-request failures are logged and
    /// retained while later requests run.
    ///
    /// Disconnect events are suppressed while the requests are in flight. Without that a
    /// detection timeout publishes a disconnect, which re-triggers variant detection, which
    /// times out again - a loop.
    async fn gather_detection_responses(
        &self,
        ecu: &ResolvedEcu<'_, T>,
    ) -> Result<DetectionResponses<<T as PayloadDecoder>::Response>, DiagServiceError> {
        let ecu_name = ecu.name();
        let ecu_read = ecu.read().await;
        let requests = ecu_read
            .get_variant_detection_requests()
            .iter()
            .map(|(name, service)| Ok((name.to_owned(), service.clone())))
            .collect::<Result<Vec<(String, DiagComm)>, DiagServiceError>>()?;
        let is_loaded = ecu_read.is_loaded();
        // `load` below takes the write guard on this same lock.
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
        // The sends below re-lock this ECU; a queued writer would deadlock the nested read.
        drop(ecu_read);

        let mut service_responses = HashMap::new();
        // Detection is the one send path that runs without a `CommunicationGuard`:
        // it is driven while communication is still `Enabling`, when no guard can
        // be acquired yet. See `send_with_raw_payload`'s readiness contract.
        //
        // Detection owns the final reachability verdict, so intermediate
        // disconnects must not publish one. The send loop `break`s instead of
        // propagating, so `restore` below always runs and suppression cannot
        // outlive this call.
        //
        // Suppress for every group member: the members share one transport,
        // so a timeout would otherwise mark the non-representative members
        // offline and no later reconnect event would bring them back.
        let coordinator = ecu.data().state_coordinator();
        let group_members = Self::duplicate_group_members(ecu).await;
        for member in &group_members {
            coordinator.suppress_disconnect_handling(member).await;
        }
        let mut last_error = None;
        let mut connectivity_failed = false;
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
                )
                .await;
            match result {
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
        for member in &group_members {
            coordinator.restore_disconnect_handling(member).await;
        }

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
        ecu: &ResolvedEcu<'_, T>,
    ) -> Result<Option<ServicePayload>, DiagServiceError> {
        const UDS_VERSION_PROBE: [u8; 3] = [0x22, 0xFF, 0x00];

        let ecu_name = ecu.name();
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
        // Suppress for every group member, as in `gather_detection_responses`:
        // the members share one transport.
        let coordinator = ecu.data().state_coordinator();
        let group_members = Self::duplicate_group_members(ecu).await;
        for member in &group_members {
            coordinator.suppress_disconnect_handling(member).await;
        }
        let result = self.send_with_raw_payload(ecu, payload, None).await;
        for member in &group_members {
            coordinator.restore_disconnect_handling(member).await;
        }

        result
    }

    /// Probes reachability without changing any state. Connectivity failures
    /// count as unreachable, so other detection results can still decide.
    async fn probe_reachability(&self, ecu: &ResolvedEcu<'_, T>) -> Result<bool, DiagServiceError> {
        match self.send_reachability_probe(ecu).await {
            Ok(response) => Ok(response.is_some()),
            Err(error) if is_connectivity_failure(&error) => {
                tracing::debug!(ecu_name = ecu.name(), error = %error, "Reachability probe failed");
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    /// Probes reachability and marks the group unreachable when the ECU does
    /// not answer. On connectivity failures the original error is returned.
    async fn probe_reachability_or_mark_unreachable(
        &self,
        ecu: &ResolvedEcu<'_, T>,
    ) -> Result<bool, DiagServiceError> {
        match self.send_reachability_probe(ecu).await {
            Ok(Some(_)) => Ok(true),
            Ok(None) => {
                self.mark_group_unreachable(ecu).await?;
                Ok(false)
            }
            Err(error) if is_connectivity_failure(&error) => {
                if let Err(mark_err) = self.mark_group_unreachable(ecu).await {
                    tracing::warn!(
                        ecu_name = ecu.name(),
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
    async fn mark_group_unreachable(
        &self,
        ecu: &ResolvedEcu<'_, T>,
    ) -> Result<(), DiagServiceError> {
        let mut ecu_write = ecu.write().await;
        let result = ecu_write
            .detect_variant::<<T as PayloadDecoder>::Response>(HashMap::new())
            .await;
        result.map_err(|e| {
            DiagServiceError::VariantDetectionError(format!("Failed to detect variant: {e:?}"))
        })?;
        // The read below takes this same lock, so the write guard must go first.
        drop(ecu_write);

        let ecu_read = ecu.read().await;
        let duplicates = ecu_read
            .duplicating_ecu_names()
            .cloned()
            .filter(|d| !d.is_empty());
        // Writers on this ECU must not wait for the whole duplicate-marking loop below.
        drop(ecu_read);
        if let Some(duplicates) = duplicates {
            for dup_name in &duplicates {
                if let Some(dup_ecu) = ecu.data().ecus().get(dup_name) {
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
        data: &crate::VehicleEcuData<T>,
        duplicated_ecus: &[String],
        responses_by_member: &HashMap<String, HashMap<String, <T as PayloadDecoder>::Response>>,
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
            let Some(service_responses) = responses_by_member.get(ecu_name) else {
                continue;
            };

            let mut ecu_write = ecu.write().await;
            let result = ecu_write.detect_variant(service_responses.clone()).await;
            // Both branches below take a read guard on this same lock.
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
        let data = self.ecu_data.read().await;
        self.detect_variant_with_trigger(&data, ecu_name, DetectionTrigger::Forced)
            .await
    }

    async fn get_ecu_state(&self, ecu_name: &str) -> Result<EcuState, DiagServiceError> {
        let data = self.ecu_data.read().await;
        let status = Self::db_lookup(&data, ecu_name)?.read().await.ecu_status();
        Ok(status)
    }

    async fn get_logical_address(&self, ecu_name: &str) -> Result<u16, DiagServiceError> {
        let data = self.ecu_data.read().await;
        let logical_address = Self::db_lookup(&data, ecu_name)?
            .read()
            .await
            .logical_address();
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
                    if uds_manager.communication_access.variant_detection()
                        == VariantDetectionMode::Never
                    {
                        continue;
                    }
                    let data = uds_manager.ecu_data.read().await;
                    uds_manager
                        .start_variant_detection_for_ecus(&data, ecus, &task_cancel)
                        .await;
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
        self.stop_variant_detection_listener(ReceiverRetention::Keep)
            .await;
        self.suspend_tester_present().await;
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
        Connectivity, DiagServiceError, EcuManager, EcuState, HashMap, ServicePayload,
        TransportResponse, UdsVariant, VariantDetection, VariantState,
        communication_control::CommunicationLifecycle, datatypes::FaultConfig, service_ids,
    };
    use cda_plugin_communication_management::lifecycle::enabled_communication_access_for_test;
    use tokio::sync::RwLock;

    use super::{DetectionPermit, DetectionTrigger, claim_detection, needs_offline_retry};
    use crate::{
        UdsManager,
        coordinator::EcuCoordinatorHandle,
        test_helpers::{
            TestEcuDb, TestGateway, TestGatewayResponseSender, build_uds_manager, finished_task,
        },
    };

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

    struct DetectionFixture {
        manager: UdsManager<TestGateway, TestEcuDb>,
        gateway: Arc<DetectionGatewayControl>,
    }

    impl DetectionFixture {
        fn new() -> Self {
            Self::build(false)
        }

        fn new_duplicate() -> Self {
            Self::build(true)
        }

        /// The gateway never answers: every send parks until the caller drops
        /// the response channel, which is what makes these detection sends time
        /// out and produce the empty response set the aggregation then judges.
        fn build(with_duplicate: bool) -> Self {
            let mut primary = TestEcuDb::for_detection();
            let duplicate_ecu = with_duplicate.then(|| {
                primary.set_duplicating_ecu_names(cda_interfaces::HashSet::from_iter([
                    "DuplicateECU".to_owned(),
                ]));
                // Duplicate groups are symmetric, as in a real database.
                TestEcuDb::for_detection_with_identity("DuplicateECU", 0x0002)
                    .with_duplicates(&["TestECU"])
            });
            let mut ecus = HashMap::from_iter([("TestECU".to_owned(), RwLock::new(primary))]);
            if let Some(duplicate) = duplicate_ecu {
                ecus.insert("DuplicateECU".to_owned(), RwLock::new(duplicate));
            }
            let gateway = Arc::new(DetectionGatewayControl {
                sends: AtomicUsize::new(0),
                active_children: AtomicUsize::new(0),
                completed_children: AtomicUsize::new(0),
            });
            let manager = build_uds_manager(
                TestGateway::new({
                    let control = Arc::clone(&gateway);
                    move |_, response_sender, _| {
                        control.sends.fetch_add(1, Ordering::SeqCst);
                        let control = Arc::clone(&control);
                        Ok(tokio::spawn(async move {
                            control.active_children.fetch_add(1, Ordering::SeqCst);
                            let _completion = ChildCompletion(Arc::clone(&control));
                            response_sender.closed().await;
                        }))
                    }
                }),
                ecus,
                cda_interfaces::datatypes::FaultConfig::default(),
                enabled_communication_access_for_test(),
            )
            .manager;
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
        let fixture = DetectionFixture::new();
        fixture.initialize().await;
        let mutations = fixture.detection_mutations("TestECU").await;

        // A forced detection that times out reports it, after marking the
        // unreachable ECUs offline.
        assert_eq!(
            UdsVariant::detect_variant(&fixture.manager, "TestECU").await,
            Err(DiagServiceError::Timeout)
        );

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

        // A forced detection that times out reports it, after marking the
        // unreachable ECUs offline.
        assert_eq!(
            UdsVariant::detect_variant(&fixture.manager, "TestECU").await,
            Err(DiagServiceError::Timeout)
        );

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
    async fn dropped_old_coordinator_releases_before_new_coordinator_runs() {
        let handle = EcuCoordinatorHandle::spawn("TestECU".to_owned());
        let old_guard = handle.begin_detection().await.expect("old guard");
        let queued = {
            let handle = handle.clone();
            tokio::spawn(async move { handle.begin_detection().await })
        };
        tokio::task::yield_now().await;
        assert!(!queued.is_finished());
        // The queued task is parked on the detection lock; awaiting it
        // before dropping the guard would hang.
        drop(old_guard);
        assert!(queued.await.expect("new task").is_some());
    }

    #[tokio::test]
    async fn queued_automatic_detection_is_skipped_after_success() {
        let handle = EcuCoordinatorHandle::spawn("TestECU".to_owned());
        let in_flight = handle.begin_detection().await.expect("first entrant");

        let queued_handle = handle.clone();
        let queued = tokio::spawn(async move {
            claim_detection(
                Some(&queued_handle),
                &[&queued_handle],
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
                &[&queued_handle],
                DetectionTrigger::IfNeeded,
            )
            .await
        });
        tokio::task::yield_now().await;
        drop(in_flight);

        assert!(
            matches!(
                queued.await.expect("queued trigger"),
                DetectionPermit::Run(_)
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
                claim_detection(Some(&handle), &[&handle], DetectionTrigger::Forced).await,
                DetectionPermit::Run(_)
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
                &[&forced_handle],
                DetectionTrigger::Forced,
            )
            .await
        });
        tokio::task::yield_now().await;

        let automatic_handle = handle.clone();
        let automatic = tokio::spawn(async move {
            claim_detection(
                Some(&automatic_handle),
                &[&automatic_handle],
                DetectionTrigger::IfNeeded,
            )
            .await
        });
        tokio::task::yield_now().await;
        drop(in_flight);

        let forced_permit = forced.await.expect("forced trigger");
        assert!(
            matches!(forced_permit, DetectionPermit::Run(_)),
            "explicit detection must not be coalesced"
        );
        drop(forced_permit);

        assert!(
            matches!(
                automatic.await.expect("automatic trigger"),
                DetectionPermit::Run(_)
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

    fn test_manager(
        gateway: TestGateway,
        ecus: HashMap<String, RwLock<TestEcuDb>>,
    ) -> UdsManager<TestGateway, TestEcuDb> {
        build_uds_manager(
            gateway,
            ecus,
            FaultConfig::default(),
            enabled_communication_access_for_test(),
        )
        .manager
    }

    /// Leaves a request unanswered: the sender stays open until the caller
    /// gives up and drops the receiver, so the caller sees a timeout rather
    /// than a closed channel.
    fn unanswered(response_tx: TestGatewayResponseSender) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move { response_tx.closed().await })
    }

    async fn base_variant_selected(
        manager: &UdsManager<TestGateway, TestEcuDb>,
        name: &str,
    ) -> bool {
        let data = manager.ecu_data.read().await;
        data.ecus()
            .get(name)
            .expect("member")
            .read()
            .await
            .base_variant_selected
            .load(Ordering::SeqCst)
    }

    fn probe_reply_gateway(reply: Vec<u8>, send_count: Arc<AtomicUsize>) -> TestGateway {
        TestGateway::new(move |_, response_tx, _| {
            send_count.fetch_add(1, Ordering::SeqCst);
            let msg = TransportResponse::UdsResponse(ServicePayload {
                data: reply.clone(),
                source_address: 0x0001,
                target_address: 0x0E00,
                new_session: None,
                new_security: None,
            });
            response_tx.try_send(Ok(Some(msg))).ok();
            Ok(finished_task())
        })
    }

    async fn detect_schema_less_ecu(
        gateway: TestGateway,
        ecu_db: TestEcuDb,
    ) -> (Result<(), DiagServiceError>, bool) {
        let ecus = HashMap::from_iter([("TestECU".to_owned(), RwLock::new(ecu_db))]);
        let manager = test_manager(gateway, ecus);
        let result = manager.detect_variant("TestECU").await;
        let selected = base_variant_selected(&manager, "TestECU").await;
        (result, selected)
    }

    #[tokio::test]
    async fn detection_without_requests_selects_base_variant_on_probe_response() {
        let send_count = Arc::new(AtomicUsize::new(0));
        let gateway = probe_reply_gateway(vec![0x62, 0xFF, 0x00, 0x01], Arc::clone(&send_count));

        let (result, selected) =
            detect_schema_less_ecu(gateway, TestEcuDb::with_detected_variant()).await;

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

        let (result, selected) =
            detect_schema_less_ecu(gateway, TestEcuDb::with_detected_variant()).await;

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
        let gateway = TestGateway::new(move |_, response_tx, _| {
            gateway_send_count.fetch_add(1, Ordering::SeqCst);
            Ok(unanswered(response_tx))
        });

        let (result, selected) = detect_schema_less_ecu(
            gateway,
            TestEcuDb::with_timeout_default_and_repeat_req_count_app(
                std::time::Duration::from_millis(1),
                0,
            )
            .detected(),
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
        TestGateway::new(move |_, response_tx, _| {
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
                Ok(finished_task())
            } else {
                Ok(unanswered(response_tx))
            }
        })
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
            .detected()
            .with_duplicates(group)
    }

    async fn detect_group(
        gateway: TestGateway,
        members: Vec<(&str, TestEcuDb)>,
        trigger: &str,
    ) -> (
        Result<(), DiagServiceError>,
        UdsManager<TestGateway, TestEcuDb>,
    ) {
        let ecus = members
            .into_iter()
            .map(|(name, db)| (name.to_owned(), RwLock::new(db)))
            .collect();
        let manager = test_manager(gateway, ecus);
        let result = manager.detect_variant(trigger).await;
        (result, manager)
    }

    async fn state_of(manager: &UdsManager<TestGateway, TestEcuDb>, name: &str) -> EcuState {
        let data = manager.ecu_data.read().await;
        data.ecus()
            .get(name)
            .expect("member")
            .read()
            .await
            .ecu_status()
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

        let (result, manager) = detect_group(gateway, members, "B").await;

        assert_eq!(result, Ok(()));
        assert_eq!(
            send_count.load(Ordering::SeqCst),
            1,
            "no probe after exact match"
        );
        assert!(state_of(&manager, "A").await.is_online_and_detected());
        assert_eq!(
            state_of(&manager, "B").await.variant_state,
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

        let (result, manager) = detect_group(gateway, members, "A").await;

        assert_eq!(result, Ok(()));
        assert_eq!(send_count.load(Ordering::SeqCst), 2);
        assert!(state_of(&manager, "A").await.is_online_and_detected());
        assert_eq!(
            state_of(&manager, "B").await.variant_state,
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

        let (result, manager) = detect_group(gateway, members, "A").await;

        assert_eq!(result, Err(DiagServiceError::Timeout));
        for name in ["A", "B"] {
            assert_eq!(
                state_of(&manager, name).await.connectivity,
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
                    .with_detection_outcome(TestEcuDb::with_detected_variant().ecu_status()),
            ),
        ];

        let (result, manager) = detect_group(gateway, members, "A").await;

        assert_eq!(result, Ok(()));
        assert_eq!(send_count.load(Ordering::SeqCst), 2);
        assert_eq!(
            state_of(&manager, "A").await.variant_state,
            VariantState::Duplicate
        );
        assert!(state_of(&manager, "B").await.is_online_and_detected());
    }

    #[tokio::test]
    async fn incomplete_schema_cannot_select_schema_less_duplicate() {
        let send_count = Arc::new(AtomicUsize::new(0));
        let gateway_send_count = Arc::clone(&send_count);
        let gateway = TestGateway::new(move |_, response_tx, _| {
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
                Ok(finished_task())
            } else {
                Err(DiagServiceError::BadPayload(
                    "Invalid detection request".to_owned(),
                ))
            }
        });
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

        let (result, manager) = detect_group(gateway, members, "A").await;

        assert_eq!(
            result,
            Err(DiagServiceError::BadPayload(
                "Invalid detection request".to_owned()
            ))
        );
        assert_eq!(send_count.load(Ordering::SeqCst), 2);
        assert!(!base_variant_selected(&manager, "B").await);
    }

    #[tokio::test]
    async fn schema_less_group_propagates_non_connectivity_probe_error() {
        let gateway = TestGateway::new(|_, _, _| {
            Err(DiagServiceError::BadPayload("Invalid probe".to_owned()))
        });
        let members = vec![
            ("B", schema_less_member(&["C"])),
            ("C", schema_less_member(&["B"])),
        ];

        let (result, manager) = detect_group(gateway, members, "B").await;

        assert_eq!(
            result,
            Err(DiagServiceError::BadPayload("Invalid probe".to_owned()))
        );
        for name in ["B", "C"] {
            assert!(state_of(&manager, name).await.is_online_and_detected());
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

        let (result, manager) = detect_group(gateway, members, "A").await;

        assert_eq!(result, Ok(()));
        assert_eq!(send_count.load(Ordering::SeqCst), 2);
        assert!(base_variant_selected(&manager, "B").await);
        assert_eq!(
            state_of(&manager, "B").await.connectivity,
            Connectivity::Online
        );
        assert_eq!(
            state_of(&manager, "A").await.variant_state,
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

        let (result, manager) = detect_group(gateway, members, "A").await;

        assert_eq!(result, Ok(()));
        assert_eq!(send_count.load(Ordering::SeqCst), 2);
        for name in ["A", "B"] {
            assert_eq!(
                state_of(&manager, name).await.variant_state,
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

        let (result, manager) = detect_group(gateway, members, "B").await;

        assert_eq!(result, Ok(()));
        assert_eq!(send_count.load(Ordering::SeqCst), 1, "group is probed once");
        for name in ["B", "C"] {
            assert!(!base_variant_selected(&manager, name).await);
            assert_eq!(
                state_of(&manager, name).await.variant_state,
                VariantState::NotDetected
            );
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

        let (result, manager) = detect_group(gateway, members, "C").await;

        assert_eq!(result, Ok(()));
        assert_eq!(send_count.load(Ordering::SeqCst), 1);
        for name in ["B", "C"] {
            assert_eq!(
                state_of(&manager, name).await.connectivity,
                Connectivity::Offline,
                "{name} must be marked unreachable"
            );
        }
    }

    #[tokio::test]
    async fn forced_detection_timeout_is_returned_after_sending() {
        let send_count = Arc::new(AtomicUsize::new(0));
        let gateway_send_count = Arc::clone(&send_count);
        let gateway = TestGateway::new(move |_, response_tx, _| {
            gateway_send_count.fetch_add(1, Ordering::SeqCst);
            Ok(unanswered(response_tx))
        });
        let ecus = HashMap::from_iter([(
            "TestECU".to_owned(),
            RwLock::new(TestEcuDb::with_variant_detection_request(
                std::time::Duration::from_millis(1),
            )),
        )]);
        let manager = test_manager(gateway, ecus);

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
                    &[&representative, &duplicate],
                    DetectionTrigger::IfNeeded
                )
                .await,
                DetectionPermit::Run(_)
            ),
            "triggering duplicate still needs detection"
        );
    }

    fn set_detected(handle: &EcuCoordinatorHandle) {
        let mut state = handle.state.ecu_state.write().unwrap();
        state.connectivity = Connectivity::Online;
        state.variant_state = VariantState::Detected {
            name: "MyVariant".to_owned(),
            is_base_variant: false,
            is_fallback: false,
        };
    }

    // Regression: after a reconnect reset a non-representative member to
    // NotTested, an automatic trigger is mapped to the (detected)
    // representative. It must still run, otherwise the member stays stuck.
    #[tokio::test]
    async fn automatic_detection_runs_when_non_representative_member_reset() {
        let representative = EcuCoordinatorHandle::spawn("Representative".to_owned());
        let member = EcuCoordinatorHandle::spawn("Member".to_owned());
        set_detected(&representative);
        {
            let mut state = member.state.ecu_state.write().unwrap();
            state.connectivity = Connectivity::Online;
            state.variant_state = VariantState::NotTested;
        }

        assert!(
            matches!(
                claim_detection(
                    Some(&representative),
                    &[&representative, &member],
                    DetectionTrigger::IfNeeded
                )
                .await,
                DetectionPermit::Run(_)
            ),
            "reset group member must permit automatic detection"
        );
    }

    #[tokio::test]
    async fn automatic_detection_skipped_when_whole_group_resolved() {
        let representative = EcuCoordinatorHandle::spawn("Representative".to_owned());
        let member = EcuCoordinatorHandle::spawn("Member".to_owned());
        set_detected(&representative);
        {
            let mut state = member.state.ecu_state.write().unwrap();
            state.connectivity = Connectivity::Online;
            state.variant_state = VariantState::Duplicate;
        }

        assert!(
            matches!(
                claim_detection(
                    Some(&representative),
                    &[&representative, &member],
                    DetectionTrigger::IfNeeded
                )
                .await,
                DetectionPermit::Skip
            ),
            "resolved group must skip automatic detection"
        );
    }

    fn set_state(handle: &EcuCoordinatorHandle, connectivity: Connectivity, variant: VariantState) {
        let mut state = handle.state.ecu_state.write().unwrap();
        state.connectivity = connectivity;
        state.variant_state = variant;
    }

    // An offline Duplicate member is skipped by the detection gate, so
    // retrying would only burn the retry delays without any effect.
    #[tokio::test]
    async fn offline_duplicate_member_does_not_trigger_retry() {
        let representative = EcuCoordinatorHandle::spawn("Representative".to_owned());
        let member = EcuCoordinatorHandle::spawn("Member".to_owned());
        set_detected(&representative);
        set_state(&member, Connectivity::Offline, VariantState::Duplicate);

        assert!(
            !needs_offline_retry(&[&representative, &member]),
            "offline duplicate must not trigger a retry"
        );
        assert!(
            matches!(
                claim_detection(
                    Some(&representative),
                    &[&representative, &member],
                    DetectionTrigger::IfNeeded
                )
                .await,
                DetectionPermit::Skip
            ),
            "retry decision must agree with the detection gate"
        );
    }

    #[tokio::test]
    async fn offline_member_needing_detection_triggers_retry() {
        let representative = EcuCoordinatorHandle::spawn("Representative".to_owned());
        let member = EcuCoordinatorHandle::spawn("Member".to_owned());
        set_detected(&representative);
        set_state(
            &member,
            Connectivity::Offline,
            VariantState::Detected {
                name: "MyVariant".to_owned(),
                is_base_variant: false,
                is_fallback: false,
            },
        );

        assert!(
            needs_offline_retry(&[&representative, &member]),
            "offline member with known variant must trigger a retry"
        );
    }

    #[tokio::test]
    async fn online_group_does_not_trigger_retry() {
        let representative = EcuCoordinatorHandle::spawn("Representative".to_owned());
        let member = EcuCoordinatorHandle::spawn("Member".to_owned());
        set_detected(&representative);
        set_state(&member, Connectivity::Online, VariantState::NotTested);

        assert!(
            !needs_offline_retry(&[&representative, &member]),
            "online members must not trigger an offline retry"
        );
    }
}
