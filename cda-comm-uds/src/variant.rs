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
    HashMap, HashMapExtensions, PayloadDecoder, UdsVariant, VariantState,
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
/// group contends for the same lock. `state_handle` is this ECU's own, read
/// only to decide whether the trigger is still worth acting on.
///
/// Contention skips rather than waits: the detection already running for the
/// group publishes a verdict for every member, so queueing behind it would buy
/// nothing but a redundant second pass.
///
/// The `IfNeeded` re-check deliberately happens *after* the lock is held. The
/// detection this call waited for may have just concluded and made the trigger
/// obsolete; checking before acquiring would miss that and detect again.
///
/// A missing `lock_handle` skips. It is unreachable in production -
/// `assemble_vehicle_data_source` builds the coordinator's handles from the
/// same database map that becomes the ECU data, so every ECU that resolves has
/// a handle - and skipping is the safe reading should that ever stop holding:
/// no detection beats two unsynchronised ones writing the same group's state.
async fn claim_detection(
    lock_handle: Option<&EcuCoordinatorHandle>,
    state_handle: Option<&EcuCoordinatorHandle>,
    trigger: DetectionTrigger,
) -> DetectionPermit {
    let Some(lock_handle) = lock_handle else {
        return DetectionPermit::Skip;
    };
    let Some(guard) = lock_handle.begin_detection().await else {
        return DetectionPermit::Skip;
    };
    if matches!(trigger, DetectionTrigger::IfNeeded)
        && state_handle.is_some_and(|handle| !needs_variant_detection(&handle.ecu_status()))
    {
        return DetectionPermit::Skip;
    }
    DetectionPermit::Run(guard)
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

        let service_responses = self.gather_detection_responses(&ecu).await?;
        if service_responses.is_empty() {
            return self.mark_group_unreachable(&ecu).await;
        }

        let ecu_read = ecu.read().await;
        let duplicated_ecus = ecu_read
            .duplicating_ecu_names()
            .cloned()
            .filter(|d| !d.is_empty());
        // Both paths below take the write guard on this same lock.
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
                    let offline =
                        data.state_coordinator()
                            .get_handle(&ecu_name)
                            .is_some_and(|handle| {
                                handle.connectivity() == cda_interfaces::Connectivity::Offline
                            });
                    // Release the snapshot before the retry delay, so a runtime
                    // update is not blocked while this task sleeps.
                    drop(data);
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
            // Offline ECUs deliberately use the same coordinated per-ECU path as
            // reachable ECUs; an empty response set then produces the common offline verdict.
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

    /// Sends the ECU's variant-detection requests and returns the responses that arrived.
    /// Detection sends leave timeout reachability mutation to the aggregate result, and gathering
    /// stops at the first send failure (no need to continue if one fails).
    ///
    /// Disconnect events are suppressed while the requests are in flight. Without that a
    /// detection timeout publishes a disconnect, which re-triggers variant detection, which
    /// times out again - a loop.
    async fn gather_detection_responses(
        &self,
        ecu: &ResolvedEcu<'_, T>,
    ) -> Result<HashMap<String, <T as PayloadDecoder>::Response>, DiagServiceError> {
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
        let coordinator = ecu.data().state_coordinator();
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
        self.restart_tester_present_snapshot().await;
        Ok(())
    }

    async fn deinitialize(&self) {
        self.stop_variant_detection_listener(ReceiverRetention::Keep)
            .await;
        self.snapshot_and_abort_tester_present().await;
        self.abort_reset_tasks().await;
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
        Connectivity, EcuManager, HashMap, UdsVariant, VariantDetection, VariantState,
        communication_control::CommunicationLifecycle,
    };
    use cda_plugin_communication_management::lifecycle::enabled_communication_access_for_test;
    use tokio::sync::RwLock;

    use super::{DetectionPermit, DetectionTrigger, claim_detection};
    use crate::{
        UdsManager,
        coordinator::EcuCoordinatorHandle,
        test_helpers::{TestEcuDb, TestGateway, build_uds_manager},
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
                TestEcuDb::for_detection_with_identity("DuplicateECU", 0x0002)
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
        // The queued task is parked on the detection lock; awaiting it
        // before dropping the guard would hang.
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
        // The queued task is parked on the detection lock; awaiting it
        // before dropping the guard would hang.
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
                claim_detection(Some(&handle), Some(&handle), DetectionTrigger::Forced,).await,
                DetectionPermit::Run(_)
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
        // The queued task is parked on the detection lock; awaiting it
        // before dropping the guard would hang.
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
                    DetectionTrigger::IfNeeded
                )
                .await,
                DetectionPermit::Run(_)
            ),
            "triggering duplicate still needs detection"
        );
    }
}
