/*
 * SPDX-FileCopyrightText: 2025 Copyright (c) Contributors to the Eclipse Foundation
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

use std::{option::Option, sync::Arc, time::SystemTime};

use cda_interfaces::lock_priority_api::{
    LockPrincipal, LockPriorityDecision, LockPriorityError, LockPriorityEvaluation,
    LockPriorityOperation, LockPriorityPolicy, LockRequest, LockScope, LockSnapshot,
};
use cda_plugin_security::Claims;
use futures::FutureExt;
use uuid::Uuid;

use super::{
    ActiveLock, ApiError, LockCoverage, Locks, ScopeKey, scope_from_key, validated_expiration,
};

pub(crate) struct PendingPreemption {
    pub(super) evaluation_id: String,
    pub(super) policy: Arc<dyn LockPriorityPolicy>,
    pub(super) root_lock_ids: Vec<String>,
    pub(super) broken_by: String,
    pub(super) broken_at: SystemTime,
    armed: bool,
}
pub(crate) struct AcquisitionGuard {
    pub(super) reservation: super::TransitionReservation,
    pub(super) evaluation_id: Option<String>,
    pub(super) policy: Arc<dyn LockPriorityPolicy>,
}

impl AcquisitionGuard {
    pub(crate) fn transition_id(&self) -> super::TransitionId {
        self.reservation.id()
    }

    pub(crate) async fn finish(self) {
        self.reservation.finish().await;
    }
}

impl PendingPreemption {
    pub(super) fn rollback(mut self) {
        tracing::warn!(evaluation_id = %self.evaluation_id, "Lock acquisition failed after preemption was approved");
        self.armed = false;
    }

    pub(super) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PendingPreemption {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        tracing::warn!(evaluation_id = %self.evaluation_id, "Preemption transaction was abandoned");
        self.armed = false;
    }
}

pub(crate) async fn rollback_preemption(pending: Option<PendingPreemption>, _locks: &Locks) {
    if let Some(pending) = pending {
        pending.rollback();
    }
}

impl Locks {
    #[allow(
        clippy::too_many_lines,
        reason = "Snapshot capture, external policy evaluation, stale-state detection, and retry \
                  must remain one visible transaction. Splitting them would obscure the \
                  consistency checks between phases"
    )]
    pub(crate) async fn evaluate_acquisition(
        &self,
        scope: LockScope,
        coverage: LockCoverage,
        request: &sovd_interfaces::locking::Request,
        claims: &impl Claims,
    ) -> Result<(AcquisitionGuard, Option<PendingPreemption>, LockRequest), ApiError> {
        self.ensure_lifecycle_worker().await;
        // The lock priority/preemption mechanism is applicable to vehicle locks only
        // (see req~sovd-api-lock-priority). ECU and functional-group lock acquisition
        // never invokes the plugin and can never be preemption candidates.
        let is_vehicle_scope = matches!(scope, LockScope::Vehicle);
        let policy = Arc::clone(&self.priority_policy);
        let validated = validated_expiration(request)?;
        let coverage = if is_vehicle_scope {
            LockCoverage::vehicle()
        } else {
            coverage
        };
        let policy_request = LockRequest {
            scope: scope.clone(),
            principal: LockPrincipal {
                subject: claims.sub().to_owned(),
                claims: claims.attributes(),
            },
            expires_at: validated.expires_at,
            break_lock: request.break_lock,
            exclusive: self
                .config
                .resolve_exclusivity(validated.requested_exclusive),
            metadata: validated.metadata,
        };
        if !is_vehicle_scope {
            let reservation = self.reserve_transition().await;
            return Ok((
                AcquisitionGuard {
                    reservation,
                    evaluation_id: None,
                    policy,
                },
                None,
                policy_request,
            ));
        }
        let evaluation_id = Uuid::new_v4().to_string();
        let mut stale_attempts = 0;
        loop {
            let (revision, generation, active_locks, candidates, operation) = {
                let store = self.lock_idle().await;
                let state = &store.state;
                let mut active_locks = state.active().map(active_snapshot).collect::<Vec<_>>();
                active_locks.sort_by(|left, right| {
                    scope_sort_key(&left.scope)
                        .cmp(&scope_sort_key(&right.scope))
                        .then_with(|| left.id.cmp(&right.id))
                });
                let candidates = state
                    .active()
                    .filter(|lock| {
                        lock.parent_vehicle.is_none()
                            && lock.principal.subject != policy_request.principal.subject
                            && (lock.scope == ScopeKey::Vehicle
                                || lock.coverage.overlaps(&coverage))
                    })
                    .map(|lock| lock.id.clone())
                    .collect::<Vec<_>>();
                let operation = state
                    .active_for_scope(&ScopeKey::from(&scope))
                    .filter(|lock| lock.principal.subject == policy_request.principal.subject)
                    .map_or(LockPriorityOperation::Acquire, |lock| {
                        LockPriorityOperation::PostRenew {
                            lock_id: lock.id.clone(),
                        }
                    });
                (
                    state.revision(),
                    store.generation,
                    active_locks,
                    candidates,
                    operation,
                )
            };
            if candidates.is_empty() {
                let reservation = self.reserve_transition().await;
                let store = self.store.lock().await;
                if store.state.revision() == revision && store.generation == generation {
                    drop(store);
                    return Ok((
                        AcquisitionGuard {
                            reservation,
                            evaluation_id: None,
                            policy,
                        },
                        None,
                        policy_request,
                    ));
                }
                drop(store);
                reservation.finish().await;
                continue;
            }
            let evaluation = LockPriorityEvaluation {
                evaluation_id: evaluation_id.clone(),
                operation,
                request: policy_request.clone(),
                revision,
                captured_at: SystemTime::now(),
                active_locks,
                preemption_candidates: candidates.clone(),
            };
            let timeout = std::time::Duration::from_millis(self.config.priority_policy_timeout_ms);
            let decision = tokio::time::timeout(
                timeout,
                std::panic::AssertUnwindSafe(async { policy.evaluate(&evaluation).await })
                    .catch_unwind(),
            )
            .await
            .map_err(|_| ApiError::ServiceUnavailable {
                message: "Lock priority policy timed out".to_owned(),
                retry_after: None,
                error_code: sovd_interfaces::error::ErrorCode::SovdServerFailure,
                vendor_code: None,
            })?
            .map_err(|_| {
                tracing::error!(evaluation_id, "Lock priority policy panicked");
                ApiError::InternalServerError(Some("Lock priority policy panicked".to_owned()))
            })?
            .map_err(map_policy_error)?;

            let reservation = self.reserve_transition().await;
            let store = self.store.lock().await;
            if store.state.revision() != revision || store.generation != generation {
                drop(store);
                reservation.finish().await;
                if stale_attempts < self.config.priority_policy_stale_retries {
                    stale_attempts = stale_attempts.saturating_add(1);
                    continue;
                }
                return Err(ApiError::Conflict(
                    "Lock state changed during priority evaluation".to_owned(),
                ));
            }
            drop(store);
            let guard = AcquisitionGuard {
                reservation,
                evaluation_id: Some(evaluation_id.clone()),
                policy: Arc::clone(&policy),
            };
            let result = self
                .apply_priority_decision(
                    decision,
                    request,
                    &candidates,
                    revision,
                    guard,
                    &evaluation_id,
                )
                .await;
            let (guard, pending) = result?;
            return Ok((guard, pending, policy_request));
        }
    }

    async fn apply_priority_decision(
        &self,
        decision: LockPriorityDecision,
        request: &sovd_interfaces::locking::Request,
        candidates: &[String],
        revision: u64,
        guard: AcquisitionGuard,
        evaluation_id: &str,
    ) -> Result<(AcquisitionGuard, Option<PendingPreemption>), ApiError> {
        match decision {
            LockPriorityDecision::Allow => Ok((guard, None)),
            LockPriorityDecision::Deny { reason, parameters } => {
                Err(ApiError::LockPriorityDenied {
                    message: reason,
                    parameters: parameters.into_iter().collect(),
                })
            }
            LockPriorityDecision::Preempt {
                lock_ids,
                broken_by,
            } => {
                self.stage_preemption(
                    request,
                    candidates,
                    revision,
                    guard,
                    evaluation_id,
                    (lock_ids, broken_by),
                )
                .await
            }
        }
    }

    async fn stage_preemption(
        &self,
        request: &sovd_interfaces::locking::Request,
        candidates: &[String],
        revision: u64,
        guard: AcquisitionGuard,
        evaluation_id: &str,
        selection: (Vec<String>, String),
    ) -> Result<(AcquisitionGuard, Option<PendingPreemption>), ApiError> {
        let (lock_ids, broken_by) = selection;
        if let Err(error) =
            Self::validate_preemption_selection(request.break_lock, &lock_ids, candidates)
        {
            drop(guard);
            tracing::warn!(evaluation_id, "Policy selected an invalid preemption set");
            return Err(error);
        }
        let root_lock_ids = {
            let store = self.store.lock().await;
            let state = &store.state;
            if state.revision() != revision {
                drop(store);
                drop(guard);
                tracing::warn!(
                    evaluation_id,
                    "Lock state changed before preemption staging"
                );
                return Err(ApiError::Conflict(
                    "Lock state changed during priority evaluation".to_owned(),
                ));
            }
            let selected_ids: std::collections::HashSet<&str> =
                lock_ids.iter().map(String::as_str).collect();
            let root_lock_ids: Vec<String> = lock_ids
                .iter()
                .filter(|id| {
                    state
                        .active_by_id(id)
                        .and_then(|lock| lock.parent_vehicle.as_deref())
                        .is_none_or(|parent| !selected_ids.contains(parent))
                })
                .cloned()
                .collect();
            root_lock_ids
        };
        let pending = PendingPreemption {
            evaluation_id: evaluation_id.to_owned(),
            policy: Arc::clone(&guard.policy),
            root_lock_ids,
            broken_by,
            broken_at: SystemTime::now(),
            armed: true,
        };
        Ok((guard, Some(pending)))
    }

    pub(super) fn validate_preemption_selection(
        break_lock: bool,
        lock_ids: &[String],
        candidates: &[String],
    ) -> Result<(), ApiError> {
        if !break_lock {
            return Err(ApiError::Locked(
                "Lock preemption requires break_lock=true".to_owned(),
            ));
        }
        if lock_ids.is_empty() {
            return Err(ApiError::Locked(
                "Lock policy selected no locks to preempt".to_owned(),
            ));
        }
        let candidate_ids: std::collections::HashSet<&str> =
            candidates.iter().map(String::as_str).collect();
        let selected_ids: std::collections::HashSet<&str> =
            lock_ids.iter().map(String::as_str).collect();
        if selected_ids.len() != lock_ids.len() {
            return Err(ApiError::Locked(
                "Lock policy selected a lock more than once".to_owned(),
            ));
        }
        if lock_ids
            .iter()
            .any(|id| !candidate_ids.contains(id.as_str()))
        {
            return Err(ApiError::Locked(
                "Lock policy selected an invalid preemption candidate".to_owned(),
            ));
        }
        Ok(())
    }
}
fn map_policy_error(error: LockPriorityError) -> ApiError {
    match error {
        LockPriorityError::InvalidContext(message) => ApiError::BadRequest(message),
        LockPriorityError::Unavailable(message) => ApiError::ServiceUnavailable {
            message,
            retry_after: None,
            error_code: sovd_interfaces::error::ErrorCode::SovdServerFailure,
            vendor_code: None,
        },
        LockPriorityError::Internal(message) => ApiError::InternalServerError(Some(message)),
    }
}

pub(super) fn scope_sort_key(scope: &LockScope) -> (u8, &str) {
    match scope {
        LockScope::Vehicle => (0, ""),
        LockScope::Ecu { name } => (1, name),
        LockScope::FunctionalGroup { name } => (2, name),
    }
}

pub(super) fn active_snapshot(lock: &ActiveLock) -> LockSnapshot {
    LockSnapshot {
        id: lock.id.clone(),
        scope: scope_from_key(&lock.scope),
        principal: lock.principal.clone(),
        metadata: lock.metadata.clone(),
        exclusive: lock.exclusive,
        parent_vehicle_lock_id: lock.parent_vehicle.clone(),
        expires_at: lock.expires_at,
    }
}
