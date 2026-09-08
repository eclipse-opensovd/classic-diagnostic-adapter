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

use std::{fmt, option::Option, sync::Arc};

use cda_interfaces::{
    HashMap, HashMapExtensions,
    lock_config::LockConfig,
    lock_priority_api::{LockPriorityPolicy, LockScope},
};
use cda_plugin_security::Claims;
use chrono::{DateTime, SecondsFormat, Utc};
use tokio::sync::{Mutex, Notify, mpsc, oneshot};

use crate::{
    openapi,
    sovd::{
        error::{ApiError, ErrorWrapper},
        lock_state::{ActiveLock, DefunctLock, LockCoverage, LockState, ScopeKey, StateError},
    },
};

mod acquisition;
mod cleanup;
mod handlers;
mod lifecycle;
mod policy;
#[cfg(test)]
mod tests;
mod validation;

use acquisition::create_lock;
use cleanup::LockCleanupFnHelper;
use handlers::common::validated_expiration;
pub(crate) use handlers::{
    common::{
        LockContext, LockUpdateContext, delete_handler, get_handler, get_id_handler, post_handler,
        put_handler,
    },
    ecu, vehicle,
};
use lifecycle::{LifecycleDelivery, enqueue_lock_event};
pub(crate) use policy::rollback_preemption;
use policy::{AcquisitionGuard, PendingPreemption, active_snapshot};
#[cfg(test)]
pub(crate) use tests::{insert_test_ecu_lock, insert_test_fg_lock};
use validation::{validate_claim, validate_vehicle_children};
pub(crate) use validation::{
    validate_ecu_read, validate_ecu_write, validate_fg_read, validate_fg_write,
    validate_vehicle_owner,
};

#[derive(Debug, thiserror::Error)]
pub enum LockUpdateError {
    #[error("Cannot update while ECU locks are held")]
    EcuLocksHeld,
    #[error("Cannot update while functional-group locks are held")]
    FunctionalGroupLocksHeld,
}

type TransitionId = u64;

pub(super) struct TransitionReservation {
    id: TransitionId,
    finish: Option<oneshot::Sender<oneshot::Sender<()>>>,
}

impl TransitionReservation {
    pub(super) fn id(&self) -> TransitionId {
        self.id
    }

    pub(super) async fn finish(mut self) {
        let Some(finish) = self.finish.take() else {
            return;
        };
        let (acknowledge, acknowledged) = oneshot::channel();
        if finish.send(acknowledge).is_ok() {
            let _ = acknowledged.await;
        }
    }
}

pub(super) struct LockStore {
    state: LockState,
    cleanups: HashMap<String, LockCleanupFnHelper>,
    generation: u64,
    transition: Option<TransitionId>,
    next_transition_id: TransitionId,
}

pub struct Locks {
    store: Arc<Mutex<LockStore>>,
    transition_changed: Arc<Notify>,
    priority_policy: Arc<dyn LockPriorityPolicy>,
    lifecycle_sender: mpsc::Sender<LifecycleDelivery>,
    lifecycle_receiver: Mutex<Option<mpsc::Receiver<LifecycleDelivery>>>,
    config: LockConfig,
}

impl Default for Locks {
    fn default() -> Self {
        Self::new()
    }
}

impl Locks {
    /// Creates lock storage with default policy configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::new_with_config(LockConfig::default())
    }

    /// Creates lock storage with configured policy defaults and safety limits.
    #[must_use]
    pub fn new_with_config(config: LockConfig) -> Self {
        Self::new_with_config_and_policy(
            config,
            Arc::new(cda_plugin_lock_priority::NoPreemptionPolicy),
        )
    }

    /// Creates lock storage using a fixed lock-priority policy.
    #[must_use]
    pub fn new_with_policy(policy: Arc<dyn LockPriorityPolicy>) -> Self {
        Self::new_with_config_and_policy(LockConfig::default(), policy)
    }

    /// Creates lock storage with configuration and a fixed lock-priority policy.
    #[must_use]
    pub fn new_with_config_and_policy(
        config: LockConfig,
        policy: Arc<dyn LockPriorityPolicy>,
    ) -> Self {
        let (lifecycle_sender, lifecycle_receiver) =
            mpsc::channel(config.priority_lifecycle_queue_capacity.max(1));
        Self {
            store: Arc::new(Mutex::new(LockStore {
                state: LockState::default(),
                cleanups: HashMap::new(),
                generation: 0,
                transition: None,
                next_transition_id: 0,
            })),
            transition_changed: Arc::new(Notify::new()),
            priority_policy: policy,
            lifecycle_sender,
            lifecycle_receiver: Mutex::new(Some(lifecycle_receiver)),
            config,
        }
    }

    async fn current_holder(&self, lock: &DefunctLock) -> String {
        self.store
            .lock()
            .await
            .state
            .current_holder(lock)
            .to_owned()
    }

    async fn defunct_by_id(&self, lock_id: &str, scope: &LockScope) -> Option<DefunctLock> {
        let store = self.store.lock().await;
        store
            .state
            .defunct_by_id(lock_id)
            .filter(|lock| lock.scope == ScopeKey::from(scope))
            .cloned()
    }

    async fn delete_defunct(
        &self,
        lock_id: &str,
        scope: &LockScope,
        claims: &impl Claims,
    ) -> Result<bool, ApiError> {
        let mut store = self.store.lock().await;
        let state = &mut store.state;
        let Some(lock) = state.defunct_by_id(lock_id) else {
            return Ok(false);
        };
        if lock.scope != ScopeKey::from(scope) {
            return Ok(false);
        }
        if lock.principal.subject != claims.sub() {
            return Err(ApiError::Forbidden(Some(
                "lock validation failed".to_owned(),
            )));
        }
        state
            .acknowledge_defunct(lock_id)
            .map_err(|error| map_state_error(&error))?;
        Ok(true)
    }

    /// Prepares lock state for a runtime configuration update.
    ///
    /// # Errors
    /// Returns an error if any ECU or functional-group lock is currently held.
    pub async fn prepare_runtime_update(&self) -> Result<(), LockUpdateError> {
        let mut store = self.lock_idle().await;
        if store
            .state
            .active()
            .any(|lock| matches!(lock.scope, ScopeKey::FunctionalGroup(_)))
        {
            return Err(LockUpdateError::FunctionalGroupLocksHeld);
        }
        if store
            .state
            .active()
            .any(|lock| matches!(lock.scope, ScopeKey::Ecu(_)))
        {
            return Err(LockUpdateError::EcuLocksHeld);
        }
        store.generation = store.generation.saturating_add(1);
        Ok(())
    }

    pub(crate) async fn vehicle_lock_owner_sub(&self) -> Option<String> {
        self.store
            .lock()
            .await
            .state
            .active_for_scope(&ScopeKey::Vehicle)
            .map(|lock| lock.principal.subject.clone())
    }

    pub(crate) async fn has_non_vehicle_locks(&self) -> bool {
        self.lock_idle()
            .await
            .state
            .active()
            .any(|lock| lock.scope != ScopeKey::Vehicle)
    }

    async fn active_for_scope(&self, scope: &LockScope) -> Option<ActiveLock> {
        self.store
            .lock()
            .await
            .state
            .active_for_scope(&ScopeKey::from(scope))
            .cloned()
    }

    pub(crate) async fn open_locks(&self) -> Vec<ActiveLock> {
        self.store.lock().await.state.active().cloned().collect()
    }

    async fn reserve_transition(&self) -> TransitionReservation {
        loop {
            let notified = self.transition_changed.notified();
            let mut store = self.store.lock().await;
            if store.transition.is_none() {
                store.next_transition_id = store.next_transition_id.saturating_add(1);
                let id = store.next_transition_id;
                store.transition = Some(id);
                drop(store);
                let (finish, finished) = oneshot::channel::<oneshot::Sender<()>>();
                let store = Arc::clone(&self.store);
                let changed = Arc::clone(&self.transition_changed);
                tokio::spawn(async move {
                    let acknowledge = finished.await.ok();
                    let mut store = store.lock().await;
                    if store.transition == Some(id) {
                        store.transition = None;
                        drop(store);
                        changed.notify_waiters();
                    }
                    if let Some(acknowledge) = acknowledge {
                        let _ = acknowledge.send(());
                    }
                });
                return TransitionReservation {
                    id,
                    finish: Some(finish),
                };
            }
            drop(store);
            notified.await;
        }
    }

    async fn lock_idle(&self) -> tokio::sync::MutexGuard<'_, LockStore> {
        loop {
            let notified = self.transition_changed.notified();
            let store = self.store.lock().await;
            if store.transition.is_none() {
                return store;
            }
            drop(store);
            notified.await;
        }
    }
}

fn map_state_error(error: &StateError) -> ApiError {
    ApiError::InternalServerError(Some(error.to_string()))
}

fn scope_from_key(scope: &ScopeKey) -> LockScope {
    match scope {
        ScopeKey::Vehicle => LockScope::Vehicle,
        ScopeKey::Ecu(name) => LockScope::Ecu { name: name.clone() },
        ScopeKey::FunctionalGroup(name) => LockScope::FunctionalGroup { name: name.clone() },
    }
}

impl DefunctLock {
    fn to_sovd_lock(&self, claims: &impl Claims) -> sovd_interfaces::locking::Lock {
        sovd_interfaces::locking::Lock {
            id: self.id.clone(),
            lock_expiration: Some(
                DateTime::<Utc>::from(self.original_expires_at)
                    .to_rfc3339_opts(SecondsFormat::Secs, true),
            ),
            owned: Some(self.principal.subject == claims.sub()),
            x_sovd2uds_broken_by: Some(self.broken_by.clone()),
            x_sovd2uds_broken_at: Some(
                DateTime::<Utc>::from(self.broken_at).to_rfc3339_opts(SecondsFormat::Secs, true),
            ),
            x_sovd2uds_current_holder: None,
            schema: None,
        }
    }

    fn details(&self) -> sovd_interfaces::locking::id::get::Response {
        sovd_interfaces::locking::id::get::Response {
            lock_expiration: DateTime::<Utc>::from(self.original_expires_at)
                .to_rfc3339_opts(SecondsFormat::Secs, true),
            x_sovd2uds_broken_by: Some(self.broken_by.clone()),
            x_sovd2uds_broken_at: Some(
                DateTime::<Utc>::from(self.broken_at).to_rfc3339_opts(SecondsFormat::Secs, true),
            ),
            x_sovd2uds_current_holder: None,
            schema: None,
        }
    }

    fn broken_error(&self, current_holder: &str) -> ApiError {
        let mut parameters = HashMap::new();
        parameters.insert(
            "broken_by".to_owned(),
            serde_json::Value::String(self.broken_by.clone()),
        );
        parameters.insert(
            "broken_at".to_owned(),
            serde_json::Value::String(
                DateTime::<Utc>::from(self.broken_at).to_rfc3339_opts(SecondsFormat::Secs, true),
            ),
        );
        parameters.insert(
            "current_holder".to_owned(),
            serde_json::Value::String(current_holder.to_owned()),
        );
        ApiError::LockBroken {
            message: "Client lock was broken".to_owned(),
            parameters,
        }
    }
}

#[derive(Clone, Copy)]
pub enum LockTarget {
    Vehicle,
    Ecu,
    FunctionalGroup,
}

impl fmt::Display for LockTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        let type_name = match self {
            Self::Vehicle => "Vehicle",
            Self::Ecu => "ECU",
            Self::FunctionalGroup => "FunctionalGroup",
        };
        write!(formatter, "{type_name}")
    }
}

openapi::aide_helper::gen_path_param!(LockPathParam lock String);
