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

use std::{option::Option, sync::Arc};

use cda_interfaces::{
    HashMap, HashMapExtensions,
    lock_config::LockConfig,
    lock_priority_api::{LockId, LockPriorityPolicy, LockScope},
};
use cda_plugin_security::Claims;
use chrono::{DateTime, SecondsFormat, Utc};
use tokio::sync::{Mutex, mpsc};

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

macro_rules! require_ecu_access {
    (read, $plugin:expr, $ecu_name:expr, $locks:expr, $include_schema:expr $(,)?) => {
        if let Err(response) = $crate::sovd::locks::validate_ecu_read(
            &$plugin.as_auth_plugin().claims(),
            $ecu_name,
            $locks,
            $include_schema,
        )
        .await
        {
            return ::axum::response::IntoResponse::into_response(response);
        }
    };
    (write, $plugin:expr, $ecu_name:expr, $locks:expr, $include_schema:expr $(,)?) => {
        if let Err(response) = $crate::sovd::locks::validate_ecu_write(
            &$plugin.as_auth_plugin().claims(),
            $ecu_name,
            $locks,
            $include_schema,
        )
        .await
        {
            return ::axum::response::IntoResponse::into_response(response);
        }
    };
}
pub(crate) use require_ecu_access;

#[derive(Debug, thiserror::Error)]
pub enum LockUpdateError {
    #[error("Cannot update while ECU locks are held")]
    EcuLocksHeld,
    #[error("Cannot update while functional-group locks are held")]
    FunctionalGroupLocksHeld,
}

pub(super) struct LockStore {
    state: LockState,
    cleanups: HashMap<LockId, LockCleanupFnHelper>,
    generation: u64,
}

mod lock_core {
    use std::sync::Arc;

    use tokio::sync::{Mutex, OwnedMutexGuard, RwLock, RwLockWriteGuard};

    use super::LockStore;

    /// Coordinates concurrent reads with serialized lock-state transitions.
    ///
    /// Reads may run while a transition performs asynchronous work, but writes
    /// require a [`TransitionReservation`] issued by the same core.
    #[derive(Clone)]
    pub(super) struct LockCore {
        store: Arc<RwLock<LockStore>>,
        transition_gate: Arc<Mutex<()>>,
    }

    impl LockCore {
        pub(super) fn new(store: LockStore) -> Self {
            Self {
                store: Arc::new(RwLock::new(store)),
                transition_gate: Arc::new(Mutex::new(())),
            }
        }

        pub(super) async fn reserve_transition(&self) -> TransitionReservation {
            TransitionReservation {
                store: Arc::clone(&self.store),
                _gate: Arc::clone(&self.transition_gate).lock_owned().await,
            }
        }

        pub(super) async fn read_store<T>(&self, read: impl FnOnce(&LockStore) -> T) -> T {
            let store = self.store.read().await;
            read(&store)
        }
    }

    pub(super) struct TransitionReservation {
        store: Arc<RwLock<LockStore>>,
        _gate: OwnedMutexGuard<()>,
    }

    impl TransitionReservation {
        pub(super) async fn write_store(&self) -> RwLockWriteGuard<'_, LockStore> {
            self.store.write().await
        }

        pub(super) fn finish(self) {
            drop(self);
        }
    }
}

use lock_core::{LockCore, TransitionReservation};

/// Lock transitions held back from a successful
/// [`Locks::reserve_runtime_update`] until it is dropped.
pub(crate) struct RuntimeUpdateReservation {
    _transitions: TransitionReservation,
}

pub struct Locks {
    core: LockCore,
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
            core: LockCore::new(LockStore {
                state: LockState::default(),
                cleanups: HashMap::new(),
                generation: 0,
            }),
            priority_policy: policy,
            lifecycle_sender,
            lifecycle_receiver: Mutex::new(Some(lifecycle_receiver)),
            config,
        }
    }

    async fn current_holder(&self, lock: &DefunctLock) -> String {
        self.core
            .read_store(|store| store.state.current_holder(lock).to_owned())
            .await
    }

    async fn defunct_by_id(&self, lock_id: &str, scope: &LockScope) -> Option<DefunctLock> {
        self.core
            .read_store(|store| {
                store
                    .state
                    .defunct_by_id(lock_id)
                    .filter(|lock| lock.scope == ScopeKey::from(scope))
                    .cloned()
            })
            .await
    }

    async fn delete_defunct(
        lock_id: &str,
        scope: &LockScope,
        claims: &impl Claims,
        reservation: &TransitionReservation,
    ) -> Result<bool, ApiError> {
        let mut store = reservation.write_store().await;
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
        self.reserve_runtime_update().await.map(drop)
    }

    /// Prepares lock state for a runtime configuration update and holds every
    /// lock transition back until the returned reservation is dropped.
    ///
    /// The check alone only holds for the instant it runs: a lock taken
    /// between it and the update it admits would be validated as absent and
    /// then outlive the databases it was taken against.
    ///
    /// # Errors
    /// Returns an error if any ECU or functional-group lock is currently held.
    pub(crate) async fn reserve_runtime_update(
        &self,
    ) -> Result<RuntimeUpdateReservation, LockUpdateError> {
        let reservation = self.core.reserve_transition().await;
        {
            let mut store = reservation.write_store().await;
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
        }
        Ok(RuntimeUpdateReservation {
            _transitions: reservation,
        })
    }

    pub(crate) async fn vehicle_lock_owner_sub(&self) -> Option<String> {
        self.core
            .read_store(|store| {
                store
                    .state
                    .active_for_scope(&ScopeKey::Vehicle)
                    .map(|lock| lock.principal.subject.clone())
            })
            .await
    }

    pub(crate) async fn has_non_vehicle_locks(&self) -> bool {
        self.core
            .read_store(|store| {
                store
                    .state
                    .active()
                    .any(|lock| lock.scope != ScopeKey::Vehicle)
            })
            .await
    }

    async fn active_for_scope(&self, scope: &LockScope) -> Option<ActiveLock> {
        self.core
            .read_store(|store| {
                store
                    .state
                    .active_for_scope(&ScopeKey::from(scope))
                    .cloned()
            })
            .await
    }

    pub(crate) async fn open_locks(&self) -> Vec<ActiveLock> {
        self.core
            .read_store(|store| store.state.active().cloned().collect())
            .await
    }
}

fn map_state_error(error: &StateError) -> ApiError {
    match error {
        StateError::RenewalNotExtension => ApiError::BadRequest(error.to_string()),
        StateError::LockExpired
        | StateError::DuplicateScope
        | StateError::ReplacementScopeConflict
        | StateError::CoverageConflict(_) => ApiError::Conflict(error.to_string()),
        StateError::DuplicateId(_)
        | StateError::ActiveLockNotFound(_)
        | StateError::ParentNotFound(_)
        | StateError::ParentNotVehicle(_)
        | StateError::RevisionOverflow
        | StateError::Invariant(_) => ApiError::InternalServerError(Some(error.to_string())),
    }
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
            id: self.id.to_string(),
            lock_expiration: Some(
                DateTime::<Utc>::from(self.original_expires_at)
                    .to_rfc3339_opts(SecondsFormat::Secs, true),
            ),
            owned: self.principal.subject == claims.sub(),
            x_sovd2uds_isexclusive: self.exclusive,
            x_sovd2uds_broken_by: Some(self.broken_by.clone()),
            x_sovd2uds_broken_at: Some(
                DateTime::<Utc>::from(self.broken_at).to_rfc3339_opts(SecondsFormat::Secs, true),
            ),
            x_sovd2uds_current_holder: None,
            schema: None,
        }
    }

    fn details(&self, claims: &impl Claims) -> sovd_interfaces::locking::id::get::Response {
        sovd_interfaces::locking::id::get::Response {
            lock_expiration: DateTime::<Utc>::from(self.original_expires_at)
                .to_rfc3339_opts(SecondsFormat::Secs, true),
            owned: self.principal.subject == claims.sub(),
            x_sovd2uds_isexclusive: self.exclusive,
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

openapi::aide_helper::gen_path_param!(LockPathParam lock String);
