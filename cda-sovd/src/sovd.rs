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

use std::{
    path::PathBuf,
    sync::{Arc, Mutex as StdMutex, RwLock as StdRwLock},
    time::Duration,
};

pub mod request_guard;

use aide::{
    axum::{
        ApiRouter as Router,
        routing::{self, get_with},
    },
    transform::TransformOperation,
};
use async_trait::async_trait;
use axum::{
    Json,
    body::Bytes,
    extract::{FromRequestParts as _, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header::RETRY_AFTER},
    middleware,
    response::{IntoResponse, Response},
};
use axum_extra::extract::WithRejection;
use cda_interfaces::{
    Connectivity, HashMap, HashMapExtensions as _, HashSet, ReloadComponent, SchemaProvider,
    UdsEcu, VariantState,
    communication_control::{ActivationCause, CommunicationAccess, CommunicationGuard},
    datatypes::ComponentsConfig,
    diagservices::{FieldParseError, UdsPayloadData},
    mdd_chunks::EmbeddedFilesProvider,
    runtime_update_api::{LockStateProvider, PreparedApply, VehicleDatabaseLockUpdater},
    util::std_ext::{self, lock_read, lock_write},
};
use cda_plugin_security::{SecurityPluginLoader, security_plugin_middleware};
use error::{ApiError, api_error_from_diag_response};
use http::{Uri, header};
use indexmap::IndexMap;
pub use locks::Locks;
use schemars::Schema;
use sovd_interfaces::{
    IncludeSchemaQuery, Resource,
    components::{ComponentsResponse, ecu as sovd_ecu},
    error::DataError,
};
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock};
use uuid::Uuid;

use crate::{
    VendorErrorCode,
    sovd::components::ecu::{
        configurations, data, faults, genericservice, modes, operations, x_single_ecu_jobs,
        x_sovd2uds_bulk_data, x_sovd2uds_download,
    },
};

pub(crate) mod apps;
pub(crate) mod components;
pub(crate) mod docs;
pub(crate) mod error;
pub(crate) mod functions;
pub(crate) mod locks;

trait IntoSovd {
    type SovdType;
    fn into_sovd(self) -> Self::SovdType;
}

trait IntoSovdWithSchema {
    type SovdType;
    fn into_sovd_with_schema(self, include_schema: bool) -> Result<Self::SovdType, ApiError>;
}

impl IntoSovd for cda_interfaces::EcuState {
    type SovdType = sovd_ecu::State;

    fn into_sovd(self) -> Self::SovdType {
        match (&self.connectivity, &self.variant_state) {
            (_, VariantState::Duplicate) => sovd_ecu::State::Duplicate,
            (Connectivity::Online, VariantState::Detected { .. }) => sovd_ecu::State::Online,
            (Connectivity::Online, VariantState::NotDetected) => sovd_ecu::State::NoVariantDetected,
            (Connectivity::Online, VariantState::NotTested) => sovd_ecu::State::NotTested,
            (Connectivity::Offline, VariantState::NotTested) => sovd_ecu::State::Offline,
            (Connectivity::Offline, VariantState::Detected { .. } | VariantState::NotDetected) => {
                sovd_ecu::State::Disconnected
            }
        }
    }
}

/// Synchronous lock for short execution-map operations so reservation cleanup can run in `Drop`.
/// Lock guards must never be held across an `.await`.
pub(crate) type ExecutionLock<E> = StdRwLock<HashMap<String, IndexMap<Uuid, E>>>;

#[derive(Clone)]
pub(crate) struct WebserverEcuState<T: UdsEcu + Clone> {
    ecu_name: String,
    uds: T,
    locks: ResolvedLocks,
    lock_provider: Arc<SovdLockStateView>,
    /// The registry entry itself, not its fields: holding the one `Arc` the
    /// lookup returned is what keeps the execution maps from being combined
    /// across two different installations.
    pub(crate) entry: Arc<EcuRegistryEntry>,
    communication_access: Arc<dyn CommunicationAccess>,
    flash_data: Arc<RwLock<sovd_interfaces::sovd2uds::FileList>>,
}

/// Per-ECU execution state belonging to one installation of the vehicle
/// databases. An update replaces the entry, so nothing recorded here outlives
/// the installation it was recorded against.
#[derive(Default)]
pub(crate) struct EcuRegistryEntry {
    // Map of Execution Id -> ComParamMap
    pub(crate) comparam_executions: Arc<RwLock<IndexMap<Uuid, ComparamExecution>>>,
    // Map of Service Name -> (Execution Id -> ServiceExecution) for ECU routine operations
    pub(crate) service_executions: Arc<ExecutionLock<ServiceExecution>>,
}

impl EcuRegistryEntry {
    /// Counts the communication leases the executions of this entry still hold.
    async fn held_communication_leases(&self) -> usize {
        let comparams = self.comparam_executions.read().await.len();
        let services = lock_read(&self.service_executions)
            .values()
            .flat_map(IndexMap::values)
            .filter(|execution| execution.communication_lease.is_some())
            .count();
        comparams.saturating_add(services)
    }
}

/// The complete set of ECU and functional-group identities one registry commit
/// makes live.
///
/// Both what an update hands in and what readers get back: a commit replaces
/// the identities wholesale, so there is nothing to distinguish the two.
///
/// Both halves are lowercased names, and a name is all either one needs: the
/// vehicle databases are keyed by the lowercased ECU name, and every lookup
/// that takes a functional-group name matches it case-insensitively.
#[derive(Clone, Default)]
pub struct SovdIdentities {
    ecus: HashSet<String>,
    functional_groups: HashSet<String>,
}

impl SovdIdentities {
    #[must_use]
    pub fn new(ecus: HashSet<String>, functional_groups: HashSet<String>) -> Self {
        Self {
            ecus,
            functional_groups,
        }
    }

    pub(crate) fn ecu_index(&self) -> &HashSet<String> {
        &self.ecus
    }

    pub(crate) fn functional_group_index(&self) -> &HashSet<String> {
        &self.functional_groups
    }
}

#[derive(Default)]
struct SovdRegistryState {
    ecus: HashMap<String, Arc<EcuRegistryEntry>>,
    functional_groups: HashMap<String, Arc<functions::functional_groups::FgRegistryEntry>>,
    live: SovdIdentities,
}

/// Owns execution state for the currently live ECU and functional-group identities.
/// Route keys are normalized at every registry boundary.
///
/// Hand callers [`Self::view`] for reads and the [`ReloadComponent`] impl for
/// the authority to replace the identities; publishing exists only in that
/// impl, so the trait object is the only way to publish from outside.
#[derive(Clone, Default)]
pub struct SovdRegistry {
    state: Arc<StdMutex<SovdRegistryState>>,
}

/// Cloneable read-only view of live SOVD identities and execution state.
#[derive(Clone)]
pub struct SovdRegistryView {
    state: Arc<StdMutex<SovdRegistryState>>,
}

impl From<SovdRegistry> for SovdRegistryView {
    fn from(owner: SovdRegistry) -> Self {
        owner.view()
    }
}

impl From<&SovdRegistry> for SovdRegistryView {
    fn from(owner: &SovdRegistry) -> Self {
        owner.view()
    }
}

impl SovdRegistryView {
    pub(crate) fn live(&self) -> SovdIdentities {
        std_ext::lock_mutex(&self.state).live.clone()
    }

    /// Resolves a live ECU's name and live execution state under one lock, so
    /// the two can never come from different installations.
    pub(crate) fn resolve_ecu(&self, route_name: &str) -> Option<(String, Arc<EcuRegistryEntry>)> {
        let key = route_name.to_lowercase();
        let state = std_ext::lock_mutex(&self.state);
        let name = state.live.ecus.get(&key)?.clone();
        Some((name, Arc::clone(state.ecus.get(&key)?)))
    }

    /// Functional-group counterpart of [`resolve_ecu`](Self::resolve_ecu).
    pub(crate) fn resolve_functional_group(
        &self,
        route_name: &str,
    ) -> Option<(String, Arc<functions::functional_groups::FgRegistryEntry>)> {
        let key = route_name.to_lowercase();
        let state = std_ext::lock_mutex(&self.state);
        let name = state.live.functional_groups.get(&key)?.clone();
        Some((name, Arc::clone(state.functional_groups.get(&key)?)))
    }
}

impl SovdRegistry {
    /// Builds the registry through the same path an update takes, so the first
    /// publish and later republishes cannot diverge: both go through
    /// [`Self::prepare_update`].
    #[must_use]
    pub fn new(identities: SovdIdentities) -> Self {
        Self {
            state: Arc::new(StdMutex::new(Self::prepare_update(identities))),
        }
    }

    /// Returns a cloneable view without authority to replace or publish.
    #[must_use]
    pub fn view(&self) -> SovdRegistryView {
        SovdRegistryView {
            state: Arc::clone(&self.state),
        }
    }
    /// Builds the state one commit makes live.
    ///
    /// Execution state never carries over. Every update rebuilds every
    /// `EcuManager` behind these names, so an entry that keeps its name is no
    /// more the same installation than one that disappeared and came back;
    /// starting all of them over is the only rule that does not depend on which
    /// updates happened in between. Keys are normalized here so every registry
    /// boundary sees the same shape regardless of how a caller spelled them.
    fn prepare_update(identities: SovdIdentities) -> SovdRegistryState {
        fn fresh_entries<'a, T: Default>(
            keys: impl Iterator<Item = &'a String>,
        ) -> HashMap<String, Arc<T>> {
            keys.map(|key| (key.clone(), Arc::new(T::default())))
                .collect()
        }

        fn normalized(names: HashSet<String>) -> HashSet<String> {
            names.into_iter().map(|name| name.to_lowercase()).collect()
        }

        let ecus = normalized(identities.ecus);
        let functional_groups = normalized(identities.functional_groups);

        SovdRegistryState {
            ecus: fresh_entries(ecus.iter()),
            functional_groups: fresh_entries(functional_groups.iter()),
            live: SovdIdentities {
                ecus,
                functional_groups,
            },
        }
    }

    /// Reports communication leases an update is about to drop.
    ///
    /// An update is refused with 409 while a lease is held, so there should
    /// never be one left here. Replacing the entries releases any that slipped
    /// through, and silently: the next request would then reach an ECU the
    /// update believes it has to itself. Checked rather than assumed, since
    /// dropping every entry is what makes the rule uniform.
    async fn report_dropped_communication_leases(&self) {
        let (ecus, functional_groups) = {
            let state = std_ext::lock_mutex(&self.state);
            (
                state
                    .ecus
                    .iter()
                    .map(|(name, entry)| (name.clone(), Arc::clone(entry)))
                    .collect::<Vec<_>>(),
                state
                    .functional_groups
                    .iter()
                    .map(|(name, entry)| (name.clone(), Arc::clone(entry)))
                    .collect::<Vec<_>>(),
            )
        };

        let report = |kind: &str, name: &str, held: usize| {
            if held > 0 {
                tracing::error!(
                    kind,
                    name = %name,
                    held,
                    "Update is dropping held communication leases; it should have been \
                     refused while any is held"
                );
            }
        };
        for (name, entry) in ecus {
            report("ecu", &name, entry.held_communication_leases().await);
        }
        for (name, entry) in functional_groups {
            report("functional_group", &name, entry.held_communication_leases());
        }
    }

    #[cfg(test)]
    fn ecu(&self, route_name: &str) -> Option<Arc<EcuRegistryEntry>> {
        self.view().resolve_ecu(route_name).map(|(_, entry)| entry)
    }

    #[cfg(test)]
    fn functional_group(
        &self,
        route_name: &str,
    ) -> Option<Arc<functions::functional_groups::FgRegistryEntry>> {
        self.view()
            .resolve_functional_group(route_name)
            .map(|(_, entry)| entry)
    }
}

#[async_trait]
impl ReloadComponent<SovdIdentities> for SovdRegistry {
    async fn apply(&self, data: SovdIdentities) {
        self.report_dropped_communication_leases().await;
        let mut state = std_ext::lock_mutex(&self.state);
        *state = Self::prepare_update(data);
    }
}

/// Extracts live per-ECU state for the templated component route.
pub(crate) struct EcuContext<T: UdsEcu + Clone>(pub(crate) WebserverEcuState<T>);

#[derive(serde::Deserialize)]
struct ComponentIdParam {
    component_id: String,
}

/// Rejection returned when `component_id` names no currently loaded ECU.
/// Mirrors [`error::sovd_not_found_handler`] so a removed ECU stays
/// indistinguishable from a route that never existed.
pub(crate) enum EcuContextRejection {
    NotFound(Uri),
}

impl IntoResponse for EcuContextRejection {
    fn into_response(self) -> Response {
        match self {
            Self::NotFound(uri) => error::not_found_response(&uri),
        }
    }
}

// No-op body: `component_id` is an artifact of routing, not part of the
// documented operation, which emits one concrete path per ECU.
impl<T: UdsEcu + Clone> aide::OperationInput for EcuContext<T> {}

/// Resolves `{component_id}` to a live ECU, shared by the extractors that key off
/// one. The request URI comes back with it: a rejection built later still has to
/// render the path the client asked for.
async fn resolve_component<T: UdsEcu + Clone>(
    parts: &mut http::request::Parts,
    state: &WebserverState<T>,
) -> Result<(Uri, String, Arc<EcuRegistryEntry>), EcuContextRejection> {
    let request_uri = parts
        .extensions
        .get::<axum::extract::OriginalUri>()
        .map_or_else(|| parts.uri.clone(), |uri| uri.0.clone());
    // A named field, not `Path<String>`: nesting composes path params from every
    // nest boundary a request crosses, so more than one may be in scope.
    let axum::extract::Path(ComponentIdParam { component_id }) =
        axum::extract::Path::<ComponentIdParam>::from_request_parts(parts, state)
            .await
            .map_err(|_| EcuContextRejection::NotFound(request_uri.clone()))?;
    let route_name = component_id.to_lowercase();
    let Some((ecu_name, entry)) = state.registry.resolve_ecu(&route_name) else {
        return Err(EcuContextRejection::NotFound(request_uri));
    };
    Ok((request_uri, ecu_name, entry))
}

impl<T: UdsEcu + Clone> axum::extract::FromRequestParts<WebserverState<T>> for EcuContext<T> {
    type Rejection = EcuContextRejection;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        state: &WebserverState<T>,
    ) -> Result<Self, Self::Rejection> {
        let (_, ecu_name, entry) = resolve_component(parts, state).await?;
        let locks = state.lock_provider.current_locks().await;
        Ok(EcuContext(WebserverEcuState {
            ecu_name,
            uds: state.uds.clone(),
            locks,
            lock_provider: Arc::clone(&state.lock_provider),
            entry,
            communication_access: Arc::clone(&state.communication_access),
            flash_data: Arc::clone(&state.flash_data),
        }))
    }
}

/// Extracts the embedded-file store of the ECU named by `{component_id}`.
///
/// Resolved per request like [`EcuContext`], and rejecting the same way: an ECU
/// that went away between two requests must not be distinguishable from a route
/// that never existed. Only the bulk-data endpoints need the store, so it is not
/// part of [`WebserverEcuState`].
pub(crate) struct EcuEmbeddedFiles<T: EmbeddedFilesProvider>(pub(crate) Arc<T::Files>);

// No-op body, for the reason given on `EcuContext`'s.
impl<T: EmbeddedFilesProvider> aide::OperationInput for EcuEmbeddedFiles<T> {}

impl<T: UdsEcu + EmbeddedFilesProvider + Clone> axum::extract::FromRequestParts<WebserverState<T>>
    for EcuEmbeddedFiles<T>
{
    type Rejection = EcuContextRejection;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        state: &WebserverState<T>,
    ) -> Result<Self, Self::Rejection> {
        let (request_uri, ecu_name, _) = resolve_component(parts, state).await?;
        state
            .uds
            .embedded_files(&ecu_name)
            .await
            .map(EcuEmbeddedFiles)
            .map_err(|_| EcuContextRejection::NotFound(request_uri))
    }
}

pub(crate) fn with_retry_after(mut response: Response, retry_after: Option<Duration>) -> Response {
    if let Some(retry_after) = retry_after {
        // `HeaderValue: From<u64>` is infallible, so the header needs no
        // fallible conversion and no intermediate string.
        response
            .headers_mut()
            .insert(RETRY_AFTER, HeaderValue::from(retry_after.as_secs()));
    }
    response
}

/// Acquires a communication lease or starts authorized on-demand activation before
/// returning a retryable SOVD error.
/// [[ dimpl~deferred-sovd-admission, Deferred diagnostic request admission, dimpl ]]
pub(crate) fn acquire_communication_activity(
    communication_access: &dyn CommunicationAccess,
) -> Result<CommunicationGuard, ApiError> {
    match communication_access.acquire() {
        Ok(activity) => Ok(activity),
        Err(error) => {
            communication_access.request_activate(ActivationCause::DiagnosticRequest);
            Err(ApiError::from_communication_error(
                error,
                communication_access.retry_after(),
            ))
        }
    }
}

/// Shared behavior for execution-state types (`ServiceExecution` for single-ECU
/// operations, `FgServiceExecution` for functional-group operations).
pub(crate) trait ExecutionStatus {
    fn execution_status(&self) -> &sovd_ecu::operations::ExecutionStatus;
    /// Returns `true` if an HTTP handler currently has exclusive processing access to this
    /// execution. Used to avoid sending multiple UDS requests simultaneously for the same
    /// execution.
    fn is_in_flight(&self) -> bool;
    /// Sets whether an HTTP handler currently has exclusive processing access to this execution.
    /// This is independent of the diagnostic execution status.
    fn set_in_flight(&mut self, in_flight: bool);
    /// Should return `false` if an execution was created as a placeholder,
    /// but not finalized.
    fn is_created(&self) -> bool;
    fn set_created(&mut self, created: bool);
    /// Creates a placeholder entry used to reserve a slot in the executions map
    /// before the UDS command is sent.
    fn placeholder(communication_guard: CommunicationGuard) -> Self
    where
        Self: Sized;
}

/// Rolls back a newly inserted execution unless it is committed as asynchronous.
/// The execution entry owns the communication lease; rollback releases it by removing the entry.
pub(crate) struct ExecutionReservation<E> {
    executions: Arc<ExecutionLock<E>>,
    service: String,
    exec_id: Uuid,
    state: ReservationState,
}

#[derive(PartialEq)]
enum ReservationState {
    Pending,
    Committed,
}

impl<E> ExecutionReservation<E> {
    fn new(executions: Arc<ExecutionLock<E>>, service: String, exec_id: Uuid) -> Self {
        Self {
            executions,
            service,
            exec_id,
            state: ReservationState::Pending,
        }
    }

    /// Commits the reserved entry as a persistent asynchronous execution.
    ///
    /// The entry already owns the communication lease. While the reservation is pending, its
    /// `Drop` removes that entry as a rollback. Committing disables only that rollback; the entry
    /// remains stored and releases its lease automatically when it is completed or removed.
    pub(crate) fn commit_async(mut self, update_fn: impl FnOnce(&mut E)) -> Uuid
    where
        E: ExecutionStatus,
    {
        finalize_execution(&self.executions, &self.service, &self.exec_id, update_fn);
        self.state = ReservationState::Committed;
        self.exec_id
    }
}

impl<E> Drop for ExecutionReservation<E> {
    fn drop(&mut self) {
        if self.state == ReservationState::Pending {
            remove_reserved_execution(&self.executions, &self.service, &self.exec_id);
        }
    }
}

/// Owns a communication-use slot; dropping it releases that slot.
struct ExecutionLease {
    _guard: CommunicationGuard,
}

impl std::fmt::Debug for ExecutionLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ExecutionLease")
    }
}

pub(crate) struct ComparamExecution {
    execution: sovd_ecu::operations::comparams::Execution,
    _lease: ExecutionLease,
}

impl ComparamExecution {
    pub(crate) fn new(
        execution: sovd_ecu::operations::comparams::Execution,
        communication_guard: CommunicationGuard,
    ) -> Self {
        Self {
            execution,
            _lease: ExecutionLease {
                _guard: communication_guard,
            },
        }
    }

    pub(crate) fn snapshot(&self) -> sovd_ecu::operations::comparams::Execution {
        self.execution.clone()
    }
}

impl std::ops::Deref for ComparamExecution {
    type Target = sovd_ecu::operations::comparams::Execution;

    fn deref(&self) -> &Self::Target {
        &self.execution
    }
}

impl std::ops::DerefMut for ComparamExecution {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.execution
    }
}

/// Stored state for a single ECU routine execution (async lifecycle).
#[derive(Debug)]
pub(crate) struct ServiceExecution {
    pub parameters: serde_json::Map<String, serde_json::Value>,
    pub status: sovd_ecu::operations::ExecutionStatus,
    pub in_flight: bool,
    pub is_created: bool,
    communication_lease: Option<ExecutionLease>,
}

impl Clone for ServiceExecution {
    fn clone(&self) -> Self {
        Self {
            parameters: self.parameters.clone(),
            status: self.status.clone(),
            in_flight: self.in_flight,
            is_created: self.is_created,
            communication_lease: None,
        }
    }
}

impl ServiceExecution {
    pub(crate) fn complete(&mut self) {
        self.status = sovd_ecu::operations::ExecutionStatus::Completed;
        self.communication_lease = None;
    }
}

impl ExecutionStatus for ServiceExecution {
    fn execution_status(&self) -> &sovd_ecu::operations::ExecutionStatus {
        &self.status
    }
    fn is_in_flight(&self) -> bool {
        self.in_flight
    }
    fn set_in_flight(&mut self, in_flight: bool) {
        self.in_flight = in_flight;
    }
    fn is_created(&self) -> bool {
        self.is_created
    }
    fn set_created(&mut self, created: bool) {
        self.is_created = created;
    }
    fn placeholder(communication_guard: CommunicationGuard) -> Self {
        ServiceExecution {
            parameters: serde_json::Map::new(),
            status: sovd_ecu::operations::ExecutionStatus::Running,
            in_flight: false,
            is_created: false,
            communication_lease: Some(ExecutionLease {
                _guard: communication_guard,
            }),
        }
    }
}

/// Stored state for a functional-group routine execution (async lifecycle).
/// Unlike `ServiceExecution`, parameters are keyed by ECU name so that
/// per-ECU identity is preserved across the execution lifecycle.
#[derive(Debug)]
pub(crate) struct FgServiceExecution {
    pub parameters: HashMap<String, serde_json::Map<String, serde_json::Value>>,
    pub status: sovd_ecu::operations::ExecutionStatus,
    pub in_flight: bool,
    pub is_created: bool,
    communication_lease: Option<ExecutionLease>,
}

impl Clone for FgServiceExecution {
    fn clone(&self) -> Self {
        Self {
            parameters: self.parameters.clone(),
            status: self.status.clone(),
            in_flight: self.in_flight,
            is_created: self.is_created,
            communication_lease: None,
        }
    }
}

impl FgServiceExecution {
    pub(crate) fn complete(&mut self) {
        self.status = sovd_ecu::operations::ExecutionStatus::Completed;
        self.communication_lease = None;
    }

    pub(crate) fn holds_communication_lease(&self) -> bool {
        self.communication_lease.is_some()
    }
}

impl ExecutionStatus for FgServiceExecution {
    fn execution_status(&self) -> &sovd_ecu::operations::ExecutionStatus {
        &self.status
    }
    fn is_in_flight(&self) -> bool {
        self.in_flight
    }
    fn set_in_flight(&mut self, in_flight: bool) {
        self.in_flight = in_flight;
    }
    fn is_created(&self) -> bool {
        self.is_created
    }
    fn set_created(&mut self, created: bool) {
        self.is_created = created;
    }
    fn placeholder(communication_guard: CommunicationGuard) -> Self {
        FgServiceExecution {
            parameters: HashMap::new(),
            status: sovd_ecu::operations::ExecutionStatus::Running,
            in_flight: false,
            is_created: false,
            communication_lease: Some(ExecutionLease {
                _guard: communication_guard,
            }),
        }
    }
}

/// Which lock table a request is using, decided once when the request is
/// extracted and pinned for the rest of its life.
///
/// A runtime update replaces the table wholesale: the ECU and functional-group
/// maps become new `Arc`s, and the old ones stay allocated but unreachable. A
/// request that merely held a pointer to the table it resolved would keep
/// operating on the displaced maps, so a lock it granted would be written where
/// nothing can see it and the same resource could be handed to someone else.
/// Pinning does not make the request notice the swap; it makes the swap wait,
/// so the table the request writes to is still the live one when it writes.
///
/// The table is held through a read guard on the owner's table. Holding that
/// guard is what makes a runtime update's topology swap wait, so the request
/// cannot straddle one. The guard sits behind an `Arc` because this value is
/// cloned along with the request state; there is still exactly one underlying
/// guard, and every clone has to drop before a swap proceeds.
#[derive(Clone)]
pub(crate) struct ResolvedLocks {
    topology: Arc<OwnedRwLockReadGuard<Locks>>,
    /// The view this snapshot was resolved from. Kept whole rather than copying
    /// the vehicle lock out of it, so the view stays the only place that holds
    /// one and a snapshot cannot drift from it.
    view: SovdLockStateView,
}

impl ResolvedLocks {
    /// The vehicle lock, which is not part of the topology and is never
    /// replaced. Reaching it does not depend on the retained read guard.
    pub(crate) fn vehicle(&self) -> &locks::LockType {
        self.view.vehicle_lock()
    }
}

impl std::ops::Deref for ResolvedLocks {
    type Target = Locks;

    fn deref(&self) -> &Self::Target {
        &self.topology
    }
}

/// A checked lock-table swap that keeps the table shut until it happens.
///
/// Swapping in a new ECU set replaces the ECU and functional-group tables
/// wholesale, so it destroys every lock held in them. `validate_replacement`
/// rules that out, but only for the instant it runs: a lock taken between the
/// check and the swap would be validated as absent and then dropped. Holding
/// the table's write guard from the check through the swap removes that
/// instant, because taking a lock has to resolve the table first.
///
/// Checking and building are the fallible, asynchronous half; `apply` is the
/// synchronous, infallible half, because it only writes through a guard that is
/// already held.
struct PreparedTopologySwap {
    /// Owned rather than borrowed because it outlives the call that took it: the
    /// decision to go ahead belongs to the caller, which commits every
    /// participant of the update together, in another crate and after further
    /// awaits. A borrowing `RwLockWriteGuard<'_, Locks>` could not leave that
    /// call, so the guard is taken with `write_owned` on the `Arc`.
    live: OwnedRwLockWriteGuard<Locks>,
    /// `None` when the live topology already matches, so applying is a no-op.
    replacement: Option<Locks>,
}

impl PreparedApply for PreparedTopologySwap {
    fn apply(self: Box<Self>) {
        let Self {
            mut live,
            replacement,
        } = *self;
        if let Some(replacement) = replacement {
            *live = replacement;
        }
    }
}

/// Owns the live SOVD lock topology and the authority to replace it.
///
/// Crate-private on purpose: this is the only type that can replace the
/// topology, so the capability never reaches a crate that just reads locks.
pub(crate) struct SovdLockStateProvider {
    view: SovdLockStateView,
}

/// Cloneable read access to the live SOVD lock topology, without the authority
/// to replace it.
///
/// The half that leaves the crate, held by `VehicleResources` and every request
/// that resolves locks. A runtime update reaches the replace side through
/// `Arc<dyn VehicleDatabaseLockUpdater>` instead.
#[derive(Clone)]
pub struct SovdLockStateView {
    locks: Arc<RwLock<Locks>>,
    /// The one vehicle lock in the process. It sits beside the topology rather
    /// than inside it: a runtime update replaces `locks` wholesale, and the
    /// vehicle lock has to survive that untouched because it is what admits the
    /// update in the first place.
    vehicle_lock: locks::LockType,
}

/// Creates the private lock-topology owner and separates its capabilities.
///
/// Returns the read-only runtime and security-policy view and the opaque
/// update validation and replacement authority.
#[must_use]
pub fn new_sovd_lock_state(
    ecu_names: Vec<String>,
) -> (Arc<SovdLockStateView>, Arc<dyn VehicleDatabaseLockUpdater>) {
    let owner = Arc::new(SovdLockStateProvider::new(ecu_names));
    (
        Arc::new(owner.view()),
        Arc::clone(&owner) as Arc<dyn VehicleDatabaseLockUpdater>,
    )
}

impl SovdLockStateView {
    #[must_use]
    pub fn vehicle_lock(&self) -> &locks::LockType {
        &self.vehicle_lock
    }

    /// Resolves the topology current at request time and retains its read guard.
    pub(crate) async fn current_locks(&self) -> ResolvedLocks {
        ResolvedLocks {
            topology: Arc::new(Arc::clone(&self.locks).read_owned().await),
            view: self.clone(),
        }
    }
}

impl SovdLockStateProvider {
    /// Creates startup topology A from the initial physical ECU names.
    #[must_use]
    pub fn new(ecu_names: Vec<String>) -> Self {
        Self {
            view: SovdLockStateView {
                locks: Arc::new(RwLock::new(Locks::new(ecu_names))),
                vehicle_lock: locks::LockType::Vehicle(Arc::new(RwLock::new(None))),
            },
        }
    }

    /// Returns a cloneable view without authority to replace the data.
    #[must_use]
    pub fn view(&self) -> SovdLockStateView {
        self.view.clone()
    }
}

#[async_trait]
impl VehicleDatabaseLockUpdater for SovdLockStateProvider {
    async fn reserve_lock_resources(
        &self,
        ecu_names: Vec<String>,
    ) -> Result<Box<dyn PreparedApply>, cda_interfaces::runtime_update_api::ReloadError> {
        let live = Arc::clone(&self.view.locks).write_owned().await;
        let replacement = if live.has_ecu_topology(&ecu_names).await {
            None
        } else {
            live.validate_replacement().await.map_err(|error| {
                cda_interfaces::runtime_update_api::ReloadError::General(format!(
                    "Failed to validate runtime locks: {error}"
                ))
            })?;
            Some(Locks::new(ecu_names))
        };
        Ok(Box::new(PreparedTopologySwap { live, replacement }))
    }
}

#[async_trait]
impl LockStateProvider for SovdLockStateView {
    async fn vehicle_lock_owner_id(&self) -> Option<String> {
        let vehicle_lock = self.vehicle_lock.lock_ro().await;
        match &vehicle_lock {
            ReadLock::OptionLock(l) => l.as_ref().map(|l| l.owner().to_owned()),
            ReadLock::HashMapLock(_) => None,
        }
    }

    async fn has_locks(&self) -> bool {
        let locks = self.current_locks().await;
        let ecu_lock = locks.ecu.lock_ro().await;
        let fg_lock = locks.functional_group.lock_ro().await;
        ecu_lock.is_any_locked() || fg_lock.is_any_locked()
    }
}

/// Resets an execution's request-level concurrency marker when processing ends or is cancelled.
pub(crate) struct ExecutionRequestGuard<'a, T: ExecutionStatus> {
    executions: &'a ExecutionLock<T>,
    service: String,
    exec_id: Uuid,
    snapshot: T,
}

impl<T: ExecutionStatus> ExecutionRequestGuard<'_, T> {
    pub(crate) fn snapshot(&self) -> &T {
        &self.snapshot
    }
}

impl<T: ExecutionStatus> Drop for ExecutionRequestGuard<'_, T> {
    fn drop(&mut self) {
        if let Some(exec) = lock_write(self.executions)
            .get_mut(&self.service)
            .and_then(|entries| entries.get_mut(&self.exec_id))
        {
            exec.set_in_flight(false);
        }
    }
}

/// Acquires a write lock on `executions`, looks up `exec_id` under the given
/// `service` key, marks it `in_flight = true`, and returns a guard containing a
/// snapshot of the execution. Returns `Err(ErrorWrapper)` on not-found or conflict.
pub(crate) fn guard_execution<'a, T: ExecutionStatus + Clone>(
    executions: &'a ExecutionLock<T>,
    service: &str,
    exec_id: Uuid,
    include_schema: bool,
    conflict_msg: &str,
) -> Result<ExecutionRequestGuard<'a, T>, error::ErrorWrapper> {
    let snapshot = {
        let mut guard = lock_write(executions);
        let op_map = guard
            .get_mut(service)
            .and_then(|m| m.get_mut(&exec_id))
            // Treat placeholders (is_created == false) as non-existent.
            .filter(|e| e.is_created());
        match op_map {
            None => {
                return Err(error::ErrorWrapper {
                    error: error::ApiError::NotFound(Some(format!(
                        "Execution with id {exec_id} not found"
                    ))),
                    include_schema,
                });
            }
            Some(exec) if exec.is_in_flight() => {
                return Err(error::ErrorWrapper {
                    error: error::ApiError::Conflict(conflict_msg.to_owned()),
                    include_schema,
                });
            }
            Some(exec) => {
                exec.set_in_flight(true);
                exec.clone()
            }
        }
    };
    Ok(ExecutionRequestGuard {
        executions,
        service: service.to_owned(),
        exec_id,
        snapshot,
    })
}

/// Checks for a running-execution conflict and, if none exists,
/// inserts a placeholder entry so that a second concurrent POST for the same
/// operation will see a `409 Conflict`.
///
/// On success the returned [`Uuid`] identifies the reserved execution slot.
/// The inserted placeholder owns the communication guard and releases it when
/// the execution is completed or removed.
///
/// Runtime-update admission is enforced by the request guard and communication
/// access, so this function only reserves a per-service execution slot.
pub(crate) fn reserve_execution<E: ExecutionStatus>(
    executions: &ExecutionLock<E>,
    service: &str,
    display_name: &str,
    include_schema: bool,
    id: Uuid,
    communication_guard: CommunicationGuard,
) -> Result<Uuid, error::ErrorWrapper> {
    let mut guard = lock_write(executions);
    let has_running = guard.get(service).is_some_and(|m| {
        m.values()
            .any(|e| *e.execution_status() == sovd_ecu::operations::ExecutionStatus::Running)
    });
    if has_running {
        return Err(error::ErrorWrapper {
            error: error::ApiError::Conflict(format!(
                "An execution for operation '{display_name}' is already in progress"
            )),
            include_schema,
        });
    }
    let mut entry = E::placeholder(communication_guard);
    entry.set_in_flight(true);
    guard
        .entry(service.to_owned())
        .or_default()
        .insert(id, entry);
    Ok(id)
}

/// Publishes a communication lease before making its execution visible, so every
/// visible execution has an owner that can release the lease.
pub(crate) fn acquire_and_reserve_execution<E: ExecutionStatus>(
    communication_access: &dyn CommunicationAccess,
    executions: Arc<ExecutionLock<E>>,
    service: &str,
    display_name: &str,
    include_schema: bool,
) -> Result<ExecutionReservation<E>, error::ErrorWrapper> {
    let communication_guard =
        acquire_communication_activity(communication_access).map_err(|error| {
            error::ErrorWrapper {
                error,
                include_schema,
            }
        })?;
    let exec_id = Uuid::new_v4();
    reserve_execution(
        &executions,
        service,
        display_name,
        include_schema,
        exec_id,
        communication_guard,
    )?;
    Ok(ExecutionReservation::new(
        executions,
        service.to_owned(),
        exec_id,
    ))
}

/// Updates a previously reserved execution with the received parameters,
/// sets `is_created(true)`, and clears the `in_flight` flag.
/// After this step GET/DELETE requests can be called for this execution.
pub(crate) fn finalize_execution<E: ExecutionStatus>(
    executions: &ExecutionLock<E>,
    service: &str,
    exec_id: &Uuid,
    update_fn: impl FnOnce(&mut E),
) {
    let mut guard = lock_write(executions);
    if let Some(exec) = guard.get_mut(service).and_then(|m| m.get_mut(exec_id)) {
        update_fn(exec);
        exec.set_created(true);
        exec.set_in_flight(false);
    }
}

/// Removes a previously reserved execution slot. Called on error or after
/// a synchronous operation completes (sync operations do not persist
/// execution state).
pub(crate) fn remove_reserved_execution<E>(
    executions: &ExecutionLock<E>,
    service: &str,
    exec_id: &Uuid,
) {
    let mut guard = lock_write(executions);
    if let Some(map) = guard.get_mut(service) {
        map.shift_remove(exec_id);
        if map.is_empty() {
            guard.remove(service);
        }
    }
}

#[derive(Clone)]
pub(crate) struct WebserverState<T: UdsEcu + Clone> {
    uds: T,
    lock_provider: Arc<SovdLockStateView>,
    flash_data: Arc<RwLock<sovd_interfaces::sovd2uds::FileList>>,
    components_config: Arc<RwLock<ComponentsConfig>>,
    communication_access: Arc<dyn CommunicationAccess>,
    registry: SovdRegistryView,
}

pub(crate) fn resource_response(
    host: &str,
    uri: &Uri,
    resources: Vec<(&str, Option<&str>)>,
    include_schema: bool,
) -> Response {
    let base_path = format!("http://{host}{uri}");
    let items = resources
        .into_iter()
        .map(|(name, href)| sovd_interfaces::Resource {
            name: name.to_string(),
            href: format!("{base_path}/{}", href.unwrap_or(name)),
            id: None,
        })
        .collect();

    let schema = if include_schema {
        Some(crate::sovd::create_schema!(sovd_interfaces::Resource))
    } else {
        None
    };

    let components = sovd_interfaces::ResourceResponse { items, schema };
    (StatusCode::OK, Json(components)).into_response()
}

pub fn route<
    T: UdsEcu + SchemaProvider + EmbeddedFilesProvider + Clone,
    S: SecurityPluginLoader,
>(
    components_config: ComponentsConfig,
    uds: &T,
    flash_files_path: String,
    lock_provider: Arc<SovdLockStateView>,
    communication_access: Arc<dyn CommunicationAccess>,
    registry: SovdRegistryView,
) -> Router {
    let flash_data = Arc::new(RwLock::new(sovd_interfaces::sovd2uds::FileList {
        files: Vec::new(),
        path: Some(PathBuf::from(flash_files_path)),
        schema: None,
    }));
    let state = WebserverState {
        uds: uds.clone(),
        lock_provider,
        flash_data: Arc::clone(&flash_data),
        components_config: Arc::new(RwLock::new(components_config)),
        communication_access,
        registry,
    };

    let router = components_route::<T>(state.clone());

    vehicle_route::<T, S>(state, router)
        .layer(middleware::from_fn(security_plugin_middleware::<S>))
        .with_state(uds.clone())
}

fn vehicle_route<T: UdsEcu + SchemaProvider + Clone, S: SecurityPluginLoader>(
    state: WebserverState<T>,
    router: Router<WebserverState<T>>,
) -> Router<T> {
    let router = router.nest_api_service(
        "/vehicle/v15/functions",
        functions::functional_groups::create_functional_group_routes(state.clone()),
    );
    router
        .api_route(
            "/vehicle/v15/locks",
            routing::post_with(locks::vehicle::post, locks::vehicle::docs_post)
                .get_with(locks::vehicle::get, locks::vehicle::docs_get),
        )
        .api_route(
            "/vehicle/v15/locks/{lock}",
            routing::get_with(locks::vehicle::lock::get, locks::vehicle::lock::docs_get)
                .put_with(locks::vehicle::lock::put, locks::vehicle::lock::docs_put)
                .delete_with(
                    locks::vehicle::lock::delete,
                    locks::vehicle::lock::docs_delete,
                ),
        )
        .api_route("/vehicle/v15/apps", routing::get_with(apps::get, |op| op))
        .api_route(
            "/vehicle/v15/apps/sovd2uds",
            routing::get_with(apps::sovd2uds::get, |op| op),
        )
        .api_route(
            "/vehicle/v15/apps/sovd2uds/bulk-data",
            routing::get_with(apps::sovd2uds::bulk_data::get, |op| op),
        )
        .api_route(
            "/vehicle/v15/apps/sovd2uds/bulk-data/flashfiles",
            routing::get_with(
                apps::sovd2uds::bulk_data::flash_files::get,
                apps::sovd2uds::bulk_data::flash_files::docs_get,
            ),
        )
        .api_route(
            "/vehicle/v15/authorize",
            routing::post_with(S::authorize, |op| op),
        )
        .with_state(state)
        .api_route(
            "/vehicle/v15/apps/sovd2uds/data/networkstructure",
            routing::get_with(
                apps::sovd2uds::data::networkstructure::get::<T>,
                apps::sovd2uds::data::networkstructure::docs_get,
            ),
        )
}

async fn get_components<T: UdsEcu + SchemaProvider + Clone>(
    State(state): State<WebserverState<T>>,
    WithRejection(Query(query), _): WithRejection<Query<IncludeSchemaQuery>, ApiError>,
) -> Response {
    fn ecu_to_resource(ecu: String) -> Resource {
        Resource {
            href: format!("http://localhost:20002/Vehicle/v15/components/{ecu}"),
            id: Some(ecu.to_lowercase()),
            name: ecu,
        }
    }
    let ecus = state.uds.get_physical_ecus().await;
    let components_config = state.components_config.read().await;
    let mut additional_fields: HashMap<String, Vec<Resource>> = HashMap::new();
    for (key, conditions) in &components_config.additional_fields {
        let items = state
            .uds
            .get_ecus_with_sds(true, conditions)
            .await
            .into_iter()
            .map(ecu_to_resource)
            .collect::<Vec<_>>();
        additional_fields.insert(key.to_owned(), items);
    }

    let mut schema = if query.include_schema {
        Some(create_schema!(ComponentsResponse<Resource>))
    } else {
        None
    };
    if !additional_fields.is_empty()
        && let Some(ref mut schema) = schema
    {
        let subschema = create_schema!(Resource);
        for entry in additional_fields.keys() {
            if let Some(properties) = schema.get_mut("properties").and_then(|v| v.as_object_mut()) {
                properties.insert(entry.to_owned(), subschema.clone().to_value());
            }
        }
    }
    (
        StatusCode::OK,
        Json(ComponentsResponse::<Resource> {
            items: ecus.into_iter().map(ecu_to_resource).collect::<Vec<_>>(),
            additional_fields,
            schema,
        }),
    )
        .into_response()
}

fn docs_components(op: TransformOperation) -> TransformOperation {
    op.description("Get a list of the available components with their paths")
        .response_with::<200, Json<sovd_interfaces::ResourceResponse>, _>(|res| {
            res.example(sovd_interfaces::ResourceResponse {
                items: vec![sovd_interfaces::Resource {
                    href: "http://localhost:20002/Vehicle/v15/components/my_ecu".into(),
                    id: Some("my_ecu".into()),
                    name: "My ECU".into(),
                }],
                schema: None,
            })
        })
}

fn components_route<T: UdsEcu + SchemaProvider + EmbeddedFilesProvider + Clone>(
    state: WebserverState<T>,
) -> Router<WebserverState<T>> {
    let router = Router::new().api_route(
        "/vehicle/v15/components",
        get_with(get_components, docs_components),
    );
    router
        .nest_api_service(
            "/vehicle/v15/components/{component_id}",
            ecu_route::<T>(state.clone()),
        )
        .with_state(state)
}

/// [`EcuContext`] resolves `{component_id}` per request, so this route table is
/// identical regardless of which ECUs are loaded and is built once.
/// `nest_api_service` requires a fully resolved router, so `state` is applied here.
#[allow(
    clippy::too_many_lines,
    reason = "Route creation kept together for structural clarity"
)]
fn ecu_route<T: UdsEcu + SchemaProvider + EmbeddedFilesProvider + Clone>(
    state: WebserverState<T>,
) -> Router {
    Router::new()
        .api_route(
            "/",
            routing::get_with(components::ecu::get, components::ecu::docs_get)
                .post_with(components::ecu::post, components::ecu::docs_put)
                .put_with(components::ecu::put, components::ecu::docs_put),
        )
        .api_route(
            "/locks",
            routing::post_with(locks::ecu::post, locks::ecu::docs_post)
                .get_with(locks::ecu::get, locks::ecu::docs_get),
        )
        .api_route(
            "/locks/{lock}",
            routing::delete_with(locks::ecu::lock::delete, locks::ecu::lock::docs_delete)
                .put_with(locks::ecu::lock::put, locks::ecu::lock::docs_put)
                .get_with(locks::ecu::lock::get, locks::ecu::lock::docs_get),
        )
        .api_route(
            "/configurations",
            routing::get_with(configurations::get, configurations::docs_get),
        )
        .api_route(
            "/configurations/{service}",
            routing::put_with(
                configurations::diag_service::put,
                configurations::diag_service::docs_put,
            )
            .get_with(data::diag_service::get, data::diag_service::docs_get),
        )
        .api_route(
            "/configurations/{service}/docs",
            routing::get_with(
                configurations::diag_service::docs_endpoint::get,
                configurations::diag_service::docs_endpoint::docs_transform,
            ),
        )
        .api_route("/data", routing::get_with(data::get, data::docs_get))
        .api_route(
            "/data/{service}",
            routing::get_with(data::diag_service::get, data::diag_service::docs_get)
                .put_with(data::diag_service::put, data::diag_service::docs_put),
        )
        .api_route(
            "/data/{service}/docs",
            routing::get_with(
                data::diag_service::docs_endpoint::get,
                data::diag_service::docs_endpoint::docs_transform,
            ),
        )
        .api_route(
            "/genericservice",
            routing::put_with(genericservice::put, genericservice::docs_put),
        )
        .api_route(
            "/operations",
            routing::get_with(operations::get, operations::docs_get),
        )
        .api_route(
            "/operations/{service}",
            routing::get_with(operations::service::get, operations::service::docs_get),
        )
        .api_route(
            "/operations/{service}/docs",
            routing::get_with(
                operations::service::docs_endpoint::get,
                operations::service::docs_endpoint::docs_transform,
            ),
        )
        .api_route(
            "/operations/comparam/executions",
            routing::get_with(
                operations::comparams::executions::get,
                operations::comparams::executions::docs_get,
            )
            .post_with(
                operations::comparams::executions::post,
                operations::comparams::executions::docs_post,
            ),
        )
        .api_route(
            "/operations/comparam/executions/{id}",
            routing::get_with(
                operations::comparams::executions::id::get,
                operations::comparams::executions::id::docs_get,
            )
            .delete_with(
                operations::comparams::executions::id::delete,
                operations::comparams::executions::id::docs_delete,
            )
            .put_with(
                operations::comparams::executions::id::put,
                operations::comparams::executions::id::docs_put,
            ),
        )
        .api_route(
            "/operations/{service}/executions",
            routing::get_with(
                operations::service::executions::get,
                operations::service::executions::docs_get,
            )
            .post_with(
                operations::service::executions::post,
                operations::service::executions::docs_post,
            ),
        )
        .api_route(
            "/operations/{service}/executions/{id}",
            routing::get_with(
                operations::service::executions::id::get,
                operations::service::executions::id::docs_get,
            )
            .delete_with(
                operations::service::executions::id::delete,
                operations::service::executions::id::docs_delete,
            ),
        )
        .api_route("/modes", routing::get_with(modes::get, modes::docs_get))
        .api_route(
            &format!("/modes/{}", sovd_interfaces::common::modes::SESSION_ID),
            routing::get_with(modes::session::get, modes::session::docs_get)
                .put_with(modes::session::put, modes::session::docs_put),
        )
        .api_route(
            &format!("/modes/{}", sovd_interfaces::common::modes::SECURITY_ID),
            routing::get_with(modes::security::get, modes::security::docs_get)
                .put_with(modes::security::put, modes::security::docs_put),
        )
        .api_route(
            &format!("/modes/{}", sovd_interfaces::common::modes::COMM_CONTROL_ID),
            routing::get_with(modes::commctrl::get, modes::commctrl::docs_get)
                .put_with(modes::commctrl::put, modes::commctrl::docs_put),
        )
        .api_route(
            &format!("/modes/{}", sovd_interfaces::common::modes::DTC_SETTING_ID),
            routing::get_with(modes::dtcsetting::get, modes::dtcsetting::docs_get)
                .put_with(modes::dtcsetting::put, modes::dtcsetting::docs_put),
        )
        .api_route(
            "/x-single-ecu-jobs",
            routing::get_with(
                x_single_ecu_jobs::single_ecu::get,
                x_single_ecu_jobs::single_ecu::docs_get,
            ),
        )
        .api_route(
            "/x-single-ecu-jobs/{job_name}",
            routing::get_with(
                x_single_ecu_jobs::single_ecu::name::get,
                x_single_ecu_jobs::single_ecu::name::docs_get,
            ),
        )
        .api_route(
            "/x-sovd2uds-download",
            routing::get_with(x_sovd2uds_download::get, |op| op),
        )
        .api_route(
            "/x-sovd2uds-download/requestdownload",
            routing::put_with(
                x_sovd2uds_download::request_download::put,
                x_sovd2uds_download::request_download::docs_put,
            ),
        )
        .api_route(
            "/x-sovd2uds-download/flashtransfer",
            routing::post_with(
                x_sovd2uds_download::flash_transfer::post,
                x_sovd2uds_download::flash_transfer::docs_post,
            )
            .get_with(
                x_sovd2uds_download::flash_transfer::get,
                x_sovd2uds_download::flash_transfer::docs_get,
            ),
        )
        .api_route(
            "/x-sovd2uds-download/flashtransfer/{id}",
            routing::get_with(
                x_sovd2uds_download::flash_transfer::id::get,
                x_sovd2uds_download::flash_transfer::id::docs_get,
            )
            .delete_with(
                x_sovd2uds_download::flash_transfer::id::delete,
                x_sovd2uds_download::flash_transfer::id::docs_delete,
            ),
        )
        .api_route(
            "/x-sovd2uds-download/transferexit",
            routing::put_with(
                x_sovd2uds_download::transferexit::put,
                x_sovd2uds_download::transferexit::docs_put,
            ),
        )
        .api_route(
            "/x-sovd2uds-bulk-data",
            routing::get_with(x_sovd2uds_bulk_data::get, |op| op),
        )
        .api_route(
            "/x-sovd2uds-bulk-data/mdd-embedded-files",
            routing::get_with(
                x_sovd2uds_bulk_data::mdd_embedded_files::get,
                x_sovd2uds_bulk_data::mdd_embedded_files::docs_get,
            ),
        )
        .api_route(
            "/x-sovd2uds-bulk-data/mdd-embedded-files/{id}",
            routing::get_with(
                x_sovd2uds_bulk_data::mdd_embedded_files::id::get,
                x_sovd2uds_bulk_data::mdd_embedded_files::id::docs_get,
            ),
        )
        .api_route(
            "/faults",
            routing::get_with(faults::get, faults::docs_get)
                .delete_with(faults::delete, faults::docs_delete),
        )
        .api_route(
            "/faults/{id}",
            routing::get_with(faults::id::get, faults::id::docs_get)
                .delete_with(faults::id::delete, faults::id::docs_delete),
        )
        .with_state(state)
}

fn get_payload_data<'a, T>(
    content_type: Option<&mime::Mime>,
    headers: &HeaderMap,
    body: &'a Bytes,
) -> Result<Option<UdsPayloadData>, ApiError>
where
    T: sovd_interfaces::Payload + serde::de::Deserialize<'a>,
{
    let Some(content_type) = content_type else {
        return Ok(None);
    };
    Ok(match (content_type.type_(), content_type.subtype()) {
        (mime::APPLICATION, mime::JSON) => {
            let sovd_request = serde_json::from_slice::<T>(body)
                .map_err(|e| ApiError::BadRequest(format!("Invalid JSON: {e:?}")))?;
            Some(UdsPayloadData::ParameterMap(sovd_request.get_data_map()))
        }
        (mime::APPLICATION, mime::OCTET_STREAM) => get_octet_stream_payload(headers, body)?,
        _ => {
            return Err(ApiError::BadRequest(format!(
                "Unsupported mime-type: {content_type:?}"
            )));
        }
    })
}

fn get_octet_stream_payload(
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<Option<UdsPayloadData>, ApiError> {
    let content_length = headers
        .get(header::CONTENT_LENGTH)
        .ok_or_else(|| ApiError::BadRequest("Missing Content-Length".to_owned()))
        .and_then(|v| {
            v.to_str()
                .map_err(|e| ApiError::BadRequest(format!("Invalid Content-Length: {e:?}")))
                .and_then(|v| {
                    v.parse::<usize>()
                        .map_err(|e| ApiError::BadRequest(format!("Invalid Content-Length: {e}")))
                })
        })?;

    if content_length == 0 {
        return Ok(None);
    }

    let mut data = body.to_vec();

    if data.len() < content_length {
        return Err(ApiError::BadRequest(format!(
            "Invalid Content-Length: {content_length} is bigger than the size of the data {}",
            data.len()
        )));
    }

    data.truncate(content_length);

    Ok(Some(UdsPayloadData::Raw(data)))
}

/// Helper Fn to convert a `serde_json::Value` into a `schemars::Schema`, without cloning
fn value_to_schema(mut value: serde_json::Value) -> Result<Schema, ApiError> {
    let value = value
        .as_object_mut()
        .map(std::mem::take)
        .ok_or(ApiError::InternalServerError(Some(
            "Failed to create schema".to_string(),
        )))?;
    Ok(schemars::Schema::from(value))
}

/// Helper Fn to remove descriptions from a schema, in cases where a
/// schema reduced on the necessary parameters for automated parsing is
/// desired.
///
/// Due to schemars not offering an option to skip generating
/// the description from rusts docstrings as a workaround the generated
/// json Value of the schema is traversed recursively and all descriptions
/// are removed.
fn remove_descriptions_recursive(value: &mut serde_json::Value) {
    if let Some(obj) = value.as_object_mut() {
        obj.remove("description");
        for v in obj.values_mut() {
            if v.is_object() || v.is_array() {
                remove_descriptions_recursive(v);
            }
        }
    } else if let Some(arr) = value.as_array_mut() {
        for v in arr {
            if v.is_object() || v.is_array() {
                remove_descriptions_recursive(v);
            }
        }
    }
}

/// This Macro allows to generate a schema for Responses including
/// the inlined schema for the target field.
///
/// # Arguments
/// - `base_type`: The base type for the response schema.
/// - `target_field`: The field in the base type where the sub schema should be inserted.
/// - `sub_schema`: The sub schema to be inserted.
///
/// # Returns
/// A codeblock that returns the enriched response schema
macro_rules! create_response_schema {
    ($base_type:ty, $target_field:expr, $sub_schema:ident) => {{
        use schemars::JsonSchema as _;

        use crate::sovd::error::VendorErrorCode;

        let mut generator = schemars::SchemaGenerator::new(
            schemars::generate::SchemaSettings::draft07().with(|s| s.inline_subschemas = true),
        );
        let mut schema = <$base_type>::json_schema(&mut generator);

        if let Some(props) = schema.get_mut("properties") {
            if let Some(obj) = props.as_object_mut() {
                let value = match $sub_schema {
                    None => serde_json::Value::Null,
                    Some(s) => s.to_value(),
                };
                obj.insert($target_field.into(), value);
                if let Some(errs) = obj.get_mut("errors") {
                    crate::sovd::remove_descriptions_recursive(&mut *errs);
                }
            }
        }

        schema
    }};
}
pub(crate) use create_response_schema;

/// This Macro allows to generate a schema for a type.
/// Ensures that the schema is generated with inlined subschemas
/// and draft07 settings.
#[macro_export]
macro_rules! create_schema {
    ($type_:ty) => {{
        #[allow(
            unused_imports,
            reason = "Import may already be in scope at the macro call site"
        )]
        use schemars::JsonSchema as _;

        let mut generator = schemars::SchemaGenerator::new(
            schemars::generate::SchemaSettings::draft07().with(|s| s.inline_subschemas = true),
        );
        <$type_>::json_schema(&mut generator)
    }};
}
pub use create_schema;

use crate::sovd::locks::ReadLock;

pub(crate) mod static_data {
    use aide::{
        axum::{ApiRouter, routing},
        transform::TransformOperation,
    };
    use axum::{
        Json,
        extract::{Query, State},
        response::{IntoResponse, Response},
    };
    use http::StatusCode;

    use crate::{dynamic_router::DynamicRouter, sovd::error::ApiError};

    /// Add an endpoint serving static data.
    /// For example it can be used, to serve version information.
    /// The standard defines these routes for version data:
    /// * `/vehicle/v15/apps/sovd2uds/data/version`.
    /// * `/vehicle/v15/data/version`
    /// # Arguments
    /// * `dynamic_router` - The dynamic router to add the endpoint to.
    /// * `data` - The version data to return.
    /// * `path` - The path to serve the data from.
    ///   There is no processing of this, it will be returned as is in the response.
    pub async fn add_static_data_endpoint(
        dynamic_router: &DynamicRouter,
        data: serde_json::Map<String, serde_json::Value>,
        path: &str,
    ) {
        let data_docs = data.clone();
        let router = ApiRouter::new()
            .api_route(
                path,
                routing::get_with(get, move |transformation| {
                    docs_get(transformation, data_docs.clone())
                }),
            )
            .with_state(data);
        dynamic_router.add_routes(router).await;
    }

    pub(crate) async fn get(
        State(state): State<serde_json::Map<String, serde_json::Value>>,
        Query(query): Query<sovd_interfaces::IncludeSchemaQuery>,
    ) -> Response {
        let mut response_map = state.clone();
        if query.include_schema {
            let schema = match serde_json::to_value(
                create_schema!(serde_json::Map<String, serde_json::Value>),
            ) {
                Ok(s) => s,
                Err(e) => {
                    return ApiError::InternalServerError(Some(format!(
                        "Failed to build static data with schema: {e}"
                    )))
                    .into_response();
                }
            };

            response_map.insert("schema".to_string(), schema);
        }
        (StatusCode::OK, Json(response_map)).into_response()
    }

    pub(crate) fn docs_get(
        op: TransformOperation,
        data: serde_json::Map<String, serde_json::Value>,
    ) -> TransformOperation {
        op.description("Get static information")
            .response_with::<200, Json<serde_json::Map<String, serde_json::Value>>, _>(|res| {
                let mut example = data;
                example.insert("schema".to_string(), serde_json::Value::Null);
                res.description("Successful response").example(example)
            })
    }
}

/// Wrapper Struct around [`FieldParseError`] to allow implementing
/// [From] for [`DataError`<VendorErrorCode>]
struct FieldParseErrorWrapper(FieldParseError);
impl From<FieldParseErrorWrapper> for DataError<VendorErrorCode> {
    fn from(value: FieldParseErrorWrapper) -> Self {
        let value: FieldParseError = value.0;
        Self {
            path: value.path,
            error: sovd_interfaces::error::ApiErrorResponse {
                message: "Failed to parse parameter".to_owned(),
                error_code: sovd_interfaces::error::ErrorCode::VendorSpecific,
                vendor_code: Some(VendorErrorCode::ErrorInterpretingMessage),
                parameters: Some(
                    [
                        ("details", value.error.details),
                        ("value", value.error.value),
                    ]
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), serde_json::Value::String(v)))
                    .collect(),
                ),
                error_source: None,
                schema: None,
            },
        }
    }
}

fn field_parse_errors_to_json(
    errors: impl IntoIterator<Item = FieldParseError>,
    data_field_ref: &str,
) -> Vec<DataError<VendorErrorCode>> {
    errors
        .into_iter()
        .map(|v| {
            let mut data_error = DataError::from(FieldParseErrorWrapper(v));
            data_error.path = format!("/{data_field_ref}{}", data_error.path);
            data_error
        })
        .collect()
}

impl IntoSovd for FieldParseError {
    type SovdType = DataError<VendorErrorCode>;

    fn into_sovd(self) -> Self::SovdType {
        FieldParseErrorWrapper(self).into()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use cda_interfaces::{
        UdsEcu,
        communication_control::{
            ActivationCause, CommunicationAccess, CommunicationError, CommunicationState,
            VariantDetectionMode,
        },
        runtime_update_api::VehicleDatabaseLockUpdater,
    };
    use cda_plugin_communication_management::lifecycle::enabled_communication_access_for_test;
    use sovd_interfaces::sovd2uds::FileList;

    use super::*;

    struct DeferredCommunicationAccess {
        activation_requests: AtomicUsize,
    }

    struct CountingCommunicationAccess {
        /// Used as counter for active instances.
        /// As tests hold this too active 'access' instances are `Arc::strong_count` - 1
        active: Arc<()>,
    }

    impl CommunicationAccess for CountingCommunicationAccess {
        fn state(&self) -> CommunicationState {
            CommunicationState::Enabled
        }

        fn acquire(&self) -> Result<CommunicationGuard, CommunicationError> {
            Ok(CommunicationGuard::new(Arc::clone(&self.active)))
        }

        fn request_activate(&self, _cause: ActivationCause) -> CommunicationState {
            CommunicationState::Enabled
        }

        fn retry_after(&self) -> Duration {
            Duration::ZERO
        }

        fn variant_detection(&self) -> VariantDetectionMode {
            VariantDetectionMode::Always
        }
    }

    impl CommunicationAccess for DeferredCommunicationAccess {
        fn state(&self) -> CommunicationState {
            CommunicationState::Disabled
        }

        fn acquire(&self) -> Result<CommunicationGuard, CommunicationError> {
            Err(CommunicationError::Disabled)
        }

        fn request_activate(&self, _cause: ActivationCause) -> CommunicationState {
            self.activation_requests.fetch_add(1, Ordering::SeqCst);
            CommunicationState::Disabled
        }

        fn retry_after(&self) -> Duration {
            Duration::from_secs(7)
        }

        fn variant_detection(&self) -> VariantDetectionMode {
            VariantDetectionMode::Always
        }
    }

    fn live_ecus(names: &[&str]) -> HashSet<String> {
        names.iter().map(|name| name.to_lowercase()).collect()
    }

    fn live_groups(names: &[&str]) -> HashSet<String> {
        live_ecus(names)
    }

    /// An update replaces every entry, whether or not it still names the same
    /// ECU: the databases behind the name were rebuilt either way, so a record
    /// taken against the previous installation does not describe this one.
    #[tokio::test]
    async fn registry_starts_execution_state_over_on_every_update() {
        let registry = SovdRegistry::new(SovdIdentities::new(
            live_ecus(&["MyEcU"]),
            live_groups(&["MyGrOuP"]),
        ));
        let ecu_state = registry.ecu("MYECU").unwrap();
        let group_state = registry.functional_group("MYGROUP").unwrap();
        let execution_id = Uuid::new_v4();
        lock_write(&ecu_state.service_executions).insert(
            "routine".to_owned(),
            [(
                execution_id,
                ServiceExecution {
                    parameters: serde_json::Map::new(),
                    status: sovd_ecu::operations::ExecutionStatus::Completed,
                    in_flight: false,
                    is_created: true,
                    communication_lease: None,
                },
            )]
            .into_iter()
            .collect(),
        );

        registry
            .apply(SovdIdentities::new(
                live_ecus(&["MYECU"]),
                live_groups(&["MYGROUP"]),
            ))
            .await;
        let updated_ecu = registry.ecu("myecu").unwrap();
        assert!(!Arc::ptr_eq(&ecu_state, &updated_ecu));
        assert!(lock_read(&updated_ecu.service_executions).is_empty());
        assert!(!Arc::ptr_eq(
            &group_state,
            &registry.functional_group("mygroup").unwrap()
        ));

        registry.apply(SovdIdentities::default()).await;
        assert!(registry.ecu("myecu").is_none());
        assert!(registry.functional_group("mygroup").is_none());

        registry
            .apply(SovdIdentities::new(
                live_ecus(&["myecu"]),
                live_groups(&["mygroup"]),
            ))
            .await;
        let readded_ecu = registry.ecu("MYECU").unwrap();
        assert!(!Arc::ptr_eq(&updated_ecu, &readded_ecu));
        assert!(lock_read(&readded_ecu.service_executions).is_empty());
    }

    #[tokio::test]
    async fn registry_growth_is_bounded_across_remove_readd_cycles() {
        let registry = SovdRegistry::default();
        for _ in 0..100 {
            registry
                .apply(SovdIdentities::new(
                    live_ecus(&["ECU"]),
                    live_groups(&["GROUP"]),
                ))
                .await;
            registry.apply(SovdIdentities::default()).await;
        }
        let state = std_ext::lock_mutex(&registry.state);
        assert!(state.ecus.is_empty());
        assert!(state.functional_groups.is_empty());
    }

    /// [[ test~deferred-sovd-admission, Deferred request admission triggers activation and returns a retry hint, test ]]
    #[test]
    fn communication_denial_requests_activation_and_returns_retry_hint() {
        let access = DeferredCommunicationAccess {
            activation_requests: AtomicUsize::new(0),
        };

        let Err(error) = acquire_communication_activity(&access) else {
            panic!("disabled communication must reject acquisition");
        };

        assert_eq!(access.activation_requests.load(Ordering::SeqCst), 1);
        let ApiError::ServiceUnavailable {
            retry_after,
            vendor_code,
            ..
        } = error
        else {
            panic!("disabled communication must return service unavailable");
        };
        assert_eq!(retry_after, Some(Duration::from_secs(7)));
        assert_eq!(vendor_code, Some(VendorErrorCode::CommunicationNotReady));
    }

    #[test]
    fn request_guard_drop_resets_in_flight() {
        let exec_id = Uuid::new_v4();
        let mut entries = IndexMap::new();
        entries.insert(
            exec_id,
            ServiceExecution {
                parameters: serde_json::Map::new(),
                status: sovd_ecu::operations::ExecutionStatus::Running,
                in_flight: false,
                is_created: true,
                communication_lease: None,
            },
        );
        let executions = StdRwLock::new(HashMap::from_iter([("routine".to_owned(), entries)]));

        let Ok(request_guard) = guard_execution(
            &executions,
            "routine",
            exec_id,
            false,
            "execution already in flight",
        ) else {
            panic!("execution must be guarded");
        };
        assert!(
            lock_read(&executions)
                .get("routine")
                .and_then(|entries| entries.get(&exec_id))
                .is_some_and(|execution| execution.in_flight)
        );

        drop(request_guard);

        assert!(
            lock_read(&executions)
                .get("routine")
                .and_then(|entries| entries.get(&exec_id))
                .is_some_and(|execution| !execution.in_flight)
        );
    }

    #[test]
    fn reservation_drop_releases_execution_and_lease() {
        let executions = Arc::new(StdRwLock::new(HashMap::default()));
        let access = CountingCommunicationAccess {
            active: Arc::new(()),
        };

        let Ok(reservation) = acquire_and_reserve_execution::<ServiceExecution>(
            &access,
            Arc::clone(&executions),
            "routine",
            "routine",
            false,
        ) else {
            panic!("enabled communication must reserve execution");
        };
        let id = reservation.exec_id;

        assert_eq!(Arc::strong_count(&access.active), 2);
        assert!(
            lock_read(&executions)
                .get("routine")
                .is_some_and(|entries| entries.contains_key(&id))
        );

        drop(reservation);

        assert_eq!(Arc::strong_count(&access.active), 1);
        assert!(lock_read(&executions).get("routine").is_none());
    }

    #[test]
    fn comparam_execution_removal_releases_lease() {
        let access = CountingCommunicationAccess {
            active: Arc::new(()),
        };
        let Ok(communication_guard) = access.acquire() else {
            panic!("enabled communication must provide a guard");
        };
        let id = Uuid::new_v4();
        let mut executions = IndexMap::new();
        executions.insert(
            id,
            ComparamExecution::new(
                sovd_ecu::operations::comparams::Execution {
                    capability: sovd_ecu::operations::comparams::executions::Capability::Execute,
                    status: sovd_ecu::operations::comparams::executions::Status::Running,
                    comparam_override: HashMap::default(),
                },
                communication_guard,
            ),
        );

        assert_eq!(Arc::strong_count(&access.active), 2);
        executions.shift_remove(&id);
        assert_eq!(Arc::strong_count(&access.active), 1);
    }

    #[test]
    fn async_handoff_preserves_execution_and_releases_lease_on_completion() {
        let executions = Arc::new(StdRwLock::new(HashMap::default()));
        let access = CountingCommunicationAccess {
            active: Arc::new(()),
        };
        let Ok(reservation) = acquire_and_reserve_execution::<ServiceExecution>(
            &access,
            Arc::clone(&executions),
            "routine",
            "routine",
            false,
        ) else {
            panic!("enabled communication must reserve execution");
        };

        let id = reservation.commit_async(|execution| {
            execution
                .parameters
                .insert("result".to_owned(), serde_json::json!("ok"));
        });

        assert_eq!(Arc::strong_count(&access.active), 2);
        let mut executions_guard = lock_write(&executions);
        let execution = executions_guard
            .get_mut("routine")
            .and_then(|entries| entries.get_mut(&id))
            .expect("async execution");
        assert!(execution.is_created && !execution.in_flight);
        execution.complete();
        drop(executions_guard);

        assert_eq!(Arc::strong_count(&access.active), 1);
        assert!(
            lock_read(&executions)
                .get("routine")
                .is_some_and(|entries| entries.contains_key(&id))
        );
    }

    #[test]
    fn failed_reservation_releases_acquired_lease() {
        let mut entries = IndexMap::new();
        entries.insert(
            Uuid::new_v4(),
            ServiceExecution {
                parameters: serde_json::Map::new(),
                status: sovd_ecu::operations::ExecutionStatus::Running,
                in_flight: false,
                is_created: true,
                communication_lease: None,
            },
        );
        let mut execution_map = HashMap::default();
        execution_map.insert("routine".to_owned(), entries);
        let executions = Arc::new(StdRwLock::new(execution_map));
        let access = CountingCommunicationAccess {
            active: Arc::new(()),
        };

        let result = acquire_and_reserve_execution::<ServiceExecution>(
            &access, executions, "routine", "routine", false,
        );
        let Err(error) = result else {
            panic!("second running execution must be rejected");
        };

        assert!(matches!(error.error, ApiError::Conflict(_)));
        assert_eq!(Arc::strong_count(&access.active), 1);
    }

    async fn ecu_lock_names(locks: &Locks) -> Vec<String> {
        let ReadLock::HashMapLock(entries) = locks.ecu.lock_ro().await else {
            panic!("ECU lock has the wrong shape");
        };
        let mut names: Vec<_> = entries.keys().cloned().collect();
        names.sort();
        names
    }

    #[tokio::test]
    async fn topology_reservation_defers_lock_reads_until_published() {
        let provider = Arc::new(SovdLockStateProvider::new(vec!["A".to_owned()]));
        let reservation = provider
            .reserve_lock_resources(vec!["B".to_owned()])
            .await
            .unwrap();
        let resolving = {
            let provider = Arc::clone(&provider);
            tokio::spawn(async move { provider.view().current_locks().await })
        };
        tokio::task::yield_now().await;
        assert!(!resolving.is_finished());

        drop(reservation);
        let resolved = resolving.await.unwrap();
        assert_eq!(ecu_lock_names(&resolved).await, ["A"]);
    }

    /// The vehicle lock is not part of the topology at all, so it stays
    /// obtainable while a preflight holds the topology write guard - an update
    /// reaches its own owner without waiting on its own preflight.
    #[tokio::test]
    async fn stable_vehicle_lock_bypasses_topology_reservation() {
        let provider = Arc::new(SovdLockStateProvider::new(vec!["A".to_owned()]));
        let view = provider.view();
        let reservation = provider
            .reserve_lock_resources(vec!["B".to_owned()])
            .await
            .unwrap();
        let resolving = {
            let provider = Arc::clone(&provider);
            tokio::spawn(async move { provider.view().current_locks().await })
        };
        tokio::task::yield_now().await;
        assert!(!resolving.is_finished());

        tokio::time::timeout(Duration::from_millis(100), view.vehicle_lock().lock_ro())
            .await
            .expect("the stable vehicle lock must not wait for topology reservation");

        drop(reservation);
        resolving.await.unwrap();
    }

    /// A held ECU lock vetoes a topology *change*, never a reservation of the
    /// topology already live: recovery re-reserves the current state with those
    /// same locks still held.
    #[tokio::test]
    async fn held_ecu_lock_rejects_topology_preparation() {
        let provider = SovdLockStateProvider::new(vec!["A".to_owned()]);
        let view = provider.view();
        let current = view.current_locks().await;
        crate::sovd::locks::insert_test_ecu_lock(&current, "A").await;
        drop(current);

        // `let Err(..) else`, not `unwrap_err`: the success type is a
        // `Box<dyn PreparedApply>`, which has no `Debug`.
        let Err(error) = provider.reserve_lock_resources(vec!["B".to_owned()]).await else {
            panic!("held ECU lock must reject topology preflight")
        };
        assert!(error.to_string().contains("ECU"), "{error}");
        assert_eq!(ecu_lock_names(&*view.current_locks().await).await, ["A"]);

        // Persistent recovery reserves the previous A state. Its lock topology
        // is already live, so the held A lock does not block recovery.
        provider
            .reserve_lock_resources(vec!["A".to_owned()])
            .await
            .expect("recovery to the live topology is always admitted")
            .apply();
        assert_eq!(ecu_lock_names(&*view.current_locks().await).await, ["A"]);
    }

    pub async fn create_test_webserver_state<T: UdsEcu + Clone>(
        ecu_name: String,
        uds: T,
    ) -> WebserverEcuState<T> {
        let lock_provider = Arc::new(SovdLockStateProvider::new(vec![ecu_name.clone()]).view());
        WebserverEcuState {
            ecu_name,
            uds,
            locks: lock_provider.current_locks().await,
            lock_provider,
            entry: Arc::new(EcuRegistryEntry::default()),
            communication_access: enabled_communication_access_for_test(),
            flash_data: Arc::new(RwLock::new(FileList {
                files: Vec::new(),
                path: Some(PathBuf::new()),
                schema: None,
            })),
        }
    }
}
