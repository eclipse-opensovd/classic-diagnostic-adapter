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

use std::{path::PathBuf, sync::Arc};

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
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Response},
};
use axum_extra::extract::WithRejection;
use cda_interfaces::{
    Connectivity, FunctionalDescriptionConfig, HashMap, HashMapExtensions as _, SchemaProvider,
    UdsEcu, VariantState,
    datatypes::ComponentsConfig,
    diagservices::{FieldParseError, UdsPayloadData},
    file_manager::FileManager,
    runtime_update_api::LockStateProvider,
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
use tokio::sync::RwLock;
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
pub mod execution_registry;
pub(crate) mod functions;
pub(crate) mod locks;
pub mod update_guard;

pub use execution_registry::EcuExecutionRegistry;

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

#[derive(Debug, thiserror::Error)]
pub(crate) enum SovdError {
    #[error("Failed to create route: {0}")]
    RouteError(String),
}

#[derive(Clone)]
pub(crate) struct WebserverEcuState<T: UdsEcu + Clone, U: FileManager> {
    ecu_name: String,
    uds: T,
    locks: Arc<Locks>,
    // Map of Execution Id -> ComParamMap
    comparam_executions: Arc<RwLock<IndexMap<Uuid, sovd_ecu::operations::comparams::Execution>>>,
    // Map of Service Name -> (Execution Id -> ServiceExecution) for ECU routine operations
    pub(crate) service_executions: Arc<RwLock<HashMap<String, IndexMap<Uuid, ServiceExecution>>>>,
    flash_data: Arc<RwLock<sovd_interfaces::sovd2uds::FileList>>,
    mdd_embedded_files: Arc<U>,
    update_in_progress: Arc<std::sync::atomic::AtomicBool>,
}

/// Shared behaviour for execution-state types (`ServiceExecution` for single-ECU
/// operations, `FgServiceExecution` for functional-group operations).
pub(crate) trait ExecutionStatus {
    fn execution_status(&self) -> &sovd_ecu::operations::ExecutionStatus;
    /// Returns `true` if a request for this execution is currently being processed.
    /// Used to avoid sending multiple UDS requests simultaneously for the same execution.
    fn is_in_flight(&self) -> bool;
    fn set_in_flight(&mut self, in_flight: bool);
    /// Should return `false` if an execution was created as a placeholder,
    /// but not finalized.
    fn is_created(&self) -> bool;
    fn set_created(&mut self, created: bool);
    /// Creates a placeholder entry used to reserve a slot in the executions map
    /// before the UDS command is sent.
    fn placeholder() -> Self
    where
        Self: Sized;
}

/// Stored state for a single ECU routine execution (async lifecycle).
#[derive(Clone, Debug)]
pub(crate) struct ServiceExecution {
    pub parameters: serde_json::Map<String, serde_json::Value>,
    pub status: sovd_ecu::operations::ExecutionStatus,
    pub in_flight: bool,
    pub is_created: bool,
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
    fn placeholder() -> Self {
        ServiceExecution {
            parameters: serde_json::Map::new(),
            status: sovd_ecu::operations::ExecutionStatus::Running,
            in_flight: false,
            is_created: false,
        }
    }
}

/// Stored state for a functional-group routine execution (async lifecycle).
/// Unlike `ServiceExecution`, parameters are keyed by ECU name so that
/// per-ECU identity is preserved across the execution lifecycle.
#[derive(Clone, Debug)]
pub(crate) struct FgServiceExecution {
    pub parameters: HashMap<String, serde_json::Map<String, serde_json::Value>>,
    pub status: sovd_ecu::operations::ExecutionStatus,
    pub in_flight: bool,
    pub is_created: bool,
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
    fn placeholder() -> Self {
        FgServiceExecution {
            parameters: HashMap::new(),
            status: sovd_ecu::operations::ExecutionStatus::Running,
            in_flight: false,
            is_created: false,
        }
    }
}

/// Implementation of [`LockStateProvider`] that reads from the in-memory [`Locks`] state.
pub struct SovdLockStateProvider {
    locks: Arc<RwLock<Arc<Locks>>>,
}

impl SovdLockStateProvider {
    /// Creates a new provider wrapping the given shared [`Locks`] state.
    #[must_use]
    pub fn new(locks: Arc<Locks>) -> Self {
        Self {
            locks: Arc::new(RwLock::new(locks)),
        }
    }

    /// Updates the ECU and functional-group entries in the current locks in-place,
    /// preserving only the vehicle lock.
    ///
    /// # Errors
    /// Returns an error if any ECU or functional-group lock is currently held.
    pub async fn update_entries(
        &self,
        new_ecu_names: Vec<String>,
    ) -> Result<(), locks::LockUpdateError> {
        let locks = self.locks.read().await.clone();
        locks.update_entries(new_ecu_names).await
    }

    pub async fn current_locks(&self) -> Arc<Locks> {
        self.locks.read().await.clone()
    }
}

#[async_trait]
impl LockStateProvider for SovdLockStateProvider {
    async fn vehicle_lock_owner_sub(&self) -> Option<String> {
        let locks = self.locks.read().await.clone();
        let vehicle_lock = locks.vehicle.lock_ro().await;
        match &vehicle_lock {
            ReadLock::OptionLock(l) => l.as_ref().map(|l| l.owner().to_owned()),
            ReadLock::HashMapLock(_) => None,
        }
    }

    async fn has_non_vehicle_locks(&self) -> bool {
        let locks = self.locks.read().await.clone();
        let ecu_lock = locks.ecu.lock_ro().await;
        let fg_lock = locks.functional_group.lock_ro().await;
        ecu_lock.is_any_locked() || fg_lock.is_any_locked()
    }
}

/// Acquires a write lock on `executions`, looks up `exec_id` under the given
/// `service` key, marks it `in_flight = true`, and returns a clone of the
/// execution.  Returns `Err(ErrorWrapper)` (with the lock released) on
/// not-found or in-flight conflict.
pub(crate) async fn guard_execution<T: ExecutionStatus + Clone>(
    executions: &RwLock<HashMap<String, IndexMap<Uuid, T>>>,
    service: &str,
    exec_id: Uuid,
    include_schema: bool,
    conflict_msg: &str,
) -> Result<T, error::ErrorWrapper> {
    let mut guard = executions.write().await;
    let op_map = guard
        .get_mut(service)
        .and_then(|m| m.get_mut(&exec_id))
        // Treat placeholders (is_created == false) as non-existent.
        .filter(|e| e.is_created());
    match op_map {
        None => Err(error::ErrorWrapper {
            error: error::ApiError::NotFound(Some(format!(
                "Execution with id {exec_id} not found"
            ))),
            include_schema,
        }),
        Some(exec) if exec.is_in_flight() => Err(error::ErrorWrapper {
            error: error::ApiError::Conflict(conflict_msg.to_owned()),
            include_schema,
        }),
        Some(exec) => {
            exec.set_in_flight(true);
            Ok(exec.clone())
        }
    }
}

/// Checks for a running-execution conflict and, if none exists,
/// inserts a placeholder entry so that a second concurrent POST for the same
/// operation will see a `409 Conflict`.
///
/// On success the returned [`Uuid`] identifies the reserved execution slot.
/// The caller **must** later call either [`finalize_execution`] (async
/// success) or [`remove_reserved_execution`] (sync success / any error).
pub(crate) async fn reserve_execution<E: ExecutionStatus>(
    executions: &RwLock<HashMap<String, IndexMap<Uuid, E>>>,
    service: &str,
    display_name: &str,
    include_schema: bool,
    update_in_progress: &std::sync::atomic::AtomicBool,
) -> Result<Uuid, error::ErrorWrapper> {
    let mut guard = executions.write().await;
    if update_in_progress.load(std::sync::atomic::Ordering::Acquire) {
        return Err(error::ErrorWrapper {
            error: ApiError::Conflict("Runtime update in progress, operation blocked".to_owned()),
            include_schema,
        });
    }
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
    let id = Uuid::new_v4();
    let mut entry = E::placeholder();
    entry.set_in_flight(true);
    guard
        .entry(service.to_owned())
        .or_default()
        .insert(id, entry);
    Ok(id)
}

/// Updates a previously reserved execution with the received parameters,
/// sets `is_created(true)`, and clears the `in_flight` flag.
/// After this step GET/DELETE requests can be called for this execution.
pub(crate) async fn finalize_execution<E: ExecutionStatus>(
    executions: &RwLock<HashMap<String, IndexMap<Uuid, E>>>,
    service: &str,
    exec_id: &Uuid,
    update_fn: impl FnOnce(&mut E),
) {
    let mut guard = executions.write().await;
    if let Some(exec) = guard.get_mut(service).and_then(|m| m.get_mut(exec_id)) {
        update_fn(exec);
        exec.set_created(true);
        exec.set_in_flight(false);
    }
}

/// Removes a previously reserved execution slot.  Called on error or after
/// a synchronous operation completes (sync operations do not persist
/// execution state).
pub(crate) async fn remove_reserved_execution<E: ExecutionStatus>(
    executions: &RwLock<HashMap<String, IndexMap<Uuid, E>>>,
    service: &str,
    exec_id: &Uuid,
) {
    let mut guard = executions.write().await;
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
    locks: Arc<Locks>,
    flash_data: Arc<RwLock<sovd_interfaces::sovd2uds::FileList>>,
    components_config: Arc<RwLock<ComponentsConfig>>,
    update_in_progress: Arc<std::sync::atomic::AtomicBool>,
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

pub async fn route<T: UdsEcu + SchemaProvider + Clone, U: FileManager, S: SecurityPluginLoader>(
    functional_group_config: FunctionalDescriptionConfig,
    components_config: ComponentsConfig,
    uds: &T,
    flash_files_path: String,
    mut file_manager: HashMap<String, U>,
    locks: Arc<Locks>,
    update_in_progress: Arc<std::sync::atomic::AtomicBool>,
) -> (Router, EcuExecutionRegistry) {
    let flash_data = Arc::new(RwLock::new(sovd_interfaces::sovd2uds::FileList {
        files: Vec::new(),
        path: Some(PathBuf::from(flash_files_path)),
        schema: None,
    }));
    let state = WebserverState {
        uds: uds.clone(),
        locks,
        flash_data: Arc::clone(&flash_data),
        components_config: Arc::new(RwLock::new(components_config)),
        update_in_progress,
    };

    let registry = EcuExecutionRegistry::default();
    let router = components_route::<T, U>(state.clone(), &mut file_manager, &registry).await;

    let vehicle_router = vehicle_route::<T, S>(state, router, functional_group_config)
        .await
        .layer(middleware::from_fn(security_plugin_middleware::<S>))
        .with_state(uds.clone());
    (vehicle_router, registry)
}

async fn vehicle_route<T: UdsEcu + SchemaProvider + Clone, S: SecurityPluginLoader>(
    state: WebserverState<T>,
    router: Router<WebserverState<T>>,
    functional_group_config: FunctionalDescriptionConfig,
) -> Router<T> {
    let router = router.nest_api_service(
        "/vehicle/v15/functions",
        functions::functional_groups::create_functional_group_routes(
            state.clone(),
            functional_group_config,
        )
        .await,
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
        .route("/vehicle/v15/apps", routing::get(apps::get))
        .route(
            "/vehicle/v15/apps/sovd2uds",
            routing::get(apps::sovd2uds::get),
        )
        .route(
            "/vehicle/v15/apps/sovd2uds/bulk-data",
            routing::get(apps::sovd2uds::bulk_data::get),
        )
        .api_route(
            "/vehicle/v15/apps/sovd2uds/bulk-data/flashfiles",
            routing::get_with(
                apps::sovd2uds::bulk_data::flash_files::get,
                apps::sovd2uds::bulk_data::flash_files::docs_get,
            ),
        )
        .route("/vehicle/v15/authorize", routing::post(S::authorize))
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

async fn components_route<T: UdsEcu + SchemaProvider + Clone, U: FileManager + 'static>(
    state: WebserverState<T>,
    file_manager: &mut HashMap<String, U>,
    registry: &EcuExecutionRegistry,
) -> Router<WebserverState<T>> {
    let mut router = Router::new().api_route(
        "/vehicle/v15/components",
        get_with(get_components, docs_components),
    );
    let mut ecus = state.uds.get_physical_ecus().await;
    for ecu_name in ecus.drain(0..) {
        match ecu_route::<T, U>(&ecu_name, &state, file_manager, registry).await {
            Ok((ecu_path, nested)) => {
                router = router.nest_api_service(&ecu_path, nested);
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to create route for ECU '{ecu_name}'");
            }
        }
    }
    router.with_state(state)
}

#[allow(
    clippy::too_many_lines,
    reason = "Route creation kept together for structural clarity"
)]
async fn ecu_route<T: UdsEcu + SchemaProvider + Clone, U: FileManager + 'static>(
    ecu_name: &str,
    state: &WebserverState<T>,
    file_manager: &mut HashMap<String, U>,
    registry: &EcuExecutionRegistry,
) -> Result<(String, Router), SovdError> {
    let ecu_lower = ecu_name.to_lowercase();
    let ecu_state = WebserverEcuState {
        ecu_name: ecu_lower.clone(),
        uds: state.uds.clone(),
        locks: Arc::<Locks>::clone(&state.locks),
        comparam_executions: Arc::new(RwLock::new(IndexMap::new())),
        service_executions: Arc::new(RwLock::new(HashMap::default())),
        flash_data: Arc::clone(&state.flash_data),
        mdd_embedded_files: Arc::new(file_manager.remove(&ecu_lower).ok_or_else(|| {
            SovdError::RouteError(format!(
                "FileManager for ECU '{ecu_name}' not found in provided FileManager map"
            ))
        })?),
        update_in_progress: Arc::clone(&state.update_in_progress),
    };
    registry
        .register(
            Arc::clone(&ecu_state.comparam_executions),
            Arc::clone(&ecu_state.service_executions),
        )
        .await;
    let ecu_path = format!("/vehicle/v15/components/{ecu_lower}");

    let router = Router::new()
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
        .route(
            "/x-sovd2uds-download",
            routing::get(x_sovd2uds_download::get),
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
        .route(
            "/x-sovd2uds-bulk-data",
            routing::get(x_sovd2uds_bulk_data::get),
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
        .with_state(ecu_state)
        .with_path_items(|op| op.tag(ecu_name));

    Ok((ecu_path, router))
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
                if let Some(mut errs) = obj.get_mut("errors") {
                    crate::sovd::remove_descriptions_recursive(&mut errs);
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

    use cda_interfaces::{UdsEcu, file_manager::FileManager};
    use sovd_interfaces::sovd2uds::FileList;

    use super::*;
    use crate::sovd::locks::LockType;

    pub fn create_test_webserver_state<T: UdsEcu + Clone, U: FileManager>(
        ecu_name: String,
        uds: T,
        file_manager: U,
    ) -> WebserverEcuState<T, U> {
        WebserverEcuState {
            ecu_name: ecu_name.clone(),
            uds,
            locks: Arc::new(Locks {
                vehicle: LockType::Vehicle(Arc::new(RwLock::new(None))),
                ecu: LockType::Ecu(Arc::new(RwLock::new(
                    [(ecu_name, None)].into_iter().collect(),
                ))),
                functional_group: LockType::FunctionalGroup(Arc::new(RwLock::new(
                    HashMap::default(),
                ))),
            }),
            comparam_executions: Arc::new(RwLock::new(IndexMap::new())),
            service_executions: Arc::new(RwLock::new(HashMap::default())),
            flash_data: Arc::new(RwLock::new(FileList {
                files: Vec::new(),
                path: Some(PathBuf::new()),
                schema: None,
            })),
            mdd_embedded_files: Arc::new(file_manager),
            update_in_progress: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }
}
