/*
 * Copyright (c) 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
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

use auth::authorize;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing,
};
use cda_interfaces::{
    DiagComm, DiagCommAction, DiagCommType, UdsEcu,
    datatypes::{ComponentConfigurationsInfo, ComponentDataInfo, SdSdg},
    diagservices::{DiagServiceResponse, DiagServiceResponseType, UdsPayloadData},
    file_manager::FileManager,
};
use error::{ApiError, ErrorWrapper, api_error_from_diag_response};
use hashbrown::HashMap;
use http::{Uri, header};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::sovd::{
    locking::{
        LockType, Locks, delete_ecu_lock_handler, delete_functionalgroup_lock_handler,
        delete_vehicle_lock_handler, get_ecu_active_lock, get_ecu_locks_handler,
        get_functionalgroup_active_lock, get_functionalgroup_lock_handler, get_vehicle_active_lock,
        get_vehicle_locks_handler, post_ecu_locks_handler, post_functionalgroup_locks_handler,
        post_vehicle_lock_handler, put_ecu_lock_handler, put_functionalgroup_lock_handler,
        put_vehicle_lock_handler,
    },
    operations::{comparams, executions},
};

mod apps;
mod auth;
pub(crate) mod error;
mod jobs;
pub(crate) mod locking;
mod modes;
mod operations;
mod x_sovd2uds_bulk_data;
mod x_sovd2uds_download;

trait SovdPayload {
    fn get_data_map(&self) -> HashMap<String, serde_json::Value>;
}

#[derive(Deserialize)]
struct DataRequestPayload {
    data: HashMap<String, serde_json::Value>,
}

impl SovdPayload for DataRequestPayload {
    fn get_data_map(&self) -> HashMap<String, serde_json::Value> {
        self.data.clone()
    }
}

#[derive(Serialize)]
struct Resource {
    href: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    name: String,
}

#[derive(Deserialize, Serialize, Debug)]
struct SovdItems<T> {
    items: Vec<T>,
}

type ResourceItems = SovdItems<Resource>;

#[derive(Serialize)]
struct EcuStruct {
    id: String,
    name: String,
    variant: String,
    locks: String,
    operations: String,
    data: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sdgs: Option<Vec<SdSdg>>,
    #[serde(rename = "x-single-ecu-jobs")]
    single_ecu_jobs: String,
}

#[derive(Serialize)]
struct ServicesSdgs {
    items: HashMap<String, ServiceSdgs>,
}
#[derive(Serialize)]
struct ServiceSdgs {
    sdgs: Vec<SdSdg>,
}

#[derive(Deserialize)]
struct DiagServiceQuery {
    #[serde(rename = "x-include-sdgs")]
    include_sdgs: Option<bool>,
}
#[derive(Deserialize)]
struct ComponentQuery {
    #[serde(rename = "x-include-sdgs")]
    include_sdgs: Option<bool>,
}

#[derive(Serialize)]
struct SovdFileList {
    #[serde(rename = "items")]
    files: Vec<SovdFile>,
    #[serde(skip_serializing)]
    path: Option<PathBuf>,
}

#[derive(Serialize, Debug, Clone)]
struct SovdFile {
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash_algorithm: Option<HashAlgorithm>,
    id: String,
    mimetype: String,
    size: u64,
    #[serde(rename = "x-sovd2uds-OrigPath")]
    origin_path: String,
}

#[derive(Serialize, Debug, Clone)]
enum HashAlgorithm {
    None,
    // todo out of scope for POC: support hashing algorithms
}

pub(crate) struct WebserverEcuState<
    R: DiagServiceResponse,
    T: UdsEcu + Send + Sync + Clone,
    U: FileManager + Send + Sync + Clone,
> {
    ecu_name: String,
    uds: T,
    locks: Arc<Locks>,
    // Map of Execution Id -> ComParamMap
    comparam_executions: Arc<RwLock<IndexMap<Uuid, comparams::Execution>>>,
    flash_data: Arc<RwLock<SovdFileList>>,
    mdd_embedded_files: Arc<U>,
    _phantom: std::marker::PhantomData<R>,
}

impl<R: DiagServiceResponse, T: UdsEcu + Send + Sync + Clone, U: FileManager + Send + Sync + Clone>
    Clone for WebserverEcuState<R, T, U>
{
    fn clone(&self) -> Self {
        Self {
            ecu_name: self.ecu_name.clone(),
            uds: self.uds.clone(),
            locks: self.locks.clone(),
            comparam_executions: self.comparam_executions.clone(),
            flash_data: self.flash_data.clone(),
            mdd_embedded_files: self.mdd_embedded_files.clone(),
            _phantom: std::marker::PhantomData::<R>,
        }
    }
}

#[derive(Clone)]
pub(crate) struct WebserverState {
    locks: Arc<Locks>,
    flash_data: Arc<RwLock<SovdFileList>>,
}

pub(in crate::sovd) fn resource_response(
    host: &str,
    uri: &Uri,
    resources: Vec<(&str, Option<&str>)>,
) -> Response {
    let base_path = format!("http://{host}{uri}");
    let items = resources
        .into_iter()
        .map(|(name, href)| Resource {
            name: name.to_string(),
            href: format!("{base_path}/{}", href.unwrap_or(name)),
            id: None,
        })
        .collect();

    let components = ResourceItems { items };
    (StatusCode::OK, Json(components)).into_response()
}

#[allow(clippy::too_many_lines)] // todo refactor this, to solve the warning
pub async fn route<
    R: DiagServiceResponse,
    T: UdsEcu + Send + Sync + Clone + 'static,
    U: FileManager + Send + Sync + Clone + 'static,
>(
    uds: &T,
    flash_files_path: String,
    mut file_manager: HashMap<String, U>,
) -> Router {
    let mut ecu_names = uds.get_ecus().await;

    let flash_data = Arc::new(RwLock::new(SovdFileList {
        files: Vec::new(),
        path: Some(PathBuf::from(flash_files_path)),
    }));
    let state = WebserverState {
        locks: Arc::new(Locks {
            vehicle: LockType::Vehicle(Arc::new(RwLock::new(None))),
            ecu: LockType::Ecu(Arc::new(RwLock::new(
                ecu_names.iter().map(|ecu| (ecu.clone(), None)).collect(),
            ))),
            functional_group: LockType::FunctionalGroup(Arc::new(RwLock::new(HashMap::new()))),
        }),
        flash_data: Arc::clone(&flash_data),
    };

    let ecus = ecu_names.clone();
    let mut router = Router::new().route(
        "/vehicle/v15/components",
        routing::get(|| async move {
            (
                StatusCode::OK,
                Json(ResourceItems {
                    items: ecus
                        .iter()
                        .map(|ecu| Resource {
                            href: format!("http://localhost:20002/Vehicle/v15/components/{ecu}"),
                            id: Some(ecu.to_lowercase()),
                            name: ecu.clone(),
                        })
                        .collect::<Vec<Resource>>(),
                }),
            )
                .into_response()
        }),
    );

    for ecu_name in ecu_names.drain(0..) {
        let ecu_lower = ecu_name.to_lowercase();
        let ecu_state = WebserverEcuState {
            ecu_name: ecu_lower.clone(),
            uds: uds.clone(),
            locks: Arc::<Locks>::clone(&state.locks),
            comparam_executions: Arc::new(RwLock::new(IndexMap::new())),
            flash_data: Arc::clone(&flash_data),
            mdd_embedded_files: Arc::new(file_manager.remove(&ecu_lower).unwrap()),
            _phantom: std::marker::PhantomData::<R>,
        };
        let ecu_path = format!("/vehicle/v15/components/{ecu_lower}");

        let nested = Router::new()
            .route(
                "/",
                routing::get(get_component_handler)
                    .post(post_and_put_component_handler)
                    .put(post_and_put_component_handler),
            )
            .route(
                "/locks",
                routing::post(post_ecu_locks_handler).get(get_ecu_locks_handler),
            )
            .route(
                "/locks/{lock}",
                routing::delete(delete_ecu_lock_handler)
                    .put(put_ecu_lock_handler)
                    .get(get_ecu_active_lock),
            )
            .route("/configurations", routing::get(ecu_configuration_handler))
            .route("/data", routing::get(ecu_data_handler))
            .route(
                "/data/{service}",
                routing::get(get_diag_service_data_handler)
                    .post(post_diag_service_data_handler)
                    .put(put_diag_service_data_handler),
            )
            .route(
                "/operations/comparam/executions",
                routing::get(comparams::get_executions_handler)
                    .post(comparams::post_executions_handler),
            )
            .route(
                "/operations/comparam/executions/{id}",
                routing::get(comparams::get_execution_handler)
                    .delete(comparams::delete_execution_handler)
                    .put(comparams::update_execution_handler),
            )
            .route(
                "/operations/{service}/executions",
                routing::get(executions::get_ecu_operation_handler)
                    .post(executions::post_ecu_operation_handler),
            )
            .route(
                "/x-single-ecu-jobs",
                routing::get(jobs::single_ecu::get_ecu_single_job_handler),
            )
            .route(
                "/x-single-ecu-jobs/{name}",
                routing::get(jobs::single_ecu::get_ecu_single_jobs_handler),
            )
            .route("/modes", routing::get(modes::get_modes))
            .route(
                "/modes/session",
                routing::get(modes::session::get_session).put(modes::session::put_session),
            )
            .route(
                "/modes/security",
                routing::get(modes::security::get_security).put(modes::security::put_security),
            )
            .route(
                "/x-sovd2uds-download",
                routing::get(x_sovd2uds_download::get),
            )
            .route(
                "/x-sovd2uds-download/requestdownload",
                routing::put(x_sovd2uds_download::request_download::put),
            )
            .route(
                "/x-sovd2uds-download/flashtransfer",
                routing::post(x_sovd2uds_download::flashtransfer::post)
                    .get(x_sovd2uds_download::flashtransfer::get),
            )
            .route(
                "/x-sovd2uds-download/flashtransfer/{id}",
                routing::get(x_sovd2uds_download::flashtransfer::get_id)
                    .delete(x_sovd2uds_download::flashtransfer::delete),
            )
            .route(
                "/x-sovd2uds-download/transferexit",
                routing::put(x_sovd2uds_download::transferexit::put),
            )
            .route(
                "/x-sovd2uds-bulk-data",
                routing::get(x_sovd2uds_bulk_data::get),
            )
            .route(
                "/x-sovd2uds-bulk-data/mdd-embedded-files",
                routing::get(x_sovd2uds_bulk_data::mdd_embedded_files::get),
            )
            .route(
                "/x-sovd2uds-bulk-data/mdd-embedded-files/{id}",
                routing::get(x_sovd2uds_bulk_data::mdd_embedded_files::get_id),
            )
            .with_state(ecu_state);
        router = router.nest(&ecu_path, nested);
    }
    router
        .route(
            "/vehicle/v15/locks",
            routing::post(post_vehicle_lock_handler).get(get_vehicle_locks_handler),
        )
        .route(
            "/vehicle/v15/locks/{lock}",
            routing::delete(delete_vehicle_lock_handler)
                .put(put_vehicle_lock_handler)
                .get(get_vehicle_active_lock),
        )
        .route(
            "/vehicle/v15/functions/functionalgroups/{group}/locks",
            routing::post(post_functionalgroup_locks_handler).get(get_functionalgroup_lock_handler),
        )
        .route(
            "/vehicle/v15/functions/functionalgroups/{group}/locks/{lock}",
            routing::delete(delete_functionalgroup_lock_handler)
                .put(put_functionalgroup_lock_handler)
                .get(get_functionalgroup_active_lock),
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
        .route(
            "/vehicle/v15/apps/sovd2uds/bulk-data/flashfiles",
            routing::get(apps::sovd2uds::bulk_data::flash_files::get),
        )
        .route("/vehicle/v15/authorize", routing::post(authorize))
        .with_state(state)
        .route(
            // todo move this into the apps module
            "/vehicle/v15/apps/sovd2uds/data/networkstructure",
            routing::get(|State(gateway): State<T>| async move {
                let networkstructure_data =
                    match serde_json::to_value(vec![gateway.get_network_structure().await]) {
                        Ok(v) => v,
                        Err(e) => {
                            return ErrorWrapper(ApiError::InternalServerError(Some(format!(
                                "Failed to create network structure json: {e:?}"
                            ))))
                            .into_response();
                        }
                    };

                (
                    StatusCode::OK,
                    Json(SovdDataItem {
                        id: "networkstructure".to_owned(),
                        data: networkstructure_data,
                    }),
                )
                    .into_response()
            }),
        )
        .with_state(uds.clone())
}

async fn get_component_handler<
    R: DiagServiceResponse + Send + Sync,
    T: UdsEcu + Send + Sync + Clone,
    U: FileManager + Send + Sync + Clone,
>(
    State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
    Query(query): Query<ComponentQuery>,
) -> Response {
    let base_path = format!("http://localhost:20002/vehicle/v15/components/{ecu_name}");
    let variant = match uds.get_variant(&ecu_name).await {
        Ok(v) => v,
        Err(e) => return ErrorWrapper(ApiError::BadRequest(e)).into_response(),
    };

    let mut sdgs = None;
    if Some(true) == query.include_sdgs {
        sdgs = match uds
            .get_sdgs(&ecu_name, None)
            .await
            .map_err(ApiError::BadRequest)
        {
            Ok(v) => Some(v),
            Err(e) => return ErrorWrapper(e).into_response(),
        }
    }
    (
        StatusCode::OK,
        Json(EcuStruct {
            id: ecu_name.to_lowercase(),
            name: ecu_name.clone(),
            variant,
            locks: format!("{base_path}/locks"),
            operations: format!("{base_path}/operations"),
            data: format!("{base_path}/data"),
            sdgs,
            single_ecu_jobs: format!("{base_path}/x-single-ecu-jobs"),
        }),
    )
        .into_response()
}

async fn post_and_put_component_handler<
    R: DiagServiceResponse + Send + Sync,
    T: UdsEcu + Send + Sync + Clone,
    U: FileManager + Send + Sync + Clone,
>(
    State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
) -> Response {
    match uds.detect_variant(&ecu_name).await {
        Ok(()) => (StatusCode::CREATED, ()).into_response(),
        Err(e) => ErrorWrapper(ApiError::BadRequest(e)).into_response(),
    }
}

async fn ecu_configuration_handler<
    R: DiagServiceResponse + Send + Sync,
    T: UdsEcu + Send + Sync + Clone,
    U: FileManager + Send + Sync + Clone,
>(
    State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
) -> Response {
    match uds.get_components_configuration_info(&ecu_name).await {
        Ok(mut items) => {
            let sovd_component_configuration = SovdComponentConfigurations {
                items: items
                    .drain(0..)
                    .map(SovdComponentConfigurationsItem::from)
                    .collect::<Vec<SovdComponentConfigurationsItem>>(),
            };
            (StatusCode::OK, Json(sovd_component_configuration)).into_response()
        }
        Err(e) => ErrorWrapper(ApiError::from(e)).into_response(),
    }
}

async fn ecu_data_handler<
    R: DiagServiceResponse + Send + Sync,
    T: UdsEcu + Send + Sync + Clone,
    U: FileManager + Send + Sync + Clone,
>(
    State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
) -> Response {
    match uds.get_components_data_info(&ecu_name).await {
        Ok(mut items) => {
            let sovd_component_data = SovdComponentData {
                items: items.drain(0..).map(|info| info.into()).collect(),
            };
            (StatusCode::OK, Json(sovd_component_data)).into_response()
        }
        Err(e) => ErrorWrapper(ApiError::BadRequest(e)).into_response(),
    }
}

async fn get_diag_service_sdgs_handler<T: UdsEcu + Send + Sync + Clone>(
    service: String,
    ecu_name: &str,
    gateway: &T,
) -> Response {
    let service_ops = vec![
        DiagComm {
            name: service.clone(),
            action: DiagCommAction::Read,
            type_: DiagCommType::Data,
            lookup_name: None,
        },
        DiagComm {
            name: service.clone(),
            action: DiagCommAction::Write,
            type_: DiagCommType::Data,
            lookup_name: None,
        },
        DiagComm {
            name: service,
            action: DiagCommAction::Start,
            type_: DiagCommType::Data,
            lookup_name: None,
        },
    ];
    let mut resp = ServicesSdgs {
        items: HashMap::new(),
    };
    for service in service_ops {
        match gateway.get_sdgs(ecu_name, Some(&service)).await {
            Ok(sdgs) => {
                if sdgs.is_empty() {
                    continue;
                }
                resp.items.insert(
                    format!("{}_{:?}", service.name, service.action).to_lowercase(),
                    ServiceSdgs { sdgs },
                );
            }
            Err(e) => return ErrorWrapper(ApiError::BadRequest(e)).into_response(),
        }
    }
    (StatusCode::OK, Json(resp)).into_response()
}

async fn get_diag_service_data_handler<
    R: DiagServiceResponse + Send + Sync,
    T: UdsEcu + Send + Sync + Clone,
    U: FileManager + Send + Sync + Clone,
>(
    headers: HeaderMap,
    Path(service): Path<String>,
    Query(query): Query<DiagServiceQuery>,
    State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
    body: Bytes,
) -> Response {
    if Some(true) == query.include_sdgs {
        get_diag_service_sdgs_handler::<T>(service, &ecu_name, &uds).await
    } else {
        diag_service_data_request::<T>(Op::Read, service, &ecu_name, &uds, headers, body).await
    }
}

async fn post_diag_service_data_handler<
    R: DiagServiceResponse + Send + Sync,
    T: UdsEcu + Send + Sync + Clone,
    U: FileManager + Send + Sync + Clone,
>(
    headers: HeaderMap,
    Path(service): Path<String>,
    State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
    body: Bytes,
) -> Response {
    diag_service_data_request::<T>(Op::Write, service, &ecu_name, &uds, headers, body).await
}

async fn put_diag_service_data_handler<
    R: DiagServiceResponse + Send + Sync,
    T: UdsEcu + Send + Sync + Clone,
    U: FileManager + Send + Sync + Clone,
>(
    headers: HeaderMap,
    Path(service): Path<String>,
    State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
    body: Bytes,
) -> Response {
    diag_service_data_request::<T>(Op::Update, service, &ecu_name, &uds, headers, body).await
}

enum Op {
    Read,
    Write,
    Update,
}

async fn diag_service_data_request<T: UdsEcu + Send + Sync + Clone>(
    op: Op,
    service_name: String,
    ecu_name: &str,
    gateway: &T,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if service_name.contains('/') {
        return ErrorWrapper(ApiError::BadRequest("Invalid path".to_owned())).into_response();
    }
    let service = match op {
        Op::Read => DiagComm {
            name: service_name.clone(),
            action: DiagCommAction::Read,
            type_: DiagCommType::Data,
            lookup_name: None,
        },
        Op::Write | Op::Update => DiagComm {
            name: service_name.clone(),
            action: DiagCommAction::Write,
            type_: DiagCommType::Configurations,
            lookup_name: None,
        },
    };

    let data = match get_payload_data::<DataRequestPayload>(&headers, &body) {
        Ok(value) => value,
        Err(e) => return ErrorWrapper(e).into_response(),
    };

    let (response_mime, map_to_json) = match headers.get(header::ACCEPT) {
        Some(v)
            if v == mime::APPLICATION_JSON.essence_str() || v == mime::STAR_STAR.essence_str() =>
        {
            (Some(v), true)
        }
        Some(v) if v == mime::APPLICATION_OCTET_STREAM.essence_str() => (Some(v), false),
        Some(unsupported) => {
            return ErrorWrapper(ApiError::BadRequest(format!(
                "Unsupported Accept: {unsupported:?}"
            )))
            .into_response();
        }
        _ => (None, true),
    };

    let response = match gateway
        .send(ecu_name, service, data, map_to_json)
        .await
        .map_err(std::convert::Into::into)
    {
        Err(e) => return ErrorWrapper(e).into_response(),
        Ok(v) => v,
    };

    if let DiagServiceResponseType::Negative = response.response_type() {
        return api_error_from_diag_response(response).into_response();
    }

    match response_mime {
        Some(v) if v == mime::APPLICATION_OCTET_STREAM.essence_str() => {
            let data = response.get_raw().to_vec();
            (StatusCode::OK, Bytes::from_owner(data)).into_response()
        }
        _ => {
            let mapped_data = match response
                .into_json()
                .map_err(|e| ApiError::InternalServerError(Some(format!("{e:?}"))))
            {
                Err(e) => {
                    return ErrorWrapper(ApiError::InternalServerError(Some(format!(
                        "Failed to serialize response: {e:?}"
                    ))))
                    .into_response();
                }
                Ok(v) => v,
            };

            if mapped_data.is_null() {
                StatusCode::NO_CONTENT.into_response()
            } else {
                (
                    StatusCode::OK,
                    Json(SovdDataItem {
                        id: service_name.to_lowercase(),
                        data: mapped_data,
                    }),
                )
                    .into_response()
            }
        }
    }
}

fn get_payload_data<'a, T>(
    headers: &HeaderMap,
    body: &'a Bytes,
) -> Result<Option<UdsPayloadData>, ApiError>
where
    T: SovdPayload + serde::de::Deserialize<'a>,
{
    Ok(
        match headers.get(header::CONTENT_TYPE).map(|h| {
            h.to_str()
                .map_err(|e| ApiError::BadRequest(format!("Unable to read mime-type: {e:}")))
                .and_then(|s| {
                    s.parse::<mime::Mime>()
                        .map_err(|e| ApiError::BadRequest(format!("Invalid mime-type: {e:?}")))
                })
        }) {
            Some(Err(e)) => {
                return Err(e);
            }
            Some(Ok(v)) if v.essence_str() == mime::APPLICATION_JSON.essence_str() => {
                let sovd_request = serde_json::from_slice::<T>(body)
                    .map_err(|e| ApiError::BadRequest(format!("Invalid JSON: {e:?}")))?;
                Some(UdsPayloadData::ParameterMap(sovd_request.get_data_map()))
            }
            Some(Ok(v)) if v.essence_str() == mime::APPLICATION_OCTET_STREAM.essence_str() => {
                let content_length = headers
                    .get(header::CONTENT_LENGTH)
                    .ok_or_else(|| ApiError::BadRequest("Missing Content-Length".to_owned()))
                    .and_then(|v| {
                        v.to_str()
                            .map_err(|e| {
                                ApiError::BadRequest(format!("Invalid Content-Length: {e:?}"))
                            })
                            .and_then(|v| {
                                v.parse::<usize>().map_err(|e| {
                                    ApiError::BadRequest(format!("Invalid Content-Length: {e}"))
                                })
                            })
                    })?;

                if content_length == 0 {
                    return Ok(None);
                }

                Some(UdsPayloadData::Raw(body.to_vec()))
            }
            Some(Ok(v)) => {
                return Err(ApiError::BadRequest(format!(
                    "Unsupported mime-type: {v:?}"
                )));
            }

            _ => None,
        },
    )
}

#[derive(Deserialize, Serialize, Debug)]
struct SovdComponentData {
    items: Vec<SovdComponentItem>,
}

#[derive(Deserialize, Serialize, Debug)]
struct SovdComponentItem {
    category: String,
    id: String,
    name: String,
}

impl From<ComponentDataInfo> for SovdComponentItem {
    fn from(info: ComponentDataInfo) -> Self {
        SovdComponentItem {
            category: info.category,
            id: info.id,
            name: info.name,
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
struct SovdComponentConfigurations {
    items: Vec<SovdComponentConfigurationsItem>,
}

#[derive(Deserialize, Serialize, Debug)]
struct SovdComponentConfigurationsItem {
    pub id: String,
    pub name: String,
    pub configurations_type: String,

    #[serde(rename = "x-sovd2uds-ServiceAbstract")]
    pub service_abstract: Vec<String>,
}

impl From<ComponentConfigurationsInfo> for SovdComponentConfigurationsItem {
    fn from(info: ComponentConfigurationsInfo) -> Self {
        SovdComponentConfigurationsItem {
            id: info.id,
            name: info.name,
            configurations_type: info.configurations_type,
            service_abstract: info
                .service_abstract
                .iter()
                .map(|service_abstract| {
                    service_abstract
                        .iter()
                        .map(|byte| format!("{byte:02X}"))
                        .collect()
                })
                .collect(),
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
struct SovdExecutionRequestBody {
    timeout: Option<u32>,
    parameters: Option<HashMap<String, serde_json::Value>>,
}

impl SovdPayload for SovdExecutionRequestBody {
    fn get_data_map(&self) -> HashMap<String, serde_json::Value> {
        self.parameters
            .as_ref()
            .map_or(HashMap::new(), std::clone::Clone::clone)
    }
}

#[derive(Deserialize, Serialize, Debug)]
struct SovdDataItem {
    id: String,
    data: serde_json::Value,
}
