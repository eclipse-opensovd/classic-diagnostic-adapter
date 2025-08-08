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
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing,
};
use cda_interfaces::{
    UdsEcu,
    diagservices::{DiagServiceResponse, UdsPayloadData},
    file_manager::FileManager,
};
use error::{ApiError, ErrorWrapper, api_error_from_diag_response};
use hashbrown::HashMap;
use http::{Uri, header};
use indexmap::IndexMap;
use sovd_interfaces::components::ecu as sovd_ecu;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::sovd::{
    components::ecu::{
        configurations, data, genericservice, modes, operations, x_single_ecu_jobs,
        x_sovd2uds_bulk_data, x_sovd2uds_download,
    },
    locks::{LockType, Locks},
};

pub(crate) mod apps;
pub(crate) mod auth;
pub(crate) mod components;
pub(crate) mod error;
pub(crate) mod locks;

trait IntoSovd {
    type SovdType;
    fn into_sovd(self) -> Self::SovdType;
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
    comparam_executions: Arc<RwLock<IndexMap<Uuid, sovd_ecu::operations::comparams::Execution>>>,
    flash_data: Arc<RwLock<sovd_interfaces::sovd2uds::FileList>>,
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
    flash_data: Arc<RwLock<sovd_interfaces::sovd2uds::FileList>>,
}

pub(crate) fn resource_response(
    host: &str,
    uri: &Uri,
    resources: Vec<(&str, Option<&str>)>,
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

    let components = sovd_interfaces::ResourceResponse { items };
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

    let flash_data = Arc::new(RwLock::new(sovd_interfaces::sovd2uds::FileList {
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
                Json(sovd_interfaces::ResourceResponse {
                    items: ecus
                        .iter()
                        .map(|ecu| sovd_interfaces::Resource {
                            href: format!("http://localhost:20002/Vehicle/v15/components/{ecu}"),
                            id: Some(ecu.to_lowercase()),
                            name: ecu.clone(),
                        })
                        .collect::<Vec<sovd_interfaces::Resource>>(),
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
                routing::get(components::ecu::get)
                    .post(components::ecu::post)
                    .put(components::ecu::put),
            )
            .route(
                "/locks",
                routing::post(locks::ecu::post).get(locks::ecu::get),
            )
            .route(
                "/locks/{lock}",
                routing::delete(locks::ecu::lock::delete)
                    .put(locks::ecu::lock::put)
                    .get(locks::ecu::lock::get),
            )
            .route("/configurations", routing::get(configurations::get))
            .route(
                "/configurations/{diag_service}",
                routing::put(configurations::diag_service::put),
            )
            .route("/data", routing::get(data::get))
            .route(
                "/data/{diag_service}",
                routing::get(data::diag_service::get).put(data::diag_service::put),
            )
            .route("/genericservice", routing::put(genericservice::put))
            .route(
                "/operations/comparam/executions",
                routing::get(operations::comparams::executions::get)
                    .post(operations::comparams::executions::post),
            )
            .route(
                "/operations/comparam/executions/{id}",
                routing::get(operations::comparams::executions::id::get)
                    .delete(operations::comparams::executions::id::delete)
                    .put(operations::comparams::executions::id::put),
            )
            .route(
                "/operations/{service}/executions",
                routing::get(operations::service::executions::get)
                    .post(operations::service::executions::post),
            )
            .route("/modes", routing::get(modes::get))
            .route(
                "/modes/session",
                routing::get(modes::session::get).put(modes::session::put),
            )
            .route(
                "/modes/security",
                routing::get(modes::security::get).put(modes::security::put),
            )
            .route(
                "/x-single-ecu-jobs",
                routing::get(x_single_ecu_jobs::single_ecu::get),
            )
            .route(
                "/x-single-ecu-jobs/{name}",
                routing::get(x_single_ecu_jobs::single_ecu::name::get),
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
                routing::post(x_sovd2uds_download::flash_transfer::post)
                    .get(x_sovd2uds_download::flash_transfer::get),
            )
            .route(
                "/x-sovd2uds-download/flashtransfer/{id}",
                routing::get(x_sovd2uds_download::flash_transfer::id::get)
                    .delete(x_sovd2uds_download::flash_transfer::id::delete),
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
                routing::get(x_sovd2uds_bulk_data::mdd_embedded_files::id::get),
            )
            .with_state(ecu_state);
        router = router.nest(&ecu_path, nested);
    }
    router
        .route(
            "/vehicle/v15/locks",
            routing::post(locks::vehicle::post).get(locks::vehicle::get),
        )
        .route(
            "/vehicle/v15/locks/{lock}",
            routing::delete(locks::vehicle::lock::delete)
                .put(locks::vehicle::lock::put)
                .get(locks::vehicle::lock::get),
        )
        .route(
            "/vehicle/v15/functions/functionalgroups/{group}/locks",
            routing::post(locks::functional_group::post).get(locks::functional_group::get),
        )
        .route(
            "/vehicle/v15/functions/functionalgroups/{group}/locks/{lock}",
            routing::delete(locks::functional_group::lock::delete)
                .put(locks::functional_group::lock::put)
                .get(locks::functional_group::lock::get),
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
                    Json(
                        sovd_interfaces::apps::sovd2uds::data::network_structure::get::Response {
                            id: "networkstructure".to_owned(),
                            data: networkstructure_data,
                        },
                    ),
                )
                    .into_response()
            }),
        )
        .with_state(uds.clone())
}

fn get_payload_data<'a, T>(
    headers: &HeaderMap,
    body: &'a Bytes,
) -> Result<Option<UdsPayloadData>, ApiError>
where
    T: sovd_interfaces::Payload + serde::de::Deserialize<'a>,
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
