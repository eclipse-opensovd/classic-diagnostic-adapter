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

use aide::{
    axum::{ApiRouter as Router, routing},
    transform::TransformOperation,
};
use auth::authorize;
use axum::{
    Json,
    body::Bytes,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use cda_interfaces::{
    SchemaProvider, UdsEcu,
    diagservices::{DiagServiceResponse, UdsPayloadData},
    file_manager::FileManager,
};
use error::{ApiError, api_error_from_diag_response};
use hashbrown::HashMap;
use http::{Uri, header};
use indexmap::IndexMap;
use sovd_interfaces::{components::ecu as sovd_ecu, sovd2uds::FileList};
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

pub async fn route<R: DiagServiceResponse, T: UdsEcu + SchemaProvider + Clone, U: FileManager>(
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
    let mut router = Router::new().api_route(
        "/vehicle/v15/components",
        routing::get_with(
            || async move {
                (
                    StatusCode::OK,
                    Json(sovd_interfaces::ResourceResponse {
                        items: ecus
                            .iter()
                            .map(|ecu| sovd_interfaces::Resource {
                                href: format!(
                                    "http://localhost:20002/Vehicle/v15/components/{ecu}"
                                ),
                                id: Some(ecu.to_lowercase()),
                                name: ecu.clone(),
                            })
                            .collect::<Vec<sovd_interfaces::Resource>>(),
                    }),
                )
                    .into_response()
            },
            |op: TransformOperation| {
                op.description("Get a list of the available components with their paths")
                    .response_with::<200, Json<sovd_interfaces::ResourceResponse>, _>(|res| {
                        res.example(sovd_interfaces::ResourceResponse {
                            items: vec![sovd_interfaces::Resource {
                                href: "http://localhost:20002/Vehicle/v15/components/my_ecu".into(),
                                id: Some("my_ecu".into()),
                                name: "My ECU".into(),
                            }],
                        })
                    })
            },
        ),
    );

    for ecu_name in ecu_names.drain(0..) {
        let (ecu_path, nested) =
            ecu_route::<R, T, U>(&ecu_name, uds, &state, &flash_data, &mut file_manager);
        router = router.nest_api_service(&ecu_path, nested);
    }

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
        .api_route(
            "/vehicle/v15/functions/functionalgroups/{group}/locks",
            routing::post_with(
                locks::functional_group::post,
                locks::functional_group::docs_post,
            )
            .get_with(
                locks::functional_group::get,
                locks::functional_group::docs_get,
            ),
        )
        .api_route(
            "/vehicle/v15/functions/functionalgroups/{group}/locks/{lock}",
            routing::get_with(
                locks::functional_group::lock::get,
                locks::functional_group::lock::docs_get,
            )
            .put_with(
                locks::functional_group::lock::put,
                locks::functional_group::lock::docs_put,
            )
            .delete_with(
                locks::functional_group::lock::delete,
                locks::functional_group::lock::docs_delete,
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
        .route("/vehicle/v15/authorize", routing::post(authorize))
        .with_state(state)
        .api_route(
            "/vehicle/v15/apps/sovd2uds/data/networkstructure",
            routing::get_with(
                apps::sovd2uds::data::networkstructure::get::<T>,
                apps::sovd2uds::data::networkstructure::docs_get,
            ),
        )
        .with_state(uds.clone())
}

fn ecu_route<
    R: DiagServiceResponse,
    T: UdsEcu + SchemaProvider + Clone,
    U: FileManager + Send + Sync + Clone + 'static,
>(
    ecu_name: &str,
    uds: &T,
    state: &WebserverState,
    flash_data: &Arc<RwLock<FileList>>,
    file_manager: &mut HashMap<String, U>,
) -> (String, Router) {
    let ecu_lower = ecu_name.to_lowercase();
    let ecu_state = WebserverEcuState {
        ecu_name: ecu_lower.clone(),
        uds: uds.clone(),
        locks: Arc::<Locks>::clone(&state.locks),
        comparam_executions: Arc::new(RwLock::new(IndexMap::new())),
        flash_data: Arc::clone(flash_data),
        mdd_embedded_files: Arc::new(file_manager.remove(&ecu_lower).unwrap()),
        _phantom: std::marker::PhantomData::<R>,
    };
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
            "/configurations/{diag_service}",
            routing::put_with(
                configurations::diag_service::put,
                configurations::diag_service::docs_put,
            ),
        )
        .api_route("/data", routing::get_with(data::get, data::docs_get))
        .api_route(
            "/data/{diag_service}",
            routing::get_with(data::diag_service::get, data::diag_service::docs_get)
                .put_with(data::diag_service::put, data::diag_service::docs_put),
        )
        .api_route(
            "/genericservice",
            routing::put_with(genericservice::put, genericservice::docs_put),
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
        .api_route("/modes", routing::get_with(modes::get, modes::docs_get))
        .api_route(
            "/modes/session",
            routing::get_with(modes::session::get, modes::session::docs_get)
                .put_with(modes::session::put, modes::session::docs_put),
        )
        .api_route(
            "/modes/security",
            routing::get_with(modes::security::get, modes::security::docs_get)
                .put_with(modes::security::put, modes::security::docs_put),
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
        .with_state(ecu_state)
        .with_path_items(|op| op.tag(ecu_name));

    (ecu_path, router)
}

fn get_payload_data<'a, T>(
    content_type: Option<&mime::Mime>,
    headers: &HeaderMap,
    body: &'a Bytes,
) -> Result<Option<UdsPayloadData>, ApiError>
where
    T: sovd_interfaces::Payload + serde::de::Deserialize<'a>,
{
    let content_type = match content_type {
        Some(content_type) => content_type,
        None => return Ok(None),
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

    Ok(Some(UdsPayloadData::Raw(body.to_vec())))
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
                obj.insert($target_field.into(), $sub_schema.to_value());
                if let Some(mut errs) = obj.get_mut("errors") {
                    crate::sovd::remove_descriptions_recursive(&mut errs);
                }
            }
        }

        schema
    }};
}
pub(crate) use create_response_schema;
