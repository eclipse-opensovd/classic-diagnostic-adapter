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

use std::sync::Arc;

use aide::{UseApi, transform::TransformOperation};
use axum::{
    Json,
    extract::{OriginalUri, Path, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse as _, Response},
};
use axum_extra::extract::WithRejection;
use cda_interfaces::{
    HashMap, HashMapExtensions, UdsEcu, communication_control::CommunicationAccess,
    file_manager::FileManager,
};
use cda_plugin_security::Secured;
use indexmap::IndexMap;
use opensovd_axum_extra::ExtractHost;
use sovd_interfaces::components::ecu::operations::{ExecutionStatus, comparams as sovd_comparams};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::sovd::{
    ComparamExecution, IntoSovd, WebserverEcuState, acquire_communication_activity, create_schema,
    error::{ApiError, ErrorWrapper},
    locks::require_ecu_access,
};

pub(crate) mod id;
#[cfg(test)]
mod tests;

pub(crate) async fn get<T: UdsEcu + Clone, U: FileManager>(
    UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
    WithRejection(Query(query), _): WithRejection<
        Query<sovd_comparams::executions::get::Query>,
        ApiError,
    >,
    State(WebserverEcuState {
        ecu_name,
        locks,
        comparam_executions,
        ..
    }): State<WebserverEcuState<T, U>>,
) -> Response {
    require_ecu_access!(
        read,
        security_plugin,
        &ecu_name,
        &locks,
        query.include_schema
    );
    handler_read(comparam_executions, query.include_schema).await
}

pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
    op.description("Get all comparam executions")
        .response_with::<200, Json<sovd_comparams::executions::get::Response>, _>(|res| {
            res.description("Response with all comparam executions.")
                .example(sovd_comparams::executions::get::Response {
                    items: vec![sovd_comparams::executions::Item {
                        id: "b7e2c1a2-3f4d-4e6a-9c8b-2a1d5e7f8c9b".to_string(),
                    }],
                    schema: None,
                })
        })
}

pub(crate) async fn post<T: UdsEcu + Clone, U: FileManager>(
    UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
    WithRejection(Query(query), _): WithRejection<
        Query<sovd_comparams::executions::get::Query>,
        ApiError,
    >,
    State(WebserverEcuState {
        ecu_name,
        locks,
        comparam_executions,
        communication_access,
        ..
    }): State<WebserverEcuState<T, U>>,
    UseApi(ExtractHost(host), _): UseApi<ExtractHost, String>,
    OriginalUri(uri): OriginalUri,
    request_body: Option<Json<sovd_comparams::executions::update::Request>>,
) -> Response {
    require_ecu_access!(
        write,
        security_plugin,
        &ecu_name,
        &locks,
        query.include_schema
    );
    let path = format!("http://{host}{uri}");
    let body = if let Some(Json(body)) = request_body {
        Some(body)
    } else {
        None
    };
    handler_write(
        comparam_executions,
        communication_access,
        path,
        body,
        query.include_schema,
    )
    .await
}

pub(crate) fn docs_post(op: TransformOperation) -> TransformOperation {
    op.description("Create a new comparam execution")
        .response_with::<202, Json<sovd_comparams::executions::update::Response>, _>(|res| {
            res.description("Comparam execution created successfully.")
                .example(sovd_comparams::executions::update::Response {
                    id: "b7e2c1a2-3f4d-4e6a-9c8b-2a1d5e7f8c9b".to_string(),
                    status: ExecutionStatus::Running,
                    schema: None,
                })
        })
}

pub(crate) async fn handler_read(
    executions: Arc<RwLock<IndexMap<Uuid, ComparamExecution>>>,
    include_schema: bool,
) -> Response {
    let schema = if include_schema {
        Some(create_schema!(sovd_comparams::executions::get::Response))
    } else {
        None
    };
    (
        StatusCode::OK,
        Json(sovd_comparams::executions::get::Response {
            items: executions
                .read()
                .await
                .keys()
                .map(|id| sovd_comparams::executions::Item { id: id.to_string() })
                .collect::<Vec<_>>(),
            schema,
        }),
    )
        .into_response()
}
async fn handler_write(
    executions: Arc<RwLock<IndexMap<Uuid, ComparamExecution>>>,
    communication_access: Arc<dyn CommunicationAccess>,
    base_path: String,
    request: Option<sovd_comparams::executions::update::Request>,
    include_schema: bool,
) -> Response {
    // todo: not in scope for now: request can take body with
    // { timeout: INT, parameters: { ... }, proximity_response: STRING }
    let communication_activity = match acquire_communication_activity(&*communication_access) {
        Ok(activity) => activity,
        Err(error) => {
            return ErrorWrapper {
                error,
                include_schema,
            }
            .into_response();
        }
    };
    let id = Uuid::new_v4();
    let mut comparam_override: HashMap<String, sovd_comparams::ComParamValue> = HashMap::new();

    if let Some(sovd_comparams::executions::update::Request {
        parameters: Some(parameters),
        ..
    }) = request
    {
        for (k, v) in parameters {
            comparam_override.insert(k, v);
        }
    }

    let schema = if include_schema {
        Some(create_schema!(sovd_comparams::executions::update::Response))
    } else {
        None
    };

    let create_execution_response = sovd_comparams::executions::update::Response {
        id: id.to_string(),
        status: ExecutionStatus::Running,
        schema,
    };
    // Publish the lease before the execution becomes observable to DELETE.
    let mut executions = executions.write().await;
    executions.insert(
        id,
        ComparamExecution::new(
            sovd_comparams::Execution {
                capability: sovd_comparams::executions::Capability::Execute,
                status: create_execution_response.status.clone(),
                comparam_override,
            },
            communication_activity,
        ),
    );
    (
        StatusCode::ACCEPTED,
        [(header::LOCATION, format!("{base_path}/{id}"))],
        Json(create_execution_response),
    )
        .into_response()
}
